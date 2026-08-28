//! Path MTU: can full-size packets get through unfragmented?
//!
//! The classic invisible fault: ping is perfect, small pages load, and then
//! large downloads, uploads and VPNs stall. A PPPoE line (MTU 1492), a tunnel
//! (1400-ish) or a misconfigured router leaves the path narrower than the
//! interface, and if the ICMP "fragmentation needed" messages that would tell
//! the sender never arrive — a firewall dropping all ICMP is the usual reason —
//! every full-size packet silently disappears. That is a *PMTU black hole*,
//! and nothing else in octomon would ever see it.
//!
//! The probe sends UDP datagrams with the Don't-Fragment bit set and finds the
//! largest that is answered. The datagram is a QUIC long-header packet with a
//! deliberately unsupported version: any QUIC server (Cloudflare's and Google's
//! resolvers speak it on 443) must answer one of at least 1200 bytes with a
//! Version Negotiation packet — a guaranteed reply of a few dozen bytes, from a
//! host that is not asked to do anything else, over plain UDP with no
//! privilege. That fixes the floor of the search at 1228 bytes on the wire,
//! which covers every real path (IPv6 mandates 1280; PPPoE is 1492; tunnels
//! 1280–1420).
//!
//! What it does when a big probe times out is the diagnostic part: it sends
//! the same size again. If the kernel now refuses (`EMSGSIZE`), a
//! "fragmentation needed" arrived in between and path-MTU discovery is working
//! — the path is just narrower, which is fine and worth knowing. If the second
//! send also vanishes, nothing told the kernel: a black hole at that size.
//!
//! Where the OS does not honour DF for unprivileged sockets — current macOS
//! fragments regardless, its own `ping -D` included — the probe detects that
//! (an over-MTU datagram is answered) and reports the check as unavailable
//! rather than inventing a number. Linux honours `IP_PMTUDISC_DO`. Windows
//! (`IP_DONTFRAGMENT`) is not wired yet; see TODO.md.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::app::{AppState, PmtuResult};

/// Delay after startup / network change before probing: let discovery and the
/// interface details land first.
const SETTLE: Duration = Duration::from_secs(8);
/// Re-probe cadence when nothing changed; MTUs don't move on their own.
const PERIOD: Duration = Duration::from_secs(30 * 60);

pub async fn run(
    state: Arc<Mutex<AppState>>,
    cfg: crate::config::Config,
    changed: Arc<tokio::sync::Notify>,
) {
    let host = cfg.pmtu_probe_host.trim().to_string();
    if host.is_empty() {
        return;
    }
    loop {
        tokio::time::sleep(SETTLE).await;
        let (iface_mtu, available) = {
            let s = state.lock().unwrap();
            (s.netinfo.mtu, !s.link_lost && !s.netinfo.iface.is_empty())
        };
        // A QUIC-speaking host: the probe relies on the version-negotiation
        // answer, so it cannot be just any ping target.
        let target = match tokio::net::lookup_host((host.as_str(), QUIC_PORT)).await {
            Ok(mut addrs) => addrs.find_map(|a| match a.ip() {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            }),
            Err(_) => None,
        };
        // While the path is dropping a large share of *small* packets, a
        // timeout-read DF probe cannot tell size from loss, and a "black
        // hole" measured now would stick for the whole re-probe period.
        // Defer and retry once the weather clears.
        if available && let Some(target) = target {
            use crate::verdict::thresholds as th;
            let loss = {
                let s = state.lock().unwrap();
                s.targets
                    .iter()
                    .find(|t| t.addr == IpAddr::V4(target) && t.window.len() >= th::MIN_SAMPLES)
                    .map(|t| t.recent_loss_pct(th::RECENT))
            };
            if loss.is_some_and(|l| l >= th::PMTU_LOSS_GATE_PCT) {
                {
                    let mut s = state.lock().unwrap();
                    if s.pmtu.is_none() {
                        s.pmtu_error = Some("deferred — the path is dropping packets".to_string());
                    }
                }
                tokio::select! {
                    _ = changed.notified() => {}
                    _ = tokio::time::sleep(Duration::from_secs(120)) => {}
                }
                continue;
            }
            let result = tokio::task::spawn_blocking(move || probe(target, iface_mtu))
                .await
                .unwrap_or_else(|e| Err(e.to_string()));
            let mut s = state.lock().unwrap();
            match result {
                Ok(r) => {
                    s.pmtu = Some(r);
                    s.pmtu_error = None;
                }
                Err(e) => {
                    tracing::debug!("pmtu probe: {e}");
                    crate::errlog::log("pmtu", format!("probe toward {target} failed: {e}"));
                    s.pmtu = None;
                    s.pmtu_error = Some(e);
                }
            }
        }
        tokio::select! {
            _ = changed.notified() => {}
            _ = tokio::time::sleep(PERIOD) => {}
        }
    }
}

/// Smallest size worth searching down to: the smallest datagram a QUIC server
/// must answer (1200 bytes) plus IP and UDP headers.
#[cfg(unix)]
const FLOOR: u32 = 1228;
#[cfg(unix)]
const REPLY_WAIT: Duration = Duration::from_millis(1500);
/// QUIC's port at the probe hosts.
const QUIC_PORT: u16 = 443;

#[cfg(unix)]
fn probe(target: std::net::Ipv4Addr, iface_mtu: Option<u32>) -> Result<PmtuResult, String> {
    use std::io::ErrorKind;
    let sock = DfSocket::open(target)?;
    // Where to start: the interface MTU, else the Ethernet default.
    let top = iface_mtu.unwrap_or(1500).clamp(FLOOR, 9000);

    // Does this OS honour DF at all for an unprivileged socket? A datagram
    // larger than the interface can carry must be refused or vanish; if it is
    // *answered*, the kernel fragmented it and every result below would be
    // fiction. Say so instead.
    if let Ok(true) = sock.send_probe(top + 400) {
        return Err(
            "this OS fragments despite Don't-Fragment on unprivileged sockets — path MTU cannot be measured here"
                .to_string(),
        );
    }

    // A probe at one total packet size, with the DF bit set.
    let send = |size: u32| -> Result<Outcome, String> {
        match sock.send_probe(size) {
            Ok(true) => Ok(Outcome::Reply),
            Ok(false) => Ok(Outcome::Timeout),
            Err(e) if e.raw_os_error() == Some(libc::EMSGSIZE) => Ok(Outcome::TooBig),
            // Some stacks report the learned MTU as "message too long" under
            // a different errno; treat any size-shaped error the same way.
            Err(e) if e.kind() == ErrorKind::InvalidInput => Ok(Outcome::TooBig),
            Err(e) => Err(e.to_string()),
        }
    };

    let mut blackhole = false;
    let mut pmtud_works = false;
    match send(top)? {
        Outcome::Reply => {
            return Ok(PmtuResult {
                target: IpAddr::V4(target),
                iface_mtu,
                path_mtu: Some(top),
                blackhole: false,
                pmtud_works: true,
            });
        }
        // The kernel already knows the path is narrower (learned earlier).
        Outcome::TooBig => pmtud_works = true,
        Outcome::Timeout => {
            // The tell: does the same size now bounce off a learned MTU?
            match send(top)? {
                Outcome::TooBig => pmtud_works = true,
                Outcome::Reply => {
                    // A lost packet, nothing more.
                    return Ok(PmtuResult {
                        target: IpAddr::V4(target),
                        iface_mtu,
                        path_mtu: Some(top),
                        blackhole: false,
                        pmtud_works: true,
                    });
                }
                Outcome::Timeout => blackhole = true,
            }
        }
    }

    // Binary search for the largest size that is answered. When PMTUD works
    // the misses are instant (EMSGSIZE); in a black hole each miss costs a
    // reply timeout, so the search is bounded to a handful of steps.
    let (mut lo, mut hi) = (FLOOR, top - 1);
    let mut best: Option<u32>;
    if matches!(send(lo)?, Outcome::Reply) {
        best = Some(lo);
    } else {
        // Not even the floor gets through: the path is broken in a way this
        // probe cannot size. Report what is known.
        return Ok(PmtuResult {
            target: IpAddr::V4(target),
            iface_mtu,
            path_mtu: None,
            blackhole,
            pmtud_works,
        });
    }
    let mut steps = 0;
    while lo < hi && steps < 12 {
        steps += 1;
        let mid = lo + (hi - lo).div_ceil(2);
        match send(mid)? {
            Outcome::Reply => {
                best = Some(mid);
                lo = mid;
            }
            Outcome::TooBig | Outcome::Timeout => {
                hi = mid - 1;
            }
        }
    }
    Ok(PmtuResult {
        target: IpAddr::V4(target),
        iface_mtu,
        path_mtu: best,
        blackhole,
        pmtud_works,
    })
}

#[cfg(not(unix))]
fn probe(_target: std::net::Ipv4Addr, _iface_mtu: Option<u32>) -> Result<PmtuResult, String> {
    Err("path-MTU probe not implemented on this platform".to_string())
}

#[cfg(unix)]
enum Outcome {
    Reply,
    Timeout,
    TooBig,
}

/// A UDP socket with Don't-Fragment set, connected to the probe host's QUIC
/// port. Blocking, with a receive timeout; runs on a blocking thread.
#[cfg(unix)]
struct DfSocket {
    sock: socket2::Socket,
}

#[cfg(unix)]
impl DfSocket {
    fn open(target: std::net::Ipv4Addr) -> Result<Self, String> {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::os::fd::AsRawFd;
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| format!("udp socket: {e}"))?;
        sock.set_read_timeout(Some(REPLY_WAIT))
            .map_err(|e| e.to_string())?;
        // Don't-Fragment. Linux: path-MTU discovery mode "DO" — set DF and let
        // the kernel enforce whatever MTU it has learned for the route, which
        // is what makes the second send after a timeout informative. macOS /
        // BSD: the plain DF flag (honoured or not; the caller checks).
        let fd = sock.as_raw_fd();
        // SAFETY: setsockopt on a socket this function owns, with a correctly
        // sized int option value; the pointer does not outlive the call.
        let rc = unsafe {
            #[cfg(target_os = "linux")]
            {
                let val: libc::c_int = libc::IP_PMTUDISC_DO;
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_MTU_DISCOVER,
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            }
            #[cfg(not(target_os = "linux"))]
            {
                let val: libc::c_int = 1;
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_DONTFRAG,
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            }
        };
        if rc != 0 {
            return Err(format!(
                "cannot set DF: {}",
                std::io::Error::last_os_error()
            ));
        }
        let dest = std::net::SocketAddr::new(IpAddr::V4(target), QUIC_PORT);
        sock.connect(&dest.into()).map_err(|e| e.to_string())?;
        Ok(Self { sock })
    }

    /// One probe of `total` bytes on the wire (IP header included). `Ok(true)`
    /// answered, `Ok(false)` timed out, `Err` for a send failure — EMSGSIZE
    /// being the interesting one.
    fn send_probe(&self, total: u32) -> std::io::Result<bool> {
        use std::io::{Read, Write};
        let payload = total.saturating_sub(20 + 8) as usize;
        let pkt = quic_probe(payload);
        (&self.sock).write_all(&pkt)?;

        let deadline = std::time::Instant::now() + REPLY_WAIT;
        let mut buf = [0u8; 2048];
        loop {
            if std::time::Instant::now() >= deadline {
                return Ok(false);
            }
            match (&self.sock).read(&mut buf) {
                Ok(n) if is_version_negotiation(&buf[..n]) => return Ok(true),
                Ok(_) => continue, // something else on the socket; keep waiting
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(false);
                }
                // A connected UDP socket surfaces ICMP errors here (port
                // unreachable → refused; fragmentation needed → EMSGSIZE).
                Err(e) => return Err(e),
            }
        }
    }
}

/// A QUIC long-header packet with an unsupported version, padded to `len`
/// bytes: the one datagram every QUIC server must answer without a handshake
/// (RFC 9000 §6 — Version Negotiation). Versions of the form 0x?a?a?a?a are
/// reserved for exactly this purpose.
pub fn quic_probe(len: usize) -> Vec<u8> {
    let mut p = Vec::with_capacity(len.max(23));
    p.push(0xc0); // long header, fixed bit, type Initial
    p.extend_from_slice(&[0x1a, 0x2a, 0x3a, 0x4a]);
    // Connection ids: 8 bytes each, from the clock so they are not constant.
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x5eed);
    p.push(8);
    p.extend_from_slice(&nonce.to_be_bytes());
    p.push(8);
    p.extend_from_slice(&nonce.rotate_left(29).to_be_bytes());
    p.resize(len.max(p.len()), 0);
    p
}

/// A Version Negotiation packet: long header with version 0.
pub fn is_version_negotiation(b: &[u8]) -> bool {
    b.len() >= 5 && b[0] & 0x80 != 0 && b[1..5] == [0, 0, 0, 0]
}

/// One line for the Network panel / doctor: "path 1492 (iface 1500)".
pub fn describe(r: &PmtuResult) -> String {
    let path = r
        .path_mtu
        .map(|m| m.to_string())
        .unwrap_or_else(|| "<576".to_string());
    let iface = r
        .iface_mtu
        .map(|m| format!(" (iface {m})"))
        .unwrap_or_default();
    if r.blackhole {
        format!("path {path}{iface} · BLACK HOLE — big packets vanish silently")
    } else {
        format!("path {path}{iface}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_probe_is_a_padded_unsupported_version_quic_packet() {
        let p = quic_probe(1200);
        assert_eq!(p.len(), 1200);
        assert_eq!(p[0] & 0xc0, 0xc0, "long header + fixed bit");
        assert_eq!(&p[1..5], &[0x1a, 0x2a, 0x3a, 0x4a]);
        assert!(is_version_negotiation(&[0x80, 0, 0, 0, 0, 1, 2]));
        assert!(!is_version_negotiation(&[0x40, 0, 0, 0, 0]), "short header");
        assert!(
            !is_version_negotiation(&[0xc0, 0, 0, 0, 1]),
            "a real version"
        );
    }

    /// Against the real network. `cargo test -- --ignored --nocapture live_pmtu`.
    /// On macOS this reports "cannot be measured" (DF is not honoured), which
    /// is itself the behaviour under test.
    #[cfg(unix)]
    #[test]
    #[ignore = "requires network access"]
    fn live_pmtu() {
        match probe(std::net::Ipv4Addr::new(1, 1, 1, 1), Some(1500)) {
            Ok(r) => {
                println!("{}", describe(&r));
                assert!(r.path_mtu.is_some_and(|m| m >= FLOOR));
            }
            Err(e) => println!("unavailable: {e}"),
        }
    }
}
