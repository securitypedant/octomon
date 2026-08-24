//! DNS resolver responsiveness.
//!
//! Slow DNS is one of the most common causes of "the internet feels broken",
//! and it is invisible to ICMP: a resolver can answer pings in 2ms while taking
//! 800ms to return an answer. This probes each resolver the interface reports,
//! so a bad one is attributable rather than just felt.
//!
//! Queries are built by hand (a DNS question is ~30 bytes) to avoid pulling in a
//! full resolver stack for a latency measurement.
//!
//! Two things beyond latency, because "the resolver answers" is not the same as
//! "the resolver is honest":
//!
//! - **Reference resolver.** A public resolver (`dns_reference_resolver`,
//!   default 1.1.1.1) is probed alongside the system ones. When yours fail and
//!   it works, the fix is "change DNS"; when it fails and yours work, this
//!   network is forcing its own DNS (port 53 to the outside is filtered) —
//!   two different situations that plain resolver latency cannot tell apart.
//! - **Hijack check.** Once a minute each resolver is asked for a name that
//!   cannot exist (`<random>.<probe name>`). The honest answer is NXDOMAIN; an
//!   IP address back means the resolver is redirecting misses to a search or
//!   ad page — ISP "assistance", or a captive network. That silently breaks
//!   anything that relies on a name *not* resolving.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use crate::app::{AppState, DnsProbe};
use crate::config::Config;

/// Ticks between hijack checks per resolver: at the default 5 s interval, a
/// minute. The check is a second query on that tick, so it never displaces a
/// latency sample.
const HIJACK_EVERY: u32 = 12;

pub async fn run(state: Arc<Mutex<AppState>>, cfg: Config) {
    let mut ticker = tokio::time::interval(cfg.dns_interval());
    let name = sanitise_name(&cfg.dns_probe_name);
    let reference = cfg.dns_reference_resolver.trim().parse::<IpAddr>().ok();
    let mut id: u16 = 0;
    let mut tick: u32 = 0;

    loop {
        ticker.tick().await;
        tick = tick.wrapping_add(1);

        // Follow whatever resolvers the current interface reports; these change
        // when the network does, or when a VPN installs its own proxy.
        let (mut servers, scope): (Vec<IpAddr>, u32) = {
            let s = state.lock().unwrap();
            (canonical_servers(&s.netinfo.dns), s.netinfo.iface_index)
        };
        if servers.is_empty() {
            state.lock().unwrap().dns.clear();
            continue;
        }
        // The reference rides along unless it *is* one of the system resolvers,
        // in which case that row already answers the question — and counts as
        // a resolver, not as the reference: a network whose DHCP hands out
        // 1.1.1.1 has 1.1.1.1 as *its* resolver, and marking it "reference"
        // would make every "this network's resolvers" count come up short.
        let system = servers.clone();
        if let Some(r) = reference
            && !servers.contains(&r)
        {
            servers.push(r);
        }

        for server in servers.iter().copied() {
            id = id.wrapping_add(1);
            let started = Instant::now();
            let outcome = query(server, scope, &name, id, cfg.dns_timeout()).await;
            let elapsed = started.elapsed().as_secs_f64() * 1000.0;

            // Once a minute — and straight away for a resolver with no verdict
            // yet — the name that must not exist.
            let unjudged = state
                .lock()
                .unwrap()
                .dns
                .iter()
                .find(|p| p.server == server)
                .is_none_or(|p| p.hijack.is_none());
            let hijack = if tick % HIJACK_EVERY == 1 || unjudged {
                id = id.wrapping_add(1);
                let nx = nonexistent_name(&name, id);
                Some(query(server, scope, &nx, id, cfg.dns_timeout()).await)
            } else {
                None
            };

            let mut s = state.lock().unwrap();
            // Keep history across ticks, and drop probes for resolvers that are
            // no longer configured.
            let idx = match s.dns.iter().position(|p| p.server == server) {
                Some(i) => i,
                None => {
                    s.dns.push(DnsProbe::new(server));
                    s.dns.len() - 1
                }
            };
            let probe = &mut s.dns[idx];
            // Re-judged every tick, not just at creation: a resolver-set
            // change (DHCP renewal, VPN) can move the reference address in
            // or out of the system list while the probe lives on.
            probe.reference = reference == Some(server) && !system.contains(&server);
            match outcome {
                Ok(answers) => {
                    probe.record(Some(elapsed));
                    // An empty answer still proves the resolver is alive, but it
                    // is worth distinguishing from a real result.
                    probe.status = if answers == 0 {
                        "no answer".to_string()
                    } else {
                        String::new()
                    };
                }
                Err(reason) => {
                    probe.record(None);
                    probe.status = reason;
                }
            }
            if let Some(verdict) = hijack.and_then(|r| classify_hijack(&r)) {
                probe.hijack = Some(verdict);
            }
        }

        // Forget resolvers that dropped out of the configuration.
        let mut s = state.lock().unwrap();
        let mut live = canonical_servers(&s.netinfo.dns);
        if let Some(r) = reference {
            live.push(r);
        }
        s.dns.retain(|p| live.contains(&p.server));
    }
}

/// A name under the probe domain that cannot exist. The label mixes the query
/// id with the clock so a resolver cannot have it cached from an earlier run.
fn nonexistent_name(base: &str, id: u16) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("octomon-nx-{id:04x}{nanos:08x}.{base}")
}

/// What an answer to the nonexistent name means. `Some(true)` is a hijack:
/// an address for a name that has none. `Some(false)` is honest (NXDOMAIN, or
/// an empty answer). `None` when the query itself failed — no opinion.
pub fn classify_hijack(outcome: &Result<u16, String>) -> Option<bool> {
    match outcome {
        Ok(answers) if *answers > 0 => Some(true),
        Ok(_) => Some(false),
        Err(e) if e == "NXDOMAIN" => Some(false),
        Err(_) => None,
    }
}

/// The interface's resolver list as probeable addresses: IPv4-mapped IPv6
/// forms (`::ffff:127.0.2.2` — Windows DNS filters register both spellings)
/// unmap to their embedded IPv4, and the resulting duplicates collapse, so
/// two real resolvers don't render as four scary rows.
fn canonical_servers(configured: &[String]) -> Vec<IpAddr> {
    let mut seen = Vec::new();
    for d in configured {
        let Ok(addr) = d.parse::<IpAddr>() else {
            continue;
        };
        let addr = match addr {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            },
            v4 => v4,
        };
        if !seen.contains(&addr) {
            seen.push(addr);
        }
    }
    seen
}

/// Send one A query and time the answer. `scope` is the interface index a
/// link-local v6 resolver needs — carrier hotspots hand out `fe80::…` as the
/// DNS server, and without the scope every packet fails with "no route to
/// host" even though resolution works fine for the system.
async fn query(
    server: IpAddr,
    scope: u32,
    name: &str,
    id: u16,
    timeout: Duration,
) -> Result<u16, String> {
    let bind: SocketAddr = match server {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let sock = UdpSocket::bind(bind).await.map_err(|e| short(&e))?;
    let dest: SocketAddr = match server {
        IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80 => {
            std::net::SocketAddrV6::new(v6, 53, 0, scope).into()
        }
        other => SocketAddr::new(other, 53),
    };
    sock.connect(dest).await.map_err(|e| short(&e))?;

    let packet = build_query(id, name);
    sock.send(&packet).await.map_err(|e| short(&e))?;

    let mut buf = [0u8; 512];
    let read = tokio::time::timeout(timeout, sock.recv(&mut buf))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| short(&e))?;
    parse_response(id, &buf[..read])
}

/// Compact reason for a probe failure. OS error strings are long and get
/// clipped mid-word ("not valid in it"); the kind carries the meaning.
fn short(e: &std::io::Error) -> String {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::ConnectionRefused => "refused".to_string(),
        ErrorKind::ConnectionReset => "connection reset".to_string(),
        ErrorKind::AddrNotAvailable => "address not usable".to_string(),
        ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable => "unreachable".to_string(),
        ErrorKind::PermissionDenied => "permission denied".to_string(),
        ErrorKind::TimedOut => "timeout".to_string(),
        _ => e.to_string().chars().take(28).collect(),
    }
}

/// A resolver-probe name has to be a valid QNAME; fall back rather than send a
/// malformed question that every resolver would reject identically.
fn sanitise_name(name: &str) -> String {
    let trimmed = name.trim().trim_end_matches('.');
    let ok = !trimmed.is_empty()
        && trimmed.len() <= 253
        && trimmed
            .split('.')
            .all(|l| !l.is_empty() && l.len() <= 63 && l.is_ascii());
    if ok {
        trimmed.to_string()
    } else {
        "example.com".to_string()
    }
}

/// A standard recursive A/IN query. Wire format per RFC 1035 §4.
fn build_query(id: u16, name: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(32 + name.len());
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, recursion desired
    p.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    p.extend_from_slice(&[0u8; 6]); // ancount / nscount / arcount
    for label in name.split('.').filter(|l| !l.is_empty()) {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0); // root label
    p.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    p.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
    p
}

/// Validate the header and return the answer count. Only the header is read —
/// the measurement is the round trip, not the address.
fn parse_response(id: u16, buf: &[u8]) -> Result<u16, String> {
    if buf.len() < 12 {
        return Err("short reply".to_string());
    }
    if u16::from_be_bytes([buf[0], buf[1]]) != id {
        // A stale reply to an earlier query; treat as unanswered rather than
        // crediting this query with someone else's round trip.
        return Err("id mismatch".to_string());
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 == 0 {
        return Err("not a reply".to_string());
    }
    match flags & 0x000f {
        0 => Ok(u16::from_be_bytes([buf[6], buf[7]])),
        1 => Err("FORMERR".to_string()),
        2 => Err("SERVFAIL".to_string()),
        3 => Err("NXDOMAIN".to_string()),
        4 => Err("NOTIMP".to_string()),
        5 => Err("REFUSED".to_string()),
        other => Err(format!("rcode {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_is_well_formed() {
        let p = build_query(0xbeef, "example.com");
        assert_eq!(&p[0..2], &[0xbe, 0xef]); // id
        assert_eq!(&p[2..4], &[0x01, 0x00]); // RD set
        assert_eq!(&p[4..6], &[0x00, 0x01]); // one question
        // Labels are length-prefixed and root-terminated.
        assert_eq!(&p[12..20], b"\x07example");
        assert_eq!(&p[20..24], b"\x03com");
        assert_eq!(&p[24..], &[0, 0, 1, 0, 1]); // root, qtype A, qclass IN
    }

    #[test]
    fn response_header_is_validated() {
        let mut ok = vec![0u8; 12];
        ok[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        ok[2..4].copy_from_slice(&0x8180u16.to_be_bytes()); // response, NOERROR
        ok[6..8].copy_from_slice(&2u16.to_be_bytes()); // two answers
        assert_eq!(parse_response(0x1234, &ok), Ok(2));

        // A reply to a different query must not be credited to this one.
        assert!(parse_response(0x9999, &ok).is_err());

        let mut servfail = ok.clone();
        servfail[2..4].copy_from_slice(&0x8182u16.to_be_bytes());
        assert_eq!(parse_response(0x1234, &servfail), Err("SERVFAIL".into()));

        assert!(parse_response(0x1234, &[0u8; 4]).is_err());
    }

    /// The Windows DNS-filter shape: `::ffff:127.0.2.2` alongside `127.0.2.2`.
    /// The mapped form must unmap (a v6 socket can't reach it) and the
    /// duplicates must collapse — two real resolvers, not four scary rows.
    #[test]
    fn mapped_v6_resolvers_unmap_and_deduplicate() {
        let configured: Vec<String> = [
            "::ffff:127.0.2.2",
            "::ffff:127.0.2.3",
            "127.0.2.2",
            "127.0.2.3",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let servers = canonical_servers(&configured);
        assert_eq!(servers.len(), 2);
        assert!(servers.iter().all(|a| a.is_ipv4() && a.is_loopback()));

        // Real v6 resolvers stay v6; order is preserved.
        let mixed: Vec<String> = ["2606:4700:4700::1111", "1.1.1.1"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let servers = canonical_servers(&mixed);
        assert_eq!(servers.len(), 2);
        assert!(servers[0].is_ipv6());
    }

    #[test]
    fn failure_reasons_are_compact_words_not_clipped_prose() {
        use std::io::{Error, ErrorKind};
        assert_eq!(
            short(&Error::from(ErrorKind::ConnectionReset)),
            "connection reset"
        );
        assert_eq!(
            short(&Error::from(ErrorKind::AddrNotAvailable)),
            "address not usable"
        );
        assert_eq!(short(&Error::from(ErrorKind::ConnectionRefused)), "refused");
    }

    #[test]
    fn hijack_is_an_address_for_a_name_that_has_none() {
        assert_eq!(classify_hijack(&Ok(1)), Some(true));
        assert_eq!(classify_hijack(&Ok(0)), Some(false));
        assert_eq!(classify_hijack(&Err("NXDOMAIN".into())), Some(false));
        assert_eq!(classify_hijack(&Err("timeout".into())), None);
        // The probe name is fresh every time and sits under the base name.
        let a = nonexistent_name("example.com", 1);
        let b = nonexistent_name("example.com", 2);
        assert!(a.ends_with(".example.com") && a != b);
    }

    #[test]
    fn probe_names_are_sanitised() {
        assert_eq!(sanitise_name("cloudflare.com"), "cloudflare.com");
        assert_eq!(sanitise_name(" example.com. "), "example.com");
        // Malformed names fall back rather than producing a bad question.
        assert_eq!(sanitise_name(""), "example.com");
        assert_eq!(sanitise_name("a..b"), "example.com");
        assert_eq!(sanitise_name(&"x".repeat(64)), "example.com");
        assert_eq!(sanitise_name("über.com"), "example.com");
    }

    /// Against the machine's real resolvers. Ignored — needs the network.
    /// `cargo test -- --ignored --nocapture live_dns`
    #[tokio::test]
    #[ignore = "requires network access"]
    async fn live_dns() {
        for server in ["1.1.1.1", "8.8.8.8"] {
            let ip: IpAddr = server.parse().unwrap();
            let started = Instant::now();
            let r = query(ip, 0, "example.com", 1, Duration::from_secs(2)).await;
            println!(
                "{server}: {:?} in {:.1}ms",
                r,
                started.elapsed().as_secs_f64() * 1000.0
            );
            assert!(r.is_ok(), "{server} failed: {r:?}");
        }
    }
}
