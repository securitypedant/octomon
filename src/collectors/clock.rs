//! Is the system clock right? — the invisible cause of "every HTTPS site is
//! broken" while ping and DNS are perfect. TLS certificate validity is checked
//! against local time, so a clock hours or days out makes browsers reject
//! every certificate; a clock minutes out breaks OCSP/2FA-style checks. No
//! other measurement in octomon would ever point at it.
//!
//! One SNTP exchange (RFC 4330) with a public time server gives the offset to
//! millisecond precision. When UDP 123 is filtered, the HTTP reachability probe
//! supplies a coarser reading from the `Date` header it already receives; see
//! [`crate::collectors::http`]. Whichever answered most recently is what the
//! analysis reads.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;

use crate::app::AppState;

/// Between checks; the clock does not drift fast, and time servers are shared.
const PERIOD: Duration = Duration::from_secs(15 * 60);
const TIMEOUT: Duration = Duration::from_secs(3);
/// Seconds between the NTP epoch (1900) and the Unix epoch (1970).
const NTP_UNIX_DELTA: f64 = 2_208_988_800.0;

/// One SNTP result: how far the local clock is from the server's, signed
/// (positive = local clock ahead), and the exchange's round trip.
#[derive(Clone, Copy, Debug)]
pub struct NtpReading {
    pub offset_ms: f64,
    pub rtt_ms: f64,
}

pub async fn run(
    state: Arc<Mutex<AppState>>,
    cfg: crate::config::Config,
    changed: Arc<tokio::sync::Notify>,
) {
    let server = cfg.ntp_server.trim().to_string();
    if server.is_empty() {
        return;
    }
    // Let the network settle before the first exchange.
    tokio::time::sleep(Duration::from_secs(4)).await;
    loop {
        let result = consensus(&server).await;
        {
            let mut s = state.lock().unwrap();
            match result {
                Ok(r) => {
                    s.clock.ntp_offset_ms = Some(r.offset_ms);
                    s.clock.ntp_error = None;
                    s.clock.checked = true;
                }
                Err(e) => {
                    crate::errlog::log("ntp", format!("{server}: {e}"));
                    s.clock.ntp_offset_ms = None;
                    s.clock.ntp_error = Some(e);
                    s.clock.checked = true;
                }
            }
        }
        // Re-check on a network change (a captive network may filter NTP that
        // the previous one passed) or on the slow cadence.
        tokio::select! {
            _ = changed.notified() => { tokio::time::sleep(Duration::from_secs(5)).await; }
            _ = tokio::time::sleep(PERIOD) => {}
        }
    }
}

/// Exchanges per check, and how closely their offsets must agree.
const SAMPLES: usize = 3;
const AGREE_MS: f64 = 1_000.0;

/// Several exchanges, and the median — accepted only when they agree with
/// one another. One reply is never enough to accuse the clock: a delayed
/// datagram, a reply crossing a network change, or a server having a bad
/// moment all produce a single wild offset, and "your clock is hours off" is
/// not something to say on the strength of one packet.
pub async fn consensus(server: &str) -> Result<NtpReading, String> {
    let mut readings: Vec<NtpReading> = Vec::new();
    let mut last_err = String::new();
    for i in 0..SAMPLES {
        if i > 0 {
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        match query(server).await {
            Ok(r) => readings.push(r),
            Err(e) => last_err = e,
        }
    }
    if readings.len() < 2 {
        return Err(if last_err.is_empty() {
            "too few replies".to_string()
        } else {
            last_err
        });
    }
    readings.sort_by(|a, b| a.offset_ms.total_cmp(&b.offset_ms));
    let spread = readings[readings.len() - 1].offset_ms - readings[0].offset_ms;
    if spread > AGREE_MS {
        return Err(format!(
            "replies disagree by {:.0} ms — not trusted",
            spread
        ));
    }
    Ok(readings[readings.len() / 2])
}

/// One SNTP client exchange with `server` (host or address, port 123).
pub async fn query(server: &str) -> Result<NtpReading, String> {
    let dest = resolve(server).await?;
    let bind: SocketAddr = match dest.ip() {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let sock = UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
    sock.connect(dest).await.map_err(|e| e.to_string())?;

    // Client request: LI 0, version 4, mode 3 (client); transmit timestamp
    // carries our send time so the reply echoes it back as the originate time.
    let mut pkt = [0u8; 48];
    pkt[0] = 0x23;
    let t1 = unix_now();
    pkt[40..48].copy_from_slice(&to_ntp(t1));
    sock.send(&pkt).await.map_err(|e| e.to_string())?;

    let mut buf = [0u8; 48];
    let n = tokio::time::timeout(TIMEOUT, sock.recv(&mut buf))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())?;
    let t4 = unix_now();
    parse_reply(&buf[..n], t1, t4)
}

/// Offset and round trip from a server reply, given our send (`t1`) and
/// receive (`t4`) times. Pure, for testing.
pub fn parse_reply(buf: &[u8], t1: f64, t4: f64) -> Result<NtpReading, String> {
    if buf.len() < 48 {
        return Err("short reply".to_string());
    }
    let mode = buf[0] & 0x07;
    if mode != 4 && mode != 5 {
        return Err(format!("not a server reply (mode {mode})"));
    }
    // Stratum 0 is a "kiss-o'-death": the server declined to answer.
    if buf[1] == 0 {
        return Err("server refused (kiss-of-death)".to_string());
    }
    let echoed = from_ntp(&buf[24..32]);
    // A reply to somebody else's request (or a spoof) will not echo our t1.
    if (echoed - t1).abs() > 1.0 {
        return Err("originate timestamp mismatch".to_string());
    }
    let t2 = from_ntp(&buf[32..40]);
    let t3 = from_ntp(&buf[40..48]);
    let offset = ((t2 - t1) + (t3 - t4)) / 2.0;
    let rtt = (t4 - t1) - (t3 - t2);
    Ok(NtpReading {
        offset_ms: -offset * 1000.0, // positive = local clock ahead
        rtt_ms: rtt.max(0.0) * 1000.0,
    })
}

async fn resolve(server: &str) -> Result<SocketAddr, String> {
    if let Ok(ip) = server.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 123));
    }
    tokio::net::lookup_host((server, 123))
        .await
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| "no address".to_string())
}

fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn to_ntp(unix: f64) -> [u8; 8] {
    let ntp = unix + NTP_UNIX_DELTA;
    let secs = ntp.floor();
    let frac = ((ntp - secs) * 4_294_967_296.0) as u32;
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&(secs as u32).to_be_bytes());
    out[4..].copy_from_slice(&frac.to_be_bytes());
    out
}

fn from_ntp(b: &[u8]) -> f64 {
    let secs = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as f64;
    let frac = u32::from_be_bytes([b[4], b[5], b[6], b[7]]) as f64 / 4_294_967_296.0;
    secs + frac - NTP_UNIX_DELTA
}

/// Human wording for a skew: "clock 2m 05s fast".
pub fn describe_offset(offset_ms: f64) -> String {
    let secs = (offset_ms.abs() / 1000.0).round() as u64;
    let dir = if offset_ms > 0.0 { "fast" } else { "slow" };
    format!(
        "clock {} {dir}",
        crate::verdict::fmt_duration(Duration::from_secs(secs))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(t1: f64, t2: f64, t3: f64) -> [u8; 48] {
        let mut b = [0u8; 48];
        b[0] = 0x24; // v4, mode 4 (server)
        b[1] = 2; // stratum
        b[24..32].copy_from_slice(&to_ntp(t1));
        b[32..40].copy_from_slice(&to_ntp(t2));
        b[40..48].copy_from_slice(&to_ntp(t3));
        b
    }

    #[test]
    fn a_synchronised_clock_reads_near_zero() {
        // Server received 10 ms after we sent, replied 1 ms later, we got it
        // 10 ms after that: symmetric path, no offset.
        let t1 = 1_700_000_000.0;
        let r = parse_reply(&reply(t1, t1 + 0.010, t1 + 0.011), t1, t1 + 0.021).unwrap();
        assert!(r.offset_ms.abs() < 1.0, "{}", r.offset_ms);
        assert!((r.rtt_ms - 20.0).abs() < 1.0, "{}", r.rtt_ms);
    }

    #[test]
    fn a_fast_local_clock_reads_positive() {
        // Our clock is 90 s ahead: server timestamps look 90 s in our past.
        let t1 = 1_700_000_090.0;
        let server_now = 1_700_000_000.0;
        let r = parse_reply(
            &reply(t1, server_now + 0.010, server_now + 0.011),
            t1,
            t1 + 0.021,
        )
        .unwrap();
        assert!((r.offset_ms - 90_000.0).abs() < 50.0, "{}", r.offset_ms);
        assert_eq!(describe_offset(r.offset_ms), "clock 1m 30s fast");
    }

    #[test]
    fn foreign_and_refused_replies_are_rejected() {
        let t1 = 1_700_000_000.0;
        let mut b = reply(t1 + 5.0, t1, t1);
        assert!(
            parse_reply(&b, t1, t1 + 0.02).is_err(),
            "originate mismatch"
        );
        b = reply(t1, t1, t1);
        b[1] = 0;
        assert!(parse_reply(&b, t1, t1 + 0.02).is_err(), "kiss-of-death");
        assert!(parse_reply(&b[..20], t1, t1 + 0.02).is_err(), "short");
    }

    /// Against a real time server. `cargo test -- --ignored live_ntp`.
    #[tokio::test]
    #[ignore = "requires network access"]
    async fn live_ntp() {
        let r = query("time.cloudflare.com").await.expect("ntp answers");
        println!("offset {:.1} ms, rtt {:.1} ms", r.offset_ms, r.rtt_ms);
        assert!(
            r.offset_ms.abs() < 5_000.0,
            "this machine's clock is way off?"
        );
    }
}
