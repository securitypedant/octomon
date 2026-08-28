//! Outbound reachability by port — the [c] scan overlay.
//!
//! Guest, hotel and corporate networks routinely pass only what a browser
//! needs. Mail, SSH, DNS to a resolver of your own choosing, NTP and QUIC each
//! die on a different filter, and none of that shows in latency or a web
//! check. This asks the question directly, once, on demand: for each protocol
//! a reference host that reliably answers is contacted and the outcome
//! recorded — open, refused (the host was reached; there is just nothing
//! listening, which still proves the port is not filtered), or timed out
//! (filtered, or the host is down).
//!
//! On demand only, and a TCP handshake or a single UDP datagram per row —
//! nothing is sent beyond what the protocol needs to get an answer.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::app::AppState;

const TIMEOUT: Duration = Duration::from_secs(4);

/// One row of the scan: what to try and how.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EgressCheck {
    /// Shown as the row name ("SSH", "SMTP submission").
    pub name: String,
    pub host: String,
    pub port: u16,
    /// "tcp" for a plain connect; "dns", "ntp" or "quic" for a UDP exchange
    /// that expects the matching answer.
    pub proto: String,
    /// One line on why a user cares, shown beside a blocked row.
    #[serde(default)]
    pub note: String,
}

impl EgressCheck {
    fn new(name: &str, host: &str, port: u16, proto: &str, note: &str) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
            proto: proto.into(),
            note: note.into(),
        }
    }
}

/// The default list. Reference hosts are chosen for answering reliably on the
/// port in question, not for anything they are asked to do — every check is a
/// handshake or one datagram. Ports with no public endpoint that would answer
/// unauthenticated (RDP, WireGuard, OpenVPN, IKE) are deliberately absent: a
/// "blocked" result there would mean nothing.
pub fn default_checks() -> Vec<EgressCheck> {
    vec![
        EgressCheck::new("HTTPS", "cloudflare.com", 443, "tcp", "the web"),
        EgressCheck::new(
            "HTTP",
            "cloudflare.com",
            80,
            "tcp",
            "plain http — captive portals live here",
        ),
        EgressCheck::new(
            "QUIC / HTTP3",
            "1.1.1.1",
            443,
            "quic",
            "UDP 443 — browsers fall back to TCP, slower",
        ),
        EgressCheck::new(
            "SSH",
            "github.com",
            22,
            "tcp",
            "git over ssh, remote shells",
        ),
        EgressCheck::new(
            "DNS (UDP)",
            "1.1.1.1",
            53,
            "dns",
            "resolvers of your own choosing",
        ),
        EgressCheck::new("DNS (TCP)", "1.1.1.1", 53, "tcp", "large answers, DNSSEC"),
        EgressCheck::new(
            "DNS over TLS",
            "1.1.1.1",
            853,
            "tcp",
            "private DNS (Android, systemd)",
        ),
        EgressCheck::new(
            "NTP",
            "time.cloudflare.com",
            123,
            "ntp",
            "clock sync — see the clock row",
        ),
        EgressCheck::new(
            "SMTP",
            "smtp.gmail.com",
            25,
            "tcp",
            "blocked on most home ISPs — normal",
        ),
        EgressCheck::new(
            "SMTP submission",
            "smtp.gmail.com",
            587,
            "tcp",
            "sending mail from a mail app",
        ),
        EgressCheck::new(
            "SMTPS",
            "smtp.gmail.com",
            465,
            "tcp",
            "sending mail (implicit TLS)",
        ),
        EgressCheck::new(
            "IMAPS",
            "imap.gmail.com",
            993,
            "tcp",
            "fetching mail in a mail app",
        ),
    ]
}

#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    Pending,
    /// Answered, with the round trip.
    Open(f64),
    /// The host was reached and said no: the port is not filtered.
    Refused,
    /// No answer at all: filtered, or the host is unreachable on that port.
    Blocked,
    /// The name did not resolve, or another failure named in the string.
    Error(String),
}

impl Outcome {
    pub fn label(&self) -> String {
        match self {
            Outcome::Pending => "…".to_string(),
            Outcome::Open(ms) => format!("open {ms:.0}ms"),
            Outcome::Refused => "refused (reachable)".to_string(),
            Outcome::Blocked => "BLOCKED / timeout".to_string(),
            Outcome::Error(e) => format!("error: {e}"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CheckResult {
    pub check: EgressCheck,
    pub outcome: Outcome,
}

/// The scan's state, held in [`AppState`].
#[derive(Clone, Debug)]
pub struct Scan {
    pub started: Instant,
    pub running: bool,
    pub results: Vec<CheckResult>,
}

impl Scan {
    pub fn blocked(&self) -> usize {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, Outcome::Blocked))
            .count()
    }
}

/// Start (or restart) a scan of `checks`; each row updates as it completes.
pub fn start(state: Arc<Mutex<AppState>>, checks: Vec<EgressCheck>) {
    {
        let mut s = state.lock().unwrap();
        s.egress = Some(Scan {
            started: Instant::now(),
            running: true,
            results: checks
                .iter()
                .map(|c| CheckResult {
                    check: c.clone(),
                    outcome: Outcome::Pending,
                })
                .collect(),
        });
    }
    tokio::spawn(async move {
        let started = state.lock().unwrap().egress.as_ref().map(|s| s.started);
        // All rows at once: a filtered port costs a full timeout, and twelve
        // of those in series is a long wait for a yes/no table.
        let tasks: Vec<_> = checks
            .into_iter()
            .enumerate()
            .map(|(i, c)| {
                let state = state.clone();
                tokio::spawn(async move {
                    let outcome = run_check(&c).await;
                    // Blocked and Refused are findings the table exists to
                    // report; Error means the check itself did not happen, so
                    // the reason belongs somewhere it outlives the overlay.
                    if let Outcome::Error(e) = &outcome {
                        crate::errlog::log(
                            "egress",
                            format!("{} {}:{} check failed: {e}", c.proto, c.host, c.port),
                        );
                    }
                    let mut s = state.lock().unwrap();
                    // A newer scan may have replaced this one meanwhile.
                    if let Some(scan) = s.egress.as_mut()
                        && Some(scan.started) == started
                        && let Some(r) = scan.results.get_mut(i)
                    {
                        r.outcome = outcome;
                    }
                })
            })
            .collect();
        for t in tasks {
            let _ = t.await;
        }
        let mut s = state.lock().unwrap();
        if let Some(scan) = s.egress.as_mut()
            && Some(scan.started) == started
        {
            scan.running = false;
        }
    });
}

async fn run_check(c: &EgressCheck) -> Outcome {
    let addr = match resolve(&c.host, c.port).await {
        Ok(a) => a,
        Err(e) => return Outcome::Error(e),
    };
    let start = Instant::now();
    let ms = |start: Instant| start.elapsed().as_secs_f64() * 1000.0;
    match c.proto.as_str() {
        "tcp" => match tokio::time::timeout(TIMEOUT, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(_)) => Outcome::Open(ms(start)),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Outcome::Refused,
            Ok(Err(e)) => Outcome::Error(short(&e)),
            Err(_) => Outcome::Blocked,
        },
        "ntp" => match crate::collectors::clock::query(&c.host).await {
            Ok(r) => Outcome::Open(r.rtt_ms),
            Err(e) if e == "timeout" => Outcome::Blocked,
            Err(e) => Outcome::Error(e),
        },
        "dns" => udp_exchange(addr, dns_probe(), |b| b.len() >= 12).await,
        "quic" => {
            udp_exchange(addr, crate::collectors::pmtu::quic_probe(1200), |b| {
                crate::collectors::pmtu::is_version_negotiation(b)
            })
            .await
        }
        other => Outcome::Error(format!("unknown proto {other}")),
    }
}

/// One datagram out, one expected back within the timeout.
async fn udp_exchange(
    addr: SocketAddr,
    payload: Vec<u8>,
    accept: impl Fn(&[u8]) -> bool,
) -> Outcome {
    let bind: SocketAddr = match addr.ip() {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let sock = match tokio::net::UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(e) => return Outcome::Error(short(&e)),
    };
    if let Err(e) = sock.connect(addr).await {
        return Outcome::Error(short(&e));
    }
    let start = Instant::now();
    if let Err(e) = sock.send(&payload).await {
        return Outcome::Error(short(&e));
    }
    let mut buf = [0u8; 2048];
    match tokio::time::timeout(TIMEOUT, sock.recv(&mut buf)).await {
        Ok(Ok(n)) if accept(&buf[..n]) => Outcome::Open(start.elapsed().as_secs_f64() * 1000.0),
        Ok(Ok(_)) => Outcome::Error("unexpected answer".into()),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Outcome::Refused,
        Ok(Err(e)) => Outcome::Error(short(&e)),
        Err(_) => Outcome::Blocked,
    }
}

/// A minimal A query for `example.com`, id 0x0c70.
fn dns_probe() -> Vec<u8> {
    let mut p = vec![0x0c, 0x70, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["example", "com"] {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.extend_from_slice(&[0, 0, 1, 0, 1]);
    p
}

async fn resolve(host: &str, port: u16) -> Result<SocketAddr, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("resolve: {}", short(&e)))?;
    // Prefer v4: the check is about the network's filtering, and v4 is the
    // family a filter is written for; v6-only failures are their own finding.
    let all: Vec<SocketAddr> = addrs.by_ref().collect();
    all.iter()
        .find(|a| a.is_ipv4())
        .or(all.first())
        .copied()
        .ok_or_else(|| "no address".to_string())
}

fn short(e: &std::io::Error) -> String {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::ConnectionRefused => "refused".into(),
        ErrorKind::ConnectionReset => "reset".into(),
        ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable => "unreachable".into(),
        ErrorKind::PermissionDenied => "permission denied".into(),
        ErrorKind::TimedOut => "timeout".into(),
        _ => e.to_string().chars().take(30).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_list_covers_the_usual_filters_and_only_answerable_ports() {
        let d = default_checks();
        let ports: Vec<u16> = d.iter().map(|c| c.port).collect();
        for p in [443, 80, 22, 53, 853, 123, 25, 587, 465, 993] {
            assert!(ports.contains(&p), "port {p} missing");
        }
        // Nothing that could only ever read "blocked".
        for p in [3389, 1194, 51820, 500, 4500] {
            assert!(
                !ports.contains(&p),
                "port {p} has no answering reference host"
            );
        }
        assert!(
            d.iter()
                .all(|c| matches!(c.proto.as_str(), "tcp" | "dns" | "ntp" | "quic"))
        );
    }

    #[test]
    fn outcomes_read_as_a_person_would_say_them() {
        assert_eq!(Outcome::Refused.label(), "refused (reachable)");
        assert_eq!(Outcome::Blocked.label(), "BLOCKED / timeout");
    }

    /// Against the real network: `cargo test -- --ignored --nocapture live_egress`.
    #[tokio::test]
    #[ignore = "requires network access"]
    async fn live_egress() {
        for c in default_checks() {
            let o = run_check(&c).await;
            println!(
                "{:<16} {}:{} {} → {}",
                c.name,
                c.host,
                c.port,
                c.proto,
                o.label()
            );
        }
    }
}
