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
//! A TCP handshake or a single UDP datagram per row — nothing is sent beyond
//! what the protocol needs to get an answer. The scan is on demand. Its
//! smaller sibling, the *monitor* ([`monitor`]), is automatic but gated hard:
//! it starts only when the TCP :443 probes to every anchor are failing — the
//! web as people use it, gone — and probes a five-row list every 5 s to tell
//! a filtered network from a dead one, then stops when 443 answers again. It
//! announces itself on the timeline and in the analysis, and
//! `egress_monitor = false` turns it off.

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
    /// "v6" to resolve the host to its IPv6 address; anything else prefers
    /// v4 (filters are written for v4, so that is the default question).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub family: String,
}

impl EgressCheck {
    fn new(name: &str, host: &str, port: u16, proto: &str, note: &str) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
            proto: proto.into(),
            note: note.into(),
            family: String::new(),
        }
    }

    fn v6(mut self) -> Self {
        self.family = "v6".into();
        self
    }

    pub fn prefers_v6(&self) -> bool {
        self.family == "v6"
    }
}

/// The rows the [c] scan adds while the link holds a global IPv6 address:
/// the same question over v6 for the protocols a v6 filter treats
/// differently. Named hosts here publish AAAA records; the literal ones
/// are the anchors' v6 twins. Not in the config list, so a v4-only link
/// never shows them as "blocked".
pub fn v6_checks() -> Vec<EgressCheck> {
    vec![
        EgressCheck::new(
            "HTTPS (v6)",
            "cloudflare.com",
            443,
            "tcp",
            "the web over v6",
        )
        .v6(),
        EgressCheck::new(
            "HTTP (v6)",
            "cloudflare.com",
            80,
            "tcp",
            "plain http over v6",
        )
        .v6(),
        EgressCheck::new(
            "QUIC (v6)",
            "2606:4700:4700::1111",
            443,
            "quic",
            "UDP 443 over v6",
        )
        .v6(),
        EgressCheck::new(
            "DNS (UDP, v6)",
            "2606:4700:4700::1111",
            53,
            "dns",
            "a v6 resolver of your own choosing",
        )
        .v6(),
        EgressCheck::new(
            "NTP (v6)",
            "time.cloudflare.com",
            123,
            "ntp",
            "clock sync over v6",
        )
        .v6(),
    ]
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

/// The monitor's list: one reference host per protocol a web filter treats
/// differently. Short on purpose — it runs every 5 s while the web is dark,
/// and each row is a connection to somebody else's server. Every host here
/// is built to take connections at scale; a handshake every 5 s from one
/// machine during its own outage is noise to them.
pub fn default_monitor_checks() -> Vec<EgressCheck> {
    vec![
        EgressCheck::new(
            "HTTP",
            "cloudflare.com",
            80,
            "tcp",
            "plain http — open while HTTPS is blocked means a filter that only allows what it can inspect",
        ),
        EgressCheck::new(
            "QUIC",
            "1.1.1.1",
            443,
            "quic",
            "UDP 443 — the other way the web gets out",
        ),
        EgressCheck::new(
            "SSH",
            "github.com",
            22,
            "tcp",
            "git over ssh, remote shells",
        ),
        EgressCheck::new("NTP", "time.cloudflare.com", 123, "ntp", "clock sync"),
        EgressCheck::new(
            "DNS",
            "1.1.1.1",
            53,
            "dns",
            "resolvers of your own choosing",
        ),
    ]
}

/// How often the monitor probes its rows while it runs.
pub const MONITOR_INTERVAL: Duration = Duration::from_secs(5);
/// The web must have been dark this many consecutive seconds before the
/// monitor starts — past the analysis's own raise hysteresis, so a blip
/// that never became a finding never becomes a scan either.
const MONITOR_START_AFTER_SECS: u32 = 10;
/// And clear this long before it stops: a single web check squeaking
/// through does not end the episode.
const MONITOR_STOP_AFTER_SECS: u32 = 10;

/// One monitored port: the check, where it resolved to, and its round trips
/// as a series — the same last / avg / p95 / jitter / loss machinery the
/// quality table's other families use.
#[derive(Clone)]
pub struct MonitorRow {
    pub check: EgressCheck,
    pub addr: Option<SocketAddr>,
    pub series: crate::app::Series,
    /// The latest round's outcome, kept because a series records only
    /// "answered or not": refused (reached, reset) and blocked (silence)
    /// are the same loss to the series and a different story to a person.
    pub last: Outcome,
}

impl MonitorRow {
    pub fn open(&self) -> bool {
        matches!(self.last, Outcome::Open(_))
    }

    /// "github.com:22" — the address column.
    pub fn target(&self) -> String {
        format!("{}:{}", self.check.host, self.check.port)
    }

    /// The latest outcome as evidence reads it.
    pub fn describe(&self) -> String {
        match &self.last {
            Outcome::Pending => "no round yet".to_string(),
            Outcome::Open(ms) => format!("open {ms:.0}ms"),
            Outcome::Refused => {
                "refused — the host was reached and something reset the connection: a filter that answers rather than drops".to_string()
            }
            Outcome::Blocked => "no answer (blocked)".to_string(),
            Outcome::Error(e) => format!("error: {e}"),
        }
    }
}

/// The automatic monitor's state, held in [`AppState`]. Kept after it
/// stops, so the analysis can still say what it found.
#[derive(Clone)]
pub struct Monitor {
    pub rows: Vec<MonitorRow>,
    pub started: Instant,
    pub active: bool,
    pub stopped: Option<Instant>,
    /// Completed probe rounds; zero means nothing has been learned yet.
    pub rounds: u32,
}

impl Monitor {
    pub fn has_data(&self) -> bool {
        self.rounds > 0
    }

    /// Rows whose latest round got through.
    pub fn open(&self) -> Vec<&MonitorRow> {
        self.rows.iter().filter(|r| r.open()).collect()
    }

    /// Rows whose latest round did not — only once a round has run.
    pub fn blocked(&self) -> Vec<&MonitorRow> {
        if !self.has_data() {
            return Vec::new();
        }
        self.rows.iter().filter(|r| !r.open()).collect()
    }

    /// "SSH, NTP and DNS" — the rows by name, as a sentence lists them.
    pub fn list(rows: &[&MonitorRow]) -> String {
        let names: Vec<&str> = rows.iter().map(|r| r.check.name.as_str()).collect();
        match names.len() {
            0 => String::new(),
            1 => names[0].to_string(),
            n => format!("{} and {}", names[..n - 1].join(", "), names[n - 1]),
        }
    }
}

/// The automatic monitor task. Watches for the web going dark (see
/// [`crate::verdict::web_dark`]), runs the rows every [`MONITOR_INTERVAL`]
/// while it stays dark, stops when it clears — and says so both ways on the
/// timeline, because probing third-party ports is something a person
/// should be able to see octomon doing.
pub async fn monitor(state: Arc<Mutex<AppState>>, cfg: crate::config::Config) {
    if !cfg.egress_monitor || cfg.egress_monitor_checks.is_empty() {
        return;
    }
    let checks = cfg.egress_monitor_checks.clone();
    // Resolve the names now, while the network presumably works: a filter
    // that takes DNS with it would otherwise leave every named row
    // unresolvable at exactly the moment the rows matter. Refreshed at each
    // start when the resolver still answers.
    let mut cached = resolve_all(&checks).await;
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut dark_for: u32 = 0;
    let mut clear_for: u32 = 0;
    let mut last_round: Option<Instant> = None;
    loop {
        ticker.tick().await;
        let (dark, active) = {
            let s = state.lock().unwrap();
            (
                crate::verdict::https_dark(&s),
                s.egress_monitor.as_ref().is_some_and(|m| m.active),
            )
        };
        if dark {
            dark_for += 1;
            clear_for = 0;
        } else {
            clear_for += 1;
            dark_for = 0;
        }

        if !active && dark_for >= MONITOR_START_AFTER_SECS {
            let fresh = resolve_all(&checks).await;
            for (c, f) in cached.iter_mut().zip(fresh) {
                if f.is_some() {
                    *c = f;
                }
            }
            let names: Vec<&str> = checks.iter().map(|c| c.name.as_str()).collect();
            let mut s = state.lock().unwrap();
            let web_too = crate::verdict::web_dark(&s);
            s.egress_monitor = Some(Monitor {
                rows: checks
                    .iter()
                    .zip(cached.iter())
                    .map(|(c, a)| MonitorRow {
                        check: c.clone(),
                        addr: *a,
                        series: crate::app::Series::default(),
                        last: Outcome::Pending,
                    })
                    .collect(),
                started: Instant::now(),
                active: true,
                stopped: None,
                rounds: 0,
            });
            s.push_event(
                crate::verdict::Severity::Info,
                crate::app::EventCategory::Network,
                format!(
                    "egress monitor started — tcp :443 failing to every anchor{}; probing {} every {}s to tell a filter from an outage",
                    if web_too {
                        " and the web check too"
                    } else {
                        ""
                    },
                    names.join(", "),
                    MONITOR_INTERVAL.as_secs()
                ),
            );
            last_round = None;
            continue;
        }

        if active && clear_for >= MONITOR_STOP_AFTER_SECS {
            let mut s = state.lock().unwrap();
            let why = if s.link_lost || s.netinfo.iface.is_empty() {
                "the link went down"
            } else if matches!(s.http.v4, crate::app::FamilyProbe::Captive(_))
                || matches!(s.http.v6, crate::app::FamilyProbe::Captive(_))
            {
                "a sign-in page appeared"
            } else {
                "tcp :443 answers again"
            };
            let summary = if let Some(m) = s.egress_monitor.as_mut() {
                m.active = false;
                m.stopped = Some(Instant::now());
                format!(
                    "{} of {} ports were getting out",
                    m.open().len(),
                    m.rows.len()
                )
            } else {
                String::new()
            };
            s.push_event(
                crate::verdict::Severity::Info,
                crate::app::EventCategory::Network,
                format!("egress monitor stopped — {why} · {summary}"),
            );
            continue;
        }

        if active && last_round.is_none_or(|t| t.elapsed() >= MONITOR_INTERVAL) {
            last_round = Some(Instant::now());
            // Snapshot the rows under the lock, probe without it.
            let (started, rows) = {
                let s = state.lock().unwrap();
                match s.egress_monitor.as_ref() {
                    Some(m) => (
                        Some(m.started),
                        m.rows
                            .iter()
                            .enumerate()
                            .map(|(i, r)| (i, r.check.clone(), r.addr))
                            .collect::<Vec<_>>(),
                    ),
                    None => (None, Vec::new()),
                }
            };
            let probes = rows.into_iter().map(|(i, c, addr)| async move {
                let outcome = match addr {
                    Some(a) => probe(&c, a).await,
                    None => match resolve(&c.host, c.port, c.prefers_v6()).await {
                        Ok(a) => probe(&c, a).await,
                        Err(e) => Outcome::Error(e),
                    },
                };
                (i, outcome)
            });
            let results = futures_util::future::join_all(probes).await;
            let mut s = state.lock().unwrap();
            if let Some(m) = s.egress_monitor.as_mut()
                && Some(m.started) == started
                && m.active
            {
                for (i, outcome) in results {
                    if let Some(r) = m.rows.get_mut(i) {
                        match &outcome {
                            Outcome::Open(ms) => r.series.record_reply(*ms),
                            _ => r.series.record_loss(),
                        }
                        r.last = outcome;
                    }
                }
                m.rounds += 1;
            }
        }
    }
}

async fn resolve_all(checks: &[EgressCheck]) -> Vec<Option<SocketAddr>> {
    futures_util::future::join_all(
        checks
            .iter()
            .map(|c| async move { resolve(&c.host, c.port, c.prefers_v6()).await.ok() }),
    )
    .await
}

/// Start (or restart) a scan of `checks`; each row updates as it completes.
pub fn start(state: Arc<Mutex<AppState>>, mut checks: Vec<EgressCheck>, with_v6: bool) {
    {
        let mut s = state.lock().unwrap();
        // The v6 rows ride along on a dual-stack link, skipping any the
        // user already listed themselves.
        if with_v6 && crate::collectors::http::has_global_v6(&s.netinfo.ipv6) {
            for c in v6_checks() {
                let dup = checks.iter().any(|k| {
                    k.host == c.host
                        && k.port == c.port
                        && k.proto == c.proto
                        && k.family == c.family
                });
                if !dup {
                    checks.push(c);
                }
            }
        }
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
    let addr = match resolve(&c.host, c.port, c.prefers_v6()).await {
        Ok(a) => a,
        Err(e) => return Outcome::Error(e),
    };
    probe(c, addr).await
}

/// One check against an already-resolved address.
async fn probe(c: &EgressCheck, addr: SocketAddr) -> Outcome {
    let start = Instant::now();
    let ms = |start: Instant| start.elapsed().as_secs_f64() * 1000.0;
    match c.proto.as_str() {
        "tcp" => match tokio::time::timeout(TIMEOUT, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(_)) => Outcome::Open(ms(start)),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Outcome::Refused,
            Ok(Err(e)) => Outcome::Error(short(&e)),
            Err(_) => Outcome::Blocked,
        },
        // By address, not name: the monitor caches addresses for exactly
        // the case where the name no longer resolves.
        "ntp" => match crate::collectors::clock::query(&addr.ip().to_string()).await {
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

async fn resolve(host: &str, port: u16, prefer_v6: bool) -> Result<SocketAddr, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("resolve: {}", short(&e)))?;
    // Prefer v4 unless the row asks for v6: the check is about the network's
    // filtering, and v4 is the family a filter is written for; the v6 rows
    // ask the same question over the other family on purpose.
    let all: Vec<SocketAddr> = addrs.by_ref().collect();
    all.iter()
        .find(|a| a.is_ipv6() == prefer_v6)
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

    /// The monitor's list is the five protocols a web filter treats
    /// differently, one host each, and reads as a sentence.
    #[test]
    fn the_monitor_list_is_five_rows_and_lists_itself_as_a_sentence() {
        let d = default_monitor_checks();
        let names: Vec<&str> = d.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["HTTP", "QUIC", "SSH", "NTP", "DNS"]);
        let rows: Vec<MonitorRow> = d
            .iter()
            .map(|c| MonitorRow {
                check: c.clone(),
                addr: None,
                series: crate::app::Series::default(),
                last: Outcome::Pending,
            })
            .collect();
        let refs: Vec<&MonitorRow> = rows.iter().collect();
        assert_eq!(Monitor::list(&refs[..1]), "HTTP");
        assert_eq!(Monitor::list(&refs[..2]), "HTTP and QUIC");
        assert_eq!(Monitor::list(&refs[2..]), "SSH, NTP and DNS");
        assert_eq!(rows[2].target(), "github.com:22");
    }

    /// The v6 rows ask over v6 by construction: literal twins, or a name
    /// with the family flag set so resolution takes the AAAA answer.
    #[test]
    fn the_v6_rows_all_resolve_over_v6() {
        for c in v6_checks() {
            assert!(c.name.ends_with("v6)"), "{}", c.name);
            assert!(c.prefers_v6());
            if let Ok(ip) = c.host.parse::<IpAddr>() {
                assert!(ip.is_ipv6(), "{}", c.host);
            }
        }
        // The config list carries no family field unless set.
        let text = toml::to_string(&default_checks()[0]).unwrap();
        assert!(!text.contains("family"));
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
        for c in default_checks().into_iter().chain(v6_checks()) {
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
