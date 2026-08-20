//! The verdict engine: the one component that *interprets* what the collectors
//! measure. [`evaluate`] is a pure read of [`AppState`] producing a [`Triage`] —
//! every subsystem's status (healthy rungs included, so the conclusion is
//! auditable) plus ranked problem [`Finding`]s. [`VerdictState`] applies
//! hysteresis on top so the footer verdict doesn't flap on a single lost packet.
//!
//! Nothing here suppresses anything: simultaneous causes are all reported, and
//! contradictory evidence lowers confidence rather than picking a side. Caveat
//! findings (machine load, VPN) are co-reported but never rank above network
//! causes — a busy CPU doesn't disprove a dead gateway.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::app::{AppState, LinkMedium, TargetStat};

/// The one rulebook. The TUI's colour helpers, the triage ladder, and doctor
/// mode all judge against these, so they can never disagree.
pub mod thresholds {
    /// Packet loss that colours yellow / raises a Warn.
    pub const LOSS_WARN_PCT: f64 = 1.0;
    /// Packet loss that colours red / raises a finding.
    pub const LOSS_BAD_PCT: f64 = 5.0;
    /// Recent loss above this reads as "unresponsive" rather than "degraded".
    pub const LOSS_DOWN_PCT: f64 = 50.0;
    pub const RTT_WARN_MS: f64 = 50.0;
    pub const RTT_BAD_MS: f64 = 150.0;
    pub const DNS_WARN_MS: f64 = 30.0;
    pub const DNS_BAD_MS: f64 = 120.0;
    /// Bufferbloat grade steps (Waveform/Cloudflare scale):
    /// excellent < 5 ≤ good < 30 ≤ moderate < 60 ≤ poor < 200 ≤ bad.
    pub const BLOAT_STEPS_MS: [f64; 4] = [5.0, 30.0, 60.0, 200.0];
    /// Bufferbloat magnitude that earns a finding (the "moderate" step).
    pub const BLOAT_FINDING_MS: f64 = 60.0;
    pub const USAGE_WARN_PCT: f32 = 60.0;
    pub const USAGE_BAD_PCT: f32 = 85.0;
    pub const RSSI_WEAK_DBM: i32 = -75;
    pub const RSSI_BAD_DBM: i32 = -82;
    /// Below this the radio itself is almost certainly the problem.
    pub const RSSI_AWFUL_DBM: i32 = -85;
    pub const SNR_MIN_DB: i32 = 15;
    pub const LINK_ERR_BAD_PCT: f64 = 1.0;
    /// System clock offsets: a note from here, a finding from the second —
    /// certificate checks tolerate minutes, not much more, and time-based
    /// logins (TOTP) far less.
    pub const CLOCK_WARN_MS: f64 = 30_000.0;
    pub const CLOCK_BAD_MS: f64 = 300_000.0;
    pub const CPU_HOT_PCT: f32 = 90.0;
    pub const MEM_HOT_PCT: f32 = 90.0;
    /// Outcomes considered for *detection*. The display window (100) takes
    /// 100 s to reflect an outage; 20 reacts inside half a minute.
    pub const RECENT: usize = 20;
    /// Below this many outcomes a probe has no opinion, only noise.
    pub const MIN_SAMPLES: usize = 5;
    /// The same for a resolver — probed every 5 s, so three is fifteen seconds.
    pub const DNS_MIN_SAMPLES: usize = 3;
    /// A resolver-probe outage or hijack must persist this long before it is
    /// a finding; see [`crate::app::DNS_RECENT`] for the window it is judged in.
    pub const DNS_FAIL_PCT: f64 = 50.0;
    /// RTT counts as inflated above `max(factor × idle floor, this floor)`.
    /// The absolute floor carries most of the weight: Wi-Fi gateways with a
    /// 2 ms idle floor routinely drift into the 30s on a *good* network
    /// (power save, airtime scheduling), so anything below ~60 ms of mean is
    /// weather, not a finding.
    pub const RTT_INFLATED_FLOOR_MS: f64 = 60.0;
    pub const RTT_INFLATED_FACTOR: f64 = 3.0;
    /// A "bad" loss reading needs at least this many lost packets in the
    /// recent window — 1 of 20 is exactly LOSS_BAD_PCT, and one dropped ping
    /// is not an outage.
    pub const LOSS_MIN_LOST: usize = 2;
    /// A finding raises when present in ≥ RAISE_HITS of the last RAISE_WINDOW
    /// ticks, and clears after CLEAR_TICKS consecutive quiet ticks.
    pub const RAISE_HITS: usize = 4;
    pub const RAISE_WINDOW: usize = 6;
    pub const CLEAR_TICKS: u32 = 8;
    /// After a finding clears, its clear is held back this long: if it raises
    /// again within the window it is the same episode continuing (intermittent
    /// loss), not a fresh raise — one timeline entry each way instead of a
    /// ▲/✓ pair every half minute. The footer stops showing it at once.
    pub const FLAP_GRACE_SECS: u64 = 90;
    /// No verdict at all until this much uptime — early probes are still queued.
    pub const WARMUP_SECS: u64 = 10;
}
use thresholds as th;

/// What is at fault. Declaration order is most-specific-first and doubles as
/// the ranking tiebreak; the caveat-class causes at the end are co-reported but
/// never the sole confident answer.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Cause {
    /// The bottom rung: no default route, no address, or no gateway. Nothing
    /// measured beyond it means anything, so it ranks above everything.
    NoLink,
    /// Nothing else matters until the sign-in page is dealt with.
    CaptivePortal,
    GatewayLan,
    WifiLink,
    Dns,
    /// A resolver answers names that don't exist — redirection, not resolution.
    DnsHijack,
    IspHop,
    WideInternet,
    Ipv6Broken,
    /// Full-size packets vanish and nothing says why: a path-MTU black hole.
    PathMtu,
    HttpBlocked,
    WebTarget,
    SingleDestination,
    Bufferbloat,
    /// The system clock disagrees with the world: HTTPS breaks while every
    /// network measurement is fine.
    ClockSkew,
    Machine,
    VpnCaveat,
}

impl Cause {
    /// Caveat-class findings colour the reading of everything else but must
    /// never outrank a network cause.
    pub fn is_caveat(self) -> bool {
        matches!(self, Cause::Machine | Cause::VpnCaveat)
    }

    /// Stable slug for the JSON report.
    pub fn label(self) -> &'static str {
        match self {
            Cause::NoLink => "no-link",
            Cause::CaptivePortal => "captive-portal",
            Cause::GatewayLan => "gateway",
            Cause::WifiLink => "link",
            Cause::Dns => "dns",
            Cause::DnsHijack => "dns-hijack",
            Cause::IspHop => "isp",
            Cause::WideInternet => "internet",
            Cause::Ipv6Broken => "ipv6",
            Cause::PathMtu => "path-mtu",
            Cause::HttpBlocked => "http-blocked",
            Cause::WebTarget => "web-target",
            Cause::SingleDestination => "destination",
            Cause::Bufferbloat => "bufferbloat",
            Cause::ClockSkew => "clock",
            Cause::Machine => "machine",
            Cause::VpnCaveat => "vpn-caveat",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Severity {
    Info,
    Degraded,
    Down,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Degraded => "degraded",
            Severity::Down => "down",
        }
    }
}

/// "3m 12s" — durations in event messages ("ended after …").
pub fn fmt_duration(d: Duration) -> String {
    let secs = d.as_secs();
    match (secs / 3600, (secs % 3600) / 60, secs % 60) {
        (0, 0, s) => format!("{s}s"),
        (0, m, s) => format!("{m}m {s:02}s"),
        (h, m, _) => format!("{h}h {m:02}m"),
    }
}

/// Ordinal wording, deliberately not fake percentages.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Confidence {
    Weak,
    Likely,
    Strong,
}

impl Confidence {
    pub fn word(self) -> &'static str {
        match self {
            Confidence::Weak => "weak",
            Confidence::Likely => "likely",
            Confidence::Strong => "strong",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub cause: Cause,
    pub severity: Severity,
    pub confidence: Confidence,
    /// One line: "gateway unresponsive (100% loss)".
    pub summary: String,
    /// Supporting data lines for the triage overlay / doctor output.
    pub evidence: Vec<String>,
    /// Stable key detail (e.g. a target label) — hysteresis identity is
    /// `(cause, subject)`, so two bad destinations track independently.
    pub subject: String,
    /// True when this finding is explained by one further up the ladder (DNS
    /// failing because the gateway is dead). Still reported — nothing is
    /// suppressed — but ranked below the cause it is a symptom of, whatever
    /// its severity, so the headline names the cause and not the first thing
    /// that broke.
    pub symptom: bool,
    /// When the finding first raised, once it has passed hysteresis. `None`
    /// on the raw instantaneous evaluation.
    pub since: Option<Instant>,
}

/// The rank order: causes before their symptoms, then severity, then
/// confidence, then specificity — except caveat-class causes always sort after
/// network causes. Symptoms sorting last is what makes this a ladder: a dead
/// gateway with DNS timing out behind it headlines the gateway, however loud
/// the DNS failure is.
fn rank(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        (
            a.cause.is_caveat(),
            a.symptom,
            b.severity,
            b.confidence,
            a.cause,
            &a.subject,
        )
            .cmp(&(
                b.cause.is_caveat(),
                b.symptom,
                a.severity,
                a.confidence,
                b.cause,
                &b.subject,
            ))
    });
}

/// The headline state the footer renders.
#[derive(Clone, Debug)]
pub enum Verdict {
    /// Not enough data to say anything — never rendered as "healthy".
    Insufficient(String),
    Healthy,
    /// ALL active findings, ranked — never collapsed to one.
    Problems(Vec<Finding>),
}

impl Default for Verdict {
    fn default() -> Self {
        Verdict::Insufficient("measuring…".to_string())
    }
}

/// A subsystem on the triage ladder, in blame order from the machine outward.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Area {
    Machine,
    Link,
    Gateway,
    Dns,
    IspPath,
    Internet,
    /// HTTP-layer reachability — the internet as a browser sees it.
    Http,
    Destinations,
}

impl Area {
    pub fn label(self) -> &'static str {
        match self {
            Area::Machine => "machine",
            Area::Link => "link",
            Area::Gateway => "gateway",
            Area::Dns => "DNS",
            Area::IspPath => "ISP path",
            Area::Internet => "internet",
            Area::Http => "web (HTTP)",
            Area::Destinations => "destinations",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RungStatus {
    Ok,
    Warn,
    Bad,
    /// No data — distinct from Ok, because "not measured" must never read as
    /// "measured and fine".
    Unknown,
}

impl RungStatus {
    pub fn label(self) -> &'static str {
        match self {
            RungStatus::Ok => "ok",
            RungStatus::Warn => "warn",
            RungStatus::Bad => "bad",
            RungStatus::Unknown => "unknown",
        }
    }
}

/// One rung of the ladder: a subsystem, its status, and the data behind it —
/// healthy rungs carry their exonerating evidence.
#[derive(Clone, Debug)]
pub struct Rung {
    pub area: Area,
    pub status: RungStatus,
    pub detail: String,
}

/// The full picture: every rung, always in ladder order, plus ranked findings.
#[derive(Clone, Default, Debug)]
pub struct Triage {
    pub rungs: Vec<Rung>,
    /// The one-shot / background checks (clock, proxy, MTU, NAT, DNS honesty…).
    pub checks: Vec<Check>,
    /// Instantaneous (no hysteresis) — what the rules say *right now*. The
    /// footer shows the hysteresis-filtered set from [`VerdictState`] instead.
    pub findings: Vec<Finding>,
}

/// How healthy one probed target looks right now.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Health {
    NoData,
    Good,
    Warn,
    Bad,
}

fn probe_health(t: &TargetStat) -> Health {
    if t.window.len() < th::MIN_SAMPLES {
        return Health::NoData;
    }
    let loss = t.recent_loss_pct(th::RECENT);
    let lost = t
        .window
        .iter()
        .rev()
        .take(th::RECENT)
        .filter(|ok| !**ok)
        .count();
    if loss >= th::LOSS_BAD_PCT && lost >= th::LOSS_MIN_LOST {
        return Health::Bad;
    }
    if loss >= th::LOSS_WARN_PCT || inflated(t) {
        return Health::Warn;
    }
    Health::Good
}

/// How one round-trip reading compares with what this path normally shows.
/// The question the colour answers is "is this worse than it should be
/// *here*", not "is this far away": 160 ms through a VPN exit on another
/// continent is physics, and a 5 ms LAN gateway sitting at 40 ms is a fault.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RttGrade {
    Good,
    Warn,
    Bad,
}

/// Grade `ms` against `reference_ms`, the path's idle floor (its session
/// minimum, lowered to the learned normal for this network when there is
/// one). Relative bands — within 1.5× is fine, up to 3× is a caution, beyond
/// is bad — with the old absolute thresholds kept as floors, so a LAN path
/// with a 2 ms floor still reads yellow at 50 ms and red at 150 ms rather than
/// at 3 ms and 6 ms. With no reference at all, the absolute scale stands.
pub fn rtt_grade(ms: f64, reference_ms: Option<f64>) -> RttGrade {
    let r = reference_ms.unwrap_or(0.0).max(0.0);
    let good_max = (r * 1.5).max(th::RTT_WARN_MS);
    let bad_min = (r * th::RTT_INFLATED_FACTOR).max(th::RTT_BAD_MS);
    if ms <= good_max {
        RttGrade::Good
    } else if ms <= bad_min {
        RttGrade::Warn
    } else {
        RttGrade::Bad
    }
}

/// The reference floor for a target: its own idle minimum this session,
/// lowered to this network's learned normal for that kind of target when a
/// baseline is established — so a session that *starts* degraded still has
/// something honest to be judged against.
pub fn rtt_reference(t: &TargetStat, s: &AppState) -> Option<f64> {
    let learned = s
        .baseline
        .as_ref()
        .filter(|b| b.established())
        .and_then(|b| {
            if t.hop_ttl() == Some(1) {
                b.gateway_ms
            } else if !t.discovered {
                b.anchor_ms
            } else {
                None
            }
        });
    match (t.min_ever_ms, learned) {
        (Some(m), Some(l)) => Some(m.min(l)),
        (Some(m), None) => Some(m),
        (None, l) => l,
    }
}

/// Recent mean RTT well above the all-time idle floor.
fn inflated(t: &TargetStat) -> bool {
    match (t.stats(th::RECENT).mean, t.min_ever_ms) {
        (Some(mean), Some(min)) => {
            mean > (min * th::RTT_INFLATED_FACTOR).max(th::RTT_INFLATED_FLOOR_MS)
        }
        _ => false,
    }
}

fn fmt_ms(v: Option<f64>) -> String {
    v.map(|x| format!("{x:.0}ms")).unwrap_or_else(|| "—".into())
}

/// The auto-discovered gateway target, matched by address first (labels are
/// only a convention), falling back to the discovery label.
fn gateway_target(s: &AppState) -> Option<&TargetStat> {
    s.targets
        .iter()
        .find(|t| t.discovered && t.addr.to_string() == s.netinfo.gateway_ip)
        .or_else(|| {
            s.targets
                .iter()
                .find(|t| t.discovered && t.label == "gateway")
        })
}

/// Why no verdict can be given yet, or `None` once there is enough to judge.
pub fn insufficient_reason(s: &AppState) -> Option<String> {
    if s.icmp_error.is_some() {
        // A working HTTP probe still proves connectivity the way a browser
        // experiences it, so ICMP being blocked no longer blinds the verdict.
        let http_alive = matches!(s.http.v4, crate::app::FamilyProbe::Ok(_))
            || matches!(s.http.v6, crate::app::FamilyProbe::Ok(_))
            || matches!(s.http.v4, crate::app::FamilyProbe::Captive(_))
            || matches!(s.http.v6, crate::app::FamilyProbe::Captive(_));
        return if http_alive {
            None
        } else {
            Some("ICMP unavailable — cannot measure".to_string())
        };
    }
    let warmed = s.started.elapsed().as_secs() >= th::WARMUP_SECS;
    let sampled = s.targets.iter().any(|t| t.window.len() >= th::MIN_SAMPLES);
    if !warmed || !sampled {
        return Some("measuring…".to_string());
    }
    None
}

/// The bottom rung, before any probe is consulted: is there a link with an
/// address and a way out at all? Every failure further up is a symptom of this.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinkState {
    /// No default route — Wi-Fi off, cable out, or nothing configured yet.
    NoRoute,
    /// An interface, but only a self-assigned 169.254.x address — DHCP gave
    /// nothing. The classic "connected, no internet".
    SelfAssigned,
    /// An interface with an address but no gateway to hand packets to.
    NoGateway,
    Up,
}

pub fn link_state(s: &AppState) -> LinkState {
    let n = &s.netinfo;
    // Cold start on a machine with no network: netinfo never populates. Give
    // it the warm-up period before calling that a fault rather than "not yet".
    let warmed = s.started.elapsed().as_secs() >= th::WARMUP_SECS;
    if s.link_lost || (n.iface.is_empty() && warmed) {
        return LinkState::NoRoute;
    }
    if n.iface.is_empty() {
        return LinkState::Up; // not known yet; the rung reads Unknown from the data
    }
    let v4_self_assigned = !n.ipv4.is_empty()
        && n.ipv4.iter().all(|a| {
            a.split('/')
                .next()
                .and_then(|ip| ip.parse::<std::net::Ipv4Addr>().ok())
                .is_some_and(|ip| ip.is_link_local())
        });
    let has_global_v6 = n.ipv6.iter().any(|a| {
        a.split('/')
            .next()
            .and_then(|ip| ip.parse::<std::net::Ipv6Addr>().ok())
            .is_some_and(|ip| {
                !ip.is_loopback()
                    && (ip.segments()[0] & 0xffc0) != 0xfe80
                    && (ip.segments()[0] & 0xfe00) != 0xfc00
            })
    });
    if v4_self_assigned && !has_global_v6 {
        return LinkState::SelfAssigned;
    }
    let no_gateway = n.gateway_ip.is_empty() || n.gateway_ip == "-";
    if no_gateway && n.tunnel.is_none() {
        return LinkState::NoGateway;
    }
    LinkState::Up
}

/// One definition of confidence, so the word means the same in every rule:
/// `contradicted` (evidence against, or the finding is a symptom of something
/// upstream) → Weak; `contrast` (the discriminating comparison holds — ping
/// works but names don't, gateway fine but anchors fail) with an independent
/// `corroboration` (baseline, a second probe family, downstream persistence)
/// → Strong; contrast alone → Likely.
fn judge(contrast: bool, corroborated: bool, contradicted: bool) -> Confidence {
    if contradicted {
        Confidence::Weak
    } else if contrast && corroborated {
        Confidence::Strong
    } else {
        Confidence::Likely
    }
}

/// Pure, instantaneous read of the whole state. No hysteresis, no I/O — doctor
/// mode calls it once after a batch observation; the live task calls it every
/// tick and filters through [`VerdictState`].
pub fn evaluate(s: &AppState) -> Triage {
    let link = link_state(s);
    let gw = gateway_target(s);
    let gw_health = gw.map(probe_health).unwrap_or(Health::NoData);
    // Anchors: the user's endpoint targets (defaults: Cloudflare/Google/Quad9).
    // Discovered mid-path hops are excluded — routers deprioritise ICMP, and a
    // lossy hop that forwards fine is not a destination problem.
    // A target on the LAN (a printer, the NAS) says nothing about the internet
    // and must not vote on it; it gets its own local finding below.
    let anchors: Vec<&TargetStat> = s
        .targets
        .iter()
        .filter(|t| !t.discovered && !s.is_lan_addr(t.addr))
        .collect();
    let lan_targets: Vec<&TargetStat> = s
        .targets
        .iter()
        .filter(|t| !t.discovered && s.is_lan_addr(t.addr))
        .collect();
    let with_data: Vec<&TargetStat> = anchors
        .iter()
        .copied()
        .filter(|t| probe_health(t) != Health::NoData)
        .collect();
    let bad: Vec<&TargetStat> = with_data
        .iter()
        .copied()
        .filter(|t| probe_health(t) == Health::Bad)
        .collect();
    let fine = with_data.len() - bad.len();
    let gw_fine = matches!(gw_health, Health::Good | Health::Warn);
    // A baseline with enough healthy minutes behind it turns absolute numbers
    // into "vs your normal here" — evidence and confidence, never a gate:
    // absolute thresholds still work on the first visit to a network.
    let baseline = s.baseline.as_ref().filter(|b| b.established());

    // Self-inflicted load: the speed test saturates the link on purpose, so
    // while it runs — and until its samples have left the recent window the
    // findings below judge on — loss and latency are expected, and pinning
    // them on the network would be blaming it for what this program did.
    let speedtest_running = matches!(s.speedtest.status, crate::app::SpeedStatus::Running);
    let self_load = speedtest_running
        || s.speedtest.last_run.is_some_and(|t| {
            t.elapsed().as_secs_f64() * s.samples_per_sec.max(0.1) < th::RECENT as f64
        });

    let mut findings: Vec<Finding> = Vec::new();

    // --- link: is there anything to measure over? ---
    if link != LinkState::Up {
        let n = &s.netinfo;
        let (summary, evidence) = match link {
            LinkState::NoRoute => (
                match n.medium {
                    LinkMedium::WiFi => "not connected — Wi-Fi is off or not associated".to_string(),
                    m if m.is_wired() => "not connected — cable unplugged or link down".to_string(),
                    _ => "not connected — no default route".to_string(),
                },
                vec![if n.iface.is_empty() {
                    "no interface holds a default route".to_string()
                } else {
                    format!("{} lost its default route", n.iface)
                }],
            ),
            LinkState::SelfAssigned => (
                "no DHCP lease — self-assigned address, nothing beyond the machine is reachable"
                    .to_string(),
                vec![
                    format!("{}: {}", n.iface, n.ipv4.join(", ")),
                    "169.254.x.x is what the OS uses when no DHCP server answered — the router (or its DHCP) is the place to look".to_string(),
                ],
            ),
            LinkState::NoGateway => (
                format!("{} has an address but no gateway — nothing routes off the LAN", n.iface),
                vec![format!("{}: {} · gateway none", n.iface, n.ipv4.join(", "))],
            ),
            LinkState::Up => unreachable!(),
        };
        findings.push(Finding {
            cause: Cause::NoLink,
            severity: Severity::Down,
            confidence: Confidence::Strong,
            summary,
            evidence,
            subject: String::new(),
            symptom: false,
            since: None,
        });
    }
    let no_link = link != LinkState::Up;

    // --- gateway / LAN ---
    if let Some(g) = gw {
        let loss = g.recent_loss_pct(th::RECENT);
        // An established baseline gets a veto over the *inflation* claim: on a
        // network whose learned normal already sits near the current reading,
        // absolute thresholds are the wrong judge and would flap all day.
        // Loss-based raises are never vetoed — packets don't have a "normal".
        let baseline_says_normal = baseline
            .and_then(|b| b.gateway_ms)
            .zip(g.stats(th::RECENT).mean)
            .is_some_and(|(normal, cur)| !crate::baseline::well_above(cur, normal));
        let raise = gw_health == Health::Bad
            || (gw_health != Health::NoData && inflated(g) && !baseline_says_normal);
        if raise {
            let severity = if loss >= th::LOSS_DOWN_PCT {
                Severity::Down
            } else {
                Severity::Degraded
            };
            // Corroboration: everything behind a dead gateway fails, so bad
            // anchors make the story consistent. Fine anchors *contradict* it —
            // many gateways deprioritise ICMP while forwarding perfectly.
            // Contrast: the gateway itself is failing. Corroboration: what is
            // behind it fails too. Contradiction: anchors fine — many gateways
            // deprioritise ICMP while forwarding perfectly.
            let mut confidence = judge(true, bad.len() >= 2, fine >= 2 && bad.is_empty());
            let summary = if loss >= th::LOSS_DOWN_PCT {
                format!("gateway unresponsive ({loss:.0}% loss)")
            } else if loss >= th::LOSS_BAD_PCT {
                format!("gateway losing packets ({loss:.0}% loss)")
            } else {
                format!(
                    "gateway latency inflated ({} vs {} idle)",
                    fmt_ms(g.stats(th::RECENT).mean),
                    fmt_ms(g.min_ever_ms)
                )
            };
            let mut evidence = vec![format!(
                "gateway {}: {:.0}% loss, last {}",
                g.addr,
                loss,
                fmt_ms(g.last_rtt_ms)
            )];
            evidence.push(if fine >= 2 && bad.is_empty() {
                format!("but {fine} anchors reachable — gateway may just deprioritise ICMP")
            } else {
                format!("anchors: {} ok, {} failing", fine, bad.len())
            });
            // "vs your normal here" — the baseline agreeing hardens the claim.
            if let Some(b) = baseline
                && let (Some(cur), Some(normal)) = (g.stats(th::RECENT).mean, b.gateway_ms)
                && crate::baseline::well_above(cur, normal)
            {
                evidence.push(format!(
                    "gateway {cur:.0}ms vs ~{normal:.0}ms normal at {} ({:.1}×)",
                    b.display_name(),
                    cur / normal.max(0.1)
                ));
                // Independent corroboration hardens the claim by one level.
                confidence = match confidence {
                    Confidence::Weak => Confidence::Likely,
                    _ => Confidence::Strong,
                };
            }
            findings.push(Finding {
                cause: Cause::GatewayLan,
                severity,
                confidence,
                summary,
                evidence,
                subject: String::new(),
                symptom: false,
                since: None,
            });
        }
    }

    // --- physical link (Wi-Fi radio / cable errors) ---
    let err_pct = s.link_errors.error_pct();
    if s.netinfo.medium == LinkMedium::WiFi && s.signal.present {
        let rssi = s.signal.rssi_dbm;
        let low_snr = s
            .signal
            .noise_dbm
            .is_some_and(|noise| rssi - noise < th::SNR_MIN_DB);
        let weak = rssi <= th::RSSI_BAD_DBM || low_snr;
        if weak || err_pct > th::LINK_ERR_BAD_PCT {
            let hurting = !gw_fine && gw_health != Health::NoData;
            let mut evidence = vec![format!(
                "rssi {rssi} dBm{}, tx {:.0} Mbps",
                s.signal
                    .noise_dbm
                    .map(|n| format!(" (noise {n}, SNR {})", rssi - n))
                    .unwrap_or_default(),
                s.signal.tx_rate_mbps
            )];
            if let Some(b) = baseline
                && let Some(normal) = b.rssi_dbm
                && (rssi as f64) < normal - 10.0
            {
                evidence.push(format!(
                    "rssi {rssi} dBm vs ~{normal:.0} dBm normal at {}",
                    b.display_name()
                ));
            }
            if err_pct > th::LINK_ERR_BAD_PCT {
                evidence.push(format!("interface errors: {err_pct:.1}% of packets"));
            }
            // Contrast: the gateway suffers with it. Corroboration: the radio
            // is unambiguously bad, or the baseline says this is far below
            // this network's normal.
            let baseline_worse = baseline
                .and_then(|b| b.rssi_dbm)
                .is_some_and(|normal| (rssi as f64) < normal - 10.0);
            findings.push(if hurting {
                Finding {
                    cause: Cause::WifiLink,
                    severity: Severity::Degraded,
                    confidence: judge(true, rssi <= th::RSSI_AWFUL_DBM || baseline_worse, false),
                    summary: format!("Wi-Fi link is weak (rssi {rssi} dBm)"),
                    evidence,
                    subject: String::new(),
                    symptom: false,
                    since: None,
                }
            } else {
                Finding {
                    cause: Cause::WifiLink,
                    severity: Severity::Info,
                    confidence: Confidence::Weak,
                    summary: format!("Wi-Fi signal weak (rssi {rssi} dBm) — not yet hurting"),
                    evidence,
                    subject: String::new(),
                    symptom: false,
                    since: None,
                }
            });
        }
    } else if s.netinfo.medium.is_wired() && err_pct > th::LINK_ERR_BAD_PCT {
        findings.push(Finding {
            cause: Cause::WifiLink,
            severity: Severity::Degraded,
            confidence: Confidence::Likely,
            summary: format!("link errors ({err_pct:.1}% of packets)"),
            evidence: vec![format!(
                "{}: {} rx / {} tx errors — bad cable or duplex mismatch territory",
                s.link_errors.iface, s.link_errors.rx_err_total, s.link_errors.tx_err_total
            )],
            subject: String::new(),
            symptom: false,
            since: None,
        });
    }

    // --- DNS ---
    // Judged on the recent window, like ICMP: a resolver that died a minute ago
    // must read as failing now, and one that recovered must stop.
    let probes: Vec<&crate::app::DnsProbe> = s
        .dns
        .iter()
        .filter(|p| !p.reference && p.recent_len() >= th::DNS_MIN_SAMPLES)
        .collect();
    let reference = s
        .dns
        .iter()
        .find(|p| p.reference && p.recent_len() >= th::DNS_MIN_SAMPLES);
    let failing = |p: &crate::app::DnsProbe| p.fail_pct() >= th::DNS_FAIL_PCT;
    let reference_ok = reference.is_some_and(|r| !failing(r));
    let reference_dead = reference.is_some_and(failing);
    if !probes.is_empty() {
        let slow =
            |p: &crate::app::DnsProbe| p.recent_mean_ms().is_some_and(|m| m > th::DNS_BAD_MS);
        let n_fail = probes.iter().filter(|p| failing(p)).count();
        let n_slow = probes.iter().filter(|p| !failing(p) && slow(p)).count();
        // Contrast: ping works, names don't. Corroboration: the HTTP check —
        // which resolves a hostname — is failing too. Contradiction: the
        // gateway or the anchors are down as well, so DNS is a symptom.
        let http_ok = matches!(s.http.v4, crate::app::FamilyProbe::Ok(_))
            || matches!(s.http.v6, crate::app::FamilyProbe::Ok(_));
        let http_failing = matches!(s.http.v4, crate::app::FamilyProbe::Fail(_))
            && !matches!(s.http.v6, crate::app::FamilyProbe::Ok(_));
        let dns_symptom = no_link || gw_health == Health::Bad || bad.len() >= 2;
        let confidence = judge(fine >= 2, http_failing, dns_symptom);
        let mut evidence: Vec<String> = probes
            .iter()
            .map(|p| {
                format!(
                    "resolver {}: mean {}, {:.0}% failed recently{}",
                    p.server,
                    fmt_ms(p.recent_mean_ms()),
                    p.fail_pct(),
                    if p.status.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", p.status)
                    }
                )
            })
            .collect();
        if let Some(b) = baseline
            && let Some(normal) = b.dns_ms
        {
            let worst = probes
                .iter()
                .filter_map(|p| p.recent_mean_ms())
                .fold(0.0_f64, f64::max);
            if worst > normal * 3.0 && worst > th::DNS_WARN_MS {
                evidence.push(format!(
                    "DNS {worst:.0}ms vs ~{normal:.0}ms normal at {}",
                    b.display_name()
                ));
            }
        }
        // A working HTTP probe *proves* names resolve — it fetched a hostname
        // through the system resolver. When octomon's own resolver probes fail
        // anyway (link-local quirks, port-53 filtering on carrier networks),
        // the honest claim is "probes blocked", not "DNS down".
        let names_resolve = http_ok;
        if n_fail == probes.len() && names_resolve {
            let mut evidence = evidence.clone();
            evidence.push("HTTP check fetched a hostname fine — resolution itself works".into());
            // Loopback resolvers are a DNS filter/proxy on this machine
            // (AdGuard-style 127.0.2.x is the classic signature): it answers
            // the OS but not necessarily octomon's probes. Name the situation
            // rather than reporting a generic failure.
            let all_local = probes.iter().all(|p| p.server.is_loopback());
            findings.push(Finding {
                cause: Cause::Dns,
                severity: Severity::Info,
                confidence: Confidence::Weak,
                summary: if all_local {
                    "a local DNS proxy handles resolution — probes not answerable".to_string()
                } else {
                    "resolver probes blocked on this network — names still resolve".to_string()
                },
                evidence,
                subject: String::new(),
                symptom: false,
                since: None,
            });
        } else if n_fail == probes.len() {
            // The reference resolver is the discriminator: it answering means
            // DNS as such works and *these* resolvers are the fault.
            let (summary, confidence) = if reference_ok {
                evidence.push(format!(
                    "reference resolver {} answers fine — the configured resolvers are the problem",
                    reference.map(|r| r.server.to_string()).unwrap_or_default()
                ));
                (
                    format!(
                        "your DNS resolvers not answering — {} works: switch DNS to it",
                        reference.map(|r| r.server.to_string()).unwrap_or_default()
                    ),
                    judge(fine >= 2, true, dns_symptom),
                )
            } else {
                (
                    format!("DNS not answering (all {} resolvers failing)", probes.len()),
                    confidence,
                )
            };
            findings.push(Finding {
                cause: Cause::Dns,
                severity: Severity::Down,
                confidence,
                summary,
                evidence,
                subject: String::new(),
                symptom: dns_symptom,
                since: None,
            });
        } else if n_fail + n_slow == probes.len() {
            findings.push(Finding {
                cause: Cause::Dns,
                severity: Severity::Degraded,
                confidence,
                summary: "DNS slow on every resolver".to_string(),
                evidence,
                subject: String::new(),
                symptom: dns_symptom,
                since: None,
            });
        } else if n_fail > 0 {
            findings.push(Finding {
                cause: Cause::Dns,
                severity: Severity::Info,
                confidence: Confidence::Weak,
                summary: format!(
                    "{n_fail} of {} DNS resolvers failing — others fine",
                    probes.len()
                ),
                evidence,
                subject: String::new(),
                symptom: false,
                since: None,
            });
        }
    }

    // Outside DNS filtered while the network's own works: a fact about this
    // network worth knowing (apps with their own resolver settings will fail).
    let system_ok = !probes.is_empty() && probes.iter().all(|p| !failing(p));
    if reference_dead && system_ok && !no_link {
        let r = reference.unwrap();
        findings.push(Finding {
            cause: Cause::Dns,
            severity: Severity::Info,
            confidence: judge(true, false, false),
            summary: format!(
                "outside resolvers blocked — {} unreachable while this network's DNS works",
                r.server
            ),
            evidence: vec![
                format!("{}: {:.0}% of recent queries failed ({})", r.server, r.fail_pct(), r.status),
                "port 53 to the internet is filtered; anything configured to use its own DNS will fail here"
                    .to_string(),
            ],
            subject: "reference".to_string(),
            symptom: false,
            since: None,
        });
    }

    // Hijack: a name that cannot exist came back with an address.
    let hijackers: Vec<&crate::app::DnsProbe> =
        s.dns.iter().filter(|p| p.hijack == Some(true)).collect();
    if !hijackers.is_empty() {
        let names: Vec<String> = hijackers.iter().map(|p| p.server.to_string()).collect();
        // Corroboration: the reference resolver, asked the same, said NXDOMAIN
        // — so it is these resolvers, not the network, doing it.
        let reference_honest = reference.is_some_and(|r| r.hijack == Some(false));
        let all_hijack = s.dns.iter().all(|p| p.hijack != Some(false));
        findings.push(Finding {
            cause: Cause::DnsHijack,
            severity: Severity::Degraded,
            confidence: judge(true, reference_honest, false),
            summary: if hijackers.iter().all(|p| p.reference) {
                "DNS answers redirected on this network — even the reference resolver's misses come back with an address".to_string()
            } else {
                format!("resolver {} redirects non-existent names to an address", names.join(", "))
            },
            evidence: vec![
                "a random name that cannot exist resolved to an address instead of NXDOMAIN".to_string(),
                if reference_honest {
                    "the reference resolver answered NXDOMAIN for the same kind of name".to_string()
                } else if all_hijack {
                    "every resolver does it, the reference included — the network intercepts DNS".to_string()
                } else {
                    "typo'd hostnames land on a search/ad page; software relying on a name not resolving misbehaves".to_string()
                },
            ],
            subject: String::new(),
            symptom: false,
            since: None,
        });
    }

    // --- beyond the gateway: wide internet vs a specific destination ---
    let wide = gw_fine && bad.len() >= 2 && bad.len() * 2 >= with_data.len();
    if wide {
        let all_down = bad
            .iter()
            .all(|t| t.recent_loss_pct(th::RECENT) >= th::LOSS_DOWN_PCT);
        let severity = if all_down {
            Severity::Down
        } else {
            Severity::Degraded
        };
        let mut evidence: Vec<String> = vec![format!(
            "gateway fine ({}, {:.0}% loss) but {} of {} anchors failing",
            fmt_ms(gw.and_then(|g| g.last_rtt_ms)),
            gw.map(|g| g.recent_loss_pct(th::RECENT)).unwrap_or(0.0),
            bad.len(),
            with_data.len()
        )];
        for t in &bad {
            evidence.push(format!(
                "{} ({}): {:.0}% loss",
                t.label,
                t.addr,
                t.recent_loss_pct(th::RECENT)
            ));
        }
        // Localise with the hop monitor when one is running: loss that begins
        // within the first few hops is the ISP's segment, not the wide internet.
        // "Begins" means it persists to every later hop that answers — a lossy
        // hop followed by clean ones is only rate-limiting its own ICMP replies
        // while forwarding fine, the oldest false positive in path analysis.
        let early_bad_hop = s.hop_monitor.as_ref().and_then(|m| {
            let loss_of = |h: &crate::app::MonitoredHop| {
                h.stat
                    .as_ref()
                    .filter(|st| st.window.len() >= 10)
                    .map(|st| st.recent_loss_pct(th::RECENT))
            };
            m.hops
                .iter()
                .filter(|h| h.ttl >= 2 && h.ttl <= 4)
                .find(|h| {
                    let Some(loss) = loss_of(h) else { return false };
                    if loss < th::LOSS_BAD_PCT {
                        return false;
                    }
                    let mut later = m
                        .hops
                        .iter()
                        .filter(|o| o.ttl > h.ttl)
                        .filter_map(loss_of)
                        .peekable();
                    // No measured hop beyond it: the destinations are failing
                    // (we are inside `wide`), so the loss did carry through.
                    later.peek().is_none() || later.all(|l| l >= th::LOSS_BAD_PCT)
                })
        });
        if let Some(h) = early_bad_hop {
            let addr = h
                .addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "?".to_string());
            evidence.push(format!("loss begins at hop {} ({})", h.ttl, addr));
            evidence.push("loss persists on every later hop — not ICMP rate-limiting".to_string());
            findings.push(Finding {
                cause: Cause::IspHop,
                severity,
                confidence: judge(true, true, false),
                summary: format!("ISP path degraded — loss begins at hop {} ({addr})", h.ttl),
                evidence,
                subject: String::new(),
                symptom: false,
                since: None,
            });
        } else {
            let http_failing = matches!(s.http.v4, crate::app::FamilyProbe::Fail(_))
                && !matches!(s.http.v6, crate::app::FamilyProbe::Ok(_));
            findings.push(Finding {
                cause: Cause::WideInternet,
                severity,
                confidence: judge(true, http_failing || bad.len() == with_data.len(), false),
                summary: format!(
                    "internet {} beyond the gateway ({} of {} anchors failing)",
                    if all_down { "unreachable" } else { "degraded" },
                    bad.len(),
                    with_data.len()
                ),
                evidence,
                subject: String::new(),
                symptom: false,
                since: None,
            });
        }
    } else if gw_health != Health::Bad && fine >= 2 {
        // Consensus says the connection works; whatever is bad is *that* place.
        for t in &bad {
            let loss = t.recent_loss_pct(th::RECENT);
            let unreachable = loss >= th::LOSS_DOWN_PCT;
            let what = if unreachable {
                "unreachable".to_string()
            } else {
                format!("degraded ({loss:.0}% loss)")
            };
            // Corroboration: its web service is unanswered too, or it is the
            // only one out while several others answer.
            let web_out = t.web.status == crate::app::WebStatus::Web && t.web.fails >= 2;
            findings.push(Finding {
                cause: Cause::SingleDestination,
                // The connection is fine by construction here — this is about
                // one far end. Some loss to one anchor is a note; only a
                // destination that has gone entirely is worth more, and even
                // then it is that place's problem, not this machine's.
                severity: if unreachable {
                    Severity::Degraded
                } else {
                    Severity::Info
                },
                confidence: judge(true, web_out || (bad.len() == 1 && fine >= 3), false),
                summary: format!("{} {what} — your connection is fine", t.label),
                evidence: vec![
                    format!("{} ({}): {loss:.0}% loss", t.label, t.addr),
                    format!("{fine} other anchors fine, gateway fine"),
                ],
                subject: t.label.clone(),
                symptom: false,
                since: None,
            });
        }
    }

    // --- devices on the LAN: never an internet question ---
    for t in &lan_targets {
        if probe_health(t) != Health::Bad {
            continue;
        }
        let loss = t.recent_loss_pct(th::RECENT);
        // If the whole LAN is unreachable this is the gateway's story.
        let symptom = no_link || gw_health == Health::Bad;
        findings.push(Finding {
            cause: Cause::SingleDestination,
            severity: Severity::Degraded,
            confidence: judge(gw_fine, gw_fine && fine >= 2, symptom),
            summary: format!("{} (on your LAN) unreachable — {loss:.0}% loss", t.label),
            evidence: vec![
                format!(
                    "{} ({}) is on this network, not across the internet",
                    t.label, t.addr
                ),
                if gw_fine {
                    "gateway answers, so the LAN itself is up — that device is the place to look"
                        .to_string()
                } else {
                    "gateway not answering either".to_string()
                },
            ],
            subject: t.label.clone(),
            symptom,
            since: None,
        });
    }

    // --- HTTP layer: portals, filtered web traffic, broken IPv6 ---
    {
        use crate::app::FamilyProbe as FP;
        let http = &s.http;
        let captive = [&http.v4, &http.v6].into_iter().find_map(|f| match f {
            FP::Captive(loc) => Some(loc.clone()),
            _ => None,
        });
        if let Some(location) = captive {
            let mut evidence = vec![format!(
                "{} connectivity check answered with a sign-in page",
                http.provider
            )];
            if let Some(loc) = location {
                evidence.push(format!("redirected to {loc}"));
            }
            findings.push(Finding {
                cause: Cause::CaptivePortal,
                severity: Severity::Down,
                confidence: Confidence::Strong,
                summary: "captive portal — open this network's sign-in page".to_string(),
                evidence,
                subject: String::new(),
                symptom: false,
                since: None,
            });
        } else if let (FP::Ok(v4_ms), FP::Fail(reason)) = (&http.v4, &http.v6) {
            // Where along the way v6 breaks — the fix differs at each point.
            let no_v6_gateway = s.netinfo.gateway_ipv6.is_empty();
            let v6_dns: Vec<&crate::app::DnsProbe> = s
                .dns
                .iter()
                .filter(|p| {
                    !p.reference && p.server.is_ipv6() && p.recent_len() >= th::DNS_MIN_SAMPLES
                })
                .collect();
            let v6_dns_dead =
                !v6_dns.is_empty() && v6_dns.iter().all(|p| p.fail_pct() >= th::DNS_FAIL_PCT);
            let mut evidence = vec![format!("v6 probe: {reason} · v4 probe: ok {v4_ms:.0}ms")];
            let (where_, corroborated) = if no_v6_gateway {
                evidence.push(
                    "this interface has a global IPv6 address but no IPv6 default router — the router advertises addresses without a route"
                        .to_string(),
                );
                ("at the router: address but no route", true)
            } else if v6_dns_dead {
                evidence.push(format!(
                    "the IPv6 resolver{} ({}) not answering either",
                    if v6_dns.len() == 1 { "" } else { "s" },
                    v6_dns
                        .iter()
                        .map(|p| p.server.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
                ("beyond the router: nothing over v6 answers", true)
            } else {
                evidence.push(format!(
                    "IPv6 router {} is configured; the break is upstream of it",
                    s.netinfo.gateway_ipv6
                ));
                ("upstream of the router", false)
            };
            evidence.push(
                "browsers try v6 first and fall back, adding delay to every request".to_string(),
            );
            findings.push(Finding {
                cause: Cause::Ipv6Broken,
                severity: Severity::Degraded,
                confidence: judge(true, corroborated, false),
                summary: format!("IPv6 broken while IPv4 works — {where_}"),
                evidence,
                subject: String::new(),
                symptom: false,
                since: None,
            });
        } else if let (FP::Fail(reason), FP::Ok(v6_ms)) = (&http.v4, &http.v6) {
            // The mirror image is rarer but real (a v4 firewall rule, a broken
            // NAT) and would otherwise leave the Http rung at Warn with no story.
            findings.push(Finding {
                cause: Cause::HttpBlocked,
                severity: Severity::Degraded,
                confidence: judge(true, fine >= 2, false),
                summary: "IPv4 web broken while IPv6 works".to_string(),
                evidence: vec![
                    format!("v4 probe: {reason} · v6 probe: ok {v6_ms:.0}ms"),
                    "IPv6-capable sites still load; anything IPv4-only does not".to_string(),
                ],
                subject: String::new(),
                symptom: false,
                since: None,
            });
        } else if matches!(http.v4, FP::Fail(_)) && !matches!(http.v6, FP::Ok(_)) && fine >= 2 {
            let reason = match &http.v4 {
                FP::Fail(r) => r.clone(),
                _ => String::new(),
            };
            // A configured proxy that works turns this from a fault into how
            // this network is meant to be used.
            let proxied_ok = matches!(http.via_proxy, FP::Ok(_));
            let proxy_desc = s.proxy.as_ref().map(|p| p.describe()).unwrap_or_default();
            if proxied_ok {
                findings.push(Finding {
                    cause: Cause::HttpBlocked,
                    severity: Severity::Info,
                    confidence: judge(true, true, false),
                    summary: "direct web blocked — this network requires the configured proxy, which works".to_string(),
                    evidence: vec![
                        format!("direct HTTP probe failed ({reason}); the same check via {proxy_desc} succeeded"),
                        "browsers and apps that follow the system proxy are fine; anything going direct is not".to_string(),
                    ],
                    subject: String::new(),
                    symptom: false,
                    since: None,
                });
            } else {
                let mut evidence = vec![
                    format!("HTTP probe failed ({reason}) on two independent endpoints"),
                    format!("{fine} anchors answer ICMP normally"),
                ];
                if let Some(p) = &s.proxy {
                    evidence.push(match &http.via_proxy {
                        FP::Fail(r) => format!("via the configured proxy {}: also failing ({r})", p.describe()),
                        _ => format!("a proxy is configured ({}) — browsers use it; octomon's check is direct", p.describe()),
                    });
                }
                findings.push(Finding {
                    cause: Cause::HttpBlocked,
                    severity: Severity::Degraded,
                    // Contrast: ping works. Corroboration: a second, independent
                    // provider was consulted before the failure was reported.
                    confidence: judge(true, true, false),
                    summary: "web traffic blocked while ping works — proxy or firewall".to_string(),
                    evidence,
                    subject: String::new(),
                    symptom: false,
                    since: None,
                });
            }
        } else if let (FP::Ok(_), FP::Fail(r)) = (&http.v4, &http.via_proxy)
            && let Some(p) = &s.proxy
        {
            // The mirror: direct works, the proxy every browser is pointed at
            // does not — a stale setting from another network, or a dead proxy.
            findings.push(Finding {
                cause: Cause::HttpBlocked,
                severity: Severity::Degraded,
                confidence: judge(true, false, false),
                summary: "the configured web proxy is not answering — browsers fail while the network is fine".to_string(),
                evidence: vec![
                    format!("via {}: {r} · direct HTTP: ok", p.describe()),
                    "a proxy setting left over from another network is the usual cause".to_string(),
                ],
                subject: "proxy".to_string(),
                symptom: false,
                since: None,
            });
        }
    }

    // --- web targets that answered before and stopped ---
    // A captive portal intercepts every HTTP request, so per-target web
    // failures under one are the portal's story, already ranked first.
    let captive_active = findings.iter().any(|f| f.cause == Cause::CaptivePortal);
    if !captive_active {
        for t in s.targets.iter().filter(|t| !t.discovered) {
            if t.web.status == crate::app::WebStatus::Web
                && t.web.fails >= 2
                && matches!(probe_health(t), Health::Good | Health::Warn)
            {
                findings.push(Finding {
                    cause: Cause::WebTarget,
                    severity: Severity::Degraded,
                    // Contrast: ping is fine while HTTP is not. Corroboration
                    // would be a second vantage point, which there isn't.
                    confidence: judge(true, false, false),
                    summary: format!("web check to {} unanswered — ping still fine", t.label),
                    evidence: vec![
                        format!(
                            "{} HTTPS HEAD probes in a row unanswered by a target that answered them before",
                            t.web.fails
                        ),
                        format!(
                            "ICMP to {} still healthy ({:.0}% loss) — the web side, not the path",
                            t.addr,
                            t.recent_loss_pct(th::RECENT)
                        ),
                    ],
                    subject: t.label.clone(),
                    symptom: false,
                    since: None,
                });
            }
        }
    }

    // --- bufferbloat (only meaningful under load) ---
    // "Load" is relative to the *WAN*, which is what saturates: the learned
    // speed-test result for this network when there is one. The negotiated
    // link speed is the fallback, and a poor one — a gigabit NIC on a 50 Mb
    // line never looks loaded by that measure.
    let n = s.window_samples().min(60);
    let wan_loaded = baseline.is_some_and(|b| {
        let down_cap = b.down_mbps.map(|m| m * 1e6);
        let up_cap = b.up_mbps.map(|m| m * 1e6);
        down_cap.is_some_and(|c| s.throughput.down_bps * 8.0 > 0.5 * c)
            || up_cap.is_some_and(|c| s.throughput.up_bps * 8.0 > 0.5 * c)
    });
    let link_loaded = s
        .netinfo
        .link_speed_bps
        .is_some_and(|cap| (s.throughput.down_bps + s.throughput.up_bps) * 8.0 > 0.3 * cap as f64);
    let loaded = speedtest_running || wan_loaded || link_loaded;
    if loaded {
        let worst = anchors
            .iter()
            .filter_map(|t| t.bufferbloat_ms(n).map(|b| (b, t.label.clone())))
            .max_by(|a, b| a.0.total_cmp(&b.0));
        if let Some((bloat, label)) = worst
            && bloat >= th::BLOAT_FINDING_MS
        {
            findings.push(Finding {
                cause: Cause::Bufferbloat,
                severity: Severity::Degraded,
                // Contrast: latency up while loaded. Corroboration: the load is
                // certain — a speed test is running, or throughput is measured
                // against this network's own capacity rather than the NIC's.
                confidence: judge(true, speedtest_running || wan_loaded, false),
                summary: format!("bufferbloat: +{bloat:.0}ms latency under load"),
                evidence: vec![
                    format!(
                        "{label}: mean over the last minute is {bloat:.0}ms above the idle floor"
                    ),
                    if speedtest_running {
                        "load: speed test running".to_string()
                    } else if wan_loaded {
                        format!(
                            "load: {:.0}/{:.0} Mb/s against ~{}/{} Mb/s learned here",
                            s.throughput.down_bps * 8.0 / 1e6,
                            s.throughput.up_bps * 8.0 / 1e6,
                            baseline
                                .and_then(|b| b.down_mbps)
                                .map(|m| format!("{m:.0}"))
                                .unwrap_or("?".into()),
                            baseline
                                .and_then(|b| b.up_mbps)
                                .map(|m| format!("{m:.0}"))
                                .unwrap_or("?".into()),
                        )
                    } else {
                        "load: >30% of the negotiated link speed".to_string()
                    },
                ],
                subject: String::new(),
                symptom: false,
                since: None,
            });
        }
    }

    // --- path MTU black hole: big packets vanish, small ones sail through ---
    if let Some(p) = &s.pmtu
        && p.blackhole
        && !no_link
    {
        findings.push(Finding {
            cause: Cause::PathMtu,
            severity: Severity::Degraded,
            // Contrast: full-size probes vanish while smaller ones answer.
            // Corroboration: the kernel learned nothing between attempts —
            // the fragmentation-needed message never came.
            confidence: judge(true, !p.pmtud_works, false),
            summary: format!(
                "path MTU black hole — packets over {} bytes vanish silently",
                p.path_mtu.map(|m| m.to_string()).unwrap_or_else(|| "~1200".into())
            ),
            evidence: vec![
                format!(
                    "DF probe to {}: {} answered, {} not — and no fragmentation-needed came back",
                    p.target,
                    p.path_mtu.map(|m| format!("{m} bytes")).unwrap_or_else(|| "nothing".into()),
                    p.iface_mtu.map(|m| format!("{m} bytes")).unwrap_or_else(|| "full size".into()),
                ),
                "symptom: pings and small pages fine, big downloads / uploads / VPNs stall — lower the MTU or fix the firewall dropping ICMP".to_string(),
            ],
            subject: String::new(),
            symptom: false,
            since: None,
        });
    }

    // --- system clock: nothing on the network can explain what this breaks ---
    if let Some(off) = s.clock.offset_ms()
        && off.abs() >= th::CLOCK_WARN_MS
    {
        let ntp = s.clock.ntp_offset_ms.is_some();
        // The Date header is a coarse reading from whatever answered the HTTP
        // check; without NTP behind it the claim stays a note.
        let bad = off.abs() >= th::CLOCK_BAD_MS && ntp;
        findings.push(Finding {
            cause: Cause::ClockSkew,
            severity: if bad {
                Severity::Degraded
            } else {
                Severity::Info
            },
            // Contrast: measured against an external reference. Corroboration:
            // NTP is millisecond-precise; the HTTP Date reading is coarse.
            confidence: judge(true, ntp, false),
            summary: if bad {
                format!(
                    "{} — HTTPS certificates will be rejected until it is fixed",
                    crate::collectors::clock::describe_offset(off)
                )
            } else {
                format!(
                    "{} — time-based logins and some TLS checks may fail",
                    crate::collectors::clock::describe_offset(off)
                )
            },
            evidence: vec![
                format!(
                    "offset {:+.1} s against {}",
                    off / 1000.0,
                    if ntp {
                        "an NTP time server"
                    } else {
                        "the HTTP check's Date header (±1 s)"
                    }
                ),
                "ping and DNS cannot see this — browsers show certificate-date errors".to_string(),
            ],
            subject: String::new(),
            symptom: false,
            since: None,
        });
    }

    // --- machine (caveat-class: co-reported, never the sole confident answer) ---
    let v = &s.vitals;
    if v.throttled {
        findings.push(Finding {
            cause: Cause::Machine,
            severity: Severity::Degraded,
            confidence: Confidence::Strong,
            summary: "thermal throttling active".to_string(),
            evidence: vec![
                "the OS is limiting performance — throughput collapses while CPU reads idle"
                    .to_string(),
            ],
            subject: "thermal".to_string(),
            symptom: false,
            since: None,
        });
    }
    // Whole-machine load only: one saturated core is a compile or an encode,
    // not a reason packets are late, and it would read as "machine under
    // load (cpu 36%)" — a note nobody believes.
    let hottest = v.hottest_core().map(|(_, pct)| pct).unwrap_or(0.0);
    if v.cpu_pct >= th::CPU_HOT_PCT {
        findings.push(Finding {
            cause: Cause::Machine,
            severity: Severity::Info,
            confidence: Confidence::Likely,
            summary: format!("machine under load (cpu {:.0}%)", v.cpu_pct),
            evidence: vec![format!("cpu {:.0}%, hottest core {hottest:.0}%", v.cpu_pct)],
            subject: "cpu".to_string(),
            symptom: false,
            since: None,
        });
    }
    if v.mem_pressure_pct >= th::MEM_HOT_PCT {
        findings.push(Finding {
            cause: Cause::Machine,
            severity: Severity::Info,
            confidence: Confidence::Likely,
            summary: format!("memory pressure high ({:.0}%)", v.mem_pressure_pct),
            evidence: vec![format!(
                "pressure {:.0}%, swap {} MiB used",
                v.mem_pressure_pct,
                v.swap_used / 1_048_576
            )],
            subject: "memory".to_string(),
            symptom: false,
            since: None,
        });
    }

    // Drop the loss- and latency-driven findings raised from samples taken
    // under the speed test's own load: the gateway dropping octomon's pings
    // while the test saturates the line is not "gateway losing packets".
    // Bufferbloat stays — it is the honest reading of that interval and names
    // the test as the load — as do the content-based findings (hijack,
    // captive portal, clock), which no amount of load can fake.
    if self_load {
        findings.retain(|f| {
            !matches!(
                f.cause,
                Cause::GatewayLan
                    | Cause::Dns
                    | Cause::IspHop
                    | Cause::WideInternet
                    | Cause::SingleDestination
                    | Cause::WebTarget
            )
        });
    }

    // --- VPN caveat: everything above was measured through the tunnel ---
    if let Some(vendor) = s.netinfo.tunnel_label()
        && findings.iter().any(|f| !f.cause.is_caveat())
    {
        findings.push(Finding {
            cause: Cause::VpnCaveat,
            severity: Severity::Info,
            confidence: Confidence::Weak,
            summary: format!("measurements traverse {vendor} — the tunnel may be the cause"),
            evidence: vec![format!(
                "default route egresses via {}",
                s.netinfo.tunnel_iface
            )],
            subject: String::new(),
            symptom: false,
            since: None,
        });
    }

    // Nothing measured across a link that isn't there means anything: every
    // network finding is then a symptom of the missing link.
    if no_link {
        for f in findings.iter_mut() {
            if f.cause != Cause::NoLink && !f.cause.is_caveat() {
                f.symptom = true;
            }
        }
    }

    rank(&mut findings);
    let rungs = build_rungs(s, link, gw, gw_health, &with_data, &bad, fine);
    let checks = checks(s);
    Triage {
        rungs,
        checks,
        findings,
    }
}

/// The ladder itself: every area, always present, in blame order. Healthy rungs
/// carry their data — "we checked" is the difference between a verdict and an
/// assertion.
fn build_rungs(
    s: &AppState,
    link: LinkState,
    gw: Option<&TargetStat>,
    gw_health: Health,
    with_data: &[&TargetStat],
    bad: &[&TargetStat],
    fine: usize,
) -> Vec<Rung> {
    let mut rungs = Vec::with_capacity(7);
    let health_status = |h: Health| match h {
        Health::NoData => RungStatus::Unknown,
        Health::Good => RungStatus::Ok,
        Health::Warn => RungStatus::Warn,
        Health::Bad => RungStatus::Bad,
    };

    // Machine.
    let v = &s.vitals;
    // Warn exactly when the machine finding fires — one rulebook.
    let m_status = if v.throttled {
        RungStatus::Bad
    } else if v.cpu_pct >= th::CPU_HOT_PCT || v.mem_pressure_pct >= th::MEM_HOT_PCT {
        RungStatus::Warn
    } else if v.cores.is_empty() {
        RungStatus::Unknown
    } else {
        RungStatus::Ok
    };
    rungs.push(Rung {
        area: Area::Machine,
        status: m_status,
        detail: if v.cores.is_empty() {
            "no data yet".to_string()
        } else {
            format!(
                "cpu {:.0}% · pressure {:.0}%{}",
                v.cpu_pct,
                v.mem_pressure_pct,
                if v.throttled { " · THROTTLED" } else { "" }
            )
        },
    });

    // Link: first whether there is one at all, then its quality.
    let err_pct = s.link_errors.error_pct();
    let (l_status, l_detail) = match s.netinfo.medium {
        _ if link == LinkState::NoRoute => (
            RungStatus::Bad,
            "not connected — no default route".to_string(),
        ),
        _ if link == LinkState::SelfAssigned => (
            RungStatus::Bad,
            format!(
                "self-assigned {} — no DHCP lease",
                s.netinfo.ipv4.join(", ")
            ),
        ),
        _ if link == LinkState::NoGateway => (
            RungStatus::Bad,
            format!("{} has an address but no gateway", s.netinfo.iface),
        ),
        LinkMedium::WiFi if s.signal.present => {
            let rssi = s.signal.rssi_dbm;
            let status = if rssi <= th::RSSI_BAD_DBM || err_pct > th::LINK_ERR_BAD_PCT {
                RungStatus::Bad
            } else if rssi <= th::RSSI_WEAK_DBM {
                RungStatus::Warn
            } else {
                RungStatus::Ok
            };
            (
                status,
                format!(
                    "Wi-Fi rssi {rssi} dBm · tx {:.0} Mbps · errors {err_pct:.1}%",
                    s.signal.tx_rate_mbps
                ),
            )
        }
        m if m.is_wired() => (
            if err_pct > th::LINK_ERR_BAD_PCT {
                RungStatus::Bad
            } else {
                RungStatus::Ok
            },
            format!(
                "{}{} · errors {err_pct:.1}%",
                m.label(),
                s.netinfo
                    .link_speed_bps
                    .map(|b| format!(" {} Mb", b / 1_000_000))
                    .unwrap_or_default()
            ),
        ),
        LinkMedium::Unknown => (RungStatus::Unknown, "no data yet".to_string()),
        // Wi-Fi with no signal sample yet: not measured is not fine.
        LinkMedium::WiFi => (
            RungStatus::Unknown,
            "Wi-Fi · no signal data yet".to_string(),
        ),
        m => (RungStatus::Ok, m.label().to_string()),
    };
    rungs.push(Rung {
        area: Area::Link,
        status: l_status,
        detail: l_detail,
    });

    // Gateway.
    rungs.push(match gw {
        Some(g) if gw_health != Health::NoData => {
            let st = g.stats(th::RECENT);
            let mut detail = format!(
                "{} · p95 {} · loss {:.0}%",
                g.addr,
                fmt_ms(st.p95),
                g.recent_loss_pct(th::RECENT)
            );
            if let Some(b) = s.baseline.as_ref().filter(|b| b.established())
                && let Some(normal) = b.gateway_ms
            {
                detail.push_str(&format!(" · ~{normal:.0}ms normal here"));
            }
            Rung {
                area: Area::Gateway,
                status: health_status(gw_health),
                detail,
            }
        }
        _ => Rung {
            area: Area::Gateway,
            status: RungStatus::Unknown,
            detail: "not discovered yet".to_string(),
        },
    });

    // DNS (this network's resolvers; the reference is contrast, not a rung).
    let probes: Vec<&crate::app::DnsProbe> = s
        .dns
        .iter()
        .filter(|p| !p.reference && p.recent_len() >= th::DNS_MIN_SAMPLES)
        .collect();
    rungs.push(if probes.is_empty() {
        Rung {
            area: Area::Dns,
            status: RungStatus::Unknown,
            detail: "no data yet".to_string(),
        }
    } else {
        let worst_mean = probes
            .iter()
            .filter_map(|p| p.recent_mean_ms())
            .fold(0.0_f64, f64::max);
        let n_fail = probes
            .iter()
            .filter(|p| p.fail_pct() >= th::DNS_FAIL_PCT)
            .count();
        let status = if n_fail == probes.len() {
            RungStatus::Bad
        } else if n_fail > 0 || worst_mean > th::DNS_BAD_MS {
            RungStatus::Warn
        } else {
            RungStatus::Ok
        };
        Rung {
            area: Area::Dns,
            status,
            detail: format!(
                "{} resolver{} · worst mean {worst_mean:.0}ms{}",
                probes.len(),
                if probes.len() == 1 { "" } else { "s" },
                if n_fail > 0 {
                    format!(" · {n_fail} failing")
                } else {
                    String::new()
                }
            ),
        }
    });

    // ISP path (first hops beyond the gateway, via the hop monitor when running).
    let early: Vec<(&crate::app::MonitoredHop, f64)> = s
        .hop_monitor
        .as_ref()
        .map(|m| {
            m.hops
                .iter()
                .filter(|h| h.ttl >= 2 && h.ttl <= 4)
                .filter_map(|h| {
                    h.stat
                        .as_ref()
                        .filter(|st| st.window.len() >= th::MIN_SAMPLES)
                        .map(|st| (h, st.recent_loss_pct(th::RECENT)))
                })
                .collect()
        })
        .unwrap_or_default();
    rungs.push(if early.is_empty() {
        Rung {
            area: Area::IspPath,
            status: RungStatus::Unknown,
            detail: "no path monitor — [m] to watch every hop".to_string(),
        }
    } else {
        let worst = early.iter().map(|(_, l)| *l).fold(0.0_f64, f64::max);
        let status = if worst >= th::LOSS_BAD_PCT {
            RungStatus::Bad
        } else if worst >= th::LOSS_WARN_PCT {
            RungStatus::Warn
        } else {
            RungStatus::Ok
        };
        Rung {
            area: Area::IspPath,
            status,
            detail: format!("hops 2-{} · worst loss {worst:.0}%", 2 + early.len() - 1),
        }
    });

    // Internet (anchor consensus).
    rungs.push(if with_data.is_empty() {
        Rung {
            area: Area::Internet,
            status: RungStatus::Unknown,
            detail: "no data yet".to_string(),
        }
    } else {
        let worst_loss = with_data
            .iter()
            .map(|t| t.recent_loss_pct(th::RECENT))
            .fold(0.0_f64, f64::max);
        let worst_p95 = with_data
            .iter()
            .filter_map(|t| t.stats(th::RECENT).p95)
            .fold(0.0_f64, f64::max);
        let status = if bad.len() >= 2 {
            RungStatus::Bad
        } else if bad.len() == 1 || worst_loss >= th::LOSS_WARN_PCT {
            RungStatus::Warn
        } else {
            RungStatus::Ok
        };
        Rung {
            area: Area::Internet,
            status,
            detail: format!(
                "{} anchor{} · worst p95 {worst_p95:.0}ms · worst loss {worst_loss:.0}%",
                with_data.len(),
                if with_data.len() == 1 { "" } else { "s" }
            ),
        }
    });

    // Web (HTTP layer).
    rungs.push({
        use crate::app::FamilyProbe as FP;
        let describe = |f: &FP, name: &str| match f {
            FP::NotRun => format!("{name} not probed yet"),
            FP::NotApplicable => format!("{name} n/a"),
            FP::Ok(ms) => format!("{name} ok {ms:.0}ms"),
            FP::Captive(_) => format!("{name} CAPTIVE PORTAL"),
            FP::Fail(r) => format!("{name} failed ({r})"),
        };
        let status = match (&s.http.v4, &s.http.v6) {
            (FP::Captive(_), _) | (_, FP::Captive(_)) => RungStatus::Bad,
            (FP::Fail(_), FP::Ok(_)) | (FP::Ok(_), FP::Fail(_)) => RungStatus::Warn,
            (FP::Fail(_), _) => RungStatus::Bad,
            (FP::Ok(_), _) => RungStatus::Ok,
            (FP::NotRun, _) => RungStatus::Unknown,
            (FP::NotApplicable, _) => RungStatus::Unknown,
        };
        let mut detail = format!(
            "{} · {}",
            describe(&s.http.v4, "v4"),
            describe(&s.http.v6, "v6")
        );
        if let Some(note) = &s.http.note {
            detail.push_str(&format!(" · {note}"));
        }
        Rung {
            area: Area::Http,
            status,
            detail,
        }
    });

    // Destinations: the odd ones out while consensus says the connection works.
    rungs.push(if with_data.is_empty() {
        Rung {
            area: Area::Destinations,
            status: RungStatus::Unknown,
            detail: "no data yet".to_string(),
        }
    } else if !bad.is_empty() && fine >= 2 && bad.len() * 2 < with_data.len() {
        let names: Vec<&str> = bad.iter().map(|t| t.label.as_str()).collect();
        // Red only for a destination that has gone entirely; loss to one far
        // end while the rest answer is a caution about that place.
        let any_unreachable = bad
            .iter()
            .any(|t| t.recent_loss_pct(th::RECENT) >= th::LOSS_DOWN_PCT);
        Rung {
            area: Area::Destinations,
            status: if any_unreachable {
                RungStatus::Bad
            } else {
                RungStatus::Warn
            },
            detail: format!("struggling: {}", names.join(", ")),
        }
    } else {
        let warn: Vec<&str> = with_data
            .iter()
            .filter(|t| probe_health(t) == Health::Warn)
            .map(|t| t.label.as_str())
            .collect();
        if warn.is_empty() {
            Rung {
                area: Area::Destinations,
                status: RungStatus::Ok,
                detail: "all targets reachable".to_string(),
            }
        } else {
            Rung {
                area: Area::Destinations,
                status: RungStatus::Warn,
                detail: format!("reachable · slow or lossy: {}", warn.join(", ")),
            }
        }
    });

    rungs
}

/// One of the slow or one-shot checks that are not a rung of the ladder but
/// whose result a person wants to see: clock, proxy, path MTU, NAT, DNS
/// honesty, the reference resolver, path discovery, public IP.
#[derive(Clone, Debug)]
pub struct Check {
    pub name: &'static str,
    pub status: RungStatus,
    pub detail: String,
}

/// The startup / background checks and where they stand right now.
pub fn checks(s: &AppState) -> Vec<Check> {
    use crate::app::FamilyProbe as FP;
    let mut out = Vec::new();
    let mut push = |name: &'static str, status: RungStatus, detail: String| {
        out.push(Check {
            name,
            status,
            detail,
        })
    };

    // Path discovery + public IP.
    let hops = s.targets.iter().filter(|t| t.is_path_hop()).count();
    let gw = s.targets.iter().any(|t| t.hop_ttl() == Some(1));
    push(
        "discovery",
        if gw {
            RungStatus::Ok
        } else {
            RungStatus::Unknown
        },
        if gw {
            format!(
                "gateway + {hops} hop{} traced",
                if hops == 1 { "" } else { "s" }
            )
        } else {
            "gateway not found yet".to_string()
        },
    );
    let public = s
        .targets
        .iter()
        .find(|t| t.discovered && t.label.contains("public"));
    push(
        "public IP",
        if public.is_some() {
            RungStatus::Ok
        } else {
            RungStatus::Unknown
        },
        match (public, &s.public_ip_error) {
            (Some(t), _) => t.addr.to_string(),
            (None, Some(e)) => format!("not discovered — {e}"),
            (None, None) => "not discovered yet".to_string(),
        },
    );
    // NAT.
    match s.nat_kind() {
        Some((kind, via)) => push(
            "nat",
            RungStatus::Warn,
            format!("{} — hop 2 is {via} · {}", kind.label(), kind.advice()),
        ),
        None if gw && hops > 0 => push("nat", RungStatus::Ok, "ordinary NAT at the gateway".into()),
        None => push("nat", RungStatus::Unknown, "path not known yet".into()),
    }
    // Clock.
    match (s.clock.offset_ms(), &s.clock.ntp_error, s.clock.checked) {
        (Some(off), _, _) => {
            let status = if off.abs() >= th::CLOCK_BAD_MS {
                RungStatus::Bad
            } else if off.abs() >= th::CLOCK_WARN_MS {
                RungStatus::Warn
            } else {
                RungStatus::Ok
            };
            push(
                "clock",
                status,
                format!("offset {:+.0} ms via {}", off, s.clock.source()),
            );
        }
        (None, Some(e), _) => push(
            "clock",
            RungStatus::Unknown,
            format!("ntp failed ({e}); waiting for an http date"),
        ),
        (None, None, _) => push("clock", RungStatus::Unknown, "not checked yet".into()),
    }
    // Proxy.
    match &s.proxy {
        Some(p) => push(
            "proxy",
            match &s.http.via_proxy {
                FP::Fail(_) => RungStatus::Bad,
                _ => RungStatus::Warn,
            },
            format!(
                "{}{}",
                p.describe(),
                match &s.http.via_proxy {
                    FP::Ok(ms) => format!(" · web via proxy ok {ms:.0}ms"),
                    FP::Fail(r) => format!(" · web via proxy FAILED ({r})"),
                    _ => String::new(),
                }
            ),
        ),
        None => push("proxy", RungStatus::Ok, "none configured".into()),
    }
    // Path MTU.
    match (&s.pmtu, &s.pmtu_error) {
        (Some(p), _) => push(
            "path MTU",
            if p.blackhole {
                RungStatus::Bad
            } else if p.path_mtu.zip(p.iface_mtu).is_some_and(|(a, b)| a < b) {
                RungStatus::Warn
            } else {
                RungStatus::Ok
            },
            crate::collectors::pmtu::describe(p),
        ),
        (None, Some(e)) => push(
            "path MTU",
            RungStatus::Unknown,
            format!("not measured — {e}"),
        ),
        (None, None) => push("path MTU", RungStatus::Unknown, "not measured yet".into()),
    }
    // DNS honesty + reference.
    let judged: Vec<&crate::app::DnsProbe> = s.dns.iter().filter(|p| p.hijack.is_some()).collect();
    if judged.is_empty() {
        push("DNS honesty", RungStatus::Unknown, "not checked yet".into());
    } else {
        let bad: Vec<String> = judged
            .iter()
            .filter(|p| p.hijack == Some(true))
            .map(|p| p.server.to_string())
            .collect();
        if bad.is_empty() {
            push(
                "DNS honesty",
                RungStatus::Ok,
                format!(
                    "{} resolver{} say \"no such name\" honestly — none redirect typos",
                    judged.len(),
                    if judged.len() == 1 { "" } else { "s" }
                ),
            );
        } else {
            push(
                "DNS honesty",
                RungStatus::Bad,
                format!("{} redirect non-existent names", bad.join(", ")),
            );
        }
    }
    if let Some(r) = s.dns.iter().find(|p| p.reference) {
        let (status, detail) = if r.recent_len() < th::DNS_MIN_SAMPLES {
            (RungStatus::Unknown, format!("{} — probing", r.server))
        } else if r.fail_pct() >= th::DNS_FAIL_PCT {
            (
                RungStatus::Warn,
                format!(
                    "{} unreachable ({}) — outside DNS filtered here",
                    r.server, r.status
                ),
            )
        } else {
            (
                RungStatus::Ok,
                format!("{} answers ({})", r.server, fmt_ms(r.recent_mean_ms())),
            )
        };
        push("reference DNS", status, detail);
    }
    out
}

/// A finding raise or clear, for the event timeline.
#[derive(Clone, Debug)]
pub struct Transition {
    pub raised: bool,
    pub finding: Finding,
    /// How long the finding was active — set on clears.
    pub after: Option<Duration>,
}

#[derive(Clone)]
struct Track {
    hits: VecDeque<bool>,
    active: Option<Active>,
    /// A clear waiting out the flap grace: (when it cleared, the finding as
    /// it last stood, when it originally raised).
    cleared: Option<(Instant, Finding, Instant)>,
}

#[derive(Clone)]
struct Active {
    since: Instant,
    quiet: u32,
    last: Finding,
}

/// Hysteresis over [`evaluate`]'s raw findings, keyed by `(cause, subject)`:
/// raise on ≥4 of the last 6 ticks, clear after 8 consecutive quiet ticks.
/// Severity/confidence/evidence of an active finding update live.
#[derive(Clone, Default)]
pub struct VerdictState {
    pub current: Verdict,
    /// Latest full ladder, for the triage overlay.
    pub triage: Triage,
    tracker: HashMap<(Cause, String), Track>,
}

impl VerdictState {
    /// Fold one tick's evaluation in; returns raise/clear transitions.
    pub fn ingest(
        &mut self,
        triage: Triage,
        insufficient: Option<String>,
        now: Instant,
    ) -> Vec<Transition> {
        let mut present: HashMap<(Cause, String), Finding> = triage
            .findings
            .iter()
            .map(|f| ((f.cause, f.subject.clone()), f.clone()))
            .collect();
        for key in present.keys() {
            self.tracker.entry(key.clone()).or_insert_with(|| Track {
                hits: VecDeque::with_capacity(th::RAISE_WINDOW),
                active: None,
                cleared: None,
            });
        }

        let mut transitions = Vec::new();
        self.tracker.retain(|key, tr| {
            let hit = present.remove(key);
            if tr.hits.len() == th::RAISE_WINDOW {
                tr.hits.pop_front();
            }
            tr.hits.push_back(hit.is_some());

            match (&mut tr.active, hit) {
                (Some(active), Some(f)) => {
                    active.quiet = 0;
                    // A finding getting *worse* while active (degraded → down)
                    // is worth a timeline entry of its own — otherwise the
                    // escalation to "gateway unresponsive (100%)" never shows,
                    // only the initial partial-loss raise.
                    if f.severity > active.last.severity {
                        transitions.push(Transition {
                            raised: true,
                            finding: f.clone(),
                            after: None,
                        });
                    }
                    active.last = f;
                }
                (Some(active), None) => {
                    active.quiet += 1;
                    if active.quiet >= th::CLEAR_TICKS {
                        // Off the footer now; onto the timeline only once the
                        // grace has passed without it coming back.
                        tr.cleared = Some((now, active.last.clone(), active.since));
                        tr.active = None;
                    }
                }
                (None, Some(f)) => {
                    let hits = tr.hits.iter().filter(|h| **h).count();
                    if hits >= th::RAISE_HITS {
                        // Back within the grace: the same episode, resumed —
                        // no new raise entry, and the original start stands.
                        let resumed = tr.cleared.take().and_then(|(at, _, since)| {
                            (now.duration_since(at).as_secs() < th::FLAP_GRACE_SECS)
                                .then_some(since)
                        });
                        if resumed.is_none() {
                            transitions.push(Transition {
                                raised: true,
                                finding: f.clone(),
                                after: None,
                            });
                        }
                        tr.active = Some(Active {
                            since: resumed.unwrap_or(now),
                            quiet: 0,
                            last: f,
                        });
                    }
                }
                (None, None) => {}
            }
            // A held clear whose grace has run out is final: say so, with the
            // duration up to when it actually cleared.
            if tr.active.is_none()
                && let Some((at, _, _)) = tr.cleared
                && now.duration_since(at).as_secs() >= th::FLAP_GRACE_SECS
            {
                let (at, mut finding, since) = tr.cleared.take().unwrap();
                finding.since = Some(since);
                transitions.push(Transition {
                    raised: false,
                    finding,
                    after: Some(at.duration_since(since)),
                });
            }
            tr.active.is_some() || tr.cleared.is_some() || tr.hits.iter().any(|h| *h)
        });

        let mut active: Vec<Finding> = self
            .tracker
            .values()
            .filter_map(|t| {
                t.active.as_ref().map(|a| {
                    let mut f = a.last.clone();
                    f.since = Some(a.since);
                    f
                })
            })
            .collect();
        rank(&mut active);

        self.current = match insufficient {
            Some(reason) => Verdict::Insufficient(reason),
            None if active.is_empty() => Verdict::Healthy,
            None => Verdict::Problems(active),
        };
        self.triage = triage;
        transitions
    }
}

/// The triage ladder + findings as plain text — doctor mode's `== VERDICT ==`
/// section, the same shape as the [y] overlay so TUI and doctor can never
/// disagree.
pub fn render_text(triage: &Triage, insufficient: Option<&str>) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "== ANALYSIS ==");
    let glyph_of = |st: RungStatus| match st {
        RungStatus::Ok => "✓",
        RungStatus::Warn => "~",
        RungStatus::Bad => "✗",
        RungStatus::Unknown => "?",
    };
    for r in &triage.rungs {
        let _ = writeln!(
            out,
            "  {} {:<15} {}",
            glyph_of(r.status),
            r.area.label(),
            r.detail
        );
    }
    if !triage.checks.is_empty() {
        let _ = writeln!(out, "  checks:");
        for c in &triage.checks {
            let _ = writeln!(out, "  {} {:<15} {}", glyph_of(c.status), c.name, c.detail);
        }
    }
    let _ = writeln!(out);
    if let Some(reason) = insufficient {
        let _ = writeln!(out, "  {reason}");
    } else if triage.findings.is_empty() {
        let _ = writeln!(out, "  no findings — connection looks healthy");
    } else {
        for f in &triage.findings {
            let _ = writeln!(
                out,
                "  ▲ {}{}",
                f.summary,
                if f.symptom {
                    "  (symptom of the above)"
                } else {
                    ""
                }
            );
            for e in &f.evidence {
                let _ = writeln!(out, "      {e}");
            }
        }
    }
    out
}

/// Script-friendly exit code: 0 healthy · 1 anything ≥ Degraded (severity, not
/// confidence, drives it) · 3 could not measure. 2 is deliberately skipped —
/// clap and the bad-target path already exit 2 for usage errors, and scripts
/// must be able to tell "bad invocation" from "network is down".
pub fn exit_code(triage: &Triage, insufficient: bool) -> i32 {
    if insufficient {
        return 3;
    }
    if triage
        .findings
        .iter()
        .any(|f| f.severity >= Severity::Degraded)
    {
        1
    } else {
        0
    }
}

/// Disk work decided under the lock, executed off it.
enum BaselineIo {
    None,
    /// The network changed: load (or create) its baseline.
    Load {
        key: String,
        label: String,
    },
    /// A healthy minute was folded in: persist.
    Save {
        key: String,
        baseline: crate::baseline::Baseline,
    },
}

/// Collector task: re-evaluate every sample interval, writing the verdict and
/// triage ladder back into shared state. Finding raises and clears land on the
/// event timeline — this is where "loss spike started / ended" comes from.
/// Also owns the baseline lifecycle: it already wakes every second and knows
/// whether the verdict is Healthy, which is the anti-poisoning gate.
pub async fn run(state: std::sync::Arc<std::sync::Mutex<AppState>>, cfg: crate::config::Config) {
    let mut tick = tokio::time::interval(cfg.sample_interval());
    // Consecutive fully-healthy ticks; a fold happens each time this hits 60.
    let mut healthy_run: u32 = 0;
    let mut last_speed_total: Option<usize> = None;
    loop {
        tick.tick().await;
        let now = Instant::now();

        let mut episodes: Vec<crate::history::Episode> = Vec::new();
        let io = {
            let mut s = state.lock().unwrap();
            let triage = evaluate(&s);
            let insufficient = insufficient_reason(&s);
            let network = s.baseline_key.clone();
            for t in s.verdict.ingest(triage, insufficient, now) {
                let (severity, message) = if t.raised {
                    (t.finding.severity, format!("▲ {}", t.finding.summary))
                } else {
                    // Clears are good news: Info regardless of how bad it was.
                    let after = t.after.unwrap_or_default();
                    // A finished Degraded-or-worse episode goes to the
                    // per-network history — the "is it always like this at
                    // 9pm" record.
                    let started_at = chrono::Utc::now().timestamp() - after.as_secs() as i64;
                    if let Some(ep) = crate::history::episode_from(
                        network.as_deref(),
                        t.finding.cause,
                        t.finding.severity,
                        &t.finding.summary,
                        started_at,
                        after,
                    ) {
                        s.history.push(ep.clone());
                        episodes.push(ep);
                    }
                    (
                        Severity::Info,
                        format!(
                            "✓ {} — ended after {}",
                            t.finding.summary,
                            fmt_duration(after)
                        ),
                    )
                };
                s.push_event(severity, crate::app::EventCategory::Analysis, message);
            }

            baseline_step(&mut s, &mut healthy_run, &mut last_speed_total)
        };

        if !episodes.is_empty() {
            let _ = tokio::task::spawn_blocking(move || {
                for ep in &episodes {
                    crate::history::append(ep);
                }
            })
            .await;
        }

        // File I/O strictly off the lock.
        match io {
            BaselineIo::None => {}
            BaselineIo::Load { key, label } => {
                let loaded = tokio::task::spawn_blocking({
                    let key = key.clone();
                    move || crate::baseline::load_one(&key)
                })
                .await
                .ok()
                .flatten();
                let mut s = state.lock().unwrap();
                // The network may have moved again while we read the file.
                if crate::baseline::fingerprint(&s.netinfo).map(|f| f.0) == Some(key.clone()) {
                    s.baseline = Some(loaded.unwrap_or(crate::baseline::Baseline {
                        label,
                        ..Default::default()
                    }));
                    s.baseline_key = Some(key);
                }
            }
            BaselineIo::Save { key, baseline } => {
                let _ =
                    tokio::task::spawn_blocking(move || crate::baseline::save_one(&key, &baseline))
                        .await;
            }
        }
    }
}

/// One tick of baseline bookkeeping. Decides what disk work is needed; does
/// none of it here (the caller holds the state lock).
fn baseline_step(
    s: &mut AppState,
    healthy_run: &mut u32,
    last_speed_total: &mut Option<usize>,
) -> BaselineIo {
    // Network fingerprint changed (or never resolved): swap baselines.
    let fp = crate::baseline::fingerprint(&s.netinfo);
    match &fp {
        None => {
            if s.baseline_key.is_some() {
                s.baseline_key = None;
                s.baseline = None;
            }
            *healthy_run = 0;
            return BaselineIo::None;
        }
        Some((key, label)) if s.baseline_key.as_deref() != Some(key.as_str()) => {
            *healthy_run = 0;
            *last_speed_total = Some(s.speed_total);
            return BaselineIo::Load {
                key: key.clone(),
                label: label.clone(),
            };
        }
        Some(_) => {}
    }

    let Some(key) = s.baseline_key.clone() else {
        return BaselineIo::None;
    };
    let mut changed = false;

    // A completed speed test overwrites the expected throughput — speed tests
    // are rare enough that an EWMA would never converge. Deliberate user
    // action, so a softer gate than the fold: only a Degraded-or-worse finding
    // (which would genuinely skew a capacity reading) blocks it.
    let new_speedtest = *last_speed_total != Some(s.speed_total);
    if new_speedtest {
        *last_speed_total = Some(s.speed_total);
        let severe = match &s.verdict.current {
            Verdict::Problems(f) => f.iter().any(|x| x.severity >= Severity::Degraded),
            Verdict::Insufficient(_) => true,
            Verdict::Healthy => false,
        };
        if !severe
            && let (Some(d), Some(u)) = (s.speedtest.down_mbps, s.speedtest.up_mbps)
            && let Some(b) = s.baseline.as_mut()
        {
            b.down_mbps = Some(d);
            b.up_mbps = Some(u);
            changed = true;
        }
    }

    // The fold gate: only a *fully* healthy verdict — any active finding, even
    // an Info note, skips the update. An incident must never teach the baseline.
    let fully_healthy = matches!(s.verdict.current, Verdict::Healthy);
    if !fully_healthy {
        *healthy_run = 0;
    } else {
        *healthy_run += 1;
        let uptime_ok = s.started.elapsed().as_secs() > 120;
        if *healthy_run >= 60 && uptime_ok {
            *healthy_run = 0;
            let sample = crate::baseline::Sample::take(s);
            if let Some(b) = s.baseline.as_mut() {
                b.fold(sample);
                changed = true;
            }
        }
    }

    match (changed, s.baseline.clone()) {
        (true, Some(baseline)) => BaselineIo::Save { key, baseline },
        _ => BaselineIo::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// A target with `ok` replies (10 ms) followed by `lost` timeouts, so the
    /// *recent* outcomes are the losses.
    fn probe(label: &str, addr: [u8; 4], ok: usize, lost: usize) -> TargetStat {
        let mut t = TargetStat::new(label.into(), IpAddr::V4(Ipv4Addr::from(addr)));
        for _ in 0..ok {
            t.record_reply(10.0);
        }
        for _ in 0..lost {
            t.record_loss();
        }
        t
    }

    /// Three healthy anchors, a healthy discovered gateway, an idle machine.
    fn healthy_state() -> AppState {
        let mut s = AppState::new(vec![
            probe("Cloudflare", [1, 1, 1, 1], 20, 0),
            probe("Google", [8, 8, 8, 8], 20, 0),
            probe("Quad9", [9, 9, 9, 9], 20, 0),
        ]);
        let mut gw = probe("gateway", [192, 168, 1, 1], 20, 0);
        gw.discovered = true;
        s.targets.push(gw);
        s.netinfo.gateway_ip = "192.168.1.1".into();
        s.vitals.cores = vec![10.0; 8];
        s.vitals.cpu_pct = 12.0;
        s
    }

    fn causes(t: &Triage) -> Vec<Cause> {
        t.findings.iter().map(|f| f.cause).collect()
    }

    #[test]
    fn healthy_state_yields_no_findings_and_a_full_ladder() {
        let t = evaluate(&healthy_state());
        assert!(t.findings.is_empty(), "unexpected: {:?}", t.findings);

        // Every area, always, in ladder order — an absent rung would let
        // "not measured" masquerade as "fine".
        let areas: Vec<Area> = t.rungs.iter().map(|r| r.area).collect();
        assert_eq!(
            areas,
            vec![
                Area::Machine,
                Area::Link,
                Area::Gateway,
                Area::Dns,
                Area::IspPath,
                Area::Internet,
                Area::Http,
                Area::Destinations
            ]
        );
        let rung = |a: Area| t.rungs.iter().find(|r| r.area == a).unwrap();
        assert_eq!(rung(Area::Gateway).status, RungStatus::Ok);
        assert_eq!(rung(Area::Internet).status, RungStatus::Ok);
        assert_eq!(rung(Area::Machine).status, RungStatus::Ok);
        // No hop monitor running: unknown, not silently fine.
        assert_eq!(rung(Area::IspPath).status, RungStatus::Unknown);
    }

    #[test]
    fn dead_gateway_with_dead_anchors_is_a_strong_gateway_verdict() {
        let mut s = healthy_state();
        for t in &mut s.targets {
            for _ in 0..15 {
                t.record_loss();
            }
        }
        let t = evaluate(&s);
        let f = &t.findings[0];
        assert_eq!(f.cause, Cause::GatewayLan);
        assert_eq!(f.severity, Severity::Down);
        // Everything behind a dead gateway fails: a consistent story.
        assert_eq!(f.confidence, Confidence::Strong);
    }

    #[test]
    fn lossy_gateway_with_fine_anchors_is_only_a_weak_claim() {
        let mut s = healthy_state();
        let gw = s.targets.iter_mut().find(|t| t.discovered).unwrap();
        for _ in 0..15 {
            gw.record_loss();
        }
        let t = evaluate(&s);
        let f = t
            .findings
            .iter()
            .find(|f| f.cause == Cause::GatewayLan)
            .unwrap();
        // The internet is reachable *through* this "dead" gateway — it is
        // probably just deprioritising ICMP, and the verdict must not shout.
        assert_eq!(f.confidence, Confidence::Weak);
        assert!(f.evidence.iter().any(|e| e.contains("deprioritise")));
    }

    #[test]
    fn gateway_fine_but_anchors_dead_blames_the_internet() {
        let mut s = healthy_state();
        for t in s.targets.iter_mut().filter(|t| !t.discovered).take(2) {
            for _ in 0..15 {
                t.record_loss();
            }
        }
        let t = evaluate(&s);
        let f = &t.findings[0];
        assert_eq!(f.cause, Cause::WideInternet);
        assert_eq!(f.severity, Severity::Down);
        // Two of three anchors dead behind a fine gateway is the contrast;
        // without a second line of evidence it is Likely, not Strong.
        assert_eq!(f.confidence, Confidence::Likely);
        assert!(!causes(&t).contains(&Cause::SingleDestination));

        // The HTTP check failing too corroborates it.
        s.http.v4 = crate::app::FamilyProbe::Fail("timeout".into());
        let t = evaluate(&s);
        assert_eq!(t.findings[0].cause, Cause::WideInternet);
        assert_eq!(t.findings[0].confidence, Confidence::Strong);
    }

    #[test]
    fn one_dead_target_amid_consensus_blames_that_destination() {
        let mut s = healthy_state();
        s.targets.push(probe("myserver", [203, 0, 113, 9], 5, 15));
        let t = evaluate(&s);
        let f = &t.findings[0];
        assert_eq!(f.cause, Cause::SingleDestination);
        assert_eq!(f.confidence, Confidence::Strong);
        assert_eq!(f.subject, "myserver");
        assert!(f.summary.contains("your connection is fine"));
        assert!(!causes(&t).contains(&Cause::WideInternet));
        // 75% loss: gone, so Degraded and a red destinations rung.
        assert_eq!(f.severity, Severity::Degraded);
        let rung = t
            .rungs
            .iter()
            .find(|r| r.area == Area::Destinations)
            .unwrap();
        assert_eq!(rung.status, RungStatus::Bad);

        // Some loss to one far end while the rest answer: a note, and a
        // caution on the rung — the machine isn't even using that resolver.
        let mut s = healthy_state();
        s.targets.push(probe("Quad9-ish", [203, 0, 113, 10], 17, 3));
        let t = evaluate(&s);
        let f = t
            .findings
            .iter()
            .find(|f| f.cause == Cause::SingleDestination)
            .unwrap();
        assert_eq!(f.severity, Severity::Info);
        let rung = t
            .rungs
            .iter()
            .find(|r| r.area == Area::Destinations)
            .unwrap();
        assert_eq!(rung.status, RungStatus::Warn);
    }

    #[test]
    fn dns_failing_while_ping_works_is_a_strong_dns_verdict() {
        let mut s = healthy_state();
        let mut p = crate::app::DnsProbe::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        for _ in 0..10 {
            p.record(None);
        }
        p.status = "timeout".into();
        s.dns = vec![p];
        let t = evaluate(&s);
        let f = &t.findings[0];
        assert_eq!(f.cause, Cause::Dns);
        assert_eq!(f.severity, Severity::Down);
        assert!(!f.symptom, "ping works, so DNS is the cause, not a symptom");
        // The anchors-fine contrast makes it Likely; the HTTP check (which
        // resolves a name) failing as well is the corroboration for Strong.
        assert_eq!(f.confidence, Confidence::Likely);
        s.http.v4 = crate::app::FamilyProbe::Fail("dns error".into());
        let t = evaluate(&s);
        assert_eq!(t.findings[0].confidence, Confidence::Strong);
    }

    /// A resolver that answered for an hour and then died must read as
    /// failing within a minute — the judgement is on the recent window, not
    /// the session totals.
    #[test]
    fn dns_is_judged_on_the_recent_window() {
        let mut s = healthy_state();
        let mut p = crate::app::DnsProbe::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        for _ in 0..500 {
            p.record(Some(12.0));
        }
        for _ in 0..crate::app::DNS_RECENT {
            p.record(None);
        }
        assert_eq!(p.fail_pct(), 100.0);
        s.dns = vec![p];
        let t = evaluate(&s);
        assert_eq!(t.findings[0].cause, Cause::Dns);
        assert_eq!(t.findings[0].severity, Severity::Down);

        // And once it recovers, the outage stops being reported just as fast.
        for _ in 0..crate::app::DNS_RECENT {
            s.dns[0].record(Some(12.0));
        }
        assert!(!causes(&evaluate(&s)).contains(&Cause::Dns));
    }

    /// A speed test saturates the link on purpose, so the loss and latency it
    /// causes must not be reported as the network failing — during the run,
    /// or in the recent window just after it.
    #[test]
    fn speed_test_load_is_not_pinned_on_the_network() {
        use std::time::{Duration, Instant};
        let mut s = healthy_state();
        let gw = s.targets.iter_mut().find(|t| t.discovered).unwrap();
        for _ in 0..8 {
            gw.record_loss();
        }
        // With no test in the picture this is a gateway finding.
        assert!(causes(&evaluate(&s)).contains(&Cause::GatewayLan));
        // While one runs, the loss is the test's own load.
        s.speedtest.status = crate::app::SpeedStatus::Running;
        assert!(!causes(&evaluate(&s)).contains(&Cause::GatewayLan));
        // Just finished: samples taken under load are still in the window.
        s.speedtest.status = crate::app::SpeedStatus::Done;
        s.speedtest.last_run = Some(Instant::now());
        assert!(!causes(&evaluate(&s)).contains(&Cause::GatewayLan));
        // Long over: continuing loss is the network's again. (checked_sub —
        // a freshly booted machine may not have 120s of Instant behind it.)
        if let Some(t) = Instant::now().checked_sub(Duration::from_secs(120)) {
            s.speedtest.last_run = Some(t);
            assert!(causes(&evaluate(&s)).contains(&Cause::GatewayLan));
        }
    }

    /// The whole point of the ladder: with the gateway dead, DNS timing out is
    /// a symptom and must not headline — however loud it is.
    #[test]
    fn a_dead_gateway_outranks_the_dns_failure_behind_it() {
        let mut s = healthy_state();
        // Gateway at partial loss (Degraded), DNS at total loss (Down).
        let gw = s.targets.iter_mut().find(|t| t.discovered).unwrap();
        for _ in 0..8 {
            gw.record_loss();
        }
        let mut p = crate::app::DnsProbe::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        for _ in 0..10 {
            p.record(None);
        }
        s.dns = vec![p];
        let t = evaluate(&s);
        assert_eq!(t.findings[0].cause, Cause::GatewayLan, "{:?}", causes(&t));
        let dns = t.findings.iter().find(|f| f.cause == Cause::Dns).unwrap();
        assert!(dns.symptom);
        assert_eq!(
            dns.severity,
            Severity::Down,
            "still reported at its real severity"
        );
    }

    /// Cable out: the answer is "not connected", not whatever failed first.
    #[test]
    fn no_default_route_is_the_bottom_rung_and_explains_everything() {
        let mut s = healthy_state();
        s.link_lost = true;
        s.netinfo.medium = LinkMedium::WiFi;
        for t in s.targets.iter_mut() {
            for _ in 0..20 {
                t.record_loss();
            }
        }
        let mut p = crate::app::DnsProbe::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        for _ in 0..10 {
            p.record(None);
        }
        s.dns = vec![p];
        let t = evaluate(&s);
        assert_eq!(t.findings[0].cause, Cause::NoLink);
        assert_eq!(t.findings[0].severity, Severity::Down);
        assert!(t.findings[0].summary.contains("Wi-Fi"));
        assert!(
            t.findings
                .iter()
                .skip(1)
                .all(|f| f.symptom || f.cause.is_caveat())
        );
        let link = t.rungs.iter().find(|r| r.area == Area::Link).unwrap();
        assert_eq!(link.status, RungStatus::Bad);
    }

    #[test]
    fn a_self_assigned_address_means_no_dhcp() {
        let mut s = healthy_state();
        s.netinfo.iface = "en0".into();
        s.netinfo.ipv4 = vec!["169.254.12.7/16".into()];
        s.netinfo.gateway_ip = "-".into();
        assert_eq!(link_state(&s), LinkState::SelfAssigned);
        let t = evaluate(&s);
        assert_eq!(t.findings[0].cause, Cause::NoLink);
        assert!(t.findings[0].summary.contains("no DHCP lease"));

        // A real address but no gateway is the other flavour.
        s.netinfo.ipv4 = vec!["192.168.1.20/24".into()];
        assert_eq!(link_state(&s), LinkState::NoGateway);
        s.netinfo.gateway_ip = "192.168.1.1".into();
        assert_eq!(link_state(&s), LinkState::Up);
    }

    /// A printer on the LAN being off is not an internet finding and must not
    /// vote against the anchors' consensus.
    #[test]
    fn a_lan_target_is_judged_locally() {
        let mut s = healthy_state();
        s.netinfo.iface = "en0".into();
        s.netinfo.ipv4 = vec!["192.168.1.20/24".into()];
        s.targets.push(probe("printer", [192, 168, 1, 50], 0, 20));
        let t = evaluate(&s);
        let f = t.findings.iter().find(|f| f.subject == "printer").unwrap();
        assert!(f.summary.contains("on your LAN"));
        assert!(!causes(&t).contains(&Cause::WideInternet));
        let internet = t.rungs.iter().find(|r| r.area == Area::Internet).unwrap();
        assert_eq!(
            internet.status,
            RungStatus::Ok,
            "the LAN device did not vote"
        );
    }

    /// The MTR rule: loss at hop 3 that the later hops don't show is hop 3
    /// rate-limiting its own ICMP replies, not the ISP path failing.
    #[test]
    fn hop_loss_that_does_not_persist_is_not_the_isp() {
        let mut s = healthy_state();
        for t in s.targets.iter_mut().filter(|t| !t.discovered).take(2) {
            for _ in 0..15 {
                t.record_loss();
            }
        }
        let hop = |ttl: u8, ok: usize, lost: usize| crate::app::MonitoredHop {
            ttl,
            addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, ttl, 1))),
            stat: Some(probe("hop", [10, 0, ttl, 1], ok, lost)),
        };
        let mut m = crate::app::HopMonitor {
            target: "Cloudflare".into(),
            dest: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            hops: vec![
                hop(1, 20, 0),
                hop(2, 20, 0),
                hop(3, 8, 12),
                hop(4, 20, 0),
                hop(5, 20, 0),
            ],
            discovering: false,
            generation: 1,
            selected: 0,
        };
        s.hop_monitor = Some(m.clone());
        let t = evaluate(&s);
        assert_eq!(t.findings[0].cause, Cause::WideInternet, "{:?}", causes(&t));

        // Loss from hop 3 onward, carried by every later hop: that *is* the ISP.
        m.hops = vec![
            hop(1, 20, 0),
            hop(2, 20, 0),
            hop(3, 8, 12),
            hop(4, 6, 14),
            hop(5, 5, 15),
        ];
        s.hop_monitor = Some(m);
        let t = evaluate(&s);
        assert_eq!(t.findings[0].cause, Cause::IspHop, "{:?}", causes(&t));
        assert!(t.findings[0].summary.contains("hop 3"));
    }

    #[test]
    fn a_working_reference_resolver_turns_dns_down_into_switch_dns() {
        let mut s = healthy_state();
        let mut mine = crate::app::DnsProbe::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        for _ in 0..10 {
            mine.record(None);
        }
        let mut reference = crate::app::DnsProbe::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        reference.reference = true;
        for _ in 0..10 {
            reference.record(Some(9.0));
        }
        s.dns = vec![mine, reference];
        let t = evaluate(&s);
        let f = &t.findings[0];
        assert_eq!(f.cause, Cause::Dns);
        assert!(f.summary.contains("switch DNS"), "{}", f.summary);
        assert_eq!(
            f.confidence,
            Confidence::Strong,
            "the reference corroborates"
        );
        // The reference is not a rung of *this network's* DNS.
        let rung = t.rungs.iter().find(|r| r.area == Area::Dns).unwrap();
        assert_eq!(rung.status, RungStatus::Bad);
    }

    #[test]
    fn a_dead_reference_while_own_dns_works_is_a_filtered_network_note() {
        let mut s = healthy_state();
        let mut mine = crate::app::DnsProbe::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        for _ in 0..10 {
            mine.record(Some(8.0));
        }
        let mut reference = crate::app::DnsProbe::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        reference.reference = true;
        for _ in 0..10 {
            reference.record(None);
        }
        reference.status = "timeout".into();
        s.dns = vec![mine, reference];
        let t = evaluate(&s);
        let f = t.findings.iter().find(|f| f.cause == Cause::Dns).unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert!(
            f.summary.contains("outside resolvers blocked"),
            "{}",
            f.summary
        );
    }

    #[test]
    fn a_resolver_answering_nonexistent_names_is_a_hijack() {
        let mut s = healthy_state();
        let mut mine = crate::app::DnsProbe::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        for _ in 0..10 {
            mine.record(Some(8.0));
        }
        mine.hijack = Some(true);
        let mut reference = crate::app::DnsProbe::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        reference.reference = true;
        reference.hijack = Some(false);
        for _ in 0..10 {
            reference.record(Some(9.0));
        }
        s.dns = vec![mine, reference];
        let t = evaluate(&s);
        let f = t
            .findings
            .iter()
            .find(|f| f.cause == Cause::DnsHijack)
            .unwrap();
        assert_eq!(f.severity, Severity::Degraded);
        assert_eq!(f.confidence, Confidence::Strong, "reference said NXDOMAIN");
        assert!(f.summary.contains("192.168.1.1"));
    }

    #[test]
    fn a_skewed_clock_is_a_finding_of_its_own() {
        let mut s = healthy_state();
        s.clock.ntp_offset_ms = Some(-400_000.0);
        let t = evaluate(&s);
        let f = t
            .findings
            .iter()
            .find(|f| f.cause == Cause::ClockSkew)
            .unwrap();
        assert_eq!(f.severity, Severity::Degraded);
        assert!(f.summary.contains("6m 40s slow"), "{}", f.summary);
        // Half a minute is a note, not a problem.
        s.clock.ntp_offset_ms = Some(45_000.0);
        let t = evaluate(&s);
        let f = t
            .findings
            .iter()
            .find(|f| f.cause == Cause::ClockSkew)
            .unwrap();
        assert_eq!(f.severity, Severity::Info);
        // The HTTP-date fallback is coarser: Likely, not Strong.
        s.clock.ntp_offset_ms = None;
        s.clock.record_http_skew(400_000.0);
        assert!(
            !causes(&evaluate(&s)).contains(&Cause::ClockSkew),
            "one HTTP Date reading alone is never believed"
        );
        s.clock.record_http_skew(401_000.0);
        // Two agreeing readings: believed, but as a note — the Date header
        // is coarse and comes from whatever answered the HTTP check.
        let f = evaluate(&s);
        let f = f
            .findings
            .iter()
            .find(|f| f.cause == Cause::ClockSkew)
            .unwrap();
        assert_eq!(f.severity, Severity::Info);
        // Readings that disagree cancel each other out.
        s.clock.record_http_skew(-27_000_000.0);
        assert!(!causes(&evaluate(&s)).contains(&Cause::ClockSkew));
        // Once the outlier has aged out of the window, agreement returns.
        s.clock.record_http_skew(400_500.0);
        s.clock.record_http_skew(400_800.0);
        s.clock.record_http_skew(400_600.0);
        let t = evaluate(&s);
        let f = t
            .findings
            .iter()
            .find(|f| f.cause == Cause::ClockSkew)
            .unwrap();
        assert_eq!(f.confidence, Confidence::Likely);
    }

    /// Colour and analysis share one question — worse than it should be
    /// *here*? — so a far-away path is not red for being far away.
    #[test]
    fn rtt_grade_is_relative_with_absolute_floors() {
        use RttGrade::*;
        // No reference: the absolute scale.
        assert_eq!(rtt_grade(40.0, None), Good);
        assert_eq!(rtt_grade(100.0, None), Warn);
        assert_eq!(rtt_grade(200.0, None), Bad);
        // A 2 ms LAN gateway: the floors hold, so 40 ms is still fine and
        // 160 ms still bad — not 3 ms and 6 ms.
        assert_eq!(rtt_grade(40.0, Some(2.0)), Good);
        assert_eq!(rtt_grade(100.0, Some(2.0)), Warn);
        assert_eq!(rtt_grade(160.0, Some(2.0)), Bad);
        // A 156 ms VPN exit: 170 is normal, 400 a caution, 600 bad.
        assert_eq!(rtt_grade(170.0, Some(156.0)), Good);
        assert_eq!(rtt_grade(400.0, Some(156.0)), Warn);
        assert_eq!(rtt_grade(600.0, Some(156.0)), Bad);

        // The reference is the session floor, lowered to the learned normal so
        // a session that started degraded is still judged honestly.
        let mut s = healthy_state();
        let t = probe("x", [203, 0, 113, 5], 5, 0);
        let mut t = t;
        t.min_ever_ms = Some(150.0);
        assert_eq!(rtt_reference(&t, &s), Some(150.0));
        s.baseline = Some(crate::baseline::Baseline {
            anchor_ms: Some(20.0),
            samples: 40,
            ..Default::default()
        });
        assert_eq!(rtt_reference(&t, &s), Some(20.0));
    }

    /// Wi-Fi with no signal sample yet is not measured, so it is not "ok".
    #[test]
    fn wifi_without_signal_data_reads_unknown_not_ok() {
        let mut s = healthy_state();
        s.netinfo.iface = "en0".into();
        s.netinfo.medium = LinkMedium::WiFi;
        s.signal.present = false;
        let t = evaluate(&s);
        let link = t.rungs.iter().find(|r| r.area == Area::Link).unwrap();
        assert_eq!(link.status, RungStatus::Unknown);
    }

    /// The Windows DNS-filter lesson: loopback resolvers (127.0.2.x) that
    /// answer the OS but not octomon's probes get named as what they are.
    #[test]
    fn loopback_resolvers_are_named_a_local_proxy() {
        let mut s = healthy_state();
        let mut p = crate::app::DnsProbe::new(IpAddr::V4(Ipv4Addr::new(127, 0, 2, 2)));
        for _ in 0..10 {
            p.record(None);
        }
        p.status = "connection reset".into();
        s.dns = vec![p];
        s.http.v4 = crate::app::FamilyProbe::Ok(30.0);
        let t = evaluate(&s);
        let f = t.findings.iter().find(|f| f.cause == Cause::Dns).unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert!(f.summary.contains("local DNS proxy"), "{}", f.summary);
    }

    /// The hotspot lesson: a carrier network handed out a link-local resolver
    /// octomon couldn't probe, while resolution worked fine. Working HTTP
    /// (which resolved a hostname) must cap the DNS claim at an Info note.
    #[test]
    fn dns_probe_failures_defer_to_a_working_http_check() {
        let mut s = healthy_state();
        let mut p = crate::app::DnsProbe::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        for _ in 0..10 {
            p.record(None);
        }
        p.status = "No route to host".into();
        s.dns = vec![p];
        s.http.v4 = crate::app::FamilyProbe::Ok(30.0);

        let t = evaluate(&s);
        let f = t.findings.iter().find(|f| f.cause == Cause::Dns).unwrap();
        assert_eq!(
            f.severity,
            Severity::Info,
            "not a Down claim: {}",
            f.summary
        );
        assert!(f.summary.contains("names still resolve"));
        assert!(f.evidence.iter().any(|e| e.contains("HTTP check")));
    }

    #[test]
    fn a_web_server_that_stops_answering_is_a_finding_only_if_it_served_before() {
        use crate::app::WebStatus;
        let mut s = healthy_state();
        s.targets.push({
            let mut t = probe("bbc.co.uk", [151, 101, 0, 81], 20, 0);
            t.hostname = Some("bbc.co.uk".into());
            t.web.status = WebStatus::Web;
            t.web.fails = 3;
            t
        });
        let t = evaluate(&s);
        let f = t
            .findings
            .iter()
            .find(|f| f.cause == Cause::WebTarget)
            .unwrap();
        assert_eq!(f.subject, "bbc.co.uk");
        assert!(f.summary.contains("ping still fine"));

        // A target that never served HTTP is never judged on it.
        let mut s = healthy_state();
        s.targets.push({
            let mut t = probe("Quad9", [9, 9, 9, 10], 20, 0);
            t.web.status = WebStatus::NoService;
            t
        });
        assert!(!causes(&evaluate(&s)).contains(&Cause::WebTarget));

        // And under a captive portal the portal owns the story.
        let mut s = healthy_state();
        s.http.v4 = crate::app::FamilyProbe::Captive(None);
        s.targets.push({
            let mut t = probe("bbc.co.uk", [151, 101, 0, 81], 20, 0);
            t.web.status = WebStatus::Web;
            t.web.fails = 5;
            t
        });
        let c = causes(&evaluate(&s));
        assert!(c.contains(&Cause::CaptivePortal));
        assert!(!c.contains(&Cause::WebTarget));
    }

    /// The Unifi lesson, part 1: one dropped ping in a 20-sample window is 5%
    /// — exactly the "bad" threshold — and produced "Google degraded" blips
    /// all afternoon on a healthy network. One packet is not an outage.
    #[test]
    fn one_lost_packet_is_not_a_finding() {
        let mut s = healthy_state();
        let google = s.targets.iter_mut().find(|t| t.label == "Google").unwrap();
        google.record_loss();
        assert!(
            evaluate(&s).findings.is_empty(),
            "single packet blip must stay quiet"
        );
        // Two lost packets is a pattern.
        let google = s.targets.iter_mut().find(|t| t.label == "Google").unwrap();
        google.record_loss();
        assert!(!evaluate(&s).findings.is_empty());
    }

    /// The Unifi lesson, part 2: a Wi-Fi gateway with a 2ms idle floor drifts
    /// into the 30s constantly on a *good* network — that is weather, and it
    /// flapped "latency inflated" every minute or two.
    #[test]
    fn wifi_weather_in_the_thirties_is_not_inflation() {
        let mut s = healthy_state();
        let gw = s.targets.iter_mut().find(|t| t.discovered).unwrap();
        gw.reset();
        for _ in 0..5 {
            gw.record_reply(2.0);
        }
        for _ in 0..20 {
            gw.record_reply(34.0);
        }
        assert!(
            !causes(&evaluate(&s)).contains(&Cause::GatewayLan),
            "34ms mean on a 2ms floor is below the inflation floor"
        );
    }

    /// The Unifi lesson, part 3: where an established baseline says the
    /// current reading is normal for this network, the absolute inflation
    /// rule loses the argument. Loss keeps its vote regardless.
    #[test]
    fn the_baseline_can_veto_an_inflation_claim() {
        let mut s = healthy_state();
        let gw = s.targets.iter_mut().find(|t| t.discovered).unwrap();
        gw.reset();
        for _ in 0..5 {
            gw.record_reply(5.0);
        }
        for _ in 0..20 {
            gw.record_reply(70.0); // above the absolute floor: would raise
        }
        assert!(causes(&evaluate(&s)).contains(&Cause::GatewayLan));

        // Same readings, but this network's learned normal is ~65ms (a slow
        // powerline backhaul, say): not a finding, just how it is here.
        s.baseline = Some(crate::baseline::Baseline {
            label: "SlowNet".into(),
            samples: 10,
            gateway_ms: Some(65.0),
            ..Default::default()
        });
        assert!(!causes(&evaluate(&s)).contains(&Cause::GatewayLan));
    }

    /// The mandatory wrongness test: simultaneous causes must BOTH be reported,
    /// with the network cause ranked above the machine caveat.
    #[test]
    fn cpu_spike_never_hides_a_dead_gateway() {
        let mut s = healthy_state();
        s.vitals.cpu_pct = 97.0;
        s.vitals.cores = vec![97.0; 8];
        for t in &mut s.targets {
            for _ in 0..15 {
                t.record_loss();
            }
        }
        let t = evaluate(&s);
        let c = causes(&t);
        assert_eq!(c[0], Cause::GatewayLan, "network cause must rank first");
        assert!(c.contains(&Cause::Machine), "but the CPU is still reported");
    }

    /// Even a *severe* machine finding stays behind network causes: throttling
    /// is Degraded like the gateway here, and only the caveat rule breaks the tie.
    #[test]
    fn caveat_class_never_outranks_a_network_cause() {
        let mut s = healthy_state();
        s.vitals.throttled = true;
        let gw = s.targets.iter_mut().find(|t| t.discovered).unwrap();
        for _ in 0..3 {
            gw.record_loss(); // ~13% recent loss: Degraded, same tier as throttling
        }
        let t = evaluate(&s);
        assert_eq!(causes(&t)[0], Cause::GatewayLan);
        assert!(causes(&t).contains(&Cause::Machine));
    }

    #[test]
    fn vpn_caveat_rides_along_with_any_network_finding() {
        let mut s = healthy_state();
        s.netinfo.tunnel = Some("Cloudflare WARP".into());
        s.netinfo.tunnel_iface = "utun0".into();
        for t in s.targets.iter_mut().filter(|t| !t.discovered) {
            for _ in 0..15 {
                t.record_loss();
            }
        }
        let t = evaluate(&s);
        let last = t.findings.last().unwrap();
        assert_eq!(last.cause, Cause::VpnCaveat);
        assert!(last.summary.contains("Cloudflare WARP"));

        // ...but not on a healthy connection — a VPN is not a finding by itself.
        let mut h = healthy_state();
        h.netinfo.tunnel = Some("Tailscale".into());
        assert!(evaluate(&h).findings.is_empty());
    }

    #[test]
    fn a_captive_portal_outranks_everything() {
        use crate::app::FamilyProbe;
        let mut s = healthy_state();
        // Portal blocks everything: pings dead AND http intercepted.
        for t in &mut s.targets {
            for _ in 0..15 {
                t.record_loss();
            }
        }
        s.http.provider = "Apple".into();
        s.http.v4 = FamilyProbe::Captive(Some("http://portal.cafe/login".into()));
        s.http.v6 = FamilyProbe::NotApplicable;
        let t = evaluate(&s);
        let f = &t.findings[0];
        assert_eq!(
            f.cause,
            Cause::CaptivePortal,
            "sign-in page first: {:?}",
            causes(&t)
        );
        assert_eq!(f.severity, Severity::Down);
        assert!(f.evidence.iter().any(|e| e.contains("portal.cafe")));
    }

    #[test]
    fn broken_v6_with_working_v4_is_named() {
        use crate::app::FamilyProbe;
        let mut s = healthy_state();
        s.http.v4 = FamilyProbe::Ok(38.0);
        s.http.v6 = FamilyProbe::Fail("timeout".into());
        let t = evaluate(&s);
        let f = &t.findings[0];
        assert_eq!(f.cause, Cause::Ipv6Broken);
        assert!(f.evidence[0].contains("timeout"));

        // A v4-only LAN must never produce this finding.
        let mut s = healthy_state();
        s.http.v4 = FamilyProbe::Ok(38.0);
        s.http.v6 = FamilyProbe::NotApplicable;
        assert!(evaluate(&s).findings.is_empty());
    }

    #[test]
    fn http_dead_while_ping_works_blames_a_proxy_or_firewall() {
        use crate::app::FamilyProbe;
        let mut s = healthy_state();
        s.http.v4 = FamilyProbe::Fail("connect failed".into());
        s.http.v6 = FamilyProbe::NotApplicable;
        let t = evaluate(&s);
        assert_eq!(t.findings[0].cause, Cause::HttpBlocked);

        // With the anchors ALSO dead there is no ping/http contrast — the
        // gateway/internet findings own that story instead.
        let mut s = healthy_state();
        s.http.v4 = FamilyProbe::Fail("connect failed".into());
        for t in s.targets.iter_mut().filter(|t| !t.discovered) {
            for _ in 0..15 {
                t.record_loss();
            }
        }
        assert!(!causes(&evaluate(&s)).contains(&Cause::HttpBlocked));
    }

    #[test]
    fn a_working_http_probe_unblinds_a_no_icmp_verdict() {
        use crate::app::FamilyProbe;
        let mut s = AppState::new(vec![]);
        s.icmp_error = Some("nope".into());
        assert!(insufficient_reason(&s).is_some());
        s.http.v4 = FamilyProbe::Ok(30.0);
        assert!(
            insufficient_reason(&s).is_none(),
            "HTTP proves connectivity when ICMP cannot"
        );
    }

    #[test]
    fn baseline_turns_absolute_numbers_into_vs_normal() {
        let mut s = healthy_state();
        // Gateway idle floor 5ms, now sitting at 70ms — inflated in absolute
        // terms AND way above this network's learned normal.
        let gw = s.targets.iter_mut().find(|t| t.discovered).unwrap();
        gw.reset();
        for _ in 0..5 {
            gw.record_reply(5.0);
        }
        for _ in 0..20 {
            gw.record_reply(70.0);
        }
        s.baseline = Some(crate::baseline::Baseline {
            label: "HomeNet".into(),
            name: Some("Home".into()),
            samples: 10,
            gateway_ms: Some(9.0),
            ..Default::default()
        });
        let t = evaluate(&s);
        let f = t
            .findings
            .iter()
            .find(|f| f.cause == Cause::GatewayLan)
            .expect("inflated gateway raises");
        assert!(
            f.evidence.iter().any(|e| e.contains("~9ms normal at Home")),
            "evidence names the location: {:?}",
            f.evidence
        );
        // Anchors are fine (contradiction → Weak), but the baseline agreeing
        // it is abnormal hardens that by one level.
        assert_eq!(f.confidence, Confidence::Likely);

        // An unestablished baseline (too few samples) stays silent.
        s.baseline.as_mut().unwrap().samples = 2;
        let t = evaluate(&s);
        let f = t
            .findings
            .iter()
            .find(|f| f.cause == Cause::GatewayLan)
            .unwrap();
        assert!(!f.evidence.iter().any(|e| e.contains("normal at")));
    }

    /// The anti-poisoning rule: an active finding — even a caveat — means the
    /// baseline learns nothing this minute.
    #[test]
    fn incidents_never_teach_the_baseline() {
        let mut s = healthy_state();
        if let Some(earlier) = Instant::now().checked_sub(Duration::from_secs(300)) {
            s.started = earlier;
        }
        let (key, label) = crate::baseline::fingerprint(&s.netinfo).expect("fingerprintable");
        s.baseline_key = Some(key);
        s.baseline = Some(crate::baseline::Baseline {
            label,
            ..Default::default()
        });
        s.verdict.current = Verdict::Healthy;

        let mut healthy_run = 59;
        let mut last_speed = Some(0);
        let io = baseline_step(&mut s, &mut healthy_run, &mut last_speed);
        assert!(
            matches!(io, BaselineIo::Save { .. }),
            "60th healthy tick folds"
        );
        assert_eq!(s.baseline.as_ref().unwrap().samples, 1);

        // Now a finding is active: the fold that was one tick away is denied
        // and the healthy streak starts over.
        s.verdict.current = Verdict::Problems(vec![fake(Cause::GatewayLan)]);
        healthy_run = 59;
        let io = baseline_step(&mut s, &mut healthy_run, &mut last_speed);
        assert!(matches!(io, BaselineIo::None));
        assert_eq!(healthy_run, 0, "the streak resets");
        assert_eq!(s.baseline.as_ref().unwrap().samples, 1, "nothing learned");
    }

    #[test]
    fn insufficient_until_warmed_up_and_sampled() {
        let s = AppState::new(vec![]);
        assert!(insufficient_reason(&s).is_some(), "no samples yet");

        let mut s = healthy_state();
        assert!(insufficient_reason(&s).is_some(), "not warmed up yet");
        if let Some(earlier) = Instant::now().checked_sub(Duration::from_secs(60)) {
            s.started = earlier;
            assert!(insufficient_reason(&s).is_none());
        }

        s.icmp_error = Some("nope".into());
        let reason = insufficient_reason(&s).expect("no ICMP means no verdict");
        assert!(reason.contains("ICMP"));
    }

    fn fake(cause: Cause) -> Finding {
        Finding {
            cause,
            severity: Severity::Degraded,
            confidence: Confidence::Likely,
            summary: "x".into(),
            evidence: vec![],
            subject: String::new(),
            symptom: false,
            since: None,
        }
    }

    #[test]
    fn findings_raise_on_four_of_six_ticks_and_clear_after_eight_quiet() {
        let mut vs = VerdictState::default();
        let now = Instant::now();
        let with = Triage {
            rungs: vec![],
            checks: vec![],
            findings: vec![fake(Cause::GatewayLan)],
        };
        let without = Triage::default();

        for _ in 0..3 {
            vs.ingest(with.clone(), None, now);
            assert!(
                matches!(vs.current, Verdict::Healthy),
                "3 hits must not raise"
            );
        }
        let transitions = vs.ingest(with.clone(), None, now);
        assert!(matches!(vs.current, Verdict::Problems(_)), "4th hit raises");
        assert!(transitions.iter().any(|t| t.raised));

        for i in 0..7 {
            vs.ingest(without.clone(), None, now);
            assert!(
                matches!(vs.current, Verdict::Problems(_)),
                "still active after {} quiet ticks",
                i + 1
            );
        }
        let transitions = vs.ingest(without.clone(), None, now);
        assert!(
            matches!(vs.current, Verdict::Healthy),
            "8th quiet tick clears"
        );
        // Off the footer at once, but the timeline entry waits out the flap
        // grace in case it comes straight back.
        assert!(
            transitions.iter().all(|t| t.raised),
            "clear is held, not emitted yet"
        );
        let later = now + Duration::from_secs(th::FLAP_GRACE_SECS + 1);
        let transitions = vs.ingest(without.clone(), None, later);
        let cleared = transitions.iter().find(|t| !t.raised).unwrap();
        assert!(cleared.after.is_some(), "clears carry the active duration");
    }

    /// The Quad9 lesson: 10% loss to one anchor flapped every half minute,
    /// filling the timeline with ▲/✓ pairs. A finding that comes back within
    /// the grace is the same episode — one raise entry, one clear entry, with
    /// the duration spanning the whole thing.
    #[test]
    fn a_finding_that_flaps_within_the_grace_is_one_episode() {
        let mut vs = VerdictState::default();
        let t0 = Instant::now();
        let with = Triage {
            rungs: vec![],
            checks: vec![],
            findings: vec![fake(Cause::SingleDestination)],
        };
        let without = Triage::default();
        let mut raises = 0;
        let mut clears = 0;
        let mut count = |ts: Vec<Transition>| {
            for t in ts {
                if t.raised { raises += 1 } else { clears += 1 }
            }
        };
        let mut now = t0;
        // Three cycles of: present 6 ticks, absent 12 ticks (past CLEAR_TICKS),
        // 30 s apart in wall time.
        for _ in 0..3 {
            for _ in 0..6 {
                count(vs.ingest(with.clone(), None, now));
            }
            for _ in 0..12 {
                now += Duration::from_secs(1);
                count(vs.ingest(without.clone(), None, now));
            }
            now += Duration::from_secs(12);
        }
        assert_eq!(raises, 1, "one raise for the whole flapping episode");
        assert_eq!(clears, 0, "no clear while it keeps coming back");
        // Silence beyond the grace: the one clear, spanning the episode.
        now += Duration::from_secs(th::FLAP_GRACE_SECS + 1);
        let ts = vs.ingest(without.clone(), None, now);
        let cleared = ts.iter().find(|t| !t.raised).expect("the final clear");
        assert!(
            cleared.after.unwrap() >= Duration::from_secs(50),
            "{:?}",
            cleared.after
        );
    }

    /// The bug from live testing: Wi-Fi off showed "25% loss" on the timeline
    /// but never the escalation to "unresponsive (100%)" — an active finding
    /// getting worse must land as its own transition.
    #[test]
    fn severity_escalation_of_an_active_finding_is_a_new_transition() {
        let mut vs = VerdictState::default();
        let now = Instant::now();
        let degraded = Triage {
            rungs: vec![],
            checks: vec![],
            findings: vec![fake(Cause::GatewayLan)],
        };
        for _ in 0..4 {
            vs.ingest(degraded.clone(), None, now);
        }
        assert!(matches!(vs.current, Verdict::Problems(_)));

        let mut worse = fake(Cause::GatewayLan);
        worse.severity = Severity::Down;
        worse.summary = "gateway unresponsive (100% loss)".into();
        let t = vs.ingest(
            Triage {
                rungs: vec![],
                checks: vec![],
                findings: vec![worse.clone()],
            },
            None,
            now,
        );
        let esc = t.iter().find(|t| t.raised).expect("escalation transition");
        assert_eq!(esc.finding.severity, Severity::Down);
        assert!(esc.finding.summary.contains("100%"));

        // Same severity again: no repeat spam.
        let t = vs.ingest(
            Triage {
                rungs: vec![],
                checks: vec![],
                findings: vec![worse],
            },
            None,
            now,
        );
        assert!(t.is_empty());
    }

    #[test]
    fn a_single_blip_never_raises() {
        let mut vs = VerdictState::default();
        let now = Instant::now();
        let with = Triage {
            rungs: vec![],
            checks: vec![],
            findings: vec![fake(Cause::WideInternet)],
        };
        for _ in 0..3 {
            vs.ingest(with.clone(), None, now);
            for _ in 0..6 {
                vs.ingest(Triage::default(), None, now);
            }
        }
        assert!(matches!(vs.current, Verdict::Healthy));
    }

    #[test]
    fn render_text_carries_the_ladder_and_the_evidence() {
        let mut s = healthy_state();
        let out = render_text(&evaluate(&s), None);
        assert!(out.starts_with("== ANALYSIS =="));
        assert!(out.contains("✓ gateway"));
        assert!(
            out.contains("? ISP path"),
            "unmeasured stays a question mark"
        );
        assert!(out.contains("no findings"));

        for t in &mut s.targets {
            for _ in 0..15 {
                t.record_loss();
            }
        }
        let out = render_text(&evaluate(&s), None);
        assert!(out.contains("▲ gateway unresponsive"));
        // Confidence words stay internal; the evidence makes the case.
        assert!(!out.contains("— strong"));
        assert!(out.contains("% loss, last"), "evidence lines included");

        let out = render_text(
            &Triage::default(),
            Some("ICMP unavailable — cannot measure"),
        );
        assert!(out.contains("ICMP unavailable"));
    }

    #[test]
    fn exit_codes_separate_healthy_broken_and_unmeasurable() {
        let healthy = evaluate(&healthy_state());
        assert_eq!(exit_code(&healthy, false), 0);
        assert_eq!(exit_code(&healthy, true), 3, "insufficient wins");

        let mut s = healthy_state();
        for t in &mut s.targets {
            for _ in 0..15 {
                t.record_loss();
            }
        }
        assert_eq!(exit_code(&evaluate(&s), false), 1);

        // Info-class notes (busy CPU) are not failures.
        let mut s = healthy_state();
        s.vitals.cpu_pct = 97.0;
        s.vitals.cores = vec![97.0; 8];
        let t = evaluate(&s);
        assert!(!t.findings.is_empty());
        assert_eq!(exit_code(&t, false), 0);
    }

    #[test]
    fn insufficient_overrides_everything() {
        let mut vs = VerdictState::default();
        let now = Instant::now();
        let out = vs.ingest(Triage::default(), Some("measuring…".into()), now);
        assert!(out.is_empty());
        assert!(matches!(vs.current, Verdict::Insufficient(_)));
    }
}
