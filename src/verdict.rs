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
    pub const CPU_HOT_PCT: f32 = 90.0;
    pub const CORE_HOT_PCT: f32 = 95.0;
    pub const MEM_HOT_PCT: f32 = 90.0;
    /// Outcomes considered for *detection*. The display window (100) takes
    /// 100 s to reflect an outage; 20 reacts inside half a minute.
    pub const RECENT: usize = 20;
    /// Below this many outcomes a probe has no opinion, only noise.
    pub const MIN_SAMPLES: usize = 5;
    /// RTT counts as inflated above `max(factor × idle floor, this floor)` —
    /// the absolute floor keeps a 1 ms → 4 ms gateway from reading as a fault.
    pub const RTT_INFLATED_FLOOR_MS: f64 = 30.0;
    pub const RTT_INFLATED_FACTOR: f64 = 3.0;
    /// A finding raises when present in ≥ RAISE_HITS of the last RAISE_WINDOW
    /// ticks, and clears after CLEAR_TICKS consecutive quiet ticks.
    pub const RAISE_HITS: usize = 4;
    pub const RAISE_WINDOW: usize = 6;
    pub const CLEAR_TICKS: u32 = 8;
    /// No verdict at all until this much uptime — early probes are still queued.
    pub const WARMUP_SECS: u64 = 10;
}
use thresholds as th;

/// What is at fault. Declaration order is most-specific-first and doubles as
/// the ranking tiebreak; the caveat-class causes at the end are co-reported but
/// never the sole confident answer.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Cause {
    /// Highest-ranked: nothing else matters until the sign-in page is dealt with.
    CaptivePortal,
    GatewayLan,
    WifiLink,
    Dns,
    IspHop,
    WideInternet,
    Ipv6Broken,
    HttpBlocked,
    WebTarget,
    SingleDestination,
    Bufferbloat,
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
            Cause::CaptivePortal => "captive-portal",
            Cause::GatewayLan => "gateway",
            Cause::WifiLink => "link",
            Cause::Dns => "dns",
            Cause::IspHop => "isp",
            Cause::WideInternet => "internet",
            Cause::Ipv6Broken => "ipv6",
            Cause::HttpBlocked => "http-blocked",
            Cause::WebTarget => "web-target",
            Cause::SingleDestination => "destination",
            Cause::Bufferbloat => "bufferbloat",
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
}

/// The rank order: severity first, confidence second, specificity third —
/// except caveat-class causes always sort after network causes.
fn rank(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        (
            a.cause.is_caveat(),
            b.severity,
            b.confidence,
            a.cause,
            &a.subject,
        )
            .cmp(&(
                b.cause.is_caveat(),
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
    if loss >= th::LOSS_BAD_PCT {
        return Health::Bad;
    }
    if loss >= th::LOSS_WARN_PCT || inflated(t) {
        return Health::Warn;
    }
    Health::Good
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

/// Pure, instantaneous read of the whole state. No hysteresis, no I/O — doctor
/// mode calls it once after a batch observation; the live task calls it every
/// tick and filters through [`VerdictState`].
pub fn evaluate(s: &AppState) -> Triage {
    let gw = gateway_target(s);
    let gw_health = gw.map(probe_health).unwrap_or(Health::NoData);
    // Anchors: the user's endpoint targets (defaults: Cloudflare/Google/Quad9).
    // Discovered mid-path hops are excluded — routers deprioritise ICMP, and a
    // lossy hop that forwards fine is not a destination problem.
    let anchors: Vec<&TargetStat> = s.targets.iter().filter(|t| !t.discovered).collect();
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

    let mut findings: Vec<Finding> = Vec::new();

    // --- gateway / LAN ---
    if let Some(g) = gw {
        let loss = g.recent_loss_pct(th::RECENT);
        let raise = gw_health == Health::Bad || (gw_health != Health::NoData && inflated(g));
        if raise {
            let severity = if loss >= th::LOSS_DOWN_PCT {
                Severity::Down
            } else {
                Severity::Degraded
            };
            // Corroboration: everything behind a dead gateway fails, so bad
            // anchors make the story consistent. Fine anchors *contradict* it —
            // many gateways deprioritise ICMP while forwarding perfectly.
            let mut confidence = if bad.len() >= 2 {
                Confidence::Strong
            } else if fine >= 2 {
                Confidence::Weak
            } else {
                Confidence::Likely
            };
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
            findings.push(if hurting {
                Finding {
                    cause: Cause::WifiLink,
                    severity: Severity::Degraded,
                    confidence: if rssi <= th::RSSI_AWFUL_DBM {
                        Confidence::Strong
                    } else {
                        Confidence::Likely
                    },
                    summary: format!("Wi-Fi link is weak (rssi {rssi} dBm)"),
                    evidence,
                    subject: String::new(),
                }
            } else {
                Finding {
                    cause: Cause::WifiLink,
                    severity: Severity::Info,
                    confidence: Confidence::Weak,
                    summary: format!("Wi-Fi signal weak (rssi {rssi} dBm) — not yet hurting"),
                    evidence,
                    subject: String::new(),
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
        });
    }

    // --- DNS ---
    let probes: Vec<&crate::app::DnsProbe> = s.dns.iter().filter(|p| p.sent >= 3).collect();
    if !probes.is_empty() {
        let failing = |p: &crate::app::DnsProbe| p.fail_pct() >= 50.0;
        let slow = |p: &crate::app::DnsProbe| p.mean_ms().is_some_and(|m| m > th::DNS_BAD_MS);
        let n_fail = probes.iter().filter(|p| failing(p)).count();
        let n_slow = probes.iter().filter(|p| !failing(p) && slow(p)).count();
        // The anchors-fine contrast is the whole point: ping works, names don't.
        let confidence = if fine >= 2 {
            Confidence::Strong
        } else if bad.len() >= 2 {
            Confidence::Weak // everything is failing; DNS is a symptom
        } else {
            Confidence::Likely
        };
        let mut evidence: Vec<String> = probes
            .iter()
            .map(|p| {
                format!(
                    "resolver {}: mean {}, {:.0}% failed{}",
                    p.server,
                    fmt_ms(p.mean_ms()),
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
                .filter_map(|p| p.mean_ms())
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
        let names_resolve = matches!(s.http.v4, crate::app::FamilyProbe::Ok(_))
            || matches!(s.http.v6, crate::app::FamilyProbe::Ok(_));
        if n_fail == probes.len() && names_resolve {
            let mut evidence = evidence.clone();
            evidence.push("HTTP check fetched a hostname fine — resolution itself works".into());
            findings.push(Finding {
                cause: Cause::Dns,
                severity: Severity::Info,
                confidence: Confidence::Weak,
                summary: "resolver probes blocked on this network — names still resolve"
                    .to_string(),
                evidence,
                subject: String::new(),
            });
        } else if n_fail == probes.len() {
            findings.push(Finding {
                cause: Cause::Dns,
                severity: Severity::Down,
                confidence,
                summary: format!("DNS not answering (all {} resolvers failing)", probes.len()),
                evidence,
                subject: String::new(),
            });
        } else if n_fail + n_slow == probes.len() {
            findings.push(Finding {
                cause: Cause::Dns,
                severity: Severity::Degraded,
                confidence,
                summary: "DNS slow on every resolver".to_string(),
                evidence,
                subject: String::new(),
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
            });
        }
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
        let early_bad_hop = s.hop_monitor.as_ref().and_then(|m| {
            m.hops.iter().find(|h| {
                h.ttl >= 2
                    && h.ttl <= 4
                    && h.stat.as_ref().is_some_and(|st| {
                        st.window.len() >= 10 && st.recent_loss_pct(th::RECENT) >= th::LOSS_BAD_PCT
                    })
            })
        });
        if let Some(h) = early_bad_hop {
            let addr = h
                .addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "?".to_string());
            evidence.push(format!("loss begins at hop {} ({})", h.ttl, addr));
            findings.push(Finding {
                cause: Cause::IspHop,
                severity,
                confidence: Confidence::Strong,
                summary: format!("ISP path degraded — loss begins at hop {} ({addr})", h.ttl),
                evidence,
                subject: String::new(),
            });
        } else {
            findings.push(Finding {
                cause: Cause::WideInternet,
                severity,
                confidence: Confidence::Strong,
                summary: format!(
                    "internet {} beyond the gateway ({} of {} anchors failing)",
                    if all_down { "unreachable" } else { "degraded" },
                    bad.len(),
                    with_data.len()
                ),
                evidence,
                subject: String::new(),
            });
        }
    } else if gw_health != Health::Bad && fine >= 2 {
        // Consensus says the connection works; whatever is bad is *that* place.
        for t in &bad {
            let loss = t.recent_loss_pct(th::RECENT);
            let what = if loss >= th::LOSS_DOWN_PCT {
                "unreachable".to_string()
            } else {
                format!("degraded ({loss:.0}% loss)")
            };
            findings.push(Finding {
                cause: Cause::SingleDestination,
                severity: Severity::Degraded,
                confidence: if bad.len() == 1 {
                    Confidence::Strong
                } else {
                    Confidence::Likely
                },
                summary: format!("{} {what} — your connection is fine", t.label),
                evidence: vec![
                    format!("{} ({}): {loss:.0}% loss", t.label, t.addr),
                    format!("{fine} other anchors fine, gateway fine"),
                ],
                subject: t.label.clone(),
            });
        }
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
            });
        } else if let (FP::Ok(v4_ms), FP::Fail(reason)) = (&http.v4, &http.v6) {
            findings.push(Finding {
                cause: Cause::Ipv6Broken,
                severity: Severity::Degraded,
                confidence: Confidence::Likely,
                summary: "IPv6 broken while IPv4 works — pages stall then load".to_string(),
                evidence: vec![
                    format!("v6 probe: {reason} · v4 probe: ok {v4_ms:.0}ms"),
                    "browsers try v6 first and fall back, adding delay to every request"
                        .to_string(),
                ],
                subject: String::new(),
            });
        } else if matches!(http.v4, FP::Fail(_)) && !matches!(http.v6, FP::Ok(_)) && fine >= 2 {
            let reason = match &http.v4 {
                FP::Fail(r) => r.clone(),
                _ => String::new(),
            };
            findings.push(Finding {
                cause: Cause::HttpBlocked,
                severity: Severity::Degraded,
                confidence: Confidence::Likely,
                summary: "web traffic blocked while ping works — proxy or firewall".to_string(),
                evidence: vec![
                    format!("HTTP probe failed ({reason}) on two independent endpoints"),
                    format!("{fine} anchors answer ICMP normally"),
                ],
                subject: String::new(),
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
                    confidence: if t.web.fails >= 5 {
                        Confidence::Strong
                    } else {
                        Confidence::Likely
                    },
                    summary: format!("{} web service not answering — ping still fine", t.label),
                    evidence: vec![
                        format!(
                            "{} HTTP probes unanswered on a target that served HTTP before",
                            t.web.fails
                        ),
                        format!(
                            "ICMP to {} still healthy ({:.0}% loss) — the service, not the path",
                            t.addr,
                            t.recent_loss_pct(th::RECENT)
                        ),
                    ],
                    subject: t.label.clone(),
                });
            }
        }
    }

    // --- bufferbloat (only meaningful under load) ---
    let n = s.window_samples().min(60);
    let loaded = matches!(s.speedtest.status, crate::app::SpeedStatus::Running)
        || s.netinfo.link_speed_bps.is_some_and(|cap| {
            (s.throughput.down_bps + s.throughput.up_bps) * 8.0 > 0.3 * cap as f64
        });
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
                confidence: Confidence::Likely,
                summary: format!("bufferbloat: +{bloat:.0}ms latency under load"),
                evidence: vec![format!(
                    "{label}: mean over the last minute is {bloat:.0}ms above the idle floor"
                )],
                subject: String::new(),
            });
        }
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
        });
    }
    let hottest = v.hottest_core().map(|(_, pct)| pct).unwrap_or(0.0);
    if v.cpu_pct >= th::CPU_HOT_PCT || hottest >= th::CORE_HOT_PCT {
        findings.push(Finding {
            cause: Cause::Machine,
            severity: Severity::Info,
            confidence: Confidence::Likely,
            summary: format!("machine under load (cpu {:.0}%)", v.cpu_pct),
            evidence: vec![format!("cpu {:.0}%, hottest core {hottest:.0}%", v.cpu_pct)],
            subject: "cpu".to_string(),
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
        });
    }

    rank(&mut findings);
    let rungs = build_rungs(s, gw, gw_health, &with_data, &bad, fine);
    Triage { rungs, findings }
}

/// The ladder itself: every area, always present, in blame order. Healthy rungs
/// carry their data — "we checked" is the difference between a verdict and an
/// assertion.
fn build_rungs(
    s: &AppState,
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
    let m_status = if v.throttled {
        RungStatus::Bad
    } else if v.cpu_pct >= th::USAGE_BAD_PCT || v.mem_pressure_pct >= th::USAGE_BAD_PCT {
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

    // Physical link.
    let err_pct = s.link_errors.error_pct();
    let (l_status, l_detail) = match s.netinfo.medium {
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

    // DNS.
    let probes: Vec<&crate::app::DnsProbe> = s.dns.iter().filter(|p| p.sent >= 3).collect();
    rungs.push(if probes.is_empty() {
        Rung {
            area: Area::Dns,
            status: RungStatus::Unknown,
            detail: "no data yet".to_string(),
        }
    } else {
        let worst_mean = probes
            .iter()
            .filter_map(|p| p.mean_ms())
            .fold(0.0_f64, f64::max);
        let n_fail = probes.iter().filter(|p| p.fail_pct() >= 50.0).count();
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
        Rung {
            area: Area::Destinations,
            status: RungStatus::Bad,
            detail: format!("struggling: {}", names.join(", ")),
        }
    } else {
        Rung {
            area: Area::Destinations,
            status: RungStatus::Ok,
            detail: "all targets reachable".to_string(),
        }
    });

    rungs
}

/// A finding raise or clear, for the event timeline.
#[derive(Clone, Debug)]
pub struct Transition {
    pub raised: bool,
    pub finding: Finding,
    /// How long the finding was active — set on clears.
    pub after: Option<Duration>,
}

struct Track {
    hits: VecDeque<bool>,
    active: Option<Active>,
}

struct Active {
    since: Instant,
    quiet: u32,
    last: Finding,
}

/// Hysteresis over [`evaluate`]'s raw findings, keyed by `(cause, subject)`:
/// raise on ≥4 of the last 6 ticks, clear after 8 consecutive quiet ticks.
/// Severity/confidence/evidence of an active finding update live.
#[derive(Default)]
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
                        transitions.push(Transition {
                            raised: false,
                            finding: active.last.clone(),
                            after: Some(now.duration_since(active.since)),
                        });
                        tr.active = None;
                    }
                }
                (None, Some(f)) => {
                    let hits = tr.hits.iter().filter(|h| **h).count();
                    if hits >= th::RAISE_HITS {
                        transitions.push(Transition {
                            raised: true,
                            finding: f.clone(),
                            after: None,
                        });
                        tr.active = Some(Active {
                            since: now,
                            quiet: 0,
                            last: f,
                        });
                    }
                }
                (None, None) => {}
            }
            tr.active.is_some() || tr.hits.iter().any(|h| *h)
        });

        let mut active: Vec<Finding> = self
            .tracker
            .values()
            .filter_map(|t| t.active.as_ref().map(|a| a.last.clone()))
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
    for r in &triage.rungs {
        let glyph = match r.status {
            RungStatus::Ok => "✓",
            RungStatus::Warn => "~",
            RungStatus::Bad => "✗",
            RungStatus::Unknown => "?",
        };
        let _ = writeln!(out, "  {glyph} {:<13} {}", r.area.label(), r.detail);
    }
    let _ = writeln!(out);
    if let Some(reason) = insufficient {
        let _ = writeln!(out, "  {reason}");
    } else if triage.findings.is_empty() {
        let _ = writeln!(out, "  no findings — connection looks healthy");
    } else {
        for f in &triage.findings {
            let _ = writeln!(out, "  ▲ {}", f.summary);
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

        let io = {
            let mut s = state.lock().unwrap();
            let triage = evaluate(&s);
            let insufficient = insufficient_reason(&s);
            for t in s.verdict.ingest(triage, insufficient, now) {
                let (severity, message) = if t.raised {
                    (t.finding.severity, format!("▲ {}", t.finding.summary))
                } else {
                    // Clears are good news: Info regardless of how bad it was.
                    (
                        Severity::Info,
                        format!(
                            "✓ {} — ended after {}",
                            t.finding.summary,
                            fmt_duration(t.after.unwrap_or_default())
                        ),
                    )
                };
                s.push_event(severity, crate::app::EventCategory::Analysis, message);
            }

            baseline_step(&mut s, &mut healthy_run, &mut last_speed_total)
        };

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
        assert_eq!(f.confidence, Confidence::Strong);
        assert!(!causes(&t).contains(&Cause::SingleDestination));
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
    }

    #[test]
    fn dns_failing_while_ping_works_is_a_strong_dns_verdict() {
        let mut s = healthy_state();
        let mut p = crate::app::DnsProbe::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        p.sent = 10;
        p.ok = 0;
        p.status = "timeout".into();
        s.dns = vec![p];
        let t = evaluate(&s);
        let f = &t.findings[0];
        assert_eq!(f.cause, Cause::Dns);
        assert_eq!(f.severity, Severity::Down);
        // The anchors-fine contrast is the whole point.
        assert_eq!(f.confidence, Confidence::Strong);
    }

    /// The hotspot lesson: a carrier network handed out a link-local resolver
    /// octomon couldn't probe, while resolution worked fine. Working HTTP
    /// (which resolved a hostname) must cap the DNS claim at an Info note.
    #[test]
    fn dns_probe_failures_defer_to_a_working_http_check() {
        let mut s = healthy_state();
        let mut p = crate::app::DnsProbe::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        p.sent = 10;
        p.ok = 0;
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
        // Gateway idle floor 5ms, now sitting at 45ms — inflated in absolute
        // terms AND way above this network's learned normal.
        let gw = s.targets.iter_mut().find(|t| t.discovered).unwrap();
        gw.reset();
        for _ in 0..5 {
            gw.record_reply(5.0);
        }
        for _ in 0..20 {
            gw.record_reply(45.0);
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
        }
    }

    #[test]
    fn findings_raise_on_four_of_six_ticks_and_clear_after_eight_quiet() {
        let mut vs = VerdictState::default();
        let now = Instant::now();
        let with = Triage {
            rungs: vec![],
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
        let cleared = transitions.iter().find(|t| !t.raised).unwrap();
        assert!(cleared.after.is_some(), "clears carry the active duration");
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
