//! Shared application state written by collectors and read by the renderer.
//!
//! All mutation happens under a single [`std::sync::Mutex`]; critical sections are
//! short and never span an `.await`, so a std mutex is appropriate here.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::Instant;

/// Fixed-capacity ring buffer of samples backing sparklines / charts.
#[derive(Clone)]
pub struct History {
    pub data: VecDeque<f64>,
    pub cap: usize,
}

impl History {
    pub fn new(cap: usize) -> Self {
        Self {
            data: VecDeque::with_capacity(cap),
            cap,
        }
    }

    pub fn push(&mut self, v: f64) {
        if self.data.len() == self.cap {
            self.data.pop_front();
        }
        self.data.push_back(v);
    }

    pub fn last(&self) -> Option<f64> {
        self.data.back().copied()
    }

    #[allow(dead_code)] // used for future fixed-scale charts
    pub fn max(&self) -> f64 {
        self.data.iter().cloned().fold(0.0_f64, f64::max)
    }

    /// Most-recent `n` samples as `u64`, oldest first — the shape ratatui's
    /// `Sparkline` wants.
    pub fn tail_u64(&self, n: usize) -> Vec<u64> {
        let skip = self.data.len().saturating_sub(n);
        self.data
            .iter()
            .skip(skip)
            .map(|v| v.max(0.0) as u64)
            .collect()
    }
}

/// Per-target ICMP statistics. Jitter follows the RFC 3550 mean-deviation form.
/// Windowed distribution summary of recent round-trip times.
#[derive(Clone, Default)]
pub struct RttStats {
    pub min: Option<f64>,
    pub mean: Option<f64>,
    pub p95: Option<f64>,
    pub max: Option<f64>,
    pub stddev: f64,
}

/// Monotonic id source so targets have a stable identity independent of their
/// position (ping tasks look up by id, making insertion/deletion safe).
static NEXT_TARGET_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[derive(Clone)]
pub struct TargetStat {
    /// Stable identity, independent of index in the targets vec.
    pub id: u64,
    /// True when auto-added by hop discovery at startup.
    pub discovered: bool,
    pub label: String,
    pub addr: IpAddr,
    pub last_rtt_ms: Option<f64>,
    /// RFC 3550 interarrival jitter (smoothed).
    pub jitter_ms: f64,
    /// All-time minimum RTT — the idle baseline for bufferbloat.
    pub min_ever_ms: Option<f64>,
    pub sent: u64,
    pub recv: u64,
    /// Sliding window of recent outcomes (`true` = reply received).
    pub window: VecDeque<bool>,
    pub history: History,
}

impl TargetStat {
    pub fn new(label: String, addr: IpAddr) -> Self {
        Self {
            id: NEXT_TARGET_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            discovered: false,
            label,
            addr,
            last_rtt_ms: None,
            jitter_ms: 0.0,
            min_ever_ms: None,
            sent: 0,
            recv: 0,
            window: VecDeque::with_capacity(WINDOW),
            history: History::new(1000),
        }
    }

    /// Record a successful probe with round-trip time in milliseconds.
    pub fn record_reply(&mut self, rtt_ms: f64) {
        self.sent += 1;
        self.recv += 1;
        self.push_window(true);

        self.last_rtt_ms = Some(rtt_ms);
        self.min_ever_ms = Some(self.min_ever_ms.map_or(rtt_ms, |m| m.min(rtt_ms)));

        // RFC 3550 interarrival jitter: J += (|D| - J) / 16.
        if let Some(prev) = self.history.last() {
            let d = (rtt_ms - prev).abs();
            self.jitter_ms += (d - self.jitter_ms) / 16.0;
        }
        self.history.push(rtt_ms);
    }

    /// Record a lost / timed-out probe.
    pub fn record_loss(&mut self) {
        self.sent += 1;
        self.push_window(false);
        self.last_rtt_ms = None;
    }

    fn push_window(&mut self, ok: bool) {
        if self.window.len() == WINDOW {
            self.window.pop_front();
        }
        self.window.push_back(ok);
    }

    /// Clear all accumulated stats (keeps identity, label, address).
    pub fn reset(&mut self) {
        self.last_rtt_ms = None;
        self.jitter_ms = 0.0;
        self.min_ever_ms = None;
        self.sent = 0;
        self.recv = 0;
        self.window.clear();
        self.history.data.clear();
    }

    /// Packet loss over the sliding window, as a percentage.
    pub fn loss_pct(&self) -> f64 {
        if self.window.is_empty() {
            return 0.0;
        }
        let lost = self.window.iter().filter(|ok| !**ok).count();
        lost as f64 / self.window.len() as f64 * 100.0
    }

    /// Distribution over the most recent `n` successful samples.
    pub fn stats(&self, n: usize) -> RttStats {
        let mut v: Vec<f64> = self
            .history
            .data
            .iter()
            .rev()
            .take(n.max(1))
            .copied()
            .collect();
        if v.is_empty() {
            return RttStats::default();
        }
        let samples = v.len();
        let mean = v.iter().sum::<f64>() / samples as f64;
        let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / samples as f64;
        v.sort_by(f64::total_cmp);
        let pct = |p: f64| v[(((samples - 1) as f64) * p).round() as usize];
        RttStats {
            min: Some(v[0]),
            mean: Some(mean),
            p95: Some(pct(0.95)),
            max: Some(v[samples - 1]),
            stddev: var.sqrt(),
        }
    }

    /// Latency inflation over the idle baseline (mean-over-window − all-time
    /// min). Mean (not median) is used so intermittent spikes — the "jumps" a
    /// user feels — pull the figure up. Under sustained load this is the
    /// bufferbloat magnitude.
    pub fn bufferbloat_ms(&self, n: usize) -> Option<f64> {
        match (self.stats(n).mean, self.min_ever_ms) {
            (Some(mean), Some(min)) => Some((mean - min).max(0.0)),
            _ => None,
        }
    }
}

const WINDOW: usize = 100;

/// Aggregate interface throughput (bytes/sec) plus history for charts.
#[derive(Clone, Default)]
pub struct Throughput {
    pub iface: String,
    pub down_bps: f64,
    pub up_bps: f64,
    pub down_hist: History,
    pub up_hist: History,
}

/// Lifecycle of an on-demand speed test.
#[derive(Clone, Default)]
pub enum SpeedStatus {
    #[default]
    Idle,
    Running,
    Done,
    Failed(String),
}

/// Results of the most recent Cloudflare speed test, plus live progress.
#[derive(Clone, Default)]
pub struct SpeedTest {
    pub status: SpeedStatus,
    pub down_mbps: Option<f64>,
    pub up_mbps: Option<f64>,
    pub last_run: Option<Instant>,
    /// Current phase label while running: "latency", "download", "upload".
    pub phase: String,
    /// Progress within the current phase, 0.0..=1.0.
    pub progress: f64,
    /// Instantaneous throughput (Mbps) during the active phase.
    pub live_mbps: f64,
    /// Unloaded (idle) latency measured just before the test, in ms.
    pub idle_latency_ms: Option<f64>,
    /// Latency measured while the link was saturated, in ms.
    pub loaded_latency_ms: Option<f64>,
    /// Which provider produced the most recent result.
    pub provider: String,
}

impl SpeedTest {
    /// Reset live fields when (re)starting a run.
    pub fn begin(&mut self) {
        self.status = SpeedStatus::Running;
        self.phase = "connect".to_string();
        self.progress = 0.0;
        self.live_mbps = 0.0;
    }
}

/// Availability of per-process attribution, so the UI can distinguish "still
/// probing" from "not supported here".
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum ProcStatus {
    #[default]
    Probing,
    Supported,
    Unsupported,
}

/// Per-process network throughput (bytes/sec), derived from successive samples,
/// plus a couple of connection-health signals.
#[derive(Clone)]
pub struct ProcBandwidth {
    pub name: String,
    pub pid: u32,
    pub down_bps: f64,
    pub up_bps: f64,
    /// Cumulative bytes (in+out) this process has transferred this session.
    pub total_bytes: u64,
    /// TCP retransmissions per second (connection-health signal).
    pub retx_per_sec: f64,
}

/// A single traceroute hop.
#[derive(Clone)]
pub struct Hop {
    pub ttl: u8,
    /// Responding address, or `None` for a timed-out hop (`*`).
    pub addr: Option<String>,
    pub rtt_ms: Option<f64>,
}

/// State of a traceroute run to a target.
#[derive(Clone)]
pub struct Traceroute {
    pub target: String,
    pub running: bool,
    pub hops: Vec<Hop>,
}

/// A hop under continuous measurement. Reuses [`TargetStat`], so hops get the
/// same distribution / jitter / loss maths as ordinary targets.
#[derive(Clone)]
pub struct MonitoredHop {
    pub ttl: u8,
    /// `None` for a hop that never answered discovery (a `*` in traceroute).
    pub addr: Option<IpAddr>,
    /// Live statistics, present once the hop has an address to probe.
    pub stat: Option<TargetStat>,
}

/// Continuous per-hop monitoring of the path to a destination — the MTR-style
/// view. Where the whole path degrades tells you *where* the problem is, which
/// a flat list of endpoint targets cannot.
#[derive(Clone)]
pub struct HopMonitor {
    /// Display label for the destination, e.g. "Cloudflare (1.1.1.1)".
    pub target: String,
    pub dest: IpAddr,
    pub hops: Vec<MonitoredHop>,
    /// True while the path is being (re)discovered.
    pub discovering: bool,
    /// Bumped on every restart so probe tasks from a previous run exit.
    pub generation: u64,
    /// Cursor into `hops`, selecting which hop gets the large chart.
    pub selected: usize,
}

/// Which sub-pane inside the focused panel holds the cursor. Tab cycles the four
/// main panels, so sub-panes need their own key.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum SubPane {
    /// Quality: the target table. Bandwidth: the process list.
    #[default]
    Primary,
    /// Quality: the monitored hop list. Bandwidth: speed-test history.
    Secondary,
}

/// Which chart the Connection Quality panel shows beneath the target table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QualityView {
    /// Latency history for the graphed target.
    Graph,
    /// One-shot traceroute results.
    Traceroute,
    /// Continuously updated per-hop statistics.
    HopMonitor,
}

/// Another access point sharing the airspace. SSIDs are deliberately not kept:
/// modern macOS redacts them without Location permission, and congestion only
/// depends on where each network sits in the spectrum.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Neighbour {
    pub channel: u16,
    /// 2, 5 or 6 (GHz).
    pub band_ghz: u16,
    pub width_mhz: u16,
}

impl Neighbour {
    /// Centre frequency in MHz. Channel numbering is band-relative, so the band
    /// is what makes two channel numbers comparable at all.
    pub fn centre_mhz(&self) -> u32 {
        let base = match self.band_ghz {
            2 => 2407,
            6 => 5950,
            _ => 5000,
        };
        base + 5 * self.channel as u32
    }

    /// Whether two networks' occupied spectrum intersects. Adjacent-channel
    /// interference is what actually degrades throughput — counting only exact
    /// channel matches badly understates 2.4GHz congestion, where the common
    /// 1/6/11 spacing exists precisely because neighbours bleed into each other.
    pub fn overlaps(&self, other: &Neighbour) -> bool {
        if self.band_ghz != other.band_ghz {
            return false;
        }
        let half = |n: &Neighbour| (n.width_mhz.max(20) / 2) as u32;
        let (a, b) = (self.centre_mhz(), other.centre_mhz());
        let (ha, hb) = (half(self), half(other));
        a.abs_diff(b) < ha + hb
    }
}

/// How crowded the airspace is around the channel in use.
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct Congestion {
    /// Networks on exactly the same channel.
    pub co_channel: usize,
    /// Networks whose spectrum overlaps ours without matching it.
    pub overlapping: usize,
    /// Every network seen, on any band.
    pub total: usize,
}

/// Wi-Fi radio details (best-effort, platform-specific).
#[derive(Clone, Default)]
pub struct WifiInfo {
    pub ssid: String,
    pub phy: String,
    pub channel: String,
    pub rssi: String,
    pub tx_rate: String,
    /// Other networks visible from this radio.
    pub neighbours: Vec<Neighbour>,
}

impl WifiInfo {
    /// Parse the channel description macOS reports, e.g. "161 (5GHz, 80MHz)".
    pub fn channel_spec(&self) -> Option<Neighbour> {
        parse_channel(&self.channel)
    }

    /// Crowding around our own channel. `None` until a scan has happened.
    pub fn congestion(&self) -> Option<Congestion> {
        let ours = self.channel_spec()?;
        if self.neighbours.is_empty() {
            return Some(Congestion {
                total: 0,
                ..Default::default()
            });
        }
        let mut c = Congestion {
            total: self.neighbours.len(),
            ..Default::default()
        };
        for n in &self.neighbours {
            if n.band_ghz == ours.band_ghz && n.channel == ours.channel {
                c.co_channel += 1;
            } else if n.overlaps(&ours) {
                c.overlapping += 1;
            }
        }
        Some(c)
    }
}

/// Parse "161 (5GHz, 80MHz)" — the shape macOS reports channels in.
pub fn parse_channel(s: &str) -> Option<Neighbour> {
    let mut it = s.split_whitespace();
    let channel: u16 = it.next()?.parse().ok()?;
    // The parenthesised part is optional; assume 20MHz on 2.4GHz without it.
    let rest = s.split_once('(').map(|(_, r)| r.trim_end_matches(')'));
    let (mut band_ghz, mut width_mhz) = (if channel > 14 { 5 } else { 2 }, 20u16);
    if let Some(rest) = rest {
        for part in rest.split(',') {
            let part = part.trim();
            if let Some(b) = part.strip_suffix("GHz") {
                band_ghz = b.trim().parse().unwrap_or(band_ghz);
            } else if let Some(w) = part.strip_suffix("MHz") {
                width_mhz = w.trim().parse().unwrap_or(width_mhz);
            }
        }
    }
    Some(Neighbour {
        channel,
        band_ghz,
        width_mhz,
    })
}

/// How the default-route interface actually carries traffic. Drives which
/// metrics make sense to show: radio signal for Wi-Fi, link utilisation for a
/// wired link, a tunnel warning for a VPN.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkMedium {
    #[default]
    Unknown,
    WiFi,
    Ethernet,
    Cellular,
    /// Default route runs through a VPN / tunnel device (utun, wg, ppp…).
    Tunnel,
    Loopback,
    Bridge,
}

impl LinkMedium {
    /// Human label for the Network panel.
    pub fn label(self) -> &'static str {
        match self {
            LinkMedium::WiFi => "Wi-Fi (wireless)",
            LinkMedium::Ethernet => "Ethernet (wired)",
            LinkMedium::Cellular => "Cellular (WWAN)",
            LinkMedium::Tunnel => "Tunnel (VPN)",
            LinkMedium::Loopback => "Loopback",
            LinkMedium::Bridge => "Bridge (wired)",
            LinkMedium::Unknown => "unknown",
        }
    }

    /// True for a cabled link, where radio metrics don't apply but negotiated
    /// link speed does.
    pub fn is_wired(self) -> bool {
        matches!(self, LinkMedium::Ethernet | LinkMedium::Bridge)
    }
}

/// Basic network identity: addresses, gateway, link.
#[derive(Clone, Default)]
pub struct NetInfo {
    pub iface: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub mac: String,
    pub gateway_ip: String,
    pub gateway_mac: String,
    /// The OS's friendly name for the interface ("Wi-Fi", "Thunderbolt
    /// Ethernet Slot 0"), when it reports one.
    pub iface_label: String,
    /// DNS resolver addresses for this interface.
    pub dns: Vec<String>,
    /// Extra link facts the OS exposes — negotiated speed, DHCP — shown after
    /// the medium. Empty when nothing is known.
    pub link_detail: String,
    /// Classified medium of the default route.
    pub medium: LinkMedium,
    /// Negotiated link speed in bits/sec, when the OS reports it.
    pub link_speed_bps: Option<u64>,
    /// Set when internet traffic leaves through a tunnel device. Carries the
    /// VPN's name when it can be identified (e.g. "Cloudflare WARP"), else empty.
    pub tunnel: Option<String>,
    /// The tunnel's interface name ("utun0"), when one was detected.
    pub tunnel_iface: String,
    /// True when the tunnel is a split route: the kernel's default route still
    /// points at a physical NIC, but internet traffic egresses via the tunnel.
    /// The gateway shown is then the real LAN gateway, not the tunnel endpoint.
    pub tunnel_is_split: bool,
    /// Present when the default interface is Wi-Fi and details are available.
    pub wifi: Option<WifiInfo>,
}

impl NetInfo {
    /// Fingerprint of "which network am I on". When this changes, the gateway,
    /// the path to the internet, and which interface carries traffic may all be
    /// different, so anything derived from them has to be rebuilt.
    pub fn identity(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.iface,
            self.ipv4.join(","),
            self.gateway_ip,
            self.tunnel_iface,
            self.medium as u8,
        )
    }

    /// Tunnel description for display: the vendor when known, else generic.
    pub fn tunnel_label(&self) -> Option<String> {
        self.tunnel.as_ref().map(|v| {
            if v.is_empty() {
                "unidentified VPN / tunnel".to_string()
            } else {
                v.clone()
            }
        })
    }
}

/// Responsiveness of one DNS resolver.
#[derive(Clone)]
pub struct DnsProbe {
    pub server: IpAddr,
    /// Round-trip of the most recent query, or `None` if it failed.
    pub last_ms: Option<f64>,
    pub hist: History,
    pub sent: u64,
    pub ok: u64,
    /// Why the last query failed ("SERVFAIL", "timeout"), else empty.
    pub status: String,
}

impl DnsProbe {
    pub fn new(server: IpAddr) -> Self {
        Self {
            server,
            last_ms: None,
            hist: History::new(300),
            sent: 0,
            ok: 0,
            status: String::new(),
        }
    }

    /// Mean round trip over the retained history.
    pub fn mean_ms(&self) -> Option<f64> {
        if self.hist.data.is_empty() {
            return None;
        }
        Some(self.hist.data.iter().sum::<f64>() / self.hist.data.len() as f64)
    }

    /// Share of queries that went unanswered, as a percentage.
    pub fn fail_pct(&self) -> f64 {
        if self.sent == 0 {
            return 0.0;
        }
        (self.sent - self.ok) as f64 / self.sent as f64 * 100.0
    }
}

/// Live Wi-Fi signal, sampled frequently (CoreWLAN on macOS) for graphing.
#[derive(Clone, Default)]
pub struct SignalState {
    pub present: bool,
    pub rssi_dbm: i32,
    pub noise_dbm: i32,
    pub tx_rate_mbps: f64,
    pub rssi_hist: History,
    pub tx_hist: History,
}

/// Machine vitals, framed only as a "is my box the bottleneck?" signal.
#[derive(Clone, Default)]
pub struct Vitals {
    pub cpu_pct: f32,
    pub mem_used: u64,
    pub mem_total: u64,
    pub cpu_hist: History,
    pub mem_hist: History,
}

impl Default for History {
    fn default() -> Self {
        History::new(300)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn target_with(samples: &[f64]) -> TargetStat {
        let mut t = TargetStat::new("t".into(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        for &s in samples {
            t.record_reply(s);
        }
        t
    }

    #[test]
    fn stats_distribution() {
        // 1..=100 ms
        let samples: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        let t = target_with(&samples);
        let st = t.stats(100);
        assert_eq!(st.min, Some(1.0));
        assert_eq!(st.max, Some(100.0));
        assert_eq!(st.mean, Some(50.5));
        // p95 index = round(99 * 0.95) = 94 -> value 95
        assert_eq!(st.p95, Some(95.0));
        assert!((st.stddev - 28.866).abs() < 0.01);
    }

    #[test]
    fn stats_respects_window() {
        let samples: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        let t = target_with(&samples);
        // Only the most recent 10 samples (91..=100).
        let st = t.stats(10);
        assert_eq!(st.min, Some(91.0));
        assert_eq!(st.max, Some(100.0));
    }

    #[test]
    fn bufferbloat_is_mean_over_idle_floor() {
        // Idle floor 10ms, then a burst of 110ms spikes.
        let mut samples = vec![10.0; 5];
        samples.extend(vec![110.0; 5]);
        let t = target_with(&samples);
        // min_ever = 10; mean over window = 60 => bloat = 50.
        assert_eq!(t.bufferbloat_ms(10), Some(50.0));
    }

    #[test]
    fn name_sort_groups_discovered_first() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut s = AppState::new(vec![
            TargetStat::new("Zebra".into(), ip),
            TargetStat::new("Alpha".into(), ip),
        ]);
        let mut gw = TargetStat::new("gateway".into(), ip);
        gw.discovered = true;
        let mut h2 = TargetStat::new("hop 2".into(), ip);
        h2.discovered = true;
        s.targets.push(gw);
        s.targets.push(h2);

        s.q_sort = Some((0, false)); // sort by name
        let order = s.quality_order();
        let labels: Vec<&str> = order.iter().map(|&i| s.targets[i].label.as_str()).collect();
        // Discovered grouped first (gateway before hop, by id), then alphabetical.
        assert_eq!(labels, vec!["gateway", "hop 2", "Alpha", "Zebra"]);
    }

    #[test]
    fn window_cycles_30_60_300() {
        let mut s = AppState::new(vec![]);
        assert_eq!(s.window_secs, 60);
        s.cycle_window();
        assert_eq!(s.window_secs, 300);
        s.cycle_window();
        assert_eq!(s.window_secs, 30);
        s.cycle_window();
        assert_eq!(s.window_secs, 60);
    }

    #[test]
    fn network_identity_tracks_what_invalidates_the_path() {
        let base = NetInfo {
            iface: "en0".into(),
            ipv4: vec!["192.168.1.89/23".into()],
            gateway_ip: "192.168.1.1".into(),
            medium: LinkMedium::WiFi,
            ..Default::default()
        };

        // Things that mean "different network" must change the fingerprint.
        let moved = |f: &dyn Fn(&mut NetInfo)| {
            let mut n = base.clone();
            f(&mut n);
            n.identity() != base.identity()
        };
        assert!(moved(&|n| n.iface = "en7".into()), "interface");
        assert!(moved(&|n| n.ipv4 = vec!["10.0.0.5/24".into()]), "subnet");
        assert!(moved(&|n| n.gateway_ip = "10.0.0.1".into()), "gateway");
        assert!(moved(&|n| n.tunnel_iface = "utun6".into()), "vpn came up");
        assert!(moved(&|n| n.medium = LinkMedium::Ethernet), "medium");

        // Things that don't change which network we're on must not, or every
        // DHCP-driven DNS tweak would tear down the discovered targets.
        assert!(!moved(&|n| n.dns = vec!["9.9.9.9".into()]), "dns");
        assert!(!moved(&|n| n.mac = "aa:bb:cc:dd:ee:ff".into()), "mac");
        assert!(!moved(&|n| n.link_detail = "1000 Mb".into()), "link speed");
    }

    #[test]
    fn channel_spec_parses_the_macos_shape() {
        let n = parse_channel("161 (5GHz, 80MHz)").unwrap();
        assert_eq!((n.channel, n.band_ghz, n.width_mhz), (161, 5, 80));
        let n = parse_channel("6 (2GHz, 20MHz)").unwrap();
        assert_eq!((n.channel, n.band_ghz, n.width_mhz), (6, 2, 20));
        // Bare channel numbers still classify by band and assume 20MHz.
        assert_eq!(parse_channel("11").unwrap().band_ghz, 2);
        assert_eq!(parse_channel("44").unwrap().band_ghz, 5);
        assert!(parse_channel("").is_none());
    }

    #[test]
    fn overlap_follows_spectrum_not_channel_numbers() {
        let n = |channel, band_ghz, width_mhz| Neighbour {
            channel,
            band_ghz,
            width_mhz,
        };
        // 2.4GHz channels sit 5MHz apart while occupying 20MHz, so neighbouring
        // numbers bleed into each other...
        assert!(n(1, 2, 20).overlaps(&n(3, 2, 20)));
        assert!(n(1, 2, 20).overlaps(&n(4, 2, 20)));
        // ...but 1 / 6 / 11 are 25MHz apart, which is exactly why that trio is
        // the canonical non-overlapping set.
        assert!(!n(1, 2, 20).overlaps(&n(6, 2, 20)));
        assert!(!n(6, 2, 20).overlaps(&n(11, 2, 20)));
        // An 80MHz channel swallows its 20MHz neighbours.
        assert!(n(157, 5, 80).overlaps(&n(161, 5, 20)));
        assert!(!n(36, 5, 20).overlaps(&n(149, 5, 20)));
        // Same channel number in different bands is not the same spectrum.
        assert!(!n(6, 2, 20).overlaps(&n(6, 5, 20)));
    }

    #[test]
    fn congestion_separates_co_channel_from_overlap() {
        let w = WifiInfo {
            channel: "6 (2GHz, 20MHz)".into(),
            neighbours: vec![
                Neighbour {
                    channel: 6,
                    band_ghz: 2,
                    width_mhz: 20,
                }, // co-channel
                Neighbour {
                    channel: 8,
                    band_ghz: 2,
                    width_mhz: 20,
                }, // overlapping
                Neighbour {
                    channel: 11,
                    band_ghz: 2,
                    width_mhz: 20,
                }, // clear
                Neighbour {
                    channel: 44,
                    band_ghz: 5,
                    width_mhz: 80,
                }, // other band
            ],
            ..Default::default()
        };
        let c = w.congestion().unwrap();
        assert_eq!(c.co_channel, 1);
        assert_eq!(c.overlapping, 1);
        assert_eq!(c.total, 4);

        // Without a known channel there is nothing to be congested relative to.
        assert!(WifiInfo::default().congestion().is_none());
    }

    #[test]
    fn loss_pct_counts_window() {
        let mut t = TargetStat::new("t".into(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        t.record_reply(10.0);
        t.record_loss();
        t.record_reply(12.0);
        t.record_loss();
        assert_eq!(t.loss_pct(), 50.0);
    }
}

/// Which panel currently has focus (for future keyboard interactions).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Panel {
    Quality,
    Bandwidth,
    NetInfo,
    Vitals,
}

/// Keyboard input mode: normal navigation vs. modal text entry.
#[derive(Clone, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    /// Typing a new ICMP target (IP or DNS name).
    AddTarget,
}

/// An in-progress session recording.
#[derive(Clone)]
pub struct LogStatus {
    pub path: std::path::PathBuf,
    /// Rows written so far.
    pub rows: u64,
    pub started: Instant,
}

/// Root shared state.
pub struct AppState {
    pub targets: Vec<TargetStat>,
    pub throughput: Throughput,
    pub speedtest: SpeedTest,
    pub netinfo: NetInfo,
    /// Per-resolver DNS responsiveness, in the order the interface reports them.
    pub dns: Vec<DnsProbe>,
    pub signal: SignalState,
    pub vitals: Vitals,
    pub focus: Panel,
    /// When set, the focused panel is drawn full-screen instead of the 2x2 grid.
    pub fullscreen: bool,
    pub speedtest_enabled: bool,
    /// Available speed-test provider display names (e.g. "Cloudflare", "M-Lab").
    pub speedtest_provider_names: Vec<String>,
    /// Index of the selected provider into `speedtest_provider_names`.
    pub speedtest_provider_idx: usize,
    /// Recent speed-test results (oldest → newest), persisted to disk.
    pub speed_history: Vec<crate::store::SpeedRecord>,
    /// How many results are stored on disk, which can exceed what is loaded.
    pub speed_total: usize,
    /// Top processes by current network throughput (highest first).
    pub processes: Vec<ProcBandwidth>,
    /// Availability of per-process attribution on this platform.
    pub proc_status: ProcStatus,
    /// Column cursor over the top-talkers header (0=proc,1=down,2=up,3=total,4=retx).
    pub bw_col: usize,
    /// Active sort of top talkers: (column, descending). None = default order.
    pub bw_sort: Option<(usize, bool)>,

    // --- Connection Quality interaction ---
    /// Cursor over the target list (Quality panel).
    pub selected: usize,
    /// Target index whose latency history drives the sparkline.
    pub graph_target: usize,
    /// Smoothing/stats window in seconds (cycled with 'w').
    pub window_secs: u64,
    /// Samples per second (1000 / ping interval); converts window to samples.
    pub samples_per_sec: f64,
    /// Column cursor over the target table (0=target,1=last,2=avg,3=p95,4=max,5=loss).
    pub q_col: usize,
    /// Active target sort: (column, descending). None = insertion order.
    pub q_sort: Option<(usize, bool)>,
    /// Traceroute result for the current target, when requested.
    pub traceroute: Option<Traceroute>,
    /// Continuous per-hop monitor, when running.
    pub hop_monitor: Option<HopMonitor>,
    /// Which chart the panel is showing.
    pub quality_view: QualityView,
    /// Cursor location within the focused panel (cycled with 'n').
    pub sub_pane: SubPane,
    /// Cursor into `speed_history`, newest-first, for the Bandwidth panel.
    pub speed_sel: usize,
    /// When 'r' was last pressed, for a transient "re-probing" note.
    pub refresh_at: Option<Instant>,
    /// Bumped by the netinfo collector whenever [`NetInfo::identity`] changes.
    /// Collectors whose results depend on the network watch this and rebuild.
    pub net_change_seq: u64,

    // --- Modal / global UI state ---
    pub input_mode: InputMode,
    pub input_buffer: String,
    /// Optional transient status/error message (e.g. failed DNS lookup).
    pub notice: Option<String>,
    /// Auto-refresh paused: the periodic redraw is suppressed.
    pub paused: bool,
    /// Help overlay visible.
    pub show_help: bool,
    /// External tools absent from this machine: (name, what it provides, how to
    /// install). Probed once at startup so failures can be explained precisely.
    pub missing_tools: Vec<(&'static str, &'static str, &'static str)>,
    /// Set by the UI to ask the logger to start/stop; the logger owns the file.
    pub logging_requested: bool,
    /// Present while a recording is actually open.
    pub log: Option<LogStatus>,

    pub should_quit: bool,
    pub started: Instant,
}

impl AppState {
    pub fn new(targets: Vec<TargetStat>) -> Self {
        Self {
            targets,
            throughput: Throughput::default(),
            speedtest: SpeedTest::default(),
            netinfo: NetInfo::default(),
            dns: Vec::new(),
            signal: SignalState::default(),
            vitals: Vitals::default(),
            focus: Panel::Quality,
            fullscreen: false,
            speedtest_enabled: true,
            speedtest_provider_names: Vec::new(),
            speedtest_provider_idx: 0,
            speed_history: Vec::new(),
            speed_total: 0,
            processes: Vec::new(),
            proc_status: ProcStatus::Probing,
            bw_col: 1,
            bw_sort: None,
            selected: 0,
            graph_target: 0,
            window_secs: 60,
            samples_per_sec: 1.0,
            q_col: 0,
            q_sort: None,
            traceroute: None,
            hop_monitor: None,
            quality_view: QualityView::Graph,
            sub_pane: SubPane::Primary,
            speed_sel: 0,
            refresh_at: None,
            net_change_seq: 0,
            input_mode: InputMode::Normal,
            input_buffer: String::new(),
            notice: None,
            paused: false,
            show_help: false,
            missing_tools: Vec::new(),
            logging_requested: false,
            log: None,
            should_quit: false,
            started: Instant::now(),
        }
    }

    /// Whether the focused panel currently offers a second cursor pane, so 'n'
    /// is a no-op rather than a confusing dead key elsewhere.
    pub fn has_sub_pane(&self) -> bool {
        match self.focus {
            Panel::Quality => {
                self.quality_view == QualityView::HopMonitor && self.hop_monitor.is_some()
            }
            // Available whenever both panes are drawn; an empty history is
            // still a pane you can focus and watch fill up.
            Panel::Bandwidth => self.fullscreen,
            _ => false,
        }
    }

    /// The hop the monitor cursor is on, when that pane holds the cursor.
    pub fn selected_hop(&self) -> Option<&MonitoredHop> {
        if self.sub_pane != SubPane::Secondary {
            return None;
        }
        self.hop_monitor.as_ref()?.hops.get(
            self.hop_monitor
                .as_ref()
                .map(|m| m.selected)
                .unwrap_or_default(),
        )
    }

    /// Number of recent samples covered by the current window.
    pub fn window_samples(&self) -> usize {
        ((self.window_secs as f64 * self.samples_per_sec).round() as usize).max(1)
    }

    /// Cycle the stats window: 30s → 60s → 300s → 30s.
    pub fn cycle_window(&mut self) {
        self.window_secs = match self.window_secs {
            w if w < 60 => 60,
            w if w < 300 => 300,
            _ => 30,
        };
    }

    /// Display order of target indices, honouring the active sort. Indices stay
    /// stable (ping tasks reference them); only the display order changes.
    pub fn quality_order(&self) -> Vec<usize> {
        let mut order: Vec<usize> = (0..self.targets.len()).collect();
        let Some((col, desc)) = self.q_sort else {
            return order;
        };
        let n = self.window_samples();
        // Sort key: missing latency → +∞ so dead targets rank "worst".
        let key = |t: &TargetStat| -> f64 {
            let st = t.stats(n);
            match col {
                1 => t.last_rtt_ms.unwrap_or(f64::INFINITY),
                2 => st.mean.unwrap_or(f64::INFINITY),
                3 => st.p95.unwrap_or(f64::INFINITY),
                4 => st.max.unwrap_or(f64::INFINITY),
                5 => t.loss_pct(),
                _ => 0.0,
            }
        };
        order.sort_by(|&a, &b| {
            let ta = &self.targets[a];
            let tb = &self.targets[b];
            if col == 0 {
                // Name sort keeps auto-discovered targets grouped together
                // (gateway first, then hops in discovery order), unaffected by
                // the sort direction; only the rest sorts alphabetically.
                return match (ta.discovered, tb.discovered) {
                    (true, true) => ta.id.cmp(&tb.id),
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    (false, false) => {
                        let o = ta.label.to_lowercase().cmp(&tb.label.to_lowercase());
                        if desc { o.reverse() } else { o }
                    }
                };
            }
            let o = key(ta).total_cmp(&key(tb));
            if desc { o.reverse() } else { o }
        });
        order
    }
}
