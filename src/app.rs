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

/// Whether a target serves HTTP, learned by probing. Absence of a web server
/// is a fact, not a fault: only a target that has *demonstrated* a web service
/// is ever judged on it.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum WebStatus {
    /// Not yet classified.
    #[default]
    Unknown,
    /// Answered HTTP at least once — probed on a slow cadence from then on.
    Web,
    /// Connection actively refused: reachable, but nothing listens. Quiet "—".
    NoService,
    /// TCP times out while ICMP answers: something drops web traffic silently.
    Filtered,
}

impl WebStatus {
    pub fn label(self) -> &'static str {
        match self {
            WebStatus::Unknown => "unknown",
            WebStatus::Web => "web",
            WebStatus::NoService => "no-service",
            WebStatus::Filtered => "filtered",
        }
    }
}

/// Per-target HTTP(S) reachability and time-to-first-byte. A latency
/// instrument, not a security check: any HTTP status counts as "up".
#[derive(Clone, Default)]
pub struct WebProbe {
    pub status: WebStatus,
    /// TTFB of the most recent successful probe.
    pub last_ttfb_ms: Option<f64>,
    pub hist: History,
    /// Consecutive failed probes while `status == Web` — the "it answered
    /// before and stopped" signal the verdict watches.
    pub fails: u32,
}

#[derive(Clone)]
pub struct TargetStat {
    /// Stable identity, independent of index in the targets vec.
    pub id: u64,
    /// True when auto-added by hop discovery at startup.
    pub discovered: bool,
    pub label: String,
    pub addr: IpAddr,
    /// The name this target was added as, when it was a name. Kept because a
    /// CDN answers differently per network (re-resolved on change), and HTTPS
    /// needs the hostname for SNI and certificates.
    pub hostname: Option<String>,
    /// HTTP(S) capability and timing, learned by the web prober.
    pub web: WebProbe,
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
            hostname: None,
            web: WebProbe::default(),
            last_rtt_ms: None,
            jitter_ms: 0.0,
            min_ever_ms: None,
            sent: 0,
            recv: 0,
            window: VecDeque::with_capacity(WINDOW),
            history: History::new(HISTORY),
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

    /// Clear all accumulated stats (keeps identity, label, address, and the
    /// learned web *capability* — whether a server exists doesn't reset, but
    /// its timings do).
    pub fn reset(&mut self) {
        self.last_rtt_ms = None;
        self.jitter_ms = 0.0;
        self.min_ever_ms = None;
        self.sent = 0;
        self.recv = 0;
        self.window.clear();
        self.history.data.clear();
        self.web.hist.data.clear();
        self.web.last_ttfb_ms = None;
        self.web.fails = 0;
    }

    /// True for auto-discovered mid-path hops ("hop 3→1.1.1.1") — routers, not
    /// destinations: the web prober skips them and the UI says so instead of
    /// "checking…" forever.
    pub fn is_path_hop(&self) -> bool {
        self.discovered && self.label.starts_with("hop ")
    }

    /// The hop's distance for a discovered path hop ("hop 3→1.1.1.1" → 3);
    /// 1 for the discovered gateway; `None` for anything else.
    pub fn hop_ttl(&self) -> Option<u8> {
        if !self.discovered {
            return None;
        }
        if self.label == "gateway" {
            return Some(1);
        }
        self.label
            .strip_prefix("hop ")?
            .split(['→', ' '])
            .next()?
            .parse()
            .ok()
    }

    /// Packet loss over the sliding window, as a percentage.
    pub fn loss_pct(&self) -> f64 {
        if self.window.is_empty() {
            return 0.0;
        }
        let lost = self.window.iter().filter(|ok| !**ok).count();
        lost as f64 / self.window.len() as f64 * 100.0
    }

    /// Loss over only the most recent `n` outcomes. The full window takes
    /// [`WINDOW`] seconds to reflect an outage, far too slow for *detection*;
    /// display keeps using [`Self::loss_pct`].
    pub fn recent_loss_pct(&self, n: usize) -> f64 {
        let take = n.min(self.window.len());
        if take == 0 {
            return 0.0;
        }
        let lost = self
            .window
            .iter()
            .rev()
            .take(take)
            .filter(|ok| !**ok)
            .count();
        lost as f64 / take as f64 * 100.0
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

/// Latency samples kept per target. Bounds memory, and with it the longest
/// window the statistics can actually cover — see [`AppState::window_samples`].
const HISTORY: usize = 1000;

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
    /// No source on this platform at all.
    Unsupported,
    /// A source exists but the process cannot reach it — Windows gates its
    /// only one behind an ETW session. Distinct from `Unsupported` because it
    /// is something the user can actually do something about.
    NeedsPrivilege,
}

/// One process's network use, accumulated over the session (so the table
/// answers "what has been using the link", not "who happened to move bytes in
/// the last two seconds"), plus its rate this interval and a connection-health
/// signal. A process that has gone quiet — or exited — keeps its row.
#[derive(Clone, Default)]
pub struct ProcBandwidth {
    pub name: String,
    pub pid: u32,
    /// Bytes received this session.
    pub down_bytes: u64,
    /// Bytes sent this session.
    pub up_bytes: u64,
    /// `down_bytes + up_bytes`, kept for sorting and display.
    pub total_bytes: u64,
    /// This process's share of all attributed traffic this session, 0–1.
    pub share: f64,
    /// TCP retransmissions this session.
    pub retx: u64,
    /// Rates this interval; zero when idle.
    pub down_bps: f64,
    pub up_bps: f64,
    /// TCP retransmissions per second this interval (connection-health signal).
    pub retx_per_sec: f64,
}

/// Bandwidth to one remote address, summed over every socket and process
/// talking to it and accumulated over the session — the "which address is
/// eating my link" view.
#[derive(Clone)]
pub struct RemoteBandwidth {
    pub addr: IpAddr,
    /// The port that has carried most of the bytes this session, when
    /// connections to this address used more than one.
    pub port: u16,
    /// Number of distinct ports seen this session; more than one means `port`
    /// is only the biggest.
    pub ports: usize,
    /// The process that has moved most bytes to this address this session.
    pub process: String,
    /// Bytes received from / sent to this address this session.
    pub down_bytes: u64,
    pub up_bytes: u64,
    /// `down_bytes + up_bytes`.
    pub total_bytes: u64,
    /// This address's share of all attributed traffic this session, 0–1.
    pub share: f64,
    /// Rates this interval; zero when idle.
    pub down_bps: f64,
    pub up_bps: f64,
}

/// Which list the bandwidth panel's talkers table shows.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum BwView {
    #[default]
    Processes,
    Remotes,
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

/// Who owns an address: the answer to "whose router is dropping my packets?".
/// `fields` come from RDAP (structured); `raw` from the system `whois` when
/// RDAP was unreachable. `running` while the query is in flight.
#[derive(Clone)]
pub struct Whois {
    pub addr: IpAddr,
    pub running: bool,
    pub fields: Vec<(String, String)>,
    pub raw: Vec<String>,
    /// Which registry / tool answered, e.g. "rdap.arin.net" or "whois".
    pub source: String,
    pub error: Option<String>,
}

/// A hop under continuous measurement. Reuses [`TargetStat`], so hops get the
/// same distribution / jitter / loss maths as ordinary targets.
#[derive(Clone)]
pub struct MonitoredHop {
    /// The hop's distance, or [`MonitoredHop::DEST_TTL`] for the destination
    /// row appended when the walk never reached it.
    pub ttl: u8,
    /// `None` for a hop that never answered discovery (a `*` in traceroute).
    pub addr: Option<IpAddr>,
    /// Live statistics, present once the hop has an address to probe.
    pub stat: Option<TargetStat>,
}

impl MonitoredHop {
    /// Sentinel ttl for the destination when the walk did not reach it: some
    /// edges (Fastly, for one) drop UDP probes but answer ping, and the whole
    /// point of the view is comparing each hop's loss with the endpoint's.
    /// Sorts after every real hop, and is pruned the moment a re-walk lands.
    pub const DEST_TTL: u8 = u8::MAX;

    pub fn is_dest_placeholder(&self) -> bool {
        self.ttl == Self::DEST_TTL
    }
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
    /// OS interface index — the scope id a link-local (fe80::) address needs
    /// to be routable, which is exactly how carrier hotspots hand out DNS.
    pub iface_index: u32,
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
    /// The interface MTU, when the OS reports it — what the path-MTU probe
    /// compares against.
    pub mtu: Option<u32>,
    /// The IPv6 default gateway, when there is one; empty otherwise. Kept apart
    /// from `gateway_ip` (v4 first) so v6 reachability can be judged on its own.
    pub gateway_ipv6: String,
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

    /// Whether `addr` sits on this machine's own LAN — inside one of the
    /// interface's own subnets, or a loopback / link-local address. Such a
    /// target says nothing about the internet and is judged separately.
    pub fn is_lan_addr(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(a) => {
                if a.is_loopback() || a.is_link_local() {
                    return true;
                }
                self.ipv4.iter().any(|cidr| {
                    let (ip, len) = match cidr.split_once('/') {
                        Some((ip, len)) => (ip, len.parse::<u32>().unwrap_or(32)),
                        // A bare address: assume the conventional /24.
                        None => (cidr.as_str(), 24),
                    };
                    let Ok(own) = ip.parse::<std::net::Ipv4Addr>() else {
                        return false;
                    };
                    let mask = if len == 0 {
                        0
                    } else {
                        u32::MAX << (32 - len.min(32))
                    };
                    (u32::from(own) & mask) == (u32::from(a) & mask)
                })
            }
            IpAddr::V6(a) => {
                if a.is_loopback() || (a.segments()[0] & 0xffc0) == 0xfe80 {
                    return true;
                }
                self.ipv6.iter().any(|cidr| {
                    let (ip, len) = match cidr.split_once('/') {
                        Some((ip, len)) => (ip, len.parse::<u32>().unwrap_or(64)),
                        None => (cidr.as_str(), 64),
                    };
                    let Ok(own) = ip.parse::<std::net::Ipv6Addr>() else {
                        return false;
                    };
                    let len = len.min(128);
                    let mask = if len == 0 {
                        0
                    } else {
                        u128::MAX << (128 - len)
                    };
                    (u128::from(own) & mask) == (u128::from(a) & mask)
                })
            }
        }
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
    /// Cumulative counters for the session, for "ok/sent" style display.
    pub sent: u64,
    pub ok: u64,
    /// The last few outcomes (answered or not), newest last — what the
    /// analysis judges on, so a resolver that died a minute ago reads as
    /// failing now and one that recovered stops.
    pub window: VecDeque<bool>,
    /// Round trips of the answered queries in that same recent window.
    pub recent: VecDeque<f64>,
    /// Why the last query failed ("SERVFAIL", "timeout"), else empty.
    pub status: String,
    /// True for the configured public reference resolver, probed alongside
    /// the system ones for contrast — not one of this network's resolvers.
    pub reference: bool,
    /// The hijack check's latest verdict: `Some(true)` when the resolver
    /// answered a name that cannot exist with an address.
    pub hijack: Option<bool>,
}

/// Outcomes kept per resolver for the recent judgement: at the default 5 s
/// probe interval, one minute.
pub const DNS_RECENT: usize = 12;

impl DnsProbe {
    pub fn new(server: IpAddr) -> Self {
        Self {
            server,
            last_ms: None,
            hist: History::new(300),
            sent: 0,
            ok: 0,
            window: VecDeque::with_capacity(DNS_RECENT),
            recent: VecDeque::with_capacity(DNS_RECENT),
            status: String::new(),
            reference: false,
            hijack: None,
        }
    }

    /// Record one query's outcome.
    pub fn record(&mut self, rtt_ms: Option<f64>) {
        self.sent += 1;
        if self.window.len() == DNS_RECENT {
            self.window.pop_front();
        }
        self.window.push_back(rtt_ms.is_some());
        if let Some(ms) = rtt_ms {
            self.ok += 1;
            self.hist.push(ms);
            if self.recent.len() == DNS_RECENT {
                self.recent.pop_front();
            }
            self.recent.push_back(ms);
        }
        self.last_ms = rtt_ms;
    }

    /// How many recent outcomes there are to judge on.
    pub fn recent_len(&self) -> usize {
        self.window.len()
    }

    /// Mean round trip over the recent window only.
    pub fn recent_mean_ms(&self) -> Option<f64> {
        if self.recent.is_empty() {
            return None;
        }
        Some(self.recent.iter().sum::<f64>() / self.recent.len() as f64)
    }

    /// Mean round trip over the retained history.
    pub fn mean_ms(&self) -> Option<f64> {
        if self.hist.data.is_empty() {
            return None;
        }
        Some(self.hist.data.iter().sum::<f64>() / self.hist.data.len() as f64)
    }

    /// Share of *recent* queries that went unanswered, as a percentage.
    pub fn fail_pct(&self) -> f64 {
        if self.window.is_empty() {
            return 0.0;
        }
        let failed = self.window.iter().filter(|ok| !**ok).count();
        failed as f64 / self.window.len() as f64 * 100.0
    }
}

/// One address family's HTTP reachability probe result.
#[derive(Clone, Default, PartialEq, Debug)]
pub enum FamilyProbe {
    #[default]
    NotRun,
    /// This family isn't configured here (e.g. no global IPv6 address) — a
    /// v4-only LAN must never read as "v6 broken".
    NotApplicable,
    /// Expected answer received; round trip in ms.
    Ok(f64),
    /// Something intercepted the request — a portal sign-in page, usually.
    /// Carries the redirect target when there was one.
    Captive(Option<String>),
    /// Connect/timeout/protocol failure, with a short reason.
    Fail(String),
}

/// HTTP-layer reachability: the internet as a *browser* experiences it, which
/// ICMP alone cannot see (captive portals, proxies, broken IPv6).
#[derive(Clone, Default)]
pub struct HttpState {
    /// Provider name the primary probe used (e.g. "Apple").
    pub provider: String,
    pub v4: FamilyProbe,
    pub v6: FamilyProbe,
    /// Set when the second-opinion endpoint had to arbitrate.
    pub note: Option<String>,
    /// The same check made *through* the configured manual proxy, when there
    /// is one — what a browser would experience. `NotRun` otherwise.
    pub via_proxy: FamilyProbe,
    /// Round-trip history per family (successful probes only), for the web
    /// graph in the Connection Quality panel.
    pub v4_hist: History,
    pub v6_hist: History,
}

/// A system-level web proxy configuration. See [`crate::collectors::proxy`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyConfig {
    pub kind: ProxyKind,
    /// Where it was read from ("System Settings", "environment").
    pub source: String,
    /// Hosts that bypass it, as the OS lists them.
    pub bypass: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyKind {
    /// Fixed proxies, as `host:port` (or a `socks5://` URL).
    Manual { http: String, https: String },
    /// A PAC script at this URL decides per request — not evaluable here.
    Pac(String),
    /// Auto-discovery (WPAD): the network names its own proxy via DHCP/DNS.
    /// (Only the macOS and GNOME readers can report it.)
    #[cfg_attr(windows, allow(dead_code))]
    Wpad,
}

impl ProxyConfig {
    /// One line for the panel: "proxy.corp:8080 (System Settings)".
    pub fn describe(&self) -> String {
        match &self.kind {
            ProxyKind::Manual { http, https } if http == https => {
                format!("{http} ({})", self.source)
            }
            ProxyKind::Manual { http, https } => {
                format!("http {http} · https {https} ({})", self.source)
            }
            ProxyKind::Pac(url) => format!("PAC {url} ({})", self.source),
            ProxyKind::Wpad => format!("auto-discovery / WPAD ({})", self.source),
        }
    }

    /// The URL to hand reqwest for the HTTPS path, when the proxy is fixed.
    pub fn https_url(&self) -> Option<String> {
        match &self.kind {
            ProxyKind::Manual { https, .. } if !https.is_empty() => {
                Some(if https.contains("://") {
                    https.clone()
                } else {
                    format!("http://{https}")
                })
            }
            _ => None,
        }
    }
}

/// One entry in the interface / network history: something about how this
/// machine is attached changed. The events overlay has the one-line version;
/// this keeps the before/after detail so "what was the signal when it roamed"
/// or "which address did we have on the old network" is answerable later.
#[derive(Clone, Debug)]
pub struct NetChange {
    /// Unix timestamp (seconds).
    pub at: i64,
    pub kind: NetChangeKind,
    /// The interface concerned ("en0", "wlan0", "utun4").
    pub iface: String,
    /// One line, as shown in the list.
    pub summary: String,
    /// The detail pane: before/after facts, one per line.
    pub detail: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NetChangeKind {
    /// An interface appeared / vanished.
    IfaceUp,
    IfaceDown,
    /// The default route moved to a different network or interface.
    NetworkChanged,
    /// Default route lost / regained.
    LinkLost,
    LinkRestored,
    /// Associated to a different SSID.
    WifiJoined,
    /// Same SSID, different access point.
    WifiRoamed,
    /// Addresses / gateway / DNS changed without the network identity moving
    /// (a DHCP renewal handing out something new, a resolver push).
    AddressChanged,
    VpnUp,
    VpnDown,
}

impl NetChangeKind {
    pub fn label(self) -> &'static str {
        match self {
            NetChangeKind::IfaceUp => "iface up",
            NetChangeKind::IfaceDown => "iface down",
            NetChangeKind::NetworkChanged => "network",
            NetChangeKind::LinkLost => "link lost",
            NetChangeKind::LinkRestored => "link back",
            NetChangeKind::WifiJoined => "wifi join",
            NetChangeKind::WifiRoamed => "wifi roam",
            NetChangeKind::AddressChanged => "address",
            NetChangeKind::VpnUp => "vpn up",
            NetChangeKind::VpnDown => "vpn down",
        }
    }
}

/// Bounded history length.
pub const NET_HISTORY_CAP: usize = 200;

/// What the path-MTU probe found. See [`crate::collectors::pmtu`].
#[derive(Clone, Debug)]
pub struct PmtuResult {
    pub target: IpAddr,
    pub iface_mtu: Option<u32>,
    /// Largest packet answered with DF set; `None` when not even the floor was.
    pub path_mtu: Option<u32>,
    /// A full-size probe vanished twice with nothing telling the kernel why:
    /// fragmentation-needed messages are not getting back.
    pub blackhole: bool,
    /// The kernel learned a smaller MTU from an ICMP message — discovery works.
    pub pmtud_works: bool,
}

/// Whether the system clock agrees with the world. See
/// [`crate::collectors::clock`].
#[derive(Clone, Default)]
pub struct ClockState {
    /// Signed offset from an SNTP exchange, ms; positive = local clock ahead.
    pub ntp_offset_ms: Option<f64>,
    /// Why the last NTP exchange failed (UDP 123 filtered, typically).
    pub ntp_error: Option<String>,
    /// The last few coarse (±1 s) offsets from the `Date` header of the HTTP
    /// reachability probe — the fallback when NTP is blocked. Kept as a short
    /// series so one odd answer (a proxy or portal with its own idea of the
    /// time, an interception during a network change) is never believed on
    /// its own: readings must agree with each other.
    pub http_offsets: VecDeque<f64>,
    /// True once any check has run, so "unknown" can be told from "fine".
    pub checked: bool,
}

/// How many HTTP `Date` readings are kept, and how closely they must agree.
pub const HTTP_SKEW_KEEP: usize = 3;
pub const HTTP_SKEW_AGREE_MS: f64 = 5_000.0;

impl ClockState {
    /// The best available offset: NTP when it answered, else the HTTP reading.
    pub fn offset_ms(&self) -> Option<f64> {
        self.ntp_offset_ms.or_else(|| self.http_offset_ms())
    }

    /// The HTTP `Date` reading, when at least two recent answers agree: their
    /// median. A single reading, or readings that disagree, say nothing.
    pub fn http_offset_ms(&self) -> Option<f64> {
        if self.http_offsets.len() < 2 {
            return None;
        }
        let mut v: Vec<f64> = self.http_offsets.iter().copied().collect();
        v.sort_by(f64::total_cmp);
        let spread = v[v.len() - 1] - v[0];
        if spread > HTTP_SKEW_AGREE_MS {
            return None;
        }
        Some(v[v.len() / 2])
    }

    pub fn record_http_skew(&mut self, ms: f64) {
        if self.http_offsets.len() == HTTP_SKEW_KEEP {
            self.http_offsets.pop_front();
        }
        self.http_offsets.push_back(ms);
        self.checked = true;
    }
    pub fn source(&self) -> &'static str {
        if self.ntp_offset_ms.is_some() {
            "ntp"
        } else {
            "http date"
        }
    }
}

/// Live Wi-Fi signal, sampled frequently (CoreWLAN on macOS) for graphing.
#[derive(Clone, Default)]
pub struct SignalState {
    pub present: bool,
    pub rssi_dbm: i32,
    /// `None` where the platform measures no noise floor (Windows).
    pub noise_dbm: Option<i32>,
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
    /// Per-core usage in core order. A single pegged core stalls a network path
    /// while the global average looks idle, so the detail earns its space.
    pub cores: Vec<f32>,
    /// 1 / 5 / 15-minute load average.
    pub load: (f64, f64, f64),
    /// Share of RAM that is *unavailable*, 0..100. On macOS "used" sits near
    /// total because of caching, so used/total reads alarming and means little;
    /// what is available is the number that tracks feeling slow.
    pub mem_pressure_pct: f32,
    pub pressure_hist: History,
    pub swap_used: u64,
    pub swap_total: u64,
    /// Thermal / power summary, platform-specific. Empty when unknown.
    pub thermal: String,
    /// True when the OS reports thermal or performance throttling. Throttling
    /// tanks throughput while CPU looks idle, which is otherwise baffling.
    pub throttled: bool,
    /// "AC Power" / "Battery Power" where known.
    pub power_source: String,
}

impl Vitals {
    /// Number of cores currently reporting.
    pub fn core_count(&self) -> usize {
        self.cores.len()
    }

    /// Busiest single core, as a zero-based index. Display adds one —
    /// people count cores from 1.
    pub fn hottest_core(&self) -> Option<(usize, f32)> {
        self.cores
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.total_cmp(b.1))
            .map(|(i, v)| (i, *v))
    }
}

/// Interface error and drop counters, as rates. Rising errors with normal CPU
/// point at the link itself — a duplex mismatch, a bad cable, a full ring
/// buffer — which nothing else in octomon would reveal.
#[derive(Clone, Default)]
pub struct LinkErrors {
    pub iface: String,
    pub rx_err_per_sec: f64,
    pub tx_err_per_sec: f64,
    /// Cumulative since octomon started, so a brief burst stays visible.
    pub rx_err_total: u64,
    pub tx_err_total: u64,
    pub rx_packets_per_sec: f64,
    pub tx_packets_per_sec: f64,
}

impl LinkErrors {
    /// Errors as a share of packets carried — a rate alone means nothing
    /// without knowing whether the link was busy.
    pub fn error_pct(&self) -> f64 {
        let packets = self.rx_packets_per_sec + self.tx_packets_per_sec;
        let errors = self.rx_err_per_sec + self.tx_err_per_sec;
        if packets + errors <= 0.0 {
            return 0.0;
        }
        errors / (packets + errors) * 100.0
    }
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
    fn the_window_ladder_only_ever_widens() {
        let mut s = AppState::new(vec![]);
        assert_eq!(s.window_secs, 60);
        s.cycle_window();
        assert_eq!(s.window_secs, 300);
        s.cycle_window();
        assert_eq!(s.window_secs, 900);
        // Wraps back to the start rather than stepping down mid-cycle.
        s.cycle_window();
        assert_eq!(s.window_secs, 60);
    }

    #[test]
    fn the_window_cannot_claim_more_history_than_is_kept() {
        let mut s = AppState::new(vec![]);
        // One sample a second: the whole ladder fits inside the buffer.
        s.samples_per_sec = 1.0;
        s.window_secs = 900;
        assert_eq!(s.window_samples(), 900);
        assert!(!s.window_is_capped());

        // Four a second is what --ping-interval 250 gives, and 900s of that is
        // 3600 samples — far more than a target keeps.
        s.samples_per_sec = 4.0;
        assert_eq!(s.window_samples(), HISTORY);
        assert!(s.window_is_capped(), "the UI has to be able to say so");
    }

    #[test]
    fn the_window_label_reads_in_minutes() {
        let mut s = AppState::new(vec![]);
        s.window_secs = 60;
        assert_eq!(s.window_label(), "1m");
        s.window_secs = 900;
        assert_eq!(s.window_label(), "15m");
        s.window_secs = 45;
        assert_eq!(s.window_label(), "45s");
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
    fn recent_loss_reacts_faster_than_the_display_window() {
        let mut t = TargetStat::new("t".into(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        for _ in 0..80 {
            t.record_reply(10.0);
        }
        for _ in 0..20 {
            t.record_loss();
        }
        // The display window dilutes the outage; detection must not.
        assert_eq!(t.loss_pct(), 20.0);
        assert_eq!(t.recent_loss_pct(20), 100.0);
        assert_eq!(t.recent_loss_pct(0), 0.0, "empty ask, no division by zero");
    }

    #[test]
    fn the_timeline_is_capped_but_the_total_keeps_counting() {
        let mut s = AppState::new(vec![]);
        for i in 0..(EVENTS_CAP + 10) {
            s.push_event(
                crate::verdict::Severity::Info,
                EventCategory::Network,
                format!("event {i}"),
            );
        }
        assert_eq!(s.events.len(), EVENTS_CAP);
        assert_eq!(s.events_total, (EVENTS_CAP + 10) as u64);
        // Oldest evicted, newest kept.
        assert_eq!(s.events.front().unwrap().message, "event 10");
        assert_eq!(
            s.events.back().unwrap().message,
            format!("event {}", EVENTS_CAP + 9)
        );
    }

    #[test]
    fn notice_event_is_both_transient_and_durable() {
        let mut s = AppState::new(vec![]);
        s.notice_event(
            crate::verdict::Severity::Info,
            EventCategory::Network,
            "network changed → en7".into(),
        );
        assert_eq!(s.notice.as_deref(), Some("network changed → en7"));
        assert_eq!(s.events.len(), 1);
        // The notice dies with the next key press; the event survives it.
        s.notice = None;
        assert_eq!(s.events.back().unwrap().message, "network changed → en7");
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
    /// Typing a name for the current network ("Home", "Office").
    NameNetwork,
}

/// Which full-screen overlay is up, if any. One at a time; the order here is
/// also the precedence at startup (setup problems before anything else).
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum Overlay {
    #[default]
    None,
    /// Startup problems worth interrupting for (missing tools, no ICMP).
    Startup,
    Help,
    /// The verdict's triage ladder: why the one-liner says what it says.
    Triage,
    /// The session timeline: what changed and when.
    Events,
    /// First-run welcome: what octomon answers and that it learns baselines.
    Explainer,
    /// Every stored network location and its learned baseline.
    Locations,
    /// Who owns the selected address (RDAP / whois).
    Whois,
    /// Outbound reachability by port — which protocols this network lets out.
    Egress,
}

/// Category of a timeline event, for the overlay and the CSV export.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EventCategory {
    /// An analysis finding raised or cleared — the flagship source: these give
    /// "loss spike started / ended after 3m" for free.
    Analysis,
    Network,
    Wifi,
    Speedtest,
    Path,
    Logging,
}

impl EventCategory {
    pub fn label(self) -> &'static str {
        match self {
            EventCategory::Analysis => "analysis",
            EventCategory::Network => "network",
            EventCategory::Wifi => "wifi",
            EventCategory::Speedtest => "speedtest",
            EventCategory::Path => "path",
            EventCategory::Logging => "logging",
        }
    }
}

/// One entry in the session timeline. People open a diagnostic tool *after*
/// the glitch; averages hide a ten-second dropout, a transition log answers it.
#[derive(Clone)]
pub struct EventItem {
    /// Unix timestamp (seconds), like [`crate::store::SpeedRecord::at`].
    pub at: i64,
    pub severity: crate::verdict::Severity,
    pub category: EventCategory,
    pub message: String,
}

impl EventItem {
    /// Local wall-clock time for display, e.g. "21:14:03".
    pub fn when(&self) -> String {
        use chrono::{Local, TimeZone};
        Local
            .timestamp_opt(self.at, 0)
            .single()
            .map(|dt| dt.format("%H:%M:%S").to_string())
            .unwrap_or_else(|| "—".to_string())
    }
}

/// Bounded timeline length; older events fall off the front.
pub const EVENTS_CAP: usize = 500;

/// An in-progress session recording.
#[derive(Clone)]
pub struct LogStatus {
    pub path: std::path::PathBuf,
    /// Rows written so far.
    pub rows: u64,
    pub started: Instant,
}

/// Root shared state.
#[derive(Clone)]
pub struct AppState {
    pub targets: Vec<TargetStat>,
    pub throughput: Throughput,
    pub speedtest: SpeedTest,
    pub netinfo: NetInfo,
    /// Per-resolver DNS responsiveness, in the order the interface reports them.
    pub dns: Vec<DnsProbe>,
    /// HTTP-layer reachability (captive portal / broken-v6 detection).
    pub http: HttpState,
    pub clock: ClockState,
    /// Finished incidents on every network this machine has used, loaded at
    /// startup and appended as findings clear. See [`crate::history`].
    pub history: Vec<crate::history::Episode>,
    /// Why public-IP discovery failed, when it did (both endpoints tried).
    pub public_ip_error: Option<String>,
    /// The system web proxy, when one is configured.
    pub proxy: Option<ProxyConfig>,
    /// The [c] egress scan, once one has been run this session.
    pub egress: Option<crate::collectors::egress::Scan>,
    /// How this machine's attachment to the network has changed this session,
    /// newest last. Shown in the full-screen Network panel.
    pub net_history: VecDeque<NetChange>,
    /// Cursor into `net_history` (0 = newest) when that pane holds it.
    pub net_history_sel: usize,
    /// Path-MTU probe result, once it has run; and why it could not, when it
    /// could not (an OS that ignores Don't-Fragment, no UDP out).
    pub pmtu: Option<PmtuResult>,
    pub pmtu_error: Option<String>,
    pub signal: SignalState,
    pub vitals: Vitals,
    /// Error/drop counters for the default interface.
    pub link_errors: LinkErrors,
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
    /// Top processes by bytes moved this session (highest first).
    pub processes: Vec<ProcBandwidth>,
    /// Top remote addresses by bytes this session, from the same samples as
    /// `processes`.
    pub remotes: Vec<RemoteBandwidth>,
    /// Set by a panel reset; the collector clears its session aggregates on
    /// its next tick and lowers it. The lists are only a projection of those
    /// aggregates, so clearing the lists alone would bring the figures back.
    pub bw_reset: bool,
    /// Whether the talkers table lists processes or remote addresses.
    pub bw_view: BwView,
    /// Row cursor in the remotes list, as an index into `remotes` (so W and a
    /// act on the right address whatever the sort).
    pub remote_sel: usize,
    /// Row cursor in the process list, an index into `processes`. Nothing acts
    /// on a process; the cursor is what scrolls the list.
    pub proc_sel: usize,
    /// Availability of per-process attribution on this platform.
    pub proc_status: ProcStatus,
    /// Column cursor over the top-talkers header. Processes:
    /// 0=name,1=total,2=down,3=up,4=now,5=share,6=retx. Remotes:
    /// 0=remote,1=process,2=total,3=down,4=up,5=now,6=share.
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
    /// Glyphs the charts plot with. Carried here because a legacy Windows
    /// console has no braille glyphs and draws every point as an empty box.
    pub graph_marker: ratatui::symbols::Marker,
    /// Column cursor over the target table (0=target,1=last,2=avg,3=p95,4=max,5=loss).
    pub q_col: usize,
    /// Active target sort: (column, descending). None = insertion order.
    pub q_sort: Option<(usize, bool)>,
    /// Traceroute result for the current target, when requested.
    pub traceroute: Option<Traceroute>,
    /// Continuous per-hop monitor, when running.
    pub hop_monitor: Option<HopMonitor>,
    /// Registry lookup for an address (the [W] overlay), when requested.
    pub whois: Option<Whois>,
    /// Scroll offset into the whois overlay.
    pub whois_scroll: usize,
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
    /// Auto-refresh paused: the periodic redraw is suppressed, and the talkers
    /// tables stop being replaced (the collector keeps counting) so a row can
    /// be selected and acted on without it moving.
    pub paused: bool,
    /// Which full-screen overlay is up, if any.
    pub overlay: Overlay,
    /// Synthesized diagnosis: the footer one-liner and the triage ladder.
    pub verdict: crate::verdict::VerdictState,
    /// This network's learned baseline (present once the network is
    /// fingerprinted; freshly created when the network is new).
    pub baseline: Option<crate::baseline::Baseline>,
    /// Fingerprint key of the current network, for persisting the baseline.
    pub baseline_key: Option<String>,
    /// Show the first-run explainer once the startup notice is dismissed.
    pub explainer_pending: bool,
    /// Stored locations for the [L] overlay: (fingerprint key, baseline),
    /// loaded from disk when the overlay opens. `None` = still loading.
    pub locations: Option<Vec<(String, crate::baseline::Baseline)>>,
    /// Scroll offset into the locations list.
    pub locations_sel: usize,
    /// Session timeline of state transitions (oldest → newest), capped.
    pub events: VecDeque<EventItem>,
    /// Events ever pushed — exceeds `events.len()` once the cap evicts, and
    /// serves as the CSV logger's high-water mark.
    pub events_total: u64,
    /// How far back the events overlay is scrolled (0 = newest).
    pub events_scroll: usize,
    /// Set when the ICMP socket could not be opened, with guidance on the fix.
    /// Everything latency-related is dead without it.
    pub icmp_error: Option<String>,
    /// True while the machine has no default route at all — Wi-Fi off, cable
    /// out. Set and cleared by the netinfo collector; the analysis reads it so
    /// the bottom rung of the ladder can say "not connected" instead of
    /// blaming whatever failed first downstream.
    pub link_lost: bool,
    /// What is degraded by running unprivileged, when anything is.
    pub privilege_notice: Option<String>,
    /// External tools absent from this machine: (name, what it provides, how to
    /// install). Probed once at startup so failures can be explained precisely.
    pub missing_tools: Vec<(&'static str, &'static str, &'static str)>,
    /// Set by the UI to ask the logger to start/stop; the logger owns the file.
    pub logging_requested: bool,
    /// Present while a recording is actually open.
    pub log: Option<LogStatus>,
    /// Set by a key handler that changed *data* the user must see even while
    /// paused (a target added or removed, a panel reset). The UI loop takes a
    /// fresh snapshot and lowers it.
    pub refreeze: bool,

    pub should_quit: bool,
    pub started: Instant,
}

/// What the first hops say about address translation on the way out.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NatKind {
    /// Hop 2 is in 100.64.0.0/10: the ISP shares one public address among
    /// customers. Inbound connections, port forwarding and some games and VoIP
    /// setups suffer; the "public IP" is the ISP's, not the router's.
    Cgnat,
    /// Hop 2 is another private (RFC 1918) address: two NAT routers in series —
    /// an ISP box in front of the user's own, typically. Same symptoms as CGNAT
    /// but fixable at home (bridge mode on the first router).
    DoubleNat,
}

impl NatKind {
    pub fn label(self) -> &'static str {
        match self {
            NatKind::Cgnat => "CGNAT",
            NatKind::DoubleNat => "double NAT",
        }
    }
}

impl AppState {
    /// See [`NetInfo::is_lan_addr`].
    pub fn is_lan_addr(&self, addr: IpAddr) -> bool {
        self.netinfo.is_lan_addr(addr)
    }

    /// CGNAT / double NAT, read off the discovered path: the gateway is private
    /// (that is ordinary NAT) and the *next* hop is still not a public address.
    /// `None` when the path is unknown or plainly routed. Returns the kind and
    /// the hop-2 address that gave it away.
    pub fn nat_kind(&self) -> Option<(NatKind, IpAddr)> {
        let hop = |ttl: u8| {
            self.targets
                .iter()
                .find(|t| t.hop_ttl() == Some(ttl))
                .map(|t| t.addr)
        };
        let IpAddr::V4(gw) = hop(1)? else {
            return None;
        };
        let IpAddr::V4(next) = hop(2)? else {
            return None;
        };
        if !gw.is_private() {
            return None;
        }
        // 100.64.0.0/10 is reserved for carrier-grade NAT (RFC 6598).
        let shared =
            |a: std::net::Ipv4Addr| a.octets()[0] == 100 && (64..=127).contains(&a.octets()[1]);
        if shared(next) {
            Some((NatKind::Cgnat, IpAddr::V4(next)))
        } else if next.is_private() {
            Some((NatKind::DoubleNat, IpAddr::V4(next)))
        } else {
            None
        }
    }

    pub fn new(targets: Vec<TargetStat>) -> Self {
        Self {
            targets,
            throughput: Throughput::default(),
            speedtest: SpeedTest::default(),
            netinfo: NetInfo::default(),
            dns: Vec::new(),
            http: HttpState::default(),
            clock: ClockState::default(),
            history: Vec::new(),
            public_ip_error: None,
            proxy: None,
            egress: None,
            net_history: VecDeque::new(),
            net_history_sel: 0,
            pmtu: None,
            pmtu_error: None,
            signal: SignalState::default(),
            vitals: Vitals::default(),
            link_errors: LinkErrors::default(),
            focus: Panel::Quality,
            fullscreen: false,
            speedtest_enabled: true,
            speedtest_provider_names: Vec::new(),
            speedtest_provider_idx: 0,
            speed_history: Vec::new(),
            speed_total: 0,
            processes: Vec::new(),
            remotes: Vec::new(),
            bw_reset: false,
            bw_view: BwView::Processes,
            remote_sel: 0,
            proc_sel: 0,
            proc_status: ProcStatus::Probing,
            bw_col: 1,
            bw_sort: None,
            selected: 0,
            graph_target: 0,
            window_secs: 60,
            samples_per_sec: 1.0,
            graph_marker: ratatui::symbols::Marker::Braille,
            q_col: 0,
            q_sort: None,
            traceroute: None,
            hop_monitor: None,
            whois: None,
            whois_scroll: 0,
            quality_view: QualityView::Graph,
            sub_pane: SubPane::Primary,
            speed_sel: 0,
            refresh_at: None,
            net_change_seq: 0,
            input_mode: InputMode::Normal,
            input_buffer: String::new(),
            notice: None,
            paused: false,
            overlay: Overlay::None,
            verdict: crate::verdict::VerdictState::default(),
            link_lost: false,
            baseline: None,
            baseline_key: None,
            explainer_pending: false,
            locations: None,
            locations_sel: 0,
            events: VecDeque::new(),
            events_total: 0,
            events_scroll: 0,
            icmp_error: None,
            privilege_notice: None,
            missing_tools: Vec::new(),
            logging_requested: false,
            log: None,
            refreeze: false,
            should_quit: false,
            started: Instant::now(),
        }
    }

    /// Bring a paused snapshot up to date with everything the user drives.
    ///
    /// While paused the screen is drawn from a copy taken at the moment of
    /// pausing, so nothing measured moves — collectors keep writing to the
    /// live state, invisibly. But the user is still at the keyboard: cursors,
    /// focus, overlays and text entry must respond, and anything they asked
    /// for by hand (a whois, a traceroute, a speed test) must arrive. Those
    /// fields are copied across before every draw; the measurements are not.
    pub fn sync_interactive_from(&mut self, live: &AppState) {
        // Navigation and view.
        self.focus = live.focus;
        self.fullscreen = live.fullscreen;
        self.sub_pane = live.sub_pane;
        self.quality_view = live.quality_view;
        self.selected = live.selected;
        self.graph_target = live.graph_target;
        self.window_secs = live.window_secs;
        self.graph_marker = live.graph_marker;
        self.q_col = live.q_col;
        self.q_sort = live.q_sort;
        self.bw_view = live.bw_view;
        self.remote_sel = live.remote_sel;
        self.proc_sel = live.proc_sel;
        self.bw_col = live.bw_col;
        self.bw_sort = live.bw_sort;
        self.speed_sel = live.speed_sel;
        self.speedtest_provider_idx = live.speedtest_provider_idx;
        // Overlays, entry and messages.
        self.overlay = live.overlay;
        self.input_mode = live.input_mode.clone();
        self.input_buffer = live.input_buffer.clone();
        self.notice = live.notice.clone();
        self.paused = live.paused;
        self.explainer_pending = live.explainer_pending;
        self.locations = live.locations.clone();
        self.locations_sel = live.locations_sel;
        self.events_scroll = live.events_scroll;
        self.whois_scroll = live.whois_scroll;
        self.logging_requested = live.logging_requested;
        self.log = live.log.clone();
        // Things the user asked for by hand: their results are wanted now.
        self.whois = live.whois.clone();
        self.traceroute = live.traceroute.clone();
        // The path monitor is a measurement, so its numbers hold; but starting
        // or stopping one, and its row cursor, are the user's.
        match (&mut self.hop_monitor, &live.hop_monitor) {
            (Some(fr), Some(lv)) if fr.generation == lv.generation => fr.selected = lv.selected,
            _ => self.hop_monitor = live.hop_monitor.clone(),
        }
        self.speedtest = live.speedtest.clone();
        self.speed_history = live.speed_history.clone();
        self.speed_total = live.speed_total;
        self.should_quit = live.should_quit;
    }

    /// Clear every latency statistic: targets, monitored hops, the one-shot
    /// traceroute. Used by Shift+R, and automatically when the link comes back
    /// or the machine moves networks — stats from before either event describe
    /// a path that no longer exists, and stale loss would stay red for minutes.
    pub fn reset_quality_stats(&mut self) {
        for t in &mut self.targets {
            t.reset();
        }
        if let Some(m) = self.hop_monitor.as_mut() {
            for h in &mut m.hops {
                if let Some(stat) = h.stat.as_mut() {
                    stat.reset();
                }
            }
        }
        self.traceroute = None;
    }

    /// Append to the session timeline, evicting the oldest past the cap.
    pub fn push_event(
        &mut self,
        severity: crate::verdict::Severity,
        category: EventCategory,
        message: String,
    ) {
        if self.events.len() == EVENTS_CAP {
            self.events.pop_front();
        }
        self.events.push_back(EventItem {
            at: chrono::Utc::now().timestamp(),
            severity,
            category,
            message,
        });
        self.events_total += 1;
    }

    /// Show a transient footer notice *and* keep it in the timeline — the
    /// durable sibling of `notice`, which any key press clears.
    pub fn notice_event(
        &mut self,
        severity: crate::verdict::Severity,
        category: EventCategory,
        message: String,
    ) {
        self.notice = Some(message.clone());
        self.push_event(severity, category, message);
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
            Panel::Bandwidth | Panel::NetInfo => self.fullscreen,
            _ => false,
        }
    }

    /// Record a change to how the machine is attached to the network. Also
    /// lands on the event timeline as `summary`, so the two never disagree.
    pub fn push_net_change(
        &mut self,
        kind: NetChangeKind,
        iface: String,
        summary: String,
        detail: Vec<String>,
    ) {
        if self.net_history.len() == NET_HISTORY_CAP {
            self.net_history.pop_front();
        }
        self.net_history.push_back(NetChange {
            at: chrono::Utc::now().timestamp(),
            kind,
            iface,
            summary,
            detail,
        });
    }

    /// This network's incident summary over the standard window, when the
    /// network is known.
    pub fn history_summary(&self) -> Option<crate::history::Summary> {
        let key = self.baseline_key.as_deref()?;
        Some(crate::history::summarise(
            &self.history,
            key,
            crate::history::WINDOW_DAYS,
        ))
    }

    /// The history entry under the cursor (0 = newest).
    pub fn selected_net_change(&self) -> Option<&NetChange> {
        self.net_history.iter().rev().nth(self.net_history_sel)
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

    /// The address under the cursor: in the Quality panel the monitored hop
    /// when the cursor is in the path pane, else the selected target; in the
    /// Bandwidth panel the selected remote. `None` for an unresponsive hop,
    /// which has no address to ask about.
    pub fn selected_addr(&self) -> Option<IpAddr> {
        match self.focus {
            Panel::Quality if self.sub_pane == SubPane::Secondary => {
                self.selected_hop().and_then(|h| h.addr)
            }
            Panel::Quality => self.targets.get(self.selected).map(|t| t.addr),
            Panel::Bandwidth => self.selected_remote().map(|r| r.addr),
            _ => None,
        }
    }

    /// The remote address under the cursor, when the bandwidth panel is showing
    /// remotes and the cursor is in that list.
    pub fn selected_remote(&self) -> Option<&RemoteBandwidth> {
        if self.focus != Panel::Bandwidth
            || self.bw_view != BwView::Remotes
            || self.sub_pane != SubPane::Primary
        {
            return None;
        }
        self.remotes.get(self.remote_sel)
    }

    /// Whether the process list holds the row cursor.
    pub fn on_process_list(&self) -> bool {
        self.focus == Panel::Bandwidth
            && self.bw_view == BwView::Processes
            && self.sub_pane == SubPane::Primary
    }

    /// Indices into `processes` in display order: the collector's ranking by
    /// session total unless a column sort is active. Shared by the renderer
    /// and the cursor, so ↑/↓ walk the rows as drawn.
    pub fn process_order(&self) -> Vec<usize> {
        let mut order: Vec<usize> = (0..self.processes.len()).collect();
        let Some((col, desc)) = self.bw_sort.filter(|_| self.bw_view == BwView::Processes) else {
            return order;
        };
        order.sort_by(|&i, &j| {
            let (a, b) = (&self.processes[i], &self.processes[j]);
            let o = match col {
                0 => a.name.cmp(&b.name),
                2 => a.down_bytes.cmp(&b.down_bytes),
                3 => a.up_bytes.cmp(&b.up_bytes),
                4 => (a.down_bps + a.up_bps).total_cmp(&(b.down_bps + b.up_bps)),
                5 => a.share.total_cmp(&b.share),
                6 => a.retx.cmp(&b.retx),
                _ => a.total_bytes.cmp(&b.total_bytes),
            };
            if desc { o.reverse() } else { o }
        });
        order
    }

    /// Indices into `remotes` in display order; see [`Self::process_order`].
    pub fn remote_order(&self) -> Vec<usize> {
        let mut order: Vec<usize> = (0..self.remotes.len()).collect();
        let Some((col, desc)) = self.bw_sort.filter(|_| self.bw_view == BwView::Remotes) else {
            return order;
        };
        order.sort_by(|&i, &j| {
            let (a, b) = (&self.remotes[i], &self.remotes[j]);
            let o = match col {
                0 => a.addr.cmp(&b.addr),
                1 => a.process.cmp(&b.process),
                3 => a.down_bytes.cmp(&b.down_bytes),
                4 => a.up_bytes.cmp(&b.up_bytes),
                5 => (a.down_bps + a.up_bps).total_cmp(&(b.down_bps + b.up_bps)),
                6 => a.share.total_cmp(&b.share),
                _ => a.total_bytes.cmp(&b.total_bytes),
            };
            if desc { o.reverse() } else { o }
        });
        order
    }

    /// Move a row cursor `delta` places through `order`, returning the new
    /// index into the underlying list. A cursor sitting on a row that has
    /// gone (the list shrank) resumes from the end.
    pub fn step_in_order(order: &[usize], current: usize, delta: isize) -> usize {
        if order.is_empty() {
            return 0;
        }
        let pos = order
            .iter()
            .position(|&i| i == current)
            .unwrap_or(order.len() - 1) as isize;
        order[(pos + delta).clamp(0, order.len() as isize - 1) as usize]
    }

    /// Number of recent samples the current window covers.
    ///
    /// Clamped to what a target actually keeps. Asking for more than the ring
    /// holds silently returns fewer, which would leave the "window 5m" label
    /// overstating the figures beneath it. A faster `--ping-interval` outruns
    /// the buffer easily: 300s at 4 samples/sec wants 1200.
    pub fn window_samples(&self) -> usize {
        self.window_samples_wanted().min(HISTORY)
    }

    /// Samples the window asks for, before the buffer limit applies.
    fn window_samples_wanted(&self) -> usize {
        ((self.window_secs as f64 * self.samples_per_sec).round() as usize).max(1)
    }

    /// True when the buffer, not the chosen window, decides how far back the
    /// statistics reach — so the UI can say so instead of quietly misleading.
    pub fn window_is_capped(&self) -> bool {
        self.window_samples_wanted() > HISTORY
    }

    /// The window as a short label: "60s" becomes "1m".
    pub fn window_label(&self) -> String {
        if self.window_secs >= 60 && self.window_secs.is_multiple_of(60) {
            format!("{}m", self.window_secs / 60)
        } else {
            format!("{}s", self.window_secs)
        }
    }

    /// Cycle the stats window: 1m → 5m → 15m → 1m.
    ///
    /// Ascending, so repeated presses go one direction rather than widening
    /// twice and then snapping narrower. Each stop is several times the last:
    /// neighbouring windows that differ by 2x produce near-identical averages,
    /// which wastes a stop. Nothing shorter than a minute, because p95 over a
    /// few dozen samples is just "second worst" and jumps on any single spike;
    /// `last` already covers the immediate picture.
    pub fn cycle_window(&mut self) {
        self.window_secs = match self.window_secs {
            w if w < 300 => 300,
            w if w < 900 => 900,
            _ => 60,
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
