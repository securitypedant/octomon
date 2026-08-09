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

#[derive(Clone)]
pub struct TargetStat {
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
        let mut v: Vec<f64> = self.history.data.iter().rev().take(n.max(1)).copied().collect();
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
    /// Current phase label while running: "connect", "download", "upload".
    pub phase: String,
    /// Progress within the current phase, 0.0..=1.0.
    pub progress: f64,
    /// Instantaneous throughput (Mbps) during the active phase.
    pub live_mbps: f64,
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

/// Per-process network throughput (bytes/sec), derived from successive samples.
#[derive(Clone)]
pub struct ProcBandwidth {
    pub name: String,
    pub pid: u32,
    pub down_bps: f64,
    pub up_bps: f64,
}

/// Wi-Fi radio details (best-effort, platform-specific).
#[derive(Clone, Default)]
pub struct WifiInfo {
    pub ssid: String,
    pub phy: String,
    pub channel: String,
    pub rssi: String,
    pub tx_rate: String,
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
    /// e.g. "Wi-Fi", "Ethernet", "Loopback" — best-effort.
    pub link_kind: String,
    /// Present when the default interface is Wi-Fi and details are available.
    pub wifi: Option<WifiInfo>,
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

/// Root shared state.
pub struct AppState {
    pub targets: Vec<TargetStat>,
    pub throughput: Throughput,
    pub speedtest: SpeedTest,
    pub netinfo: NetInfo,
    pub vitals: Vitals,
    pub focus: Panel,
    /// When set, the focused panel is drawn full-screen instead of the 2x2 grid.
    pub fullscreen: bool,
    pub speedtest_enabled: bool,
    /// Top processes by current network throughput (highest first).
    pub processes: Vec<ProcBandwidth>,
    /// Whether per-process attribution is available on this platform.
    pub proc_supported: bool,

    // --- Connection Quality interaction ---
    /// Cursor over the target list (Quality panel).
    pub selected: usize,
    /// Target index whose latency history drives the sparkline.
    pub graph_target: usize,
    /// Smoothing/stats window in seconds (cycled with 'w').
    pub window_secs: u64,
    /// Samples per second (1000 / ping interval); converts window to samples.
    pub samples_per_sec: f64,

    // --- Modal / global UI state ---
    pub input_mode: InputMode,
    pub input_buffer: String,
    /// Optional transient status/error message (e.g. failed DNS lookup).
    pub notice: Option<String>,
    /// Auto-refresh paused: the periodic redraw is suppressed.
    pub paused: bool,
    /// Help overlay visible.
    pub show_help: bool,

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
            vitals: Vitals::default(),
            focus: Panel::Quality,
            fullscreen: false,
            speedtest_enabled: true,
            processes: Vec::new(),
            proc_supported: false,
            selected: 0,
            graph_target: 0,
            window_secs: 60,
            samples_per_sec: 1.0,
            input_mode: InputMode::Normal,
            input_buffer: String::new(),
            notice: None,
            paused: false,
            show_help: false,
            should_quit: false,
            started: Instant::now(),
        }
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
}
