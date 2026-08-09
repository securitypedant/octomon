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
#[derive(Clone)]
pub struct TargetStat {
    pub label: String,
    pub addr: IpAddr,
    pub last_rtt_ms: Option<f64>,
    pub min_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub avg_ms: Option<f64>, // EWMA
    pub jitter_ms: f64,
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
            min_ms: None,
            max_ms: None,
            avg_ms: None,
            jitter_ms: 0.0,
            sent: 0,
            recv: 0,
            window: VecDeque::with_capacity(WINDOW),
            history: History::new(300),
        }
    }

    /// Record a successful probe with round-trip time in milliseconds.
    pub fn record_reply(&mut self, rtt_ms: f64) {
        self.sent += 1;
        self.recv += 1;
        self.push_window(true);

        self.last_rtt_ms = Some(rtt_ms);
        self.min_ms = Some(self.min_ms.map_or(rtt_ms, |m| m.min(rtt_ms)));
        self.max_ms = Some(self.max_ms.map_or(rtt_ms, |m| m.max(rtt_ms)));

        // EWMA average (alpha = 0.2).
        self.avg_ms = Some(match self.avg_ms {
            Some(a) => a + 0.2 * (rtt_ms - a),
            None => rtt_ms,
        });

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
            input_mode: InputMode::Normal,
            input_buffer: String::new(),
            notice: None,
            paused: false,
            show_help: false,
            should_quit: false,
            started: Instant::now(),
        }
    }
}
