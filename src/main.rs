//! octomon — a terminal dashboard for network performance.
//!
//! Architecture: independent async collectors write into a shared [`AppState`]
//! (behind a std `Mutex`); a render loop reads a snapshot and draws with ratatui.
//! Input is read on a dedicated OS thread and delivered over a channel.

mod app;
mod baseline;
mod collectors;
mod config;
mod demo;
mod history;
mod platform;
mod store;
mod theme;
mod ui;
mod util;
mod verdict;

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use tokio::sync::{Notify, mpsc};

use app::{
    AppState, BwView, InputMode, Overlay, Panel, QualityView, SpeedStatus, SubPane, TargetStat,
};
use config::Config;

/// Handles shared with the input loop for issuing side effects.
struct Ctx {
    state: Arc<Mutex<AppState>>,
    speedtest_trigger: Arc<Notify>,
    netinfo_refresh: Arc<Notify>,
    ping_clients: collectors::ping::Clients,
    cfg: Config,
    /// `--demo`: draw from a disguised copy of the state.
    demo: bool,
    /// `--demo-mac`: draw with only this machine's identifiers disguised.
    demo_mac: bool,
}

/// Terminal dashboard for network performance.
#[derive(Parser, Debug)]
#[command(name = "octomon", version = util::VERSION, about)]
struct Cli {
    /// Run collectors briefly, print a text snapshot, then exit (no TUI).
    #[arg(long)]
    check: bool,

    /// One-shot diagnosis: observe for ~20s, print the verdict with its
    /// evidence and a paste-able report, then exit. Exit codes: 0 healthy,
    /// 1 problems found, 3 could not measure.
    #[arg(long)]
    doctor: bool,

    /// With --doctor: also run a speed test (observation takes ~45s).
    #[arg(long)]
    speedtest: bool,

    /// With --doctor: print real SSIDs / IPs / MACs instead of redacting them.
    /// The default output is safe to paste into a forum or ISP ticket.
    #[arg(long)]
    full: bool,

    /// With --doctor: how many seconds to observe before reporting
    /// (default 20, or 45 with --speedtest). Longer = better loss statistics.
    #[arg(long, value_name = "SECS")]
    observe: Option<u64>,

    /// With --doctor: emit the report as JSON instead of text.
    #[arg(long)]
    json: bool,

    /// Disable the on-demand speed test.
    #[arg(long)]
    no_speedtest: bool,

    /// Demo mode: everything measures for real, but the screen shows fake
    /// MAC addresses, addresses, SSIDs and other identifying details, kept
    /// consistent for the session — safe to screen-record.
    #[arg(long)]
    demo: bool,

    /// Like --demo, but hides only what identifies *this machine* — its MAC
    /// address (and any IPv6 address embedding it). The network's own details
    /// stay real: for screenshots on a network that isn't private (a hotel,
    /// an airport) taken from a machine that is.
    #[arg(long, conflicts_with = "demo")]
    demo_mac: bool,

    /// Add an ICMP target: `LABEL=IP` or bare `IP`. Repeatable.
    #[arg(short = 't', long = "target", value_name = "[LABEL=]IP")]
    targets: Vec<String>,

    /// Override the ICMP ping interval, in milliseconds.
    #[arg(long, value_name = "MS")]
    ping_interval: Option<u64>,

    /// Start recording the session to CSV immediately (same as pressing 'l'),
    /// so octomon can be run headless as a recorder.
    #[arg(long)]
    log: bool,

    /// Colour scheme: auto (ask the terminal its background), dark, or light.
    /// Overrides the config's `theme` for this run.
    #[arg(long, value_name = "auto|dark|light")]
    theme: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Every rustls consumer (reqwest, tokio-tungstenite) resolves its crypto
    // provider from this process default. Must come before any TLS handshake.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install rustls crypto provider before any TLS use");
    use_utf8_console();
    let cli = Cli::parse();

    // Base config from file/defaults, then apply CLI overrides.
    let mut cfg = Config::load();
    if let Some(ms) = cli.ping_interval {
        cfg.ping_interval_ms = ms;
    }
    for t in &cli.targets {
        match config::parse_target(t) {
            Ok(target) => cfg.targets.push(target),
            Err(e) => {
                eprintln!("octomon: {e}");
                std::process::exit(2);
            }
        }
    }

    let targets = cfg
        .targets
        .iter()
        .map(|t| {
            let mut stat = TargetStat::new(t.label.clone(), t.addr);
            // A saved name-target keeps behaving like one: re-resolved on
            // network changes, web-probed with real SNI.
            stat.hostname = t.host.clone();
            stat
        })
        .collect();
    let state = Arc::new(Mutex::new(AppState::new(targets)));
    {
        // All providers are selectable; LibreSpeed reports a hint if it has no
        // server configured when actually run.
        let provider_names = vec![
            "Cloudflare".to_string(),
            "M-Lab".to_string(),
            "LibreSpeed".to_string(),
        ];
        let norm = |s: &str| s.to_lowercase().replace('-', "");
        let sel = provider_names
            .iter()
            .position(|n| norm(n) == norm(&cfg.speedtest_provider))
            .unwrap_or(0);

        let mut s = state.lock().unwrap();
        s.speedtest_enabled = !cli.no_speedtest;
        s.samples_per_sec = 1000.0 / cfg.ping_interval_ms.max(1) as f64;
        s.graph_marker = cfg.marker();
        s.bar_set = cfg.bar_set();
        s.bits_units = cfg.bits_units();
        s.speedtest_provider_names = provider_names;
        s.speedtest_provider_idx = sel;
        let (history, total) = store::load_recent(500);
        s.speed_history = history;
        s.speed_total = total;
        s.history = history::load();
        // The network history spans sessions: yesterday's roams and VPN
        // flips are still on record today.
        s.net_history = store::load_net_history();
        s.logging_requested = cli.log;
        // Which tools ship by default varies sharply by distribution, so a
        // missing binary is a normal condition. Say so up front rather than
        // letting the affected feature silently never appear.
        s.missing_tools = platform::tools::missing()
            .into_iter()
            .map(|t| (t.name, t.provides, t.package))
            .collect();
        s.privilege_notice = platform::tools::privilege_notice();
        s.notice = platform::tools::missing_notice();
        // The timeline's opening line: an exported events CSV or a support
        // bundle then names the version and platform that produced it without
        // anyone having to ask.
        s.push_event(
            verdict::Severity::Info,
            app::EventCategory::Logging,
            format!(
                "octomon {} started on {} — timeline begins",
                crate::util::VERSION,
                std::env::consts::OS
            ),
        );
    }

    // Triggers fired by key presses.
    let speedtest_trigger = Arc::new(Notify::new()); // 's'
    let netinfo_refresh = Arc::new(Notify::new()); // 'r'

    // Shared per-family ICMP clients so targets can be added at runtime and v6
    // addresses (common on carrier hotspots) are probed with the right socket.
    // Unprivileged datagram ICMP needs the kernel to allow it. macOS always
    // does; on Linux it depends on net.ipv4.ping_group_range, which several
    // distributions ship closed. Failing here disables every latency feature,
    // so the reason has to reach the user rather than a log nobody reads.
    let (ping_clients, v4_err) = collectors::ping::Clients::open();
    if let Some(e) = v4_err {
        tracing::error!("failed to create ICMP client: {e}");
        state.lock().unwrap().icmp_error = Some(icmp_help(&e));
    }
    {
        // Interrupt only for things that will visibly not work. A clean setup
        // starts straight into the dashboard.
        let mut s = state.lock().unwrap();
        let headless = cli.check || cli.doctor;
        if !headless && (s.icmp_error.is_some() || !s.missing_tools.is_empty()) {
            s.overlay = Overlay::Startup;
        }
        // First run: explain what the tool answers and that it learns each
        // network's normal. Setup problems keep precedence; the explainer then
        // follows the startup notice's dismissal.
        if !headless && !cfg.explainer_seen {
            if s.overlay == Overlay::Startup {
                s.explainer_pending = true;
            } else {
                s.overlay = Overlay::Explainer;
            }
        }
    }
    // Raised by the netinfo collector when the machine moves to a different
    // network, so path-dependent state can be rebuilt.
    let network_changed = Arc::new(Notify::new());

    if ping_clients.available() {
        collectors::ping::spawn_all(state.clone(), ping_clients.clone(), cfg.clone());
        // Auto-discover the gateway + next hops, and the public IP, as targets.
        if !cli.check {
            tokio::spawn(collectors::discovery::run(
                state.clone(),
                ping_clients.clone(),
                cfg.clone(),
            ));
            tokio::spawn(collectors::discovery::public_ip(
                state.clone(),
                ping_clients.clone(),
                cfg.clone(),
            ));
            tokio::spawn(collectors::discovery::watch(
                state.clone(),
                ping_clients.clone(),
                cfg.clone(),
                network_changed.clone(),
            ));
        }
    }

    // Spawn collectors, each on its own cadence.
    tokio::spawn(verdict::run(state.clone(), cfg.clone()));
    tokio::spawn(collectors::http::run(
        state.clone(),
        cfg.clone(),
        network_changed.clone(),
    ));
    tokio::spawn(collectors::clock::run(
        state.clone(),
        cfg.clone(),
        network_changed.clone(),
    ));
    tokio::spawn(collectors::pmtu::run(
        state.clone(),
        cfg.clone(),
        network_changed.clone(),
    ));
    tokio::spawn(collectors::proxy::run(
        state.clone(),
        network_changed.clone(),
    ));
    tokio::spawn(collectors::throughput::run(state.clone(), cfg.clone()));
    tokio::spawn(collectors::vitals::run(state.clone(), cfg.clone()));
    tokio::spawn(collectors::dns::run(state.clone(), cfg.clone()));
    tokio::spawn(collectors::logger::run(state.clone(), cfg.clone()));
    tokio::spawn(collectors::netinfo::run(
        state.clone(),
        netinfo_refresh.clone(),
        network_changed.clone(),
    ));
    tokio::spawn(collectors::wifi::run(
        state.clone(),
        netinfo_refresh.clone(),
    ));
    tokio::spawn(collectors::signal::run(state.clone()));
    tokio::spawn(collectors::procbw::run(state.clone()));
    tokio::spawn(collectors::web::run(state.clone()));
    tokio::spawn(collectors::resolve::run(
        state.clone(),
        ping_clients.clone(),
        cfg.clone(),
        network_changed.clone(),
    ));
    if !cli.no_speedtest {
        tokio::spawn(collectors::speedtest::run(
            state.clone(),
            speedtest_trigger.clone(),
            cfg.clone(),
        ));
    }

    // Headless verification mode: collect for a few seconds, run one speed test,
    // print a text snapshot, and exit. Exercises collectors without a TTY.
    if cli.check {
        tokio::time::sleep(Duration::from_secs(3)).await;
        if !cli.no_speedtest {
            speedtest_trigger.notify_one();
            tokio::time::sleep(Duration::from_secs(40)).await;
        } else {
            // The macOS Wi-Fi probe (system_profiler) is slow; wait for it.
            tokio::time::sleep(Duration::from_secs(17)).await;
        }
        if cli.demo || cli.demo_mac {
            let mut d = demo::Disguise::new();
            let s = state.lock().unwrap();
            let view = if cli.demo {
                demo::disguise(&s, &mut d)
            } else {
                demo::disguise_machine(&s, &mut d)
            };
            print_snapshot(&view);
        } else {
            print_snapshot(&state.lock().unwrap());
        }
        return Ok(());
    }

    // One-shot doctor: observe with everything running — including discovery
    // and a hop monitor, which --check deliberately skips — judge once, print
    // a paste-able report, and exit with a code scripts can branch on.
    if cli.doctor {
        // Let discovery find the gateway first, then watch the path to the
        // first anchor so an ISP-segment fault can be localised headless.
        tokio::time::sleep(Duration::from_secs(2)).await;
        if let Some(t) = cfg.targets.first().filter(|_| ping_clients.available()) {
            collectors::hopmon::start(
                state.clone(),
                ping_clients.clone(),
                cfg.clone(),
                t.addr,
                t.label.clone(),
            );
        }
        // 2s of discovery already elapsed; the rest is the observation window.
        let speedtest_wanted = cli.speedtest && !cli.no_speedtest;
        let observe = cli
            .observe
            .unwrap_or(if speedtest_wanted { 45 } else { 20 })
            .clamp(5, 600)
            .saturating_sub(2);
        if speedtest_wanted {
            tokio::time::sleep(Duration::from_secs(3)).await;
            speedtest_trigger.notify_one();
            tokio::time::sleep(Duration::from_secs(observe.saturating_sub(3).max(1))).await;
        } else {
            tokio::time::sleep(Duration::from_secs(observe)).await;
        }
        let (report, code) = {
            let s = state.lock().unwrap();
            if cli.json {
                doctor_json(&s, cli.full)
            } else {
                doctor_report(&s, cli.full)
            }
        };
        print!("{report}");
        use std::io::Write as _;
        let _ = std::io::stdout().flush();
        std::process::exit(code);
    }

    // Resolve dark/light before the input thread exists: theme auto-detection
    // asks the terminal its background colour and reads the reply off the
    // terminal input — once the thread below owns stdin it would eat it.
    theme::init(cli.theme.as_deref().unwrap_or(&cfg.theme));

    // Read terminal input on a blocking OS thread → async channel.
    let (tx, rx) = mpsc::unbounded_channel::<KeyEvent>();
    std::thread::spawn(move || {
        loop {
            match event::read() {
                Ok(Event::Key(k)) => {
                    if tx.send(k).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    // ratatui::init() enables raw mode + alt screen and installs a panic hook
    // that restores the terminal, so a panic never leaves it wedged.
    let mut terminal = ratatui::init();
    let ctx = Ctx {
        state,
        speedtest_trigger,
        netinfo_refresh,
        ping_clients,
        cfg,
        demo: cli.demo,
        demo_mac: cli.demo_mac,
    };
    let result = run_ui(&mut terminal, &ctx, rx).await;
    ratatui::restore();
    result
}

async fn run_ui(
    terminal: &mut ratatui::DefaultTerminal,
    ctx: &Ctx,
    mut rx: mpsc::UnboundedReceiver<KeyEvent>,
) -> Result<()> {
    let mut ticker = tokio::time::interval(Duration::from_millis(200));
    // While paused the screen is drawn from this copy, taken at the moment of
    // pausing, so every measurement holds still — collectors keep writing to
    // the live state underneath. What the user drives (cursors, overlays, a
    // whois they asked for) is copied across before each draw.
    let mut frozen: Option<Box<AppState>> = None;
    // `--demo` / `--demo-mac`: the mapping from real to fake, kept for the
    // session so the fakes stay consistent frame to frame.
    let mut disguise = (ctx.demo || ctx.demo_mac).then(demo::Disguise::new);
    let apply = |s: &AppState, d: &mut demo::Disguise, full: bool| {
        if full {
            demo::disguise(s, d)
        } else {
            demo::disguise_machine(s, d)
        }
    };
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            Some(key) = rx.recv() => handle_key(ctx, key),
        }

        let mut s = ctx.state.lock().unwrap();
        if s.should_quit {
            break;
        }
        if !s.paused {
            frozen = None;
            match disguise.as_mut() {
                Some(d) => {
                    let view = apply(&s, d, ctx.demo);
                    terminal.draw(|f| ui::render(f, &view))?;
                }
                None => {
                    terminal.draw(|f| ui::render(f, &s))?;
                }
            };
            continue;
        }
        if frozen.is_none() || s.refreeze {
            s.refreeze = false;
            frozen = Some(Box::new(s.clone()));
        }
        let fr = frozen.as_mut().unwrap();
        fr.sync_interactive_from(&s);
        match disguise.as_mut() {
            Some(d) => {
                let view = apply(fr, d, ctx.demo);
                terminal.draw(|f| ui::render(f, &view))?;
            }
            None => {
                terminal.draw(|f| ui::render(f, fr))?;
            }
        };
    }
    Ok(())
}

/// Clear everything the focused panel has accumulated. "Reset" should leave no
/// stale figure behind: a graph that keeps its history after a reset makes the
/// numbers beside it look wrong.
fn reset_panel(s: &mut AppState) {
    s.refreeze = true;
    match s.focus {
        Panel::Quality => s.reset_quality_stats(),
        Panel::Bandwidth => {
            s.throughput.down_hist.data.clear();
            s.throughput.up_hist.data.clear();
            s.throughput.down_bps = 0.0;
            s.throughput.up_bps = 0.0;
            s.processes.clear();
            s.remotes.clear();
            // The lists are rebuilt from the collector's session totals every
            // tick; tell it to start the session over.
            s.bw_reset = true;
            s.link_errors = crate::app::LinkErrors {
                iface: s.link_errors.iface.clone(),
                ..Default::default()
            };
        }
        Panel::NetInfo => {
            s.signal.rssi_hist.data.clear();
            s.signal.tx_hist.data.clear();
            for p in &mut s.dns {
                p.hist.data.clear();
                p.sent = 0;
                p.ok = 0;
                p.last_ms = None;
                p.status.clear();
            }
        }
        Panel::Vitals => {
            s.vitals.cpu_hist.data.clear();
            s.vitals.mem_hist.data.clear();
            s.vitals.pressure_hist.data.clear();
        }
    }
    s.notice = Some("panel data reset".to_string());
}

/// Make the Windows console read our output as UTF-8.
///
/// A console defaults to a legacy OEM codepage (437, 850, 866…). Rust converts
/// to UTF-16 and calls `WriteConsoleW` when it can prove stdout is a console,
/// but falls back to writing raw UTF-8 bytes when it cannot — under a pipe, a
/// redirect, or a terminal that does not present a console handle. Those bytes
/// then get decoded as OEM and every non-ASCII glyph arrives mangled: the "↓"
/// in the bandwidth listing shows up as "Γåô". One call up front covers both
/// paths. No-op everywhere else.
fn use_utf8_console() {
    #[cfg(windows)]
    {
        // SAFETY: sets a property of the calling process's console. Fails
        // harmlessly (returning 0) when there is no console attached at all.
        unsafe {
            windows_sys::Win32::System::Console::SetConsoleOutputCP(
                windows_sys::Win32::Globalization::CP_UTF8,
            )
        };
    }
}

/// Turn an ICMP socket failure into something the user can act on. The raw
/// error ("Permission denied") says nothing about the fix.
fn icmp_help(err: &str) -> String {
    if cfg!(windows) {
        format!(
            "ICMP unavailable ({err}). Latency, path monitoring and traceroute targets are \
             disabled. This is usually a firewall or endpoint-security product blocking ICMP \
             for non-administrators — an elevated terminal will confirm it."
        )
    } else if cfg!(target_os = "linux") {
        format!(
            "ICMP unavailable ({err}). Latency, path monitoring and traceroute targets need \
             unprivileged ping sockets. Enable them for everyone with:\n\
             \x20   sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"\n\
             \x20 (persist: echo 'net.ipv4.ping_group_range=0 2147483647' | sudo tee \
             /etc/sysctl.d/99-ping.conf)\n\
             \x20 Or grant just octomon: sudo setcap cap_net_raw+ep $(which octomon)"
        )
    } else {
        format!("ICMP unavailable ({err}). Latency and path features are disabled.")
    }
}

/// Side effects to run after releasing the state lock.
enum Side {
    None,
    Speedtest,
    Refresh,
    AddTarget(String),
    Traceroute(IpAddr, String),
    HopMonitor(IpAddr, String),
    /// Look up who owns an address for the [W] overlay.
    Whois(IpAddr),
    /// Read the OS routing table for the [T] overlay (a blocking shell-out).
    LoadRoutes,
    SaveProvider(String),
    /// Persist the user's name for the current network's baseline.
    NameNetwork {
        key: String,
        label: String,
        name: String,
    },
    /// Read every stored baseline off disk for the locations overlay.
    LoadLocations,
    /// Write the event timeline to a CSV in the config folder ([x] in the
    /// events overlay). Carries a snapshot so the file I/O runs off the lock.
    ExportEvents(Vec<app::EventItem>),
    /// Zip everything a remote helper needs ([D]): full doctor report, event
    /// timeline, config, and every data file. Carries a state snapshot so the
    /// report and the file I/O run off the lock.
    DumpBundle(Box<AppState>),
    /// Run the outbound port scan for the [c] overlay.
    EgressScan,
    /// Remove a deleted target from the config file (user-added ones only).
    ForgetTarget(IpAddr),
    /// Remove one speed test from the on-disk history ([d] in the history
    /// pane). Carries the record so the file rewrite runs off the lock.
    ForgetSpeedtest(Box<store::SpeedRecord>),
    /// Ask the OS what it knows about these pids (exe path, command line)
    /// for the zoom overlay — a blocking process scan, run off the lock.
    LoadProcDetails(Vec<u32>),
    /// Erase all config and stored data (Ctrl+R, confirmed by typing ERASE):
    /// the config directory and the data directory, deleted whole.
    TotalReset,
    /// Remove a deleted location's stored baseline from baselines.json.
    ForgetLocation(String),
}

/// Remove the selected target, pulling the dependent cursors back into range.
fn delete_selected_target(s: &mut AppState) {
    if s.selected >= s.targets.len() {
        return;
    }
    let idx = s.selected;
    // A path monitor outlives its target otherwise, quietly probing every hop
    // toward an address the user just removed.
    let addr = s.targets[idx].addr;
    if s.hop_monitor.as_ref().is_some_and(|m| m.dest == addr) {
        s.hop_monitor = None;
        if s.quality_view == QualityView::HopMonitor {
            s.quality_view = QualityView::Graph;
        }
    }
    s.targets.remove(idx);
    s.refreeze = true;
    let last = s.targets.len().saturating_sub(1);
    s.selected = s.selected.min(last);
    if s.graph_target >= idx {
        s.graph_target = s.graph_target.saturating_sub(1);
    }
    s.graph_target = s.graph_target.min(last);
}

/// Move whichever cursor holds focus: the sub-pane's when one is active,
/// otherwise the panel's primary list.
/// Whether the typed confirmation authorises a total reset: the word ERASE,
/// any case, nothing less. A destructive action should cost a word, not a
/// keystroke.
fn reset_confirmed(buf: &str) -> bool {
    buf.trim().eq_ignore_ascii_case("erase")
}

/// Delete the selected speed test from the in-memory history, returning the
/// side effect that removes it from the file. The pane lists newest-first;
/// storage is oldest-first.
fn delete_selected_speedtest(s: &mut AppState) -> Side {
    let len = s.speed_history.len();
    if len == 0 {
        return Side::None;
    }
    let sel = s.speed_sel.min(len - 1);
    let rec = s.speed_history.remove(len - 1 - sel);
    s.speed_total = s.speed_total.saturating_sub(1);
    s.speed_sel = s.speed_sel.min(s.speed_history.len().saturating_sub(1));
    Side::ForgetSpeedtest(Box::new(rec))
}

/// Move the zoom overlay's cursor: the same row cursors the tables use, so
/// the selection survives closing the zoom.
fn zoom_move(s: &mut AppState, delta: isize) {
    match s.zoom_view {
        app::ZoomView::Processes => move_proc_cursor(s, delta),
        app::ZoomView::Remotes => move_remote_cursor(s, delta),
        app::ZoomView::Speedtests => {
            let last = s.speed_history.len().saturating_sub(1) as isize;
            s.speed_sel = (s.speed_sel as isize + delta).clamp(0, last.max(0)) as usize;
        }
    }
}

/// Step the processes cursor by display position. While [o] is following a
/// row, moving re-anchors the follow to whatever the cursor lands on — the
/// mode means "track what I select", not "trap me on one row".
fn move_proc_cursor(s: &mut AppState, delta: isize) {
    let len = s.processes.len();
    if len == 0 {
        return;
    }
    let (pos, _) = s.proc_cursor();
    let new = (pos as isize + delta).clamp(0, len as isize - 1) as usize;
    s.proc_sel = new;
    if s.follow_proc.is_some() {
        s.follow_proc = s
            .process_order()
            .get(new)
            .map(|&i| s.processes[i].name.clone());
    }
}

/// See [`move_proc_cursor`].
fn move_remote_cursor(s: &mut AppState, delta: isize) {
    let len = s.remotes.len();
    if len == 0 {
        return;
    }
    let (pos, _) = s.remote_cursor();
    let new = (pos as isize + delta).clamp(0, len as isize - 1) as usize;
    s.remote_sel = new;
    if s.follow_remote.is_some() {
        s.follow_remote = s.remote_order().get(new).map(|&i| s.remotes[i].addr);
    }
}

/// [o]: glue the cursor to the row it is on, or release it. On release the
/// cursor parks at the row's current position rather than snapping back.
fn toggle_follow(s: &mut AppState) {
    match s.bw_view {
        BwView::Processes => {
            if s.follow_proc.is_some() {
                s.proc_sel = s.proc_cursor().0;
                s.follow_proc = None;
            } else {
                s.follow_proc = s.proc_cursor().1.map(|i| s.processes[i].name.clone());
            }
        }
        BwView::Remotes => {
            if s.follow_remote.is_some() {
                s.remote_sel = s.remote_cursor().0;
                s.follow_remote = None;
            } else {
                s.follow_remote = s.remote_cursor().1.map(|i| s.remotes[i].addr);
            }
        }
    }
}

fn move_cursor(s: &mut AppState, delta: isize) {
    let secondary = s.sub_pane == SubPane::Secondary;
    match s.focus {
        Panel::Quality if secondary => {
            if let Some(m) = s.hop_monitor.as_mut() {
                // Only hops that answer are worth landing on: an unresponsive
                // one has no statistics, no chart, and nothing to add as a
                // target, so the cursor would appear to vanish passing over it.
                let selectable: Vec<usize> = m
                    .hops
                    .iter()
                    .enumerate()
                    .filter(|(_, h)| h.addr.is_some())
                    .map(|(i, _)| i)
                    .collect();
                if selectable.is_empty() {
                    return;
                }
                // Resume from wherever the cursor sits, even if that index is
                // itself unselectable (the path can change under it).
                let pos = selectable
                    .iter()
                    .position(|&i| i >= m.selected)
                    .unwrap_or(selectable.len() - 1) as isize;
                let next = (pos + delta).clamp(0, selectable.len() as isize - 1) as usize;
                m.selected = selectable[next];
            }
        }
        Panel::Quality => {
            let order = s.quality_order();
            let Some(pos) = order.iter().position(|&i| i == s.selected) else {
                return;
            };
            let new =
                (pos as isize + delta).clamp(0, order.len().saturating_sub(1) as isize) as usize;
            s.selected = order[new];
        }
        Panel::Bandwidth if secondary => {
            let last = s.speed_history.len().saturating_sub(1) as isize;
            s.speed_sel = (s.speed_sel as isize + delta).clamp(0, last.max(0)) as usize;
        }
        // The network history list, newest first: "up" is toward the newest.
        // The detail expansion is sticky on purpose: browsing entry to entry
        // with the full story showing is what it was expanded for.
        Panel::NetInfo if secondary => {
            let last = s.net_history.len().saturating_sub(1) as isize;
            s.net_history_sel = (s.net_history_sel as isize + delta).clamp(0, last.max(0)) as usize;
        }
        // ↑/↓ hop between the panel's *rows* (ipv4 → ipv6 → gateway → dns…),
        // landing on each row's first address; ←/→ walk the entries within a
        // row. One press per visual line, not per address.
        Panel::NetInfo => {
            let addrs = s.netinfo_addrs();
            if addrs.is_empty() {
                return;
            }
            let mut cur = s.net_sel.min(addrs.len() - 1);
            for _ in 0..delta.unsigned_abs() {
                let row = addrs[cur].slot.row();
                let next = if delta > 0 {
                    addrs
                        .iter()
                        .position(|a| a.slot.row() > row)
                        .filter(|&i| i > cur)
                } else {
                    // The previous row's first entry.
                    addrs[..cur]
                        .iter()
                        .rposition(|a| a.slot.row() < row)
                        .map(|last_prev| {
                            let prev_row = addrs[last_prev].slot.row();
                            addrs
                                .iter()
                                .position(|a| a.slot.row() == prev_row)
                                .unwrap_or(last_prev)
                        })
                };
                match next {
                    Some(i) => cur = i,
                    None => break,
                }
            }
            s.net_sel = cur;
        }
        // The talkers cursors are positional: they hold their row while the
        // sort re-ranks beneath them (unless [o] is following an item).
        Panel::Bandwidth if s.bw_view == BwView::Remotes => move_remote_cursor(s, delta),
        Panel::Bandwidth => move_proc_cursor(s, delta),
        _ => {}
    }
}

fn handle_key(ctx: &Ctx, key: KeyEvent) {
    if key.kind == KeyEventKind::Release {
        return;
    }
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let mut side = Side::None;

    {
        let mut s = ctx.state.lock().unwrap();
        s.notice = None; // any key clears a transient notice

        // The setup modal is dismissed by any key, and swallows it so a stray
        // press does not also trigger an action behind the modal. The first-run
        // explainer, when pending, takes the slot the dismissal frees.
        if s.overlay == Overlay::Startup && s.input_mode == InputMode::Normal {
            s.overlay = if s.explainer_pending {
                s.explainer_pending = false;
                Overlay::Explainer
            } else {
                Overlay::None
            };
            if !matches!(key.code, KeyCode::Char('q')) && !(ctrl && key.code == KeyCode::Char('c'))
            {
                return;
            }
        }

        // The explainer is also any-key-dismissed, and is shown exactly once:
        // dismissal is persisted (off the key path) so it never reappears.
        if s.overlay == Overlay::Explainer && s.input_mode == InputMode::Normal {
            s.overlay = Overlay::None;
            tokio::task::spawn_blocking(Config::persist_explainer_seen);
            if !matches!(key.code, KeyCode::Char('q')) && !(ctrl && key.code == KeyCode::Char('c'))
            {
                return;
            }
        }

        match s.input_mode {
            // --- modal text entry: adding a target ---
            InputMode::AddTarget => match key.code {
                KeyCode::Enter => {
                    let buf = s.input_buffer.trim().to_string();
                    s.input_mode = InputMode::Normal;
                    s.input_buffer.clear();
                    if !buf.is_empty() {
                        side = Side::AddTarget(buf);
                    }
                }
                KeyCode::Esc => {
                    s.input_mode = InputMode::Normal;
                    s.input_buffer.clear();
                }
                KeyCode::Backspace => {
                    s.input_buffer.pop();
                }
                KeyCode::Char(c) if s.input_buffer.len() < 253 => s.input_buffer.push(c),
                _ => {}
            },

            // --- modal text entry: naming the current network ---
            InputMode::RenameLocation => match key.code {
                KeyCode::Enter => {
                    let name = s.input_buffer.trim().to_string();
                    s.input_mode = InputMode::Normal;
                    s.input_buffer.clear();
                    if let Some((key, label)) = s.rename_target.take() {
                        let new_name = (!name.is_empty()).then(|| name.clone());
                        // Update what is on screen at once; the file write
                        // happens off the key path.
                        if let Some(all) = s.locations.as_mut()
                            && let Some((_, b)) = all.iter_mut().find(|(k, _)| *k == key)
                        {
                            b.name = new_name.clone();
                        }
                        if s.baseline_key.as_deref() == Some(key.as_str())
                            && let Some(b) = s.baseline.as_mut()
                        {
                            b.name = new_name;
                        }
                        side = Side::NameNetwork { key, label, name };
                    }
                }
                KeyCode::Esc => {
                    s.input_mode = InputMode::Normal;
                    s.input_buffer.clear();
                    s.rename_target = None;
                }
                KeyCode::Backspace => {
                    s.input_buffer.pop();
                }
                KeyCode::Char(c) if s.input_buffer.len() < 40 => s.input_buffer.push(c),
                _ => {}
            },
            // --- modal confirmation: total reset (Ctrl+R) ---
            InputMode::ConfirmReset => match key.code {
                KeyCode::Enter => {
                    let confirmed = reset_confirmed(&s.input_buffer);
                    s.input_mode = InputMode::Normal;
                    s.input_buffer.clear();
                    if confirmed {
                        // Forget everything learned, in memory as well as on
                        // disk — the session keeps running on defaults-ish
                        // state; a restart completes the fresh start.
                        s.baseline = None;
                        s.baseline_key = None;
                        s.locations = None;
                        s.speed_history.clear();
                        s.speed_total = 0;
                        s.history.clear();
                        s.logging_requested = false;
                        side = Side::TotalReset;
                    } else {
                        s.notice = Some("total reset cancelled".to_string());
                    }
                }
                KeyCode::Esc => {
                    s.input_mode = InputMode::Normal;
                    s.input_buffer.clear();
                    s.notice = Some("total reset cancelled".to_string());
                }
                KeyCode::Backspace => {
                    s.input_buffer.pop();
                }
                KeyCode::Char(c) if s.input_buffer.len() < 8 => s.input_buffer.push(c),
                _ => {}
            },

            // --- modal text entry: a marker for the event timeline ---
            InputMode::Marker => match key.code {
                KeyCode::Enter => {
                    let text = s.input_buffer.trim().to_string();
                    s.input_mode = InputMode::Normal;
                    s.input_buffer.clear();
                    if !text.is_empty() {
                        // notice_event: the footer confirms the marker landed,
                        // and the timeline keeps it.
                        s.notice_event(
                            verdict::Severity::Info,
                            app::EventCategory::Marker,
                            format!("⚑ {text}"),
                        );
                    }
                }
                KeyCode::Esc => {
                    s.input_mode = InputMode::Normal;
                    s.input_buffer.clear();
                }
                KeyCode::Backspace => {
                    s.input_buffer.pop();
                }
                KeyCode::Char(c) if s.input_buffer.len() < 80 => s.input_buffer.push(c),
                _ => {}
            },

            InputMode::NameNetwork => match key.code {
                KeyCode::Enter => {
                    let name = s.input_buffer.trim().to_string();
                    s.input_mode = InputMode::Normal;
                    s.input_buffer.clear();
                    if let (Some(key), Some(b)) = (s.baseline_key.clone(), s.baseline.as_mut()) {
                        // Update the in-memory copy immediately for display;
                        // the file write happens off the key path.
                        b.name = if name.is_empty() {
                            None
                        } else {
                            Some(name.clone())
                        };
                        let label = b.label.clone();
                        side = Side::NameNetwork { key, label, name };
                    }
                }
                KeyCode::Esc => {
                    s.input_mode = InputMode::Normal;
                    s.input_buffer.clear();
                }
                KeyCode::Backspace => {
                    s.input_buffer.pop();
                }
                KeyCode::Char(c) if s.input_buffer.len() < 40 => s.input_buffer.push(c),
                _ => {}
            },

            // --- help / triage / events overlays: swallow most keys. Each
            // overlay's own key toggles it and switches from the others, so
            // flipping between them never needs an Esc in between.
            InputMode::Normal if s.overlay != Overlay::None => match key.code {
                KeyCode::Char('q') => s.should_quit = true,
                KeyCode::Char('c') if ctrl => s.should_quit = true,
                // Global, overlays included — before the Egress 'r' arm.
                KeyCode::Char('r') if ctrl => {
                    s.input_buffer.clear();
                    s.input_mode = InputMode::ConfirmReset;
                }
                KeyCode::Esc => {
                    // From an overlay floating above the zoom (analysis,
                    // whois), Esc peels one layer: back to the zoomed table,
                    // not all the way out.
                    s.overlay = if s.zoom_behind && s.overlay != Overlay::Zoom {
                        Overlay::Zoom
                    } else {
                        Overlay::None
                    };
                    s.zoom_behind = false;
                }
                KeyCode::Char('?') => {
                    s.overlay = if s.overlay == Overlay::Help {
                        Overlay::None
                    } else {
                        Overlay::Help
                    };
                }
                KeyCode::Char('y') => {
                    s.triage_scroll = 0;
                    s.overlay = match s.overlay {
                        // Over the zoom the analysis floats on top — the
                        // zoomed table stays drawn behind it, and closing
                        // the analysis lands back on it.
                        Overlay::Zoom => {
                            s.zoom_behind = true;
                            Overlay::Triage
                        }
                        Overlay::Triage if s.zoom_behind => {
                            s.zoom_behind = false;
                            Overlay::Zoom
                        }
                        Overlay::Triage => Overlay::None,
                        _ => Overlay::Triage,
                    };
                }
                // The support bundle works from any overlay — reading the
                // zoomed table or the analysis is exactly when the evidence
                // worth sending is on screen.
                KeyCode::Char('D') => side = Side::DumpBundle(Box::new(s.clone())),
                KeyCode::Char('e') => {
                    s.overlay = if s.overlay == Overlay::Events {
                        Overlay::None
                    } else {
                        s.events_scroll = 0;
                        Overlay::Events
                    };
                }
                KeyCode::Char('L') => {
                    s.overlay = if s.overlay == Overlay::Locations {
                        Overlay::None
                    } else {
                        s.locations = None;
                        s.locations_sel = 0;
                        side = Side::LoadLocations;
                        Overlay::Locations
                    };
                }
                KeyCode::Char('c') => {
                    s.overlay = if s.overlay == Overlay::Egress {
                        Overlay::None
                    } else {
                        // A fresh scan each time it is opened unless one is
                        // still running or is under a minute old — the answer
                        // is about this network, and networks change.
                        let stale = s
                            .egress
                            .as_ref()
                            .is_none_or(|e| !e.running && e.started.elapsed().as_secs() > 60);
                        if stale {
                            side = Side::EgressScan;
                        }
                        Overlay::Egress
                    };
                }
                // Re-run the scan from inside the overlay.
                KeyCode::Char('r') if s.overlay == Overlay::Egress => {
                    if s.egress.as_ref().is_none_or(|e| !e.running) {
                        side = Side::EgressScan;
                    }
                }
                KeyCode::Char('W') => {
                    s.overlay = if s.overlay == Overlay::Whois {
                        // Whois asked from the zoomed table floats above it;
                        // closing lands back on the zoom, not the split view.
                        if s.zoom_behind {
                            s.zoom_behind = false;
                            Overlay::Zoom
                        } else {
                            Overlay::None
                        }
                    } else if let Some(addr) = s.selected_addr() {
                        if s.overlay == Overlay::Zoom {
                            s.zoom_behind = true;
                        }
                        s.whois_scroll = 0;
                        side = Side::Whois(addr);
                        Overlay::Whois
                    } else {
                        s.overlay
                    };
                }
                // The routing table toggles from any overlay too: reading the
                // analysis ("nothing routes off the LAN") is exactly when the
                // table is wanted as evidence.
                KeyCode::Char('T') => {
                    s.overlay = if s.overlay == Overlay::Routes {
                        Overlay::None
                    } else {
                        s.routes = None; // show "reading…" while it loads
                        s.routes_scroll = 0;
                        side = Side::LoadRoutes;
                        Overlay::Routes
                    };
                }
                KeyCode::Char('r') if s.overlay == Overlay::Routes => {
                    s.routes = None;
                    side = Side::LoadRoutes;
                }
                KeyCode::Up | KeyCode::Char('k') if s.overlay == Overlay::Routes => {
                    s.routes_scroll = s.routes_scroll.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') if s.overlay == Overlay::Routes => {
                    s.routes_scroll = s.routes_scroll.saturating_add(1);
                }
                KeyCode::PageUp if s.overlay == Overlay::Routes => {
                    s.routes_scroll = s.routes_scroll.saturating_sub(10);
                }
                KeyCode::PageDown if s.overlay == Overlay::Routes => {
                    s.routes_scroll = s.routes_scroll.saturating_add(10);
                }
                // A marker can be dropped with an overlay up too — reading
                // the events list is exactly when one realises it is needed.
                KeyCode::Char('M') => {
                    s.input_buffer.clear();
                    s.input_mode = InputMode::Marker;
                }
                // The zoom's own key closes it; its cursor keys walk the
                // zoomed table with the same order (sort + pins) it draws,
                // and n cycles which table is zoomed, as it does unzoomed.
                // The speed-test keys stay live too — watching the history
                // zoomed is exactly when one wants to run another.
                KeyCode::Char('z') if s.overlay == Overlay::Zoom => s.overlay = Overlay::None,
                KeyCode::Char('s')
                    if s.overlay == Overlay::Zoom
                        && s.speedtest_enabled
                        && !matches!(s.speedtest.status, SpeedStatus::Running) =>
                {
                    s.speedtest.begin();
                    side = Side::Speedtest;
                }
                KeyCode::Char('v') if s.overlay == Overlay::Zoom => {
                    let n = s.speedtest_provider_names.len();
                    if n > 0 {
                        s.speedtest_provider_idx = (s.speedtest_provider_idx + 1) % n;
                        side = Side::SaveProvider(
                            s.speedtest_provider_names[s.speedtest_provider_idx].clone(),
                        );
                    }
                }
                KeyCode::Char('n') if s.overlay == Overlay::Zoom => {
                    s.zoom_view = match s.zoom_view {
                        app::ZoomView::Processes => app::ZoomView::Remotes,
                        app::ZoomView::Remotes => app::ZoomView::Speedtests,
                        app::ZoomView::Speedtests => app::ZoomView::Processes,
                    };
                    // The underlying selection follows, so closing the zoom
                    // lands on the table that was zoomed and reopening zooms
                    // it again — with the sort and column cursor swapped
                    // alongside, exactly as the unzoomed 'n' does.
                    let (view, pane) = match s.zoom_view {
                        app::ZoomView::Processes => (BwView::Processes, SubPane::Primary),
                        app::ZoomView::Remotes => (BwView::Remotes, SubPane::Primary),
                        app::ZoomView::Speedtests => (s.bw_view, SubPane::Secondary),
                    };
                    if view != s.bw_view {
                        let st: &mut AppState = &mut s;
                        std::mem::swap(&mut st.bw_sort, &mut st.bw_sort_other);
                        std::mem::swap(&mut st.bw_col, &mut st.bw_col_other);
                    }
                    s.bw_view = view;
                    s.sub_pane = pane;
                    if s.zoom_view == app::ZoomView::Processes {
                        side = Side::LoadProcDetails(s.processes.iter().map(|p| p.pid).collect());
                    }
                }
                KeyCode::Up | KeyCode::Char('k') if s.overlay == Overlay::Zoom => {
                    zoom_move(&mut s, -1);
                }
                KeyCode::Down | KeyCode::Char('j') if s.overlay == Overlay::Zoom => {
                    zoom_move(&mut s, 1);
                }
                KeyCode::PageUp if s.overlay == Overlay::Zoom => zoom_move(&mut s, -10),
                KeyCode::PageDown if s.overlay == Overlay::Zoom => zoom_move(&mut s, 10),
                // Deleting a bad result works zoomed too — the zoom is where
                // one actually reads the history closely enough to curate it.
                KeyCode::Char('d') | KeyCode::Delete
                    if s.overlay == Overlay::Zoom && s.zoom_view == app::ZoomView::Speedtests =>
                {
                    side = delete_selected_speedtest(&mut s);
                }
                // The zoomed talkers sort exactly like their compact versions:
                // ←/→ move the column cursor, Enter sorts and flips. The
                // speed-test history stays chronological.
                KeyCode::Left
                    if s.overlay == Overlay::Zoom && s.zoom_view != app::ZoomView::Speedtests =>
                {
                    s.bw_col = s.bw_col.saturating_sub(1);
                }
                KeyCode::Right
                    if s.overlay == Overlay::Zoom && s.zoom_view != app::ZoomView::Speedtests =>
                {
                    s.bw_col = (s.bw_col + 1).min(6);
                }
                KeyCode::Enter
                    if s.overlay == Overlay::Zoom && s.zoom_view != app::ZoomView::Speedtests =>
                {
                    let col = s.bw_col;
                    s.bw_sort = match s.bw_sort {
                        Some((c, desc)) if c == col => Some((c, !desc)),
                        _ => Some((col, col != 0)), // name asc, metrics desc
                    };
                }
                KeyCode::Char('o')
                    if s.overlay == Overlay::Zoom && s.zoom_view != app::ZoomView::Speedtests =>
                {
                    toggle_follow(&mut s);
                }
                KeyCode::Up | KeyCode::Char('k') if s.overlay == Overlay::Whois => {
                    s.whois_scroll = s.whois_scroll.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') if s.overlay == Overlay::Whois => {
                    s.whois_scroll += 1; // clamped at draw time to the content
                }
                KeyCode::PageUp if s.overlay == Overlay::Whois => {
                    s.whois_scroll = s.whois_scroll.saturating_sub(10);
                }
                KeyCode::PageDown if s.overlay == Overlay::Whois => {
                    s.whois_scroll += 10; // clamped at draw time to the content
                }
                // Scroll the analysis: a network change can raise more
                // findings than a terminal is tall.
                KeyCode::Up | KeyCode::Char('k') if s.overlay == Overlay::Triage => {
                    s.triage_scroll = s.triage_scroll.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') if s.overlay == Overlay::Triage => {
                    s.triage_scroll += 1; // clamped at draw time to the content
                }
                KeyCode::PageUp if s.overlay == Overlay::Triage => {
                    s.triage_scroll = s.triage_scroll.saturating_sub(10);
                }
                KeyCode::PageDown if s.overlay == Overlay::Triage => {
                    s.triage_scroll += 10; // clamped at draw time to the content
                }
                // Scroll the timeline; clamped so it can't run past the oldest.
                KeyCode::Up | KeyCode::Char('k') if s.overlay == Overlay::Events => {
                    s.events_scroll = (s.events_scroll + 1).min(s.events.len().saturating_sub(1));
                }
                KeyCode::Down | KeyCode::Char('j') if s.overlay == Overlay::Events => {
                    s.events_scroll = s.events_scroll.saturating_sub(1);
                }
                KeyCode::PageUp if s.overlay == Overlay::Events => {
                    s.events_scroll = (s.events_scroll + 10).min(s.events.len().saturating_sub(1));
                }
                KeyCode::PageDown if s.overlay == Overlay::Events => {
                    s.events_scroll = s.events_scroll.saturating_sub(10);
                }
                // Clear the timeline: a busy session buries the events that
                // matter. Capital C — a slip of the finger should not wipe
                // the record. The session counter in the title stays honest.
                KeyCode::Char('C') if s.overlay == Overlay::Events => {
                    s.events.clear();
                    s.events_scroll = 0;
                }
                // Export the timeline. An empty one is not worth a file.
                KeyCode::Char('x') if s.overlay == Overlay::Events => {
                    if s.events.is_empty() {
                        s.notice = Some("no events to export yet".to_string());
                    } else {
                        side = Side::ExportEvents(s.events.iter().cloned().collect());
                    }
                }
                // Scroll the locations list.
                // Rename the selected location — any of them, not just the
                // current network; a name given on the wrong day is common.
                KeyCode::Enter | KeyCode::Char('N') if s.overlay == Overlay::Locations => {
                    let picked = s
                        .locations_view()
                        .and_then(|all| all.get(s.locations_sel).cloned())
                        .map(|(key, b)| (key, b.label.clone(), b.name.clone()));
                    if let Some((key, label, name)) = picked {
                        s.rename_target = Some((key, label));
                        s.input_buffer = name.unwrap_or_default();
                        s.input_mode = InputMode::RenameLocation;
                    }
                }
                // Delete the selected location — its learned baseline and its
                // place in the list. Deleting the network we are *on* means
                // "forget what you learned here", not "stop tracking where I
                // am": it comes straight back as a blank entry that keeps
                // only its identity (label, medium) and starts learning anew.
                KeyCode::Char('d') | KeyCode::Delete if s.overlay == Overlay::Locations => {
                    let picked = s
                        .locations_view()
                        .and_then(|all| all.get(s.locations_sel).cloned())
                        .map(|(key, b)| (key, b.display_name().to_string()));
                    if let Some((key, name)) = picked {
                        // The delete and the re-add are instantaneous, so
                        // without a word the key press looks ignored.
                        if s.baseline_key.as_deref() == Some(key.as_str()) {
                            s.baseline = s.baseline.take().map(|old| baseline::Baseline {
                                label: old.label,
                                medium: old.medium,
                                ..Default::default()
                            });
                            s.notice = Some(format!(
                                "{name} deleted — you are still on it, so it is back as a blank entry learning from scratch"
                            ));
                        } else {
                            s.notice = Some(format!("{name} deleted"));
                        }
                        if let Some(list) = s.locations.as_mut() {
                            list.retain(|(k, _)| k != &key);
                        }
                        let last = s
                            .locations_view()
                            .map(|l| l.len().saturating_sub(1))
                            .unwrap_or(0);
                        s.locations_sel = s.locations_sel.min(last);
                        side = Side::ForgetLocation(key);
                    }
                }
                // Pause works from any overlay — reading a zoomed table or
                // the analysis is exactly when one wants the numbers to hold
                // still. Shift+P everywhere, so plain 'p' stays pin on the
                // talkers lists without a mode-dependent surprise.
                KeyCode::Char('P') => s.paused = !s.paused,
                // Pinning works in the zoomed talkers too — same keys as the
                // compact lists they magnify.
                KeyCode::Char('p') | KeyCode::Char('u')
                    if s.overlay == Overlay::Zoom
                        && s.zoom_view != app::ZoomView::Speedtests
                        && s.proc_status == app::ProcStatus::Supported =>
                {
                    let pin = key.code == KeyCode::Char('p');
                    match s.zoom_view {
                        app::ZoomView::Remotes => {
                            if let Some(addr) = s.remote_cursor().1.map(|i| s.remotes[i].addr) {
                                s.pinned_remotes.retain(|a| *a != addr);
                                if pin {
                                    s.pinned_remotes.push(addr);
                                }
                            }
                        }
                        _ => {
                            if let Some(name) =
                                s.proc_cursor().1.map(|i| s.processes[i].name.clone())
                            {
                                s.pinned_procs.retain(|n| *n != name);
                                if pin {
                                    s.pinned_procs.push(name);
                                }
                            }
                        }
                    }
                }
                KeyCode::Up | KeyCode::Char('k') if s.overlay == Overlay::Locations => {
                    s.locations_sel = s.locations_sel.saturating_sub(1);
                }
                KeyCode::PageUp if s.overlay == Overlay::Locations => {
                    s.locations_sel = s.locations_sel.saturating_sub(10);
                }
                KeyCode::Down | KeyCode::Char('j') | KeyCode::PageDown
                    if s.overlay == Overlay::Locations =>
                {
                    let step = if key.code == KeyCode::PageDown { 10 } else { 1 };
                    let last = s
                        .locations_view()
                        .map(|l| l.len().saturating_sub(1))
                        .unwrap_or(0);
                    s.locations_sel = (s.locations_sel + step).min(last);
                }
                _ => {}
            },

            // --- normal navigation ---
            InputMode::Normal => match key.code {
                KeyCode::Char('q') => s.should_quit = true,
                KeyCode::Char('c') if ctrl => s.should_quit = true,
                // Ctrl+R (global): total reset — erase all config and stored
                // data. Ordered before the plain 'r' arms, which would
                // otherwise swallow the modified press. Confirmation is a
                // typed word, not a keystroke: this deletes everything.
                KeyCode::Char('r') if ctrl => {
                    s.input_buffer.clear();
                    s.input_mode = InputMode::ConfirmReset;
                }
                // Esc backs out of whatever view you're in — it must never quit,
                // since reaching for it to leave a sub-view would kill the app.
                KeyCode::Esc => {
                    if s.fullscreen {
                        s.fullscreen = false;
                    } else if s.quality_view != QualityView::Graph {
                        s.quality_view = QualityView::Graph;
                    }
                }
                KeyCode::Char('?') => s.overlay = Overlay::Help,
                // 'y' answers "why does the verdict say that": the triage ladder.
                KeyCode::Char('y') => {
                    s.triage_scroll = 0;
                    s.overlay = Overlay::Triage;
                }
                // 'c' scans outbound ports and shows the table.
                KeyCode::Char('c') => {
                    let stale = s
                        .egress
                        .as_ref()
                        .is_none_or(|e| !e.running && e.started.elapsed().as_secs() > 60);
                    if stale {
                        side = Side::EgressScan;
                    }
                    s.overlay = Overlay::Egress;
                }
                // 'e' opens the session timeline.
                KeyCode::Char('e') => {
                    s.events_scroll = 0;
                    s.overlay = Overlay::Events;
                }
                KeyCode::Tab => s.focus = next_panel(s.focus),
                KeyCode::BackTab => s.focus = prev_panel(s.focus),
                KeyCode::Char('f') => s.fullscreen = !s.fullscreen,
                // On the talkers lists, 'p' pins the row under the cursor to
                // the top and 'u' unpins it — a session-only watch list, so
                // one row can be tracked while the rest keeps re-sorting.
                // (Pause is Shift+P, so the two never collide.)
                KeyCode::Char('p') | KeyCode::Char('u')
                    if s.focus == Panel::Bandwidth
                        && s.sub_pane == SubPane::Primary
                        && s.proc_status == app::ProcStatus::Supported =>
                {
                    let pin = key.code == KeyCode::Char('p');
                    match s.bw_view {
                        BwView::Remotes => {
                            if let Some(addr) = s.remote_cursor().1.map(|i| s.remotes[i].addr) {
                                s.pinned_remotes.retain(|a| *a != addr);
                                if pin {
                                    s.pinned_remotes.push(addr);
                                }
                            }
                        }
                        BwView::Processes => {
                            if let Some(name) =
                                s.proc_cursor().1.map(|i| s.processes[i].name.clone())
                            {
                                s.pinned_procs.retain(|n| *n != name);
                                if pin {
                                    s.pinned_procs.push(name);
                                }
                            }
                        }
                    }
                }
                // 'o' follows the row under the cursor: the cursor (and the
                // scroll) stay with that row as the sort re-ranks it; again
                // to release. The default is deliberately positional —
                // watching the top of the table is the common case, and a
                // cursor glued to a re-ranking row drags the view around.
                KeyCode::Char('o')
                    if s.focus == Panel::Bandwidth && s.sub_pane == SubPane::Primary =>
                {
                    toggle_follow(&mut s);
                }
                // Shift+P pauses, everywhere: plain 'p' belongs to pin on the
                // talkers lists, and a key that changes meaning per panel is
                // the confusion this replaces.
                KeyCode::Char('P') => s.paused = !s.paused,
                KeyCode::Char('r') => {
                    s.refresh_at = Some(std::time::Instant::now());
                    side = Side::Refresh;
                }
                KeyCode::Char('w') => s.cycle_window(),
                // 'l' toggles session recording; the logger task acts on this
                // and reports back, so no file I/O happens on the key path.
                KeyCode::Char('l') => s.logging_requested = !s.logging_requested,
                // Shift+D dumps a support bundle: the visual-session
                // counterpart of --doctor, for the person who was asked to
                // "run octomon and send me what it saw".
                KeyCode::Char('D') => side = Side::DumpBundle(Box::new(s.clone())),
                // Shift+R resets the focused panel's accumulated data.
                KeyCode::Char('R') => reset_panel(&mut s),
                // Shift+L lists every stored network location, from anywhere.
                KeyCode::Char('L') => {
                    s.locations = None;
                    s.locations_sel = 0;
                    s.overlay = Overlay::Locations;
                    side = Side::LoadLocations;
                }
                // Shift+T shows the OS routing table, from anywhere: "what
                // does the kernel actually do with a packet" — split tunnels,
                // 0.0.0.0/1 VPN overrides, a missing default route.
                KeyCode::Char('T') => {
                    s.routes = None;
                    s.routes_scroll = 0;
                    s.overlay = Overlay::Routes;
                    side = Side::LoadRoutes;
                }
                // Shift+N names the current network's baseline ("Home"…).
                // Pre-filled with the existing name so editing beats retyping.
                KeyCode::Char('N') if s.baseline_key.is_some() => {
                    s.input_buffer = s
                        .baseline
                        .as_ref()
                        .and_then(|b| b.name.clone())
                        .unwrap_or_default();
                    s.input_mode = InputMode::NameNetwork;
                }
                // Shift+M drops a marker into the event timeline: "at this
                // moment, this is what I was experiencing" — the one thing
                // the probes cannot record on their own.
                KeyCode::Char('M') => {
                    s.input_buffer.clear();
                    s.input_mode = InputMode::Marker;
                }
                // z zooms the active Bandwidth table across the panel's whole
                // bottom band (the graphs stay put): every column, full
                // names, per-process detail — the answer to "what is that
                // thing using my bandwidth?". From the split view it goes
                // full-screen first; the band only exists there.
                KeyCode::Char('z') if s.focus == Panel::Bandwidth => {
                    s.zoom_view = if s.fullscreen && s.sub_pane == SubPane::Secondary {
                        app::ZoomView::Speedtests
                    } else {
                        match s.bw_view {
                            BwView::Processes => app::ZoomView::Processes,
                            BwView::Remotes => app::ZoomView::Remotes,
                        }
                    };
                    if s.zoom_view == app::ZoomView::Processes {
                        // What the OS knows about each pid arrives async; the
                        // view shows "looking up…" until it lands.
                        side = Side::LoadProcDetails(s.processes.iter().map(|p| p.pid).collect());
                    }
                    s.fullscreen = true;
                    s.overlay = Overlay::Zoom;
                }
                // 'v' cycles the speed-test provider (Bandwidth panel) + persists.
                KeyCode::Char('v') if s.focus == Panel::Bandwidth => {
                    let n = s.speedtest_provider_names.len();
                    if n > 0 {
                        s.speedtest_provider_idx = (s.speedtest_provider_idx + 1) % n;
                        side = Side::SaveProvider(
                            s.speedtest_provider_names[s.speedtest_provider_idx].clone(),
                        );
                    }
                }
                // Delete the selected target. A user-added one is also
                // forgotten in the config, or it would be back next start;
                // discovered targets never reached the file.
                KeyCode::Char('d') | KeyCode::Delete if s.focus == Panel::Quality => {
                    if let Some(t) = s.targets.get(s.selected)
                        && !t.discovered
                    {
                        side = Side::ForgetTarget(t.addr);
                    }
                    delete_selected_target(&mut s);
                }
                // Delete the selected speed test from the history (and its
                // file): a test run against a rate-limited backend or in the
                // middle of an outage poisons every later comparison.
                KeyCode::Char('d') | KeyCode::Delete
                    if s.focus == Panel::Bandwidth && s.sub_pane == SubPane::Secondary =>
                {
                    side = delete_selected_speedtest(&mut s);
                }
                // Bandwidth: move the top-talkers column cursor and sort.
                KeyCode::Left if s.focus == Panel::Bandwidth => {
                    s.bw_col = s.bw_col.saturating_sub(1);
                }
                KeyCode::Right if s.focus == Panel::Bandwidth => {
                    // Both tables have seven columns; see `AppState::bw_col`.
                    s.bw_col = (s.bw_col + 1).min(6);
                }
                // Bandwidth: one key walks every lower pane — processes, the
                // remote addresses they talk to, and (full-screen) the speed
                // history. Moving between the two talkers tables resets the
                // sort: the columns differ.
                KeyCode::Char('n') if s.focus == Panel::Bandwidth => {
                    let (view, pane) = match (s.bw_view, s.sub_pane) {
                        (BwView::Processes, SubPane::Primary) => {
                            (BwView::Remotes, SubPane::Primary)
                        }
                        (BwView::Remotes, SubPane::Primary) if s.fullscreen => {
                            (BwView::Remotes, SubPane::Secondary)
                        }
                        _ => (BwView::Processes, SubPane::Primary),
                    };
                    // Each table keeps its own sort and column cursor: swap
                    // them in and out rather than resetting.
                    if view != s.bw_view {
                        let st: &mut AppState = &mut s;
                        std::mem::swap(&mut st.bw_sort, &mut st.bw_sort_other);
                        std::mem::swap(&mut st.bw_col, &mut st.bw_col_other);
                    }
                    s.bw_view = view;
                    s.sub_pane = pane;
                }
                // Only while a talkers table holds the cursor: the speed-test
                // history is chronological and Enter must not reach through
                // it to re-sort a table the cursor is not even on.
                KeyCode::Enter if s.focus == Panel::Bandwidth && s.sub_pane == SubPane::Primary => {
                    let col = s.bw_col;
                    s.bw_sort = match s.bw_sort {
                        Some((c, desc)) if c == col => Some((c, !desc)),
                        _ => Some((col, col != 0)), // name asc, metrics desc
                    };
                }
                KeyCode::Char('s')
                    if s.speedtest_enabled
                        && !matches!(s.speedtest.status, SpeedStatus::Running) =>
                {
                    s.speedtest.begin();
                    side = Side::Speedtest;
                }
                // 'n' moves between sub-panes of the focused panel (Tab is
                // already taken by the four main panels).
                KeyCode::Char('n') if s.has_sub_pane() => {
                    s.sub_pane = match s.sub_pane {
                        SubPane::Primary => SubPane::Secondary,
                        SubPane::Secondary => SubPane::Primary,
                    };
                }
                // Quality-panel actions. With a monitored hop selected, the add
                // prompt starts pre-filled with it — the usual reason to look at
                // a hop is to start watching it properly.
                KeyCode::Char('a') if s.focus == Panel::Quality => {
                    s.input_buffer = s
                        .selected_hop()
                        .and_then(|h| h.addr)
                        .map(|a| a.to_string())
                        .unwrap_or_default();
                    s.input_mode = InputMode::AddTarget;
                }
                // …and a remote address in the bandwidth panel: "what is that
                // host and how is my path to it" is the natural next question.
                KeyCode::Char('a') if s.selected_remote().is_some() => {
                    s.input_buffer = s.selected_remote().map(|r| r.addr.to_string()).unwrap();
                    s.input_mode = InputMode::AddTarget;
                }
                KeyCode::Up | KeyCode::Char('k') => move_cursor(&mut s, -1),
                KeyCode::Down | KeyCode::Char('j') => move_cursor(&mut s, 1),
                KeyCode::PageUp => move_cursor(&mut s, -10),
                KeyCode::PageDown => move_cursor(&mut s, 10),
                // ←/→ move the column cursor; Enter sorts by it (Space toggles).
                KeyCode::Left if s.focus == Panel::Quality => {
                    s.q_col = s.q_col.saturating_sub(1);
                }
                KeyCode::Right if s.focus == Panel::Quality => {
                    s.q_col = (s.q_col + 1).min(6);
                }
                // ←/→ walk the panel's addresses one at a time (the resolvers
                // sit side by side, so sideways is natural there); ↑/↓ hop
                // between rows via move_cursor.
                KeyCode::Left if s.focus == Panel::NetInfo && s.sub_pane == SubPane::Primary => {
                    s.net_sel = s.net_sel.saturating_sub(1);
                }
                KeyCode::Right if s.focus == Panel::NetInfo && s.sub_pane == SubPane::Primary => {
                    let last = s.netinfo_addrs().len().saturating_sub(1);
                    s.net_sel = (s.net_sel + 1).min(last);
                }
                // In the history pane, Enter grows the selected entry's
                // detail block to its full length — the fixed slice can hold
                // less than a resolver change carries — and the list yields
                // the rows. Enter again collapses back.
                KeyCode::Enter if s.focus == Panel::NetInfo && s.sub_pane == SubPane::Secondary => {
                    s.net_detail_expanded = !s.net_detail_expanded;
                }
                KeyCode::Enter if s.focus == Panel::Quality => {
                    let col = s.q_col;
                    s.q_sort = match s.q_sort {
                        // Same column again flips the direction, as the
                        // Bandwidth tables do.
                        Some((c, desc)) if c == col => Some((c, !desc)),
                        _ => Some((col, col != 0)), // name asc, metrics desc
                    };
                }
                // 'g' graphs the selected target (and leaves the path views).
                KeyCode::Char('g') if s.focus == Panel::Quality => {
                    s.graph_target = s.selected;
                    s.quality_view = QualityView::Graph;
                }
                // Run a traceroute to the selected target.
                KeyCode::Char('t') if s.focus == Panel::Quality => {
                    let running = s.traceroute.as_ref().is_some_and(|t| t.running);
                    if !running && let Some(t) = s.targets.get(s.selected) {
                        let (addr, label) = (t.addr, t.label.clone());
                        s.quality_view = QualityView::Traceroute;
                        side = Side::Traceroute(addr, label);
                    }
                }
                // Shift+W asks the registry who owns the selected address — a
                // target, or the hop under the cursor in the path monitor. That
                // is the question a bad hop raises: whose router is it?
                KeyCode::Char('W')
                    if matches!(s.focus, Panel::Quality | Panel::Bandwidth | Panel::NetInfo) =>
                {
                    if let Some(addr) = s.selected_addr() {
                        s.whois_scroll = 0;
                        s.overlay = Overlay::Whois;
                        side = Side::Whois(addr);
                    }
                }
                // 'm' monitors every hop to the selected target, continuously.
                // Pressing it again while already monitoring that destination
                // just returns to the view rather than restarting the stats.
                KeyCode::Char('m') if s.focus == Panel::Quality => {
                    if let Some(t) = s.targets.get(s.selected) {
                        let (addr, label) = (t.addr, t.label.clone());
                        let already = s.hop_monitor.as_ref().is_some_and(|m| m.dest == addr);
                        s.quality_view = QualityView::HopMonitor;
                        // The web strip follows the monitored target too — the
                        // point of monitoring one is that it's the one you care
                        // about right now.
                        s.graph_target = s.selected;
                        if !already {
                            side = Side::HopMonitor(addr, label);
                        }
                    }
                }
                _ => {}
            },
        }

        // The secondary pane can disappear under the cursor -- leaving
        // full-screen, or switching away from the path monitor -- and a cursor
        // parked in a pane that is no longer drawn is invisible.
        if !s.has_sub_pane() {
            s.sub_pane = SubPane::Primary;
        }
        // The zoom only survives beneath the analysis; switching to any other
        // overlay (or to none) drops the promise to return to it.
        if !matches!(s.overlay, Overlay::Zoom | Overlay::Triage) {
            s.zoom_behind = false;
        }
        s.speed_sel = s.speed_sel.min(s.speed_history.len().saturating_sub(1));
    }

    match side {
        Side::None => {}
        Side::Speedtest => ctx.speedtest_trigger.notify_one(),
        Side::Refresh => ctx.netinfo_refresh.notify_one(),
        Side::AddTarget(input) => {
            if ctx.ping_clients.available() {
                tokio::spawn(add_target(
                    ctx.state.clone(),
                    ctx.ping_clients.clone(),
                    ctx.cfg.clone(),
                    input,
                ));
            } else {
                ctx.state.lock().unwrap().notice = Some("ICMP unavailable".to_string());
            }
        }
        Side::Traceroute(addr, label) => {
            collectors::traceroute::start(ctx.state.clone(), addr, label);
        }
        Side::HopMonitor(addr, label) => {
            if ctx.ping_clients.available() {
                collectors::hopmon::start(
                    ctx.state.clone(),
                    ctx.ping_clients.clone(),
                    ctx.cfg.clone(),
                    addr,
                    label,
                );
            } else {
                ctx.state.lock().unwrap().notice = Some("ICMP unavailable".to_string());
            }
        }
        Side::Whois(addr) => collectors::whois::start(ctx.state.clone(), addr),
        Side::LoadRoutes => {
            let state = ctx.state.clone();
            tokio::spawn(async move {
                let lines = tokio::task::spawn_blocking(platform::routing_table)
                    .await
                    .unwrap_or_default();
                state.lock().unwrap().routes = Some(lines);
            });
        }
        Side::SaveProvider(name) => {
            tokio::task::spawn_blocking(move || config::Config::persist_provider(&name));
        }
        Side::ForgetTarget(addr) => {
            tokio::task::spawn_blocking(move || config::Config::persist_target_removed(addr));
        }
        Side::ForgetSpeedtest(rec) => {
            tokio::task::spawn_blocking(move || store::forget(&rec));
        }
        Side::LoadProcDetails(pids) => {
            let state = ctx.state.clone();
            tokio::task::spawn_blocking(move || {
                use chrono::TimeZone;
                use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
                let mut sys = System::new();
                sys.refresh_processes_specifics(
                    ProcessesToUpdate::All,
                    true,
                    ProcessRefreshKind::nothing()
                        .with_exe(UpdateKind::Always)
                        .with_cmd(UpdateKind::Always)
                        .with_user(UpdateKind::Always),
                );
                let users = sysinfo::Users::new_with_refreshed_list();
                let mut map = std::collections::HashMap::new();
                for pid in pids {
                    if let Some(p) = sys.process(sysinfo::Pid::from_u32(pid)) {
                        let user = p
                            .user_id()
                            .and_then(|uid| users.get_user_by_id(uid))
                            .map(|u| u.name().to_string())
                            .unwrap_or_default();
                        // "name (pid)"; empty if the parent itself has exited.
                        let parent = p
                            .parent()
                            .and_then(|pp| sys.process(pp).map(|pr| (pp, pr)))
                            .map(|(pp, pr)| format!("{} ({pp})", pr.name().to_string_lossy()))
                            .unwrap_or_default();
                        let started = chrono::Local
                            .timestamp_opt(p.start_time() as i64, 0)
                            .single()
                            .map(|dt| dt.format("%m-%d %H:%M").to_string())
                            .unwrap_or_default();
                        map.insert(
                            pid,
                            app::ProcDetail {
                                exe: p.exe().map(|x| x.display().to_string()).unwrap_or_default(),
                                cmd: p
                                    .cmd()
                                    .iter()
                                    .map(|c| c.to_string_lossy())
                                    .collect::<Vec<_>>()
                                    .join(" "),
                                user,
                                parent,
                                started,
                            },
                        );
                    }
                }
                state.lock().unwrap().proc_details = map;
            });
        }
        Side::ForgetLocation(key) => {
            tokio::task::spawn_blocking(move || baseline::forget(&key));
        }
        Side::TotalReset => {
            let state = ctx.state.clone();
            tokio::task::spawn_blocking(move || {
                config::Config::erase();
                store::erase();
                state.lock().unwrap().notice_event(
                    verdict::Severity::Info,
                    app::EventCategory::Logging,
                    "TOTAL RESET — all config and stored data erased; restart octomon for a fully fresh start"
                        .to_string(),
                );
            });
        }
        Side::NameNetwork { key, label, name } => {
            tokio::task::spawn_blocking(move || baseline::name_network(&key, &label, &name));
        }
        Side::LoadLocations => {
            let state = ctx.state.clone();
            tokio::spawn(async move {
                let mut all: Vec<(String, baseline::Baseline)> =
                    tokio::task::spawn_blocking(baseline::load)
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .collect();
                // Most recently seen first (locations_view pins the current
                // network on top regardless). Entries from before the visit
                // stamp existed tie at None and fall back to most-established,
                // then name.
                all.sort_by(|a, b| {
                    b.1.last_seen
                        .cmp(&a.1.last_seen)
                        .then(b.1.samples.cmp(&a.1.samples))
                        .then_with(|| {
                            a.1.display_name()
                                .to_lowercase()
                                .cmp(&b.1.display_name().to_lowercase())
                        })
                });
                state.lock().unwrap().locations = Some(all);
            });
        }
        Side::EgressScan => {
            collectors::egress::start(ctx.state.clone(), ctx.cfg.egress_checks.clone());
        }
        Side::ExportEvents(events) => {
            let state = ctx.state.clone();
            tokio::spawn(async move {
                let n = events.len();
                let result =
                    tokio::task::spawn_blocking(move || collectors::logger::export_events(events))
                        .await
                        .unwrap_or_else(|e| Err(e.to_string()));
                let mut s = state.lock().unwrap();
                // Lands on the timeline as well as the notice, so the file's
                // location is still findable after the notice has gone.
                match result {
                    Ok(path) => s.notice_event(
                        verdict::Severity::Info,
                        app::EventCategory::Logging,
                        format!("exported {n} events → {}", path.display()),
                    ),
                    Err(e) => s.notice_event(
                        verdict::Severity::Info,
                        app::EventCategory::Logging,
                        format!("could not export events: {e}"),
                    ),
                }
            });
        }
        Side::DumpBundle(snap) => {
            let state = ctx.state.clone();
            tokio::spawn(async move {
                let result = tokio::task::spawn_blocking(move || write_bundle(&snap))
                    .await
                    .unwrap_or_else(|e| Err(e.to_string()));
                let mut s = state.lock().unwrap();
                // Lands on the timeline as well as the notice, so the file's
                // location is still findable after the notice has gone.
                match result {
                    Ok(path) => s.notice_event(
                        verdict::Severity::Info,
                        app::EventCategory::Logging,
                        format!(
                            "support bundle → {} — send this file to whoever is helping",
                            path.display()
                        ),
                    ),
                    Err(e) => s.notice_event(
                        verdict::Severity::Info,
                        app::EventCategory::Logging,
                        format!("could not write support bundle: {e}"),
                    ),
                }
            });
        }
    }
}

/// The [D] support bundle: everything a helper needs from a machine they
/// cannot see, in one zip — the full doctor report (unredacted: the raw
/// session logs beside it carry the same addresses anyway), the session's
/// event timeline, the config, and every data file (session recordings,
/// speed history, learned locations, incident history). Written somewhere
/// the person at the keyboard can find (Desktop, else home). Blocking —
/// run it off the UI path.
fn write_bundle(s: &AppState) -> Result<std::path::PathBuf, String> {
    let path = store::bundle_path().ok_or("no home directory")?;
    write_bundle_to(&path, s)?;
    Ok(path)
}

fn write_bundle_to(path: &std::path::Path, s: &AppState) -> Result<(), String> {
    use std::io::Write as _;
    use zip::write::SimpleFileOptions;

    let file = std::fs::File::create(path).map_err(|e| e.to_string())?;
    let mut bundle = zip::ZipWriter::new(file);
    let opt = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    let mut put = |name: &str, bytes: &[u8]| -> Result<(), String> {
        bundle.start_file(name, opt).map_err(|e| e.to_string())?;
        bundle.write_all(bytes).map_err(|e| e.to_string())
    };

    put("report.txt", doctor_report(s, true).0.as_bytes())?;
    // The routing table, verbatim: the first thing a helper asks for when
    // "nothing routes" or a VPN is suspected, and unreconstructable later.
    put(
        "routes.txt",
        (platform::routing_table().join("\n") + "\n").as_bytes(),
    )?;
    put(
        "events.csv",
        collectors::logger::format_events_export(s.events.iter().cloned()).as_bytes(),
    )?;
    // The full talkers tables, not the report's top ten: "which process moved
    // the bytes" is the question a helper asks of a bundle, and the answer is
    // often in row forty.
    if !s.processes.is_empty() {
        put("processes.csv", processes_csv(s).as_bytes())?;
    }
    if !s.remotes.is_empty() {
        put("remotes.csv", remotes_csv(s).as_bytes())?;
    }
    if let Some(cfg) = config::Config::path()
        && let Ok(bytes) = std::fs::read(&cfg)
    {
        put("config/config.toml", &bytes)?;
    }
    // The whole data folder: session log CSVs, speedtests.jsonl,
    // baselines.json (the learned locations), incident history. Unreadable
    // entries are skipped rather than sinking the bundle — a partial bundle
    // still answers questions; no bundle answers none.
    if let Some(dir) = store::data_dir()
        && let Ok(entries) = std::fs::read_dir(dir)
    {
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Ok(bytes) = std::fs::read(&p) else {
                continue;
            };
            put(&format!("data/{name}"), &bytes)?;
        }
    }
    bundle.finish().map_err(|e| e.to_string())?;
    Ok(())
}

/// Every process the attribution has seen this session, one CSV row each —
/// the bundle's answer to "which process moved the bytes", complete where the
/// report's table stops at ten.
fn processes_csv(s: &AppState) -> String {
    use std::fmt::Write as _;
    let mut out =
        String::from("name,pid,down_bytes,up_bytes,total_bytes,share_pct,retx,down_bps,up_bps\n");
    for i in s.process_order() {
        let p = &s.processes[i];
        let _ = writeln!(
            out,
            "{},{},{},{},{},{:.1},{},{:.0},{:.0}",
            collectors::logger::field(&p.name),
            p.pid,
            p.down_bytes,
            p.up_bytes,
            p.total_bytes,
            p.share * 100.0,
            p.retx,
            p.down_bps,
            p.up_bps
        );
    }
    out
}

/// Every remote address seen this session; see [`processes_csv`].
fn remotes_csv(s: &AppState) -> String {
    use std::fmt::Write as _;
    let mut out = String::from(
        "remote,port,ports_seen,process,down_bytes,up_bytes,total_bytes,share_pct,down_bps,up_bps\n",
    );
    for i in s.remote_order() {
        let r = &s.remotes[i];
        let _ = writeln!(
            out,
            "{},{},{},{},{},{},{},{:.1},{:.0},{:.0}",
            r.addr,
            r.port,
            r.ports,
            collectors::logger::field(&r.process),
            r.down_bytes,
            r.up_bytes,
            r.total_bytes,
            r.share * 100.0,
            r.down_bps,
            r.up_bps
        );
    }
    out
}

/// Resolve a user-entered IP or DNS name, append it as a target, and start
/// pinging it. Reports failures via the transient `notice`.
async fn add_target(
    state: Arc<Mutex<AppState>>,
    clients: collectors::ping::Clients,
    cfg: Config,
    input: String,
) {
    // Remember whether this was a *name*: names get re-resolved when the
    // network changes (CDNs answer per location) and probed over HTTPS with
    // proper SNI, neither of which a bare IP can offer.
    let (addr, hostname): (IpAddr, Option<String>) = match input.parse() {
        Ok(ip) => (ip, None),
        Err(_) => match tokio::net::lookup_host((input.as_str(), 0)).await {
            Ok(mut addrs) => match addrs.next() {
                Some(sa) => (sa.ip(), Some(input.clone())),
                None => {
                    state.lock().unwrap().notice = Some(format!("no address for {input}"));
                    return;
                }
            },
            Err(_) => {
                state.lock().unwrap().notice = Some(format!("could not resolve {input}"));
                return;
            }
        },
    };

    let id = {
        let mut s = state.lock().unwrap();
        let idx = s.targets.len();
        let mut target = TargetStat::new(input.clone(), addr);
        target.hostname = hostname.clone();
        let id = target.id;
        s.targets.push(target);
        s.refreeze = true;
        s.selected = idx;
        s.graph_target = idx;
        id
    };
    // Added targets survive restarts: remembered in the config file the
    // moment they resolve, and forgotten again when deleted with [d].
    tokio::task::spawn_blocking(move || {
        Config::persist_target_added(&input, addr, hostname.as_deref());
    });
    collectors::ping::spawn_for(state, clients, cfg, id, addr);
}

/// Text dump of the current state for `--check` / debugging.
fn print_snapshot(s: &AppState) {
    print!("{}", strip_control(snapshot_text(s)));
}

/// Drop control characters (other than newline) so an SSID, interface or
/// process name from the environment cannot inject terminal escapes into
/// stdout. The TUI is already protected — ratatui skips control characters
/// when it fills a cell — so this covers only the non-TUI paths, whose output
/// is printed raw and meant to be pasted elsewhere. `--json` needs nothing:
/// serde escapes them.
fn strip_control(text: String) -> String {
    text.chars()
        .filter(|c| *c == '\n' || !c.is_control())
        .collect()
}

/// The measurement report as a string, so `--doctor` can embed and redact it.
#[allow(unused_macros)]
fn snapshot_text(s: &AppState) -> String {
    let mut out = String::new();
    // Shadow `println!` so the many formatting call sites below write into
    // `out` unchanged instead of straight to stdout.
    macro_rules! println {
        () => { out.push('\n') };
        ($($t:tt)*) => {{ use std::fmt::Write as _; let _ = writeln!(out, $($t)*); }};
    }
    println!("== MEASUREMENTS ==");
    let n = s.window_samples();
    println!("\n[Connection Quality]  (window {})", s.window_label());
    let ms = |v: Option<f64>| v.map(|x| format!("{x:.1}")).unwrap_or_else(|| "—".into());
    for t in &s.targets {
        let st = t.stats(n);
        let bloat = t
            .bufferbloat_ms(n)
            .map(|b| format!("{b:+.0}ms"))
            .unwrap_or_else(|| "—".into());
        println!(
            "  {:<12} {:<16} last={:<7} min={:<6} avg={:<6} p95={:<6} max={:<6} jit={:.1} sd={:.1} loss={:.0}% bloat={bloat} ({}/{})",
            t.label,
            t.addr.to_string(),
            ms(t.last_rtt_ms),
            ms(st.min),
            ms(st.mean),
            ms(st.p95),
            ms(st.max),
            t.jitter_ms,
            st.stddev,
            t.recent_loss_pct(n),
            t.recv,
            t.sent
        );
    }

    let tp = &s.throughput;
    println!("\n[Bandwidth] iface={}", tp.iface);
    println!("  down={:.0} B/s   up={:.0} B/s", tp.down_bps, tp.up_bps);
    let st = &s.speedtest;
    let status = match &st.status {
        SpeedStatus::Idle => "idle".to_string(),
        SpeedStatus::Running => "running".to_string(),
        SpeedStatus::Done => "done".to_string(),
        SpeedStatus::Failed(e) => format!("failed: {e}"),
    };
    let lat = match (st.idle_latency_ms, st.loaded_latency_ms) {
        (Some(i), Some(l)) => format!(
            " latency idle={i:.0}ms loaded={l:.0}ms (+{:.0}ms)",
            (l - i).max(0.0)
        ),
        _ => String::new(),
    };
    println!(
        "  speedtest[{status}] via {}: down={} up={}{lat}",
        if st.provider.is_empty() {
            "—"
        } else {
            &st.provider
        },
        st.down_mbps
            .map(|v| format!("{v:.1} Mb/s"))
            .unwrap_or_else(|| "—".into()),
        st.up_mbps
            .map(|v| format!("{v:.1} Mb/s"))
            .unwrap_or_else(|| "—".into()),
    );
    match s.proc_status {
        app::ProcStatus::Supported => {
            println!("  top processes by bytes this session:");
            if s.processes.is_empty() {
                println!("    (no talkers yet)");
            }
            for p in s.processes.iter().take(10) {
                println!(
                    "    {:<20} pid={:<6} ↓{:>12} ↑{:>12} B  {:>3.0}%  now ↓{:>10.0} ↑{:>10.0} B/s  retx={}",
                    p.name,
                    p.pid,
                    p.down_bytes,
                    p.up_bytes,
                    p.share * 100.0,
                    p.down_bps,
                    p.up_bps,
                    p.retx
                );
            }
        }
        app::ProcStatus::Probing => println!("  per-process bandwidth: probing…"),
        app::ProcStatus::Unsupported => println!("  per-process bandwidth: unsupported"),
        app::ProcStatus::NeedsPrivilege => println!(
            "  per-process bandwidth: needs privilege (run elevated, or join \
             \"Performance Log Users\")"
        ),
    }

    let n = &s.netinfo;
    println!("\n[Network]");
    println!(
        "  iface={} ({})  type={} {}",
        n.iface,
        n.iface_label,
        n.medium.label(),
        n.link_detail
    );
    println!("  ipv4={:?}", n.ipv4);
    println!(
        "  mac={}  gateway={} ({})",
        n.mac, n.gateway_ip, n.gateway_mac
    );
    if let Some(t) = n.tunnel_label() {
        println!(
            "  tunnel={t} ({}){}",
            n.tunnel_iface,
            if n.tunnel_is_split {
                " — split route: internet traffic bypasses the LAN gateway"
            } else {
                " — hops beyond the endpoint are encapsulated"
            }
        );
    }
    if let Some((kind, via)) = s.nat_kind() {
        println!("  nat={} (hop 2 is {via})", kind.label());
    }
    if let Some(p) = &s.proxy {
        println!(
            "  proxy={} via-proxy={}",
            p.describe(),
            match &s.http.via_proxy {
                app::FamilyProbe::Ok(ms) => format!("ok {ms:.0}ms"),
                app::FamilyProbe::Fail(r) => format!("fail ({r})"),
                _ => "not probed".to_string(),
            }
        );
    }
    match (&s.pmtu, &s.pmtu_error) {
        (Some(p), _) => println!("  mtu: {}", collectors::pmtu::describe(p)),
        (None, Some(e)) => println!("  mtu: not measured ({e})"),
        (None, None) => {}
    }
    match (s.clock.offset_ms(), &s.clock.ntp_error) {
        (Some(off), _) => println!(
            "  clock offset={:+.3}s via {}",
            off / 1000.0,
            s.clock.source()
        ),
        (None, Some(e)) => println!("  clock: ntp failed ({e}), no http date yet"),
        (None, None) => {}
    }
    println!("  dns={:?}", n.dns);
    for p in &s.dns {
        let rtt = p
            .last_ms
            .map(|v| format!("{v:.1}ms"))
            .unwrap_or_else(|| "—".into());
        let mean = p
            .mean_ms()
            .map(|v| format!("{v:.1}ms"))
            .unwrap_or_else(|| "—".into());
        println!(
            "    resolver {:<16} last={rtt:<8} avg={mean:<8} fail={:.0}% ({}/{}) {}{}{}",
            p.server.to_string(),
            p.fail_pct(),
            p.ok,
            p.sent,
            p.status,
            if p.reference { " [reference]" } else { "" },
            match p.hijack {
                Some(true) => " [REDIRECTS non-existent names]",
                Some(false) => " [nxdomain honest]",
                None => "",
            }
        );
    }
    if let Some(w) = &n.wifi {
        println!(
            "  wifi: ssid={} phy={} ch={} signal={} tx={}",
            w.ssid, w.phy, w.channel, w.rssi, w.tx_rate
        );
        if let Some(c) = w.congestion() {
            println!(
                "  airspace: {} co-channel, {} overlapping, {} networks nearby",
                c.co_channel, c.overlapping, c.total
            );
        }
    }
    let sig = &s.signal;
    if sig.present {
        // Noise is only measured on some platforms; say so rather than print a
        // zero that reads as a measurement.
        let noise = match sig.noise_dbm {
            Some(n) => format!("{n} dBm"),
            None => "n/a".to_string(),
        };
        println!(
            "  live signal: rssi={} dBm  noise={noise}  tx={:.0} Mb/s  ({} samples)",
            sig.rssi_dbm,
            sig.tx_rate_mbps,
            sig.rssi_hist.data.len()
        );
    }

    let v = &s.vitals;
    println!("\n[Machine]");
    println!(
        "  cpu={:.1}%  mem={}/{} MiB  pressure={:.0}%",
        v.cpu_pct,
        v.mem_used / 1_048_576,
        v.mem_total / 1_048_576,
        v.mem_pressure_pct
    );
    // Windows has no load average and sysinfo reports zeros, which read as a
    // permanently idle machine rather than an absent measurement. Matches what
    // the dashboard does with the same figures.
    let load = if cfg!(windows) {
        String::new()
    } else {
        format!("load={:.2} {:.2} {:.2} ", v.load.0, v.load.1, v.load.2)
    };
    println!(
        "  {load}over {} cores  swap={}/{} MiB",
        v.core_count(),
        v.swap_used / 1_048_576,
        v.swap_total / 1_048_576
    );
    if let Some((i, pct)) = v.hottest_core() {
        println!("  hottest core: {} at {pct:.0}%", i + 1);
    }
    if !v.thermal.is_empty() || !v.power_source.is_empty() {
        println!(
            "  thermal={} throttled={} power={}",
            v.thermal, v.throttled, v.power_source
        );
    }
    let e = &s.link_errors;
    println!(
        "  link {}: rx_err={} tx_err={} ({:.3}% of packets, {:.0} pkt/s)",
        e.iface,
        e.rx_err_total,
        e.tx_err_total,
        e.error_pct(),
        e.rx_packets_per_sec + e.tx_packets_per_sec
    );
    out
}

/// The `--doctor` report: verdict first, then this network's learned normal,
/// the raw measurements, and the session's events — with identifying details
/// (SSID, IPs, MACs) redacted unless `--full`, so the default output is safe
/// to paste into a forum or an ISP ticket.
fn doctor_report(s: &AppState, full: bool) -> (String, i32) {
    use std::fmt::Write as _;
    let triage = verdict::evaluate(s);
    let insufficient = verdict::insufficient_reason(s);

    let mut out = String::new();
    let _ = writeln!(
        out,
        "octomon v{} · doctor · {} · {}",
        util::VERSION,
        chrono::Local::now().format("%Y-%m-%d %H:%M"),
        s.netinfo.medium.label(),
    );
    if let Some(err) = &s.icmp_error {
        let _ = writeln!(out, "\n{err}");
    }
    let _ = writeln!(out);
    out.push_str(&verdict::render_text(&triage, insufficient.as_deref()));

    // The location always prints, named or not — knowing WHERE the report was
    // taken (and how established its baseline is) is part of the diagnosis.
    if let Some(b) = s.baseline.as_ref() {
        let _ = writeln!(
            out,
            "\n== NORMAL AT \"{}\"{} ==",
            b.display_name(),
            if b.medium.is_empty() {
                String::new()
            } else {
                format!(" ({})", b.medium)
            }
        );
        let ms = |v: Option<f64>| {
            v.map(|x| format!("~{x:.0}ms"))
                .unwrap_or_else(|| "—".into())
        };
        let _ = writeln!(
            out,
            "  gateway {} · internet {} · DNS {}{}{}",
            ms(b.gateway_ms),
            ms(b.anchor_ms),
            ms(b.dns_ms),
            b.rssi_dbm
                .map(|r| format!(" · rssi ~{r:.0} dBm"))
                .unwrap_or_default(),
            match (b.down_mbps, b.up_mbps) {
                (Some(d), Some(u)) => format!(" · speed ~{d:.0}↓/{u:.0}↑ Mb/s"),
                _ => String::new(),
            }
        );
        let _ = writeln!(
            out,
            "  ({} of healthy minutes learned{})",
            util::fmt_minutes(b.samples as u64),
            if b.established() {
                ""
            } else {
                " — still learning, comparisons not yet trusted"
            }
        );
        // The record across sessions: is it always like this here?
        if let Some(h) = s.history_summary() {
            let _ = writeln!(out, "  history {}", h.line());
            if !h.by_cause.is_empty() {
                let causes: Vec<String> = h
                    .by_cause
                    .iter()
                    .map(|(c, n)| format!("{c} ×{n}"))
                    .collect();
                let _ = writeln!(out, "  incidents by cause: {}", causes.join(", "));
            }
        }
    }

    let _ = writeln!(out);
    out.push_str(&snapshot_text(s));

    if !s.events.is_empty() {
        let _ = writeln!(out, "\n== EVENTS (last {}) ==", s.events.len().min(20));
        for e in s
            .events
            .iter()
            .rev()
            .take(20)
            .collect::<Vec<_>>()
            .iter()
            .rev()
        {
            let _ = writeln!(
                out,
                "  {}  {:<9} {}",
                e.when(),
                e.category.label(),
                e.message
            );
        }
    }

    let code = verdict::exit_code(&triage, insufficient.is_some());
    let out = if full { out } else { redact_report(out, s) };
    (strip_control(out), code)
}

/// The `--doctor --json` report: same content and redaction rules as the text
/// report, shaped for machines. Redaction runs on the serialized string, so
/// the two formats can never disagree about what is hidden.
fn doctor_json(s: &AppState, full: bool) -> (String, i32) {
    use serde_json::json;
    let triage = verdict::evaluate(s);
    let insufficient = verdict::insufficient_reason(s);
    let code = verdict::exit_code(&triage, insufficient.is_some());
    let n = s.window_samples();

    let family = |f: &app::FamilyProbe| match f {
        app::FamilyProbe::NotRun => json!({"status": "not-run"}),
        app::FamilyProbe::NotApplicable => json!({"status": "not-applicable"}),
        app::FamilyProbe::Ok(ms) => json!({"status": "ok", "rtt_ms": ms}),
        app::FamilyProbe::Captive(loc) => json!({"status": "captive", "redirect": loc}),
        app::FamilyProbe::Fail(r) => json!({"status": "fail", "reason": r}),
    };

    let doc = json!({
        "octomon_version": env!("CARGO_PKG_VERSION"),
        "octomon_build": env!("OCTOMON_BUILD"),
        "at": chrono::Local::now().to_rfc3339(),
        "medium": s.netinfo.medium.label(),
        "exit_code": code,
        "status": match (&insufficient, triage.findings.iter().any(|f| f.severity >= verdict::Severity::Degraded)) {
            (Some(_), _) => "insufficient",
            (None, true) => "problems",
            (None, false) => "healthy",
        },
        "insufficient_reason": insufficient,
        "analysis": {
            "ladder": triage.rungs.iter().map(|r| json!({
                "area": r.area.label(),
                "status": r.status.label(),
                "detail": r.detail,
            })).collect::<Vec<_>>(),
            "checks": triage.checks.iter().map(|c| json!({
                "name": c.name,
                "status": c.status.label(),
                "detail": c.detail,
            })).collect::<Vec<_>>(),
            "findings": triage.findings.iter().map(|f| json!({
                "cause": f.cause.label(),
                "severity": f.severity.label(),
                "confidence": f.confidence.word(),
                "symptom": f.symptom,
                "summary": f.summary,
                "evidence": f.evidence,
            })).collect::<Vec<_>>(),
            "performance": triage.performance.as_ref().map(|p| json!({
                "grade": p.grade.label(),
                "detail": p.detail,
            })),
        },
        "history": s.history_summary().map(|h| json!({
            "days": h.days,
            "episodes": h.episodes,
            "outages": h.outages,
            "down_secs": h.down_secs,
            "degraded_secs": h.degraded_secs,
            "cluster_start_hour": h.cluster.map(|c| c.0),
            "cluster_episodes": h.cluster.map(|c| c.1),
            "by_cause": h.by_cause.iter().map(|(c, n)| json!({"cause": c, "count": n})).collect::<Vec<_>>(),
            "summary": h.line(),
        })),
        "location": s.baseline.as_ref().map(|b| json!({
            "name": b.name,
            "label": b.label,
            "medium": b.medium,
            "healthy_minutes": b.samples,
            "established": b.established(),
            "normal": {
                "gateway_ms": b.gateway_ms,
                "internet_ms": b.anchor_ms,
                "dns_ms": b.dns_ms,
                "rssi_dbm": b.rssi_dbm,
                "down_mbps": b.down_mbps,
                "up_mbps": b.up_mbps,
            },
        })),
        "targets": s.targets.iter().map(|t| {
            let st = t.stats(n);
            json!({
                "label": t.label,
                "addr": t.addr.to_string(),
                "hostname": t.hostname,
                "discovered": t.discovered,
                "last_ms": t.last_rtt_ms,
                "mean_ms": st.mean,
                "p95_ms": st.p95,
                "jitter_ms": t.jitter_ms,
                "loss_pct": t.recent_loss_pct(n),
                "sent": t.sent,
                "recv": t.recv,
                "web_status": t.web.status.label(),
                "web_ttfb_ms": t.web.last_ttfb_ms,
            })
        }).collect::<Vec<_>>(),
        "dns": s.dns.iter().map(|p| json!({
            "server": p.server.to_string(),
            "last_ms": p.last_ms,
            "mean_ms": p.mean_ms(),
            "fail_pct": p.fail_pct(),
            "reference": p.reference,
            "hijack": p.hijack,
        })).collect::<Vec<_>>(),
        "network": {
            "iface": s.netinfo.iface,
            "medium": s.netinfo.medium.label(),
            "gateway": s.netinfo.gateway_ip,
            "tunnel": s.netinfo.tunnel_label(),
            "nat": s.nat_kind().map(|(k, via)| json!({"kind": k.label(), "hop2": via.to_string()})),
            "proxy": s.proxy.as_ref().map(|p| json!({
                "config": p.describe(),
                "bypass": p.bypass,
                "web_via_proxy": family(&s.http.via_proxy),
            })),
            "path_mtu": s.pmtu.as_ref().map(|p| json!({
                "target": p.target.to_string(),
                "iface_mtu": p.iface_mtu,
                "path_mtu": p.path_mtu,
                "blackhole": p.blackhole,
                "pmtud_works": p.pmtud_works,
            })),
            "path_mtu_error": s.pmtu_error,
            "clock": json!({
                "offset_ms": s.clock.offset_ms(),
                "source": s.clock.offset_ms().map(|_| s.clock.source()),
                "ntp_error": s.clock.ntp_error,
            }),
        },
        "http": {
            "provider": s.http.provider,
            "v4": family(&s.http.v4),
            "v6": family(&s.http.v6),
            "note": s.http.note,
        },
        "machine": {
            "cpu_pct": s.vitals.cpu_pct,
            "mem_pressure_pct": s.vitals.mem_pressure_pct,
            "throttled": s.vitals.throttled,
            "link_error_pct": s.link_errors.error_pct(),
        },
        "events": s.events.iter().rev().take(20).map(|e| json!({
            "at": e.at,
            "category": e.category.label(),
            "severity": e.severity.label(),
            "message": e.message,
        })).collect::<Vec<_>>(),
    });

    let text = serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string());
    let text = if full { text } else { redact_report(text, s) };
    (text + "\n", code)
}

/// Best-effort scrub of identifying values from a report. Deliberately
/// list-based (this machine's actual SSID/IPs/MACs) rather than pattern-based:
/// ISP-side hop addresses are the useful part of a ticket and must survive.
fn redact_report(text: String, s: &AppState) -> String {
    let mut subs: Vec<(String, &'static str)> = Vec::new();
    let mut push = |v: &str, mask: &'static str| {
        if !v.is_empty() && v != "-" {
            subs.push((v.to_string(), mask));
        }
    };
    if let Some(w) = &s.netinfo.wifi
        && !w.ssid.contains("redacted")
    {
        push(&w.ssid, "<ssid>");
    }
    for t in s.targets.iter().filter(|t| t.discovered) {
        if t.label.contains("public") {
            push(&t.addr.to_string(), "<public-ip>");
        }
    }
    for a in s.netinfo.ipv4.iter().chain(s.netinfo.ipv6.iter()) {
        push(a, "<ip>");
        if let Some(bare) = a.split('/').next() {
            push(bare, "<ip>");
        }
    }
    push(&s.netinfo.gateway_ip, "<gateway>");
    push(&s.netinfo.mac, "<mac>");
    push(&s.netinfo.gateway_mac, "<mac>");
    // LAN-side resolvers (a Pi-hole, the router) are private addresses too;
    // public resolvers are not ours to hide.
    for d in &s.netinfo.dns {
        if d.parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_private())
        {
            push(d, "<dns>");
        }
    }
    // The auto label of an unnamed baseline is the SSID or the gateway IP; a
    // user-chosen name ("Home") was picked to be shareable and stays. Pushed
    // last so the more specific masks above win a same-string tie.
    if let Some(b) = &s.baseline
        && b.name.is_none()
    {
        push(&b.label, "<network>");
    }

    // Longest first (stable, so earlier = more specific on ties), so
    // "192.168.1.100" is consumed before "192.168.1.1" can corrupt it.
    subs.sort_by_key(|(v, _)| std::cmp::Reverse(v.len()));
    subs.into_iter()
        .fold(text, |acc, (v, mask)| acc.replace(&v, mask))
}

fn next_panel(p: Panel) -> Panel {
    match p {
        Panel::Quality => Panel::Bandwidth,
        Panel::Bandwidth => Panel::NetInfo,
        Panel::NetInfo => Panel::Vitals,
        Panel::Vitals => Panel::Quality,
    }
}

fn prev_panel(p: Panel) -> Panel {
    match p {
        Panel::Quality => Panel::Vitals,
        Panel::Bandwidth => Panel::Quality,
        Panel::NetInfo => Panel::Bandwidth,
        Panel::Vitals => Panel::NetInfo,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use app::{HopMonitor, MonitoredHop, QualityView, TargetStat};
    use std::net::Ipv4Addr;

    fn monitor_state(hops: Vec<MonitoredHop>) -> AppState {
        let mut s = AppState::new(vec![]);
        s.focus = Panel::Quality;
        s.quality_view = QualityView::HopMonitor;
        s.sub_pane = SubPane::Secondary;
        s.hop_monitor = Some(HopMonitor {
            target: "t".into(),
            dest: IpAddr::V4(Ipv4Addr::LOCALHOST),
            hops,
            discovering: false,
            generation: 1,
            selected: 0,
        });
        s
    }

    fn live(ttl: u8) -> MonitoredHop {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, ttl));
        MonitoredHop {
            ttl,
            addr: Some(addr),
            stat: Some(TargetStat::new(format!("hop {ttl}"), addr)),
        }
    }
    fn silent(ttl: u8) -> MonitoredHop {
        MonitoredHop {
            ttl,
            addr: None,
            stat: None,
        }
    }

    /// The cursor must land only on hops that answer: an unresponsive one has no
    /// statistics and nothing to add, so it would look like the cursor vanished.
    #[test]
    fn hop_cursor_skips_unresponsive_hops() {
        let mut s = monitor_state(vec![
            live(1),
            silent(2),
            silent(3),
            live(4),
            silent(5),
            live(6),
        ]);
        let sel = |s: &AppState| s.hop_monitor.as_ref().unwrap().selected;

        assert_eq!(sel(&s), 0);
        move_cursor(&mut s, 1);
        assert_eq!(sel(&s), 3, "should jump the pair of silent hops");
        move_cursor(&mut s, 1);
        assert_eq!(sel(&s), 5);
        // Clamped at the last responsive hop rather than running into silence.
        move_cursor(&mut s, 1);
        assert_eq!(sel(&s), 5);
        move_cursor(&mut s, -1);
        assert_eq!(sel(&s), 3);
        move_cursor(&mut s, -5);
        assert_eq!(sel(&s), 0);
    }

    #[test]
    fn hop_cursor_survives_a_path_with_no_responsive_hops() {
        let mut s = monitor_state(vec![silent(1), silent(2)]);
        move_cursor(&mut s, 1);
        assert_eq!(s.hop_monitor.as_ref().unwrap().selected, 0);
    }

    /// "Reset" must leave nothing stale: a graph that keeps its history makes
    /// the freshly-zeroed figures beside it look wrong.
    #[test]
    fn shift_r_clears_everything_in_the_panel() {
        let mut s = monitor_state(vec![live(1)]);
        s.targets = vec![TargetStat::new(
            "t".into(),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        )];
        s.targets[0].record_reply(12.0);
        if let Some(stat) = s.hop_monitor.as_mut().unwrap().hops[0].stat.as_mut() {
            stat.record_reply(9.0);
        }

        reset_panel(&mut s);
        assert!(s.targets[0].history.data.is_empty(), "target history");
        assert_eq!(s.targets[0].sent, 0);
        // The monitored hops carry their own statistics and charts.
        let hop = &s.hop_monitor.as_ref().unwrap().hops[0];
        assert!(
            hop.stat.as_ref().unwrap().history.data.is_empty(),
            "hop history"
        );

        // Bandwidth clears its traces, rates and error counters.
        s.focus = Panel::Bandwidth;
        s.throughput.down_hist.push(10.0);
        s.throughput.down_bps = 10.0;
        s.link_errors.rx_err_total = 5;
        s.link_errors.iface = "en0".into();
        reset_panel(&mut s);
        assert!(s.throughput.down_hist.data.is_empty());
        assert_eq!(s.throughput.down_bps, 0.0);
        assert_eq!(s.link_errors.rx_err_total, 0);
        assert_eq!(s.link_errors.iface, "en0", "which interface is not data");

        // Network clears signal and resolver history.
        s.focus = Panel::NetInfo;
        s.signal.rssi_hist.push(-50.0);
        let mut probe = crate::app::DnsProbe::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        probe.hist.push(9.0);
        probe.sent = 3;
        s.dns = vec![probe];
        reset_panel(&mut s);
        assert!(s.signal.rssi_hist.data.is_empty());
        assert!(s.dns[0].hist.data.is_empty());
        assert_eq!(s.dns[0].sent, 0);

        // Machine clears its histories.
        s.focus = Panel::Vitals;
        s.vitals.cpu_hist.push(50.0);
        s.vitals.pressure_hist.push(60.0);
        reset_panel(&mut s);
        assert!(s.vitals.cpu_hist.data.is_empty());
        assert!(s.vitals.pressure_hist.data.is_empty());
    }

    /// A monitor left running against a deleted target keeps probing every hop
    /// toward an address the user just removed.
    #[test]
    fn deleting_the_monitored_target_stops_the_monitor() {
        let dest = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let mut s = monitor_state(vec![live(1)]);
        s.hop_monitor.as_mut().unwrap().dest = dest;
        s.targets = vec![
            TargetStat::new("other".into(), IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
            TargetStat::new("monitored".into(), dest),
        ];

        // Deleting an unrelated target leaves the monitor alone.
        s.selected = 0;
        delete_selected_target(&mut s);
        assert!(s.hop_monitor.is_some());
        assert_eq!(s.quality_view, QualityView::HopMonitor);

        // Deleting the monitored one stops it and leaves the path view.
        s.selected = 0; // "monitored" is now the only entry
        delete_selected_target(&mut s);
        assert!(s.hop_monitor.is_none(), "monitor should stop");
        assert_eq!(s.quality_view, QualityView::Graph);
    }

    /// 'n' needs a second pane to move to; the Bandwidth panel gains one in
    /// full-screen even before any speed test has been run.
    #[test]
    fn bandwidth_sub_pane_exists_in_fullscreen() {
        let mut s = AppState::new(vec![]);
        s.focus = Panel::Bandwidth;
        assert!(!s.has_sub_pane(), "split view has a single pane");
        s.fullscreen = true;
        assert!(
            s.has_sub_pane(),
            "an empty history is still a pane worth focusing"
        );
    }

    /// The [D] support bundle must come out as a zip other tools can open,
    /// with the two synthesised members present whatever is on disk.
    #[test]
    fn support_bundle_is_a_readable_zip_with_report_and_events() {
        let mut s = AppState::new(vec![]);
        s.push_event(
            verdict::Severity::Info,
            app::EventCategory::Network,
            "an event for the bundle".into(),
        );
        let path =
            std::env::temp_dir().join(format!("octomon-bundle-test-{}.zip", std::process::id()));
        write_bundle_to(&path, &s).unwrap();

        let mut z = zip::ZipArchive::new(std::fs::File::open(&path).unwrap()).unwrap();
        let names: Vec<String> = z.file_names().map(str::to_string).collect();
        assert!(names.contains(&"report.txt".to_string()), "got: {names:?}");
        assert!(names.contains(&"events.csv".to_string()), "got: {names:?}");
        // The members decompress and carry what was put in.
        let mut events = String::new();
        std::io::Read::read_to_string(&mut z.by_name("events.csv").unwrap(), &mut events).unwrap();
        assert!(events.contains("an event for the bundle"));
        let _ = std::fs::remove_file(&path);
    }

    /// The default doctor report must be safe to paste into a public ticket:
    /// the machine's own identifiers gone, ISP-side detail kept.
    #[test]
    fn doctor_report_redacts_by_default_and_not_with_full() {
        let mut s = AppState::new(vec![TargetStat::new(
            "Cloudflare".into(),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        )]);
        for _ in 0..20 {
            s.targets[0].record_reply(12.0);
        }
        let mut public = TargetStat::new(
            "public IP".into(),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)),
        );
        public.discovered = true;
        s.targets.push(public);
        s.netinfo.iface = "en0".into();
        s.netinfo.medium = crate::app::LinkMedium::WiFi;
        s.netinfo.ipv4 = vec!["192.168.1.100/24".into()];
        s.netinfo.gateway_ip = "192.168.1.1".into();
        s.netinfo.mac = "aa:bb:cc:11:22:33".into();
        s.netinfo.gateway_mac = "de:ad:be:ef:00:01".into();
        s.netinfo.wifi = Some(crate::app::WifiInfo {
            ssid: "MySecretWifi".into(),
            ..Default::default()
        });
        // A LAN resolver (Pi-hole) is private; Cloudflare's resolver is not.
        s.netinfo.dns = vec!["192.168.1.4".into(), "1.1.1.1".into()];

        let (out, _code) = doctor_report(&s, false);
        for secret in [
            "MySecretWifi",
            "192.168.1.100",
            "192.168.1.1",
            "192.168.1.4",
            "aa:bb:cc:11:22:33",
            "de:ad:be:ef:00:01",
            "203.0.113.77",
        ] {
            assert!(!out.contains(secret), "leaked {secret:?}");
        }
        assert!(out.contains("<ssid>"));
        assert!(out.contains("<gateway>"));
        assert!(out.contains("<public-ip>"));
        assert!(out.contains("<dns>"));
        // The anchor's address is not ours to hide — it's the useful part.
        assert!(out.contains("1.1.1.1"));
        assert!(out.contains("== ANALYSIS =="));

        let (full, _code) = doctor_report(&s, true);
        assert!(full.contains("MySecretWifi"));
        assert!(full.contains("192.168.1.1"));
    }

    /// An SSID is 32 arbitrary bytes chosen by whoever runs the access point.
    /// One carrying escape sequences must not reach stdout intact, where it
    /// could retitle the terminal or forge report lines; the TUI is guarded by
    /// ratatui, so this is the non-TUI paths' guard.
    #[test]
    fn doctor_and_check_output_carry_no_control_characters() {
        let mut s = AppState::new(vec![TargetStat::new(
            "Cloudflare".into(),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        )]);
        s.netinfo.iface = "en0".into();
        s.netinfo.medium = crate::app::LinkMedium::WiFi;
        s.netinfo.wifi = Some(crate::app::WifiInfo {
            ssid: "evil\x1b]0;pwned\x07net\r".into(),
            ..Default::default()
        });

        // `--full` so redaction cannot be what removed the SSID.
        let (out, _code) = doctor_report(&s, true);
        assert!(!out.contains('\x1b'), "ESC leaked into the report");
        assert!(!out.contains('\x07'), "BEL leaked into the report");
        assert!(!out.contains('\r'));
        assert!(
            out.contains("evil]0;pwnednet"),
            "printable remainder is kept"
        );
        assert!(out.contains('\n'), "line structure survives");

        let snap = strip_control(snapshot_text(&s));
        assert!(!snap.contains('\x1b'));
        assert!(snap.contains("evil]0;pwnednet"));
    }

    /// A user-chosen location name was picked to be shareable; the automatic
    /// label (the SSID) was not.
    #[test]
    fn doctor_keeps_chosen_names_but_hides_auto_labels() {
        let mut s = AppState::new(vec![]);
        s.baseline = Some(crate::baseline::Baseline {
            label: "MySecretWifi".into(),
            name: Some("Home".into()),
            samples: 10,
            gateway_ms: Some(9.0),
            ..Default::default()
        });
        let (out, _) = doctor_report(&s, false);
        assert!(out.contains("NORMAL AT \"Home\""));

        s.baseline.as_mut().unwrap().name = None;
        let (out, _) = doctor_report(&s, false);
        assert!(!out.contains("MySecretWifi"));
        assert!(out.contains("<network>"));
    }

    #[test]
    fn a_total_reset_needs_the_whole_word() {
        // The gate for erasing everything: the word, any case, whitespace
        // tolerated — and nothing less.
        assert!(reset_confirmed("ERASE"));
        assert!(reset_confirmed("erase"));
        assert!(reset_confirmed("  Erase "));
        assert!(!reset_confirmed(""));
        assert!(!reset_confirmed("e"));
        assert!(!reset_confirmed("yes"));
        assert!(!reset_confirmed("erase!"));
    }

    #[test]
    fn speed_history_pages_through_every_entry() {
        let mut s = AppState::new(vec![]);
        s.focus = Panel::Bandwidth;
        s.fullscreen = true;
        s.sub_pane = SubPane::Secondary;
        s.speed_history = (0..120)
            .map(|i| store::SpeedRecord {
                at: i,
                provider: "Cloudflare".into(),
                down_mbps: 100.0,
                up_mbps: 10.0,
                idle_ms: None,
                loaded_ms: None,
                network: None,
                medium: None,
                server: None,
            })
            .collect();

        move_cursor(&mut s, 10);
        assert_eq!(s.speed_sel, 10);
        // Paging reaches the oldest entry rather than stopping at a page edge.
        for _ in 0..20 {
            move_cursor(&mut s, 10);
        }
        assert_eq!(s.speed_sel, 119, "should reach the last of 120 records");
        move_cursor(&mut s, 10);
        assert_eq!(s.speed_sel, 119, "and clamp there");
    }
}
