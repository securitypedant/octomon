//! octomon — a terminal dashboard for network performance.
//!
//! Architecture: independent async collectors write into a shared [`AppState`]
//! (behind a std `Mutex`); a render loop reads a snapshot and draws with ratatui.
//! Input is read on a dedicated OS thread and delivered over a channel.

mod app;
mod baseline;
mod collectors;
mod config;
mod platform;
mod store;
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

use app::{AppState, InputMode, Overlay, Panel, QualityView, SpeedStatus, SubPane, TargetStat};
use config::Config;

/// Handles shared with the input loop for issuing side effects.
struct Ctx {
    state: Arc<Mutex<AppState>>,
    speedtest_trigger: Arc<Notify>,
    netinfo_refresh: Arc<Notify>,
    ping_clients: collectors::ping::Clients,
    cfg: Config,
}

/// Terminal dashboard for network performance.
#[derive(Parser, Debug)]
#[command(name = "octomon", version, about)]
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
}

#[tokio::main]
async fn main() -> Result<()> {
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
        .map(|t| TargetStat::new(t.label.clone(), t.addr))
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
        s.speedtest_provider_names = provider_names;
        s.speedtest_provider_idx = sel;
        let (history, total) = store::load_recent(500);
        s.speed_history = history;
        s.speed_total = total;
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
        print_snapshot(&state.lock().unwrap());
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
    loop {
        // Track whether this iteration was driven by a key press; while paused,
        // only key-driven iterations redraw (the periodic refresh is suppressed).
        let by_key = tokio::select! {
            _ = ticker.tick() => false,
            Some(key) = rx.recv() => {
                handle_key(ctx, key);
                true
            }
        };

        let s = ctx.state.lock().unwrap();
        if s.should_quit {
            break;
        }
        if by_key || !s.paused {
            terminal.draw(|f| ui::render(f, &s))?;
        }
    }
    Ok(())
}

/// Clear everything the focused panel has accumulated. "Reset" should leave no
/// stale figure behind: a graph that keeps its history after a reset makes the
/// numbers beside it look wrong.
fn reset_panel(s: &mut AppState) {
    match s.focus {
        Panel::Quality => s.reset_quality_stats(),
        Panel::Bandwidth => {
            s.throughput.down_hist.data.clear();
            s.throughput.up_hist.data.clear();
            s.throughput.down_bps = 0.0;
            s.throughput.up_bps = 0.0;
            s.processes.clear();
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
    SaveProvider(String),
    /// Persist the user's name for the current network's baseline.
    NameNetwork {
        key: String,
        label: String,
        name: String,
    },
    /// Read every stored baseline off disk for the locations overlay.
    LoadLocations,
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
    let last = s.targets.len().saturating_sub(1);
    s.selected = s.selected.min(last);
    if s.graph_target >= idx {
        s.graph_target = s.graph_target.saturating_sub(1);
    }
    s.graph_target = s.graph_target.min(last);
}

/// Move whichever cursor holds focus: the sub-pane's when one is active,
/// otherwise the panel's primary list.
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
                KeyCode::Esc => s.overlay = Overlay::None,
                KeyCode::Char('?') => {
                    s.overlay = if s.overlay == Overlay::Help {
                        Overlay::None
                    } else {
                        Overlay::Help
                    };
                }
                KeyCode::Char('y') => {
                    s.overlay = if s.overlay == Overlay::Triage {
                        Overlay::None
                    } else {
                        Overlay::Triage
                    };
                }
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
                // Scroll the timeline; clamped so it can't run past the oldest.
                KeyCode::Up | KeyCode::Char('k') if s.overlay == Overlay::Events => {
                    s.events_scroll =
                        (s.events_scroll + 1).min(s.events.len().saturating_sub(1));
                }
                KeyCode::Down | KeyCode::Char('j') if s.overlay == Overlay::Events => {
                    s.events_scroll = s.events_scroll.saturating_sub(1);
                }
                KeyCode::PageUp if s.overlay == Overlay::Events => {
                    s.events_scroll =
                        (s.events_scroll + 10).min(s.events.len().saturating_sub(1));
                }
                KeyCode::PageDown if s.overlay == Overlay::Events => {
                    s.events_scroll = s.events_scroll.saturating_sub(10);
                }
                // Scroll the locations list.
                KeyCode::Up | KeyCode::Char('k') if s.overlay == Overlay::Locations => {
                    s.locations_sel = s.locations_sel.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') if s.overlay == Overlay::Locations => {
                    let last = s
                        .locations
                        .as_ref()
                        .map(|l| l.len().saturating_sub(1))
                        .unwrap_or(0);
                    s.locations_sel = (s.locations_sel + 1).min(last);
                }
                _ => {}
            },

            // --- normal navigation ---
            InputMode::Normal => match key.code {
                KeyCode::Char('q') => s.should_quit = true,
                KeyCode::Char('c') if ctrl => s.should_quit = true,
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
                KeyCode::Char('y') => s.overlay = Overlay::Triage,
                // 'e' opens the session timeline.
                KeyCode::Char('e') => {
                    s.events_scroll = 0;
                    s.overlay = Overlay::Events;
                }
                KeyCode::Tab => s.focus = next_panel(s.focus),
                KeyCode::BackTab => s.focus = prev_panel(s.focus),
                KeyCode::Char('f') => s.fullscreen = !s.fullscreen,
                KeyCode::Char('p') => s.paused = !s.paused,
                KeyCode::Char('r') => {
                    s.refresh_at = Some(std::time::Instant::now());
                    side = Side::Refresh;
                }
                KeyCode::Char('w') => s.cycle_window(),
                // 'l' toggles session recording; the logger task acts on this
                // and reports back, so no file I/O happens on the key path.
                KeyCode::Char('l') => s.logging_requested = !s.logging_requested,
                // Shift+R resets the focused panel's accumulated data.
                KeyCode::Char('R') => reset_panel(&mut s),
                // Shift+L lists every stored network location (Network panel).
                KeyCode::Char('L') if s.focus == Panel::NetInfo => {
                    s.locations = None;
                    s.locations_sel = 0;
                    s.overlay = Overlay::Locations;
                    side = Side::LoadLocations;
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
                // Space toggles the active sort direction in the focused panel.
                KeyCode::Char(' ') => match s.focus {
                    Panel::Quality => {
                        if let Some((c, d)) = s.q_sort {
                            s.q_sort = Some((c, !d));
                        }
                    }
                    Panel::Bandwidth => {
                        if let Some((c, d)) = s.bw_sort {
                            s.bw_sort = Some((c, !d));
                        }
                    }
                    _ => {}
                },
                // Delete the selected target.
                KeyCode::Char('d') | KeyCode::Delete if s.focus == Panel::Quality => {
                    delete_selected_target(&mut s);
                }
                // Bandwidth: move the top-talkers column cursor and sort.
                KeyCode::Left if s.focus == Panel::Bandwidth => {
                    s.bw_col = s.bw_col.saturating_sub(1);
                }
                KeyCode::Right if s.focus == Panel::Bandwidth => {
                    s.bw_col = (s.bw_col + 1).min(4);
                }
                KeyCode::Enter if s.focus == Panel::Bandwidth => {
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
                KeyCode::Up | KeyCode::Char('k') => move_cursor(&mut s, -1),
                KeyCode::Down | KeyCode::Char('j') => move_cursor(&mut s, 1),
                KeyCode::PageUp => move_cursor(&mut s, -10),
                KeyCode::PageDown => move_cursor(&mut s, 10),
                // ←/→ move the column cursor; Enter sorts by it (Space toggles).
                KeyCode::Left if s.focus == Panel::Quality => {
                    s.q_col = s.q_col.saturating_sub(1);
                }
                KeyCode::Right if s.focus == Panel::Quality => {
                    s.q_col = (s.q_col + 1).min(5);
                }
                KeyCode::Enter if s.focus == Panel::Quality => {
                    let col = s.q_col;
                    s.q_sort = match s.q_sort {
                        Some((c, d)) if c == col => Some((c, d)), // keep direction
                        _ => Some((col, col != 0)),
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
        Side::SaveProvider(name) => {
            tokio::task::spawn_blocking(move || config::Config::persist_provider(&name));
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
                // Most-established first, named before unnamed on ties.
                all.sort_by(|a, b| {
                    b.1.samples
                        .cmp(&a.1.samples)
                        .then_with(|| a.1.display_name().to_lowercase().cmp(
                            &b.1.display_name().to_lowercase(),
                        ))
                });
                state.lock().unwrap().locations = Some(all);
            });
        }
    }
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
        target.hostname = hostname;
        let id = target.id;
        s.targets.push(target);
        s.selected = idx;
        s.graph_target = idx;
        id
    };
    collectors::ping::spawn_for(state, clients, cfg, id, addr);
}

/// Text dump of the current state for `--check` / debugging.
fn print_snapshot(s: &AppState) {
    print!("{}", snapshot_text(s));
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
            t.loss_pct(),
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
            .map(|v| format!("{v:.1} Mbps"))
            .unwrap_or_else(|| "—".into()),
        st.up_mbps
            .map(|v| format!("{v:.1} Mbps"))
            .unwrap_or_else(|| "—".into()),
    );
    match s.proc_status {
        app::ProcStatus::Supported => {
            println!("  top processes by bandwidth:");
            if s.processes.is_empty() {
                println!("    (no active talkers)");
            }
            for p in &s.processes {
                println!(
                    "    {:<20} pid={:<6} ↓{:>10.0} ↑{:>10.0} B/s  total={:<10} retx={:.1}/s",
                    p.name, p.pid, p.down_bps, p.up_bps, p.total_bytes, p.retx_per_sec
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
            "    resolver {:<16} last={rtt:<8} avg={mean:<8} fail={:.0}% ({}/{}) {}",
            p.server.to_string(),
            p.fail_pct(),
            p.ok,
            p.sent,
            p.status
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
            "  live signal: rssi={} dBm  noise={noise}  tx={:.0} Mbps  ({} samples)",
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
        env!("CARGO_PKG_VERSION"),
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
        let _ = writeln!(out, "\n== NORMAL AT \"{}\" ==", b.display_name());
        let ms = |v: Option<f64>| v.map(|x| format!("~{x:.0}ms")).unwrap_or_else(|| "—".into());
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
                (Some(d), Some(u)) => format!(" · speed ~{d:.0}↓/{u:.0}↑ Mbps"),
                _ => String::new(),
            }
        );
        let _ = writeln!(
            out,
            "  ({} healthy minutes learned{})",
            b.samples,
            if b.established() {
                ""
            } else {
                " — still learning, comparisons not yet trusted"
            }
        );
    }

    let _ = writeln!(out);
    out.push_str(&snapshot_text(s));

    if !s.events.is_empty() {
        let _ = writeln!(out, "\n== EVENTS (last {}) ==", s.events.len().min(20));
        for e in s.events.iter().rev().take(20).collect::<Vec<_>>().iter().rev() {
            let _ = writeln!(out, "  {}  {:<9} {}", e.when(), e.category.label(), e.message);
        }
    }

    let code = verdict::exit_code(&triage, insufficient.is_some());
    let out = if full { out } else { redact_report(out, s) };
    (out, code)
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
            "findings": triage.findings.iter().map(|f| json!({
                "cause": f.cause.label(),
                "severity": f.severity.label(),
                "confidence": f.confidence.word(),
                "summary": f.summary,
                "evidence": f.evidence,
            })).collect::<Vec<_>>(),
        },
        "location": s.baseline.as_ref().map(|b| json!({
            "name": b.name,
            "label": b.label,
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
                "loss_pct": t.loss_pct(),
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
        })).collect::<Vec<_>>(),
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
        if d.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| ip.is_private()) {
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
        let mut public = TargetStat::new("public IP".into(), IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)));
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
