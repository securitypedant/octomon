//! octomon — a terminal dashboard for network performance.
//!
//! Architecture: independent async collectors write into a shared [`AppState`]
//! (behind a std `Mutex`); a render loop reads a snapshot and draws with ratatui.
//! Input is read on a dedicated OS thread and delivered over a channel.

mod app;
mod collectors;
mod config;
mod platform;
mod store;
mod ui;
mod util;

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use surge_ping::Client;
use tokio::sync::{Notify, mpsc};

use app::{AppState, InputMode, Panel, QualityView, SpeedStatus, SubPane, TargetStat};
use config::Config;

/// Handles shared with the input loop for issuing side effects.
struct Ctx {
    state: Arc<Mutex<AppState>>,
    speedtest_trigger: Arc<Notify>,
    netinfo_refresh: Arc<Notify>,
    ping_client: Option<Arc<Client>>,
    cfg: Config,
}

/// Terminal dashboard for network performance.
#[derive(Parser, Debug)]
#[command(name = "octomon", version, about)]
struct Cli {
    /// Run collectors briefly, print a text snapshot, then exit (no TUI).
    #[arg(long)]
    check: bool,

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
        s.notice = platform::tools::missing_notice();
    }

    // Triggers fired by key presses.
    let speedtest_trigger = Arc::new(Notify::new()); // 's'
    let netinfo_refresh = Arc::new(Notify::new()); // 'r'

    // Shared ICMP client so targets can be added at runtime.
    let ping_client = match Client::new(&surge_ping::Config::default()) {
        Ok(c) => Some(Arc::new(c)),
        Err(e) => {
            tracing::error!("failed to create ICMP client: {e}");
            None
        }
    };
    // Raised by the netinfo collector when the machine moves to a different
    // network, so path-dependent state can be rebuilt.
    let network_changed = Arc::new(Notify::new());

    if let Some(client) = ping_client.clone() {
        collectors::ping::spawn_all(state.clone(), client.clone(), cfg.clone());
        // Auto-discover the gateway + next hops, and the public IP, as targets.
        if !cli.check {
            tokio::spawn(collectors::discovery::run(
                state.clone(),
                client.clone(),
                cfg.clone(),
            ));
            tokio::spawn(collectors::discovery::public_ip(
                state.clone(),
                client.clone(),
                cfg.clone(),
            ));
            tokio::spawn(collectors::discovery::watch(
                state.clone(),
                client,
                cfg.clone(),
                network_changed.clone(),
            ));
        }
    }

    // Spawn collectors, each on its own cadence.
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
        ping_client,
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

/// Side effects to run after releasing the state lock.
enum Side {
    None,
    Speedtest,
    Refresh,
    AddTarget(String),
    Traceroute(IpAddr, String),
    HopMonitor(IpAddr, String),
    SaveProvider(String),
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

            // --- help overlay: swallow most keys ---
            InputMode::Normal if s.show_help => match key.code {
                KeyCode::Char('q') => s.should_quit = true,
                KeyCode::Char('c') if ctrl => s.should_quit = true,
                KeyCode::Esc | KeyCode::Char('?') => s.show_help = false,
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
                KeyCode::Char('?') => s.show_help = true,
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
                KeyCode::Char('R') => match s.focus {
                    Panel::Quality => {
                        for t in &mut s.targets {
                            t.reset();
                        }
                    }
                    Panel::Bandwidth => {
                        s.throughput.down_hist.data.clear();
                        s.throughput.up_hist.data.clear();
                        s.processes.clear();
                    }
                    _ => {}
                },
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
        Side::AddTarget(input) => match ctx.ping_client.clone() {
            Some(client) => {
                tokio::spawn(add_target(
                    ctx.state.clone(),
                    client,
                    ctx.cfg.clone(),
                    input,
                ));
            }
            None => ctx.state.lock().unwrap().notice = Some("ICMP unavailable".to_string()),
        },
        Side::Traceroute(addr, label) => {
            collectors::traceroute::start(ctx.state.clone(), addr, label);
        }
        Side::HopMonitor(addr, label) => match ctx.ping_client.clone() {
            Some(client) => {
                collectors::hopmon::start(ctx.state.clone(), client, ctx.cfg.clone(), addr, label)
            }
            None => ctx.state.lock().unwrap().notice = Some("ICMP unavailable".to_string()),
        },
        Side::SaveProvider(name) => {
            tokio::task::spawn_blocking(move || config::Config::persist_provider(&name));
        }
    }
}

/// Resolve a user-entered IP or DNS name, append it as a target, and start
/// pinging it. Reports failures via the transient `notice`.
async fn add_target(state: Arc<Mutex<AppState>>, client: Arc<Client>, cfg: Config, input: String) {
    let addr: IpAddr = match input.parse() {
        Ok(ip) => ip,
        Err(_) => match tokio::net::lookup_host((input.as_str(), 0)).await {
            Ok(mut addrs) => match addrs.next() {
                Some(sa) => sa.ip(),
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
        let target = TargetStat::new(input.clone(), addr);
        let id = target.id;
        s.targets.push(target);
        s.selected = idx;
        s.graph_target = idx;
        id
    };
    collectors::ping::spawn_for(state, client, cfg, id, addr);
}

/// Text dump of the current state for `--check` / debugging.
fn print_snapshot(s: &AppState) {
    println!("== octomon --check ==");
    let n = s.window_samples();
    println!("\n[Connection Quality]  (window {}s)", s.window_secs);
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
        println!(
            "  live signal (CoreWLAN): rssi={} dBm  noise={} dBm  tx={:.0} Mbps  ({} samples)",
            sig.rssi_dbm,
            sig.noise_dbm,
            sig.tx_rate_mbps,
            sig.rssi_hist.data.len()
        );
    }

    let v = &s.vitals;
    println!("\n[Machine]");
    println!(
        "  cpu={:.1}%  mem={}/{} MiB",
        v.cpu_pct,
        v.mem_used / 1_048_576,
        v.mem_total / 1_048_576
    );
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
