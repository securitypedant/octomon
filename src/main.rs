//! octomon — a terminal dashboard for network performance.
//!
//! Architecture: independent async collectors write into a shared [`AppState`]
//! (behind a std `Mutex`); a render loop reads a snapshot and draws with ratatui.
//! Input is read on a dedicated OS thread and delivered over a channel.

mod app;
mod collectors;
mod config;
mod platform;
mod ui;

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use surge_ping::Client;
use tokio::sync::{mpsc, Notify};

use app::{AppState, InputMode, Panel, SpeedStatus, TargetStat};
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
        let mut s = state.lock().unwrap();
        s.speedtest_enabled = !cli.no_speedtest;
        s.samples_per_sec = 1000.0 / cfg.ping_interval_ms.max(1) as f64;
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
    if let Some(client) = ping_client.clone() {
        collectors::ping::spawn_all(state.clone(), client, cfg.clone());
    }

    // Spawn collectors, each on its own cadence.
    tokio::spawn(collectors::throughput::run(state.clone(), cfg.clone()));
    tokio::spawn(collectors::vitals::run(state.clone(), cfg.clone()));
    tokio::spawn(collectors::netinfo::run(state.clone(), netinfo_refresh.clone()));
    tokio::spawn(collectors::wifi::run(state.clone(), netinfo_refresh.clone()));
    tokio::spawn(collectors::procbw::run(state.clone()));
    if !cli.no_speedtest {
        tokio::spawn(collectors::speedtest::run(
            state.clone(),
            speedtest_trigger.clone(),
        ));
    }

    // Headless verification mode: collect for a few seconds, run one speed test,
    // print a text snapshot, and exit. Exercises collectors without a TTY.
    if cli.check {
        tokio::time::sleep(Duration::from_secs(3)).await;
        if !cli.no_speedtest {
            speedtest_trigger.notify_one();
            tokio::time::sleep(Duration::from_secs(20)).await;
        } else {
            // The macOS Wi-Fi probe (system_profiler) is slow; wait for it.
            tokio::time::sleep(Duration::from_secs(17)).await;
        }
        print_snapshot(&state.lock().unwrap());
        return Ok(());
    }

    // Read terminal input on a blocking OS thread → async channel.
    let (tx, rx) = mpsc::unbounded_channel::<KeyEvent>();
    std::thread::spawn(move || loop {
        match event::read() {
            Ok(Event::Key(k)) => {
                if tx.send(k).is_err() {
                    break;
                }
            }
            Ok(_) => {}
            Err(_) => break,
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
                KeyCode::Char('q') | KeyCode::Esc => s.should_quit = true,
                KeyCode::Char('c') if ctrl => s.should_quit = true,
                KeyCode::Char('?') => s.show_help = true,
                KeyCode::Tab => s.focus = next_panel(s.focus),
                KeyCode::Char('f') => s.fullscreen = !s.fullscreen,
                KeyCode::Char('p') => s.paused = !s.paused,
                KeyCode::Char('r') => side = Side::Refresh,
                KeyCode::Char('w') => s.cycle_window(),
                KeyCode::Char('s')
                    if s.speedtest_enabled
                        && !matches!(s.speedtest.status, SpeedStatus::Running) =>
                {
                    s.speedtest.begin();
                    side = Side::Speedtest;
                }
                // Quality-panel actions.
                KeyCode::Char('a') if s.focus == Panel::Quality => {
                    s.input_mode = InputMode::AddTarget;
                    s.input_buffer.clear();
                }
                KeyCode::Up | KeyCode::Char('k') if s.focus == Panel::Quality => {
                    s.selected = s.selected.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') if s.focus == Panel::Quality => {
                    let max = s.targets.len().saturating_sub(1);
                    s.selected = (s.selected + 1).min(max);
                }
                KeyCode::Enter if s.focus == Panel::Quality => s.graph_target = s.selected,
                _ => {}
            },
        }
    }

    match side {
        Side::None => {}
        Side::Speedtest => ctx.speedtest_trigger.notify_one(),
        Side::Refresh => ctx.netinfo_refresh.notify_one(),
        Side::AddTarget(input) => match ctx.ping_client.clone() {
            Some(client) => {
                tokio::spawn(add_target(ctx.state.clone(), client, ctx.cfg.clone(), input));
            }
            None => ctx.state.lock().unwrap().notice = Some("ICMP unavailable".to_string()),
        },
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

    let idx = {
        let mut s = state.lock().unwrap();
        let idx = s.targets.len();
        s.targets.push(TargetStat::new(input.clone(), addr));
        s.selected = idx;
        s.graph_target = idx;
        idx
    };
    collectors::ping::spawn_for(state, client, cfg, idx, addr);
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
    println!(
        "  speedtest[{status}]: down={} up={}",
        st.down_mbps.map(|v| format!("{v:.1} Mbps")).unwrap_or_else(|| "—".into()),
        st.up_mbps.map(|v| format!("{v:.1} Mbps")).unwrap_or_else(|| "—".into()),
    );
    if s.proc_supported {
        println!("  top processes by bandwidth:");
        if s.processes.is_empty() {
            println!("    (no active talkers)");
        }
        for p in &s.processes {
            println!(
                "    {:<20} pid={:<6} ↓{:>10.0} B/s  ↑{:>10.0} B/s",
                p.name, p.pid, p.down_bps, p.up_bps
            );
        }
    } else {
        println!("  per-process bandwidth: unsupported on this platform");
    }

    let n = &s.netinfo;
    println!("\n[Network]");
    println!("  iface={}  link={}", n.iface, n.link_kind);
    println!("  ipv4={:?}", n.ipv4);
    println!("  mac={}  gateway={} ({})", n.mac, n.gateway_ip, n.gateway_mac);
    if let Some(w) = &n.wifi {
        println!(
            "  wifi: ssid={} phy={} ch={} signal={} tx={}",
            w.ssid, w.phy, w.channel, w.rssi, w.tx_rate
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
