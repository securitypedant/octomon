//! octomon — a terminal dashboard for network performance.
//!
//! Architecture: independent async collectors write into a shared [`AppState`]
//! (behind a std `Mutex`); a render loop reads a snapshot and draws with ratatui.
//! Input is read on a dedicated OS thread and delivered over a channel.

mod app;
mod collectors;
mod config;
mod ui;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use tokio::sync::{mpsc, Notify};

use app::{AppState, Panel, SpeedStatus, TargetStat};
use config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = Config::load();

    let targets = cfg
        .targets
        .iter()
        .map(|t| TargetStat::new(t.label.clone(), t.addr))
        .collect();
    let state = Arc::new(Mutex::new(AppState::new(targets)));

    // Trigger for the on-demand speed test (fired by the 's' key).
    let speedtest_trigger = Arc::new(Notify::new());

    // Spawn collectors, each on its own cadence.
    tokio::spawn(collectors::ping::run(state.clone(), cfg.clone()));
    tokio::spawn(collectors::throughput::run(state.clone(), cfg.clone()));
    tokio::spawn(collectors::vitals::run(state.clone(), cfg.clone()));
    tokio::spawn(collectors::netinfo::run(state.clone()));
    tokio::spawn(collectors::speedtest::run(
        state.clone(),
        speedtest_trigger.clone(),
    ));

    // Headless verification mode: collect for a few seconds, run one speed test,
    // print a text snapshot, and exit. Exercises collectors without a TTY.
    if std::env::args().any(|a| a == "--check") {
        tokio::time::sleep(Duration::from_secs(3)).await;
        speedtest_trigger.notify_one();
        tokio::time::sleep(Duration::from_secs(20)).await;
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
    let result = run_ui(&mut terminal, state, rx, speedtest_trigger).await;
    ratatui::restore();
    result
}

async fn run_ui(
    terminal: &mut ratatui::DefaultTerminal,
    state: Arc<Mutex<AppState>>,
    mut rx: mpsc::UnboundedReceiver<KeyEvent>,
    speedtest_trigger: Arc<Notify>,
) -> Result<()> {
    let mut ticker = tokio::time::interval(Duration::from_millis(200));
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            Some(key) = rx.recv() => handle_key(&state, key, &speedtest_trigger),
        }

        let s = state.lock().unwrap();
        if s.should_quit {
            break;
        }
        terminal.draw(|f| ui::render(f, &s))?;
    }
    Ok(())
}

fn handle_key(state: &Arc<Mutex<AppState>>, key: KeyEvent, speedtest_trigger: &Arc<Notify>) {
    if key.kind == KeyEventKind::Release {
        return;
    }
    let mut s = state.lock().unwrap();
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => s.should_quit = true,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => s.should_quit = true,
        KeyCode::Tab => s.focus = next_panel(s.focus),
        KeyCode::Char('s') => {
            // Ignore if a test is already in flight.
            if !matches!(s.speedtest.status, SpeedStatus::Running) {
                s.speedtest.status = SpeedStatus::Running;
                speedtest_trigger.notify_one();
            }
        }
        _ => {}
    }
}

/// Text dump of the current state for `--check` / debugging.
fn print_snapshot(s: &AppState) {
    println!("== octomon --check ==");
    println!("\n[Connection Quality]");
    for t in &s.targets {
        let last = t.last_rtt_ms.map(|v| format!("{v:.1}ms")).unwrap_or_else(|| "—".into());
        let avg = t.avg_ms.map(|v| format!("{v:.1}ms")).unwrap_or_else(|| "—".into());
        println!(
            "  {:<11} {:<16} last={last:<8} avg={avg:<8} jitter={:.1}ms loss={:.0}% ({}/{} recv)",
            t.label, t.addr.to_string(), t.jitter_ms, t.loss_pct(), t.recv, t.sent
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

    let n = &s.netinfo;
    println!("\n[Network]");
    println!("  iface={}  link={}", n.iface, n.link_kind);
    println!("  ipv4={:?}", n.ipv4);
    println!("  mac={}  gateway={} ({})", n.mac, n.gateway_ip, n.gateway_mac);

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
