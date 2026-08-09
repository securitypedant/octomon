//! Rendering. A single [`render`] entry point draws the four panels from an
//! immutable snapshot of [`AppState`]. No data collection happens here.

use ratatui::layout::Alignment;
use ratatui::prelude::*;
use ratatui::style::Modifier;
use ratatui::widgets::{Block, Cell, Clear, Gauge, Paragraph, Row, Sparkline, Table};

use crate::app::{AppState, InputMode, Panel, SpeedStatus};

/// Draw the whole dashboard.
pub fn render(f: &mut Frame, s: &AppState) {
    let root = Layout::vertical([
        Constraint::Length(1), // header
        Constraint::Min(0),    // body
        Constraint::Length(1), // footer (input / notice / hints)
    ])
    .split(f.area());
    header(f, s, root[0]);

    if s.fullscreen {
        // Single focused panel fills the body.
        match s.focus {
            Panel::Quality => quality_panel(f, s, root[1]),
            Panel::Bandwidth => bandwidth_panel(f, s, root[1]),
            Panel::NetInfo => netinfo_panel(f, s, root[1]),
            Panel::Vitals => vitals_panel(f, s, root[1]),
        }
    } else {
        let rows = Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).split(root[1]);
        let top = Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).split(rows[0]);
        let bottom = Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).split(rows[1]);
        quality_panel(f, s, top[0]);
        bandwidth_panel(f, s, top[1]);
        netinfo_panel(f, s, bottom[0]);
        vitals_panel(f, s, bottom[1]);
    }

    footer(f, s, root[2]);

    if s.show_help {
        help_overlay(f, f.area());
    }
}

fn header(f: &mut Frame, s: &AppState, area: Rect) {
    let cols = Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).split(area);

    let up = s.started.elapsed().as_secs();
    let mut left = vec![
        Span::styled(" octomon ", Style::new().fg(Color::Black).bg(Color::Cyan).bold()),
        Span::raw(format!("  {:02}:{:02}:{:02}", up / 3600, (up % 3600) / 60, up % 60)),
    ];
    if s.paused {
        left.push(Span::styled(
            "  PAUSED",
            Style::new().fg(Color::Black).bg(Color::Yellow).bold(),
        ));
    }
    if s.fullscreen {
        left.push(Span::styled("  ⛶ full", Style::new().fg(Color::DarkGray)));
    }
    f.render_widget(Paragraph::new(Line::from(left)), cols[0]);

    // Context-sensitive actions, top-right.
    f.render_widget(
        Paragraph::new(context_line(s)).alignment(Alignment::Right),
        cols[1],
    );
}

/// Panel-specific action hints shown at top-right.
fn context_line(s: &AppState) -> Line<'static> {
    let key = |k: &str| Span::styled(k.to_string(), Style::new().fg(Color::Cyan));
    let txt = |t: &str| Span::styled(t.to_string(), Style::new().fg(Color::Gray));
    let mut spans = match s.focus {
        Panel::Quality => vec![
            key("[a]"), txt("dd "), key("[↑↓]"), txt("sel "), key("[↵]"), txt("graph "),
        ],
        Panel::Bandwidth => vec![key("[s]"), txt("peedtest "), key("[f]"), txt("ull ")],
        Panel::NetInfo => vec![key("[r]"), txt("efresh ")],
        Panel::Vitals => vec![],
    };
    spans.push(key("[?]"));
    spans.push(txt("help "));
    Line::from(spans)
}

fn footer(f: &mut Frame, s: &AppState, area: Rect) {
    let line = if s.input_mode == InputMode::AddTarget {
        Line::from(vec![
            Span::styled(" add target (IP or DNS): ", Style::new().fg(Color::Yellow).bold()),
            Span::styled(s.input_buffer.clone(), Style::new().fg(Color::White)),
            Span::styled("▏", Style::new().fg(Color::Yellow)),
            Span::styled("   [Enter] add  [Esc] cancel", Style::new().fg(Color::DarkGray)),
        ])
    } else if let Some(n) = &s.notice {
        Line::from(Span::styled(format!(" {n}"), Style::new().fg(Color::Yellow)))
    } else {
        Line::from(Span::styled(
            " [Tab] focus  [f] full  [p] pause  [r] refresh  [w] window  [s] speedtest  [?] help  [q] quit",
            Style::new().fg(Color::DarkGray),
        ))
    };
    f.render_widget(Paragraph::new(line), area);
}

fn block(title: &str, focused: bool) -> Block<'static> {
    let border = if focused { Color::Cyan } else { Color::DarkGray };
    Block::bordered()
        .title(Span::styled(format!(" {title} "), Style::new().bold()))
        .border_style(Style::new().fg(border))
}

fn quality_panel(f: &mut Frame, s: &AppState, area: Rect) {
    let b = block("Connection Quality", s.focus == Panel::Quality);
    let inner = b.inner(area);
    f.render_widget(b, area);

    // Summary line, target table, then the latency sparkline for the graphed target.
    let spark_h = if s.fullscreen { 12 } else { 6 };
    let parts = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(spark_h),
    ])
    .split(inner);

    let n = s.window_samples();
    quality_summary(f, s, n, parts[0]);

    let focused = s.focus == Panel::Quality;
    let header = Row::new(["", "Target", "Address", "last", "avg", "p95", "max", "loss"])
        .style(Style::new().fg(Color::Gray).bold());
    let rows = s.targets.iter().enumerate().map(|(i, t)| {
        let loss = t.loss_pct();
        let st = t.stats(n);
        let color = latency_color(t.last_rtt_ms, loss);
        let marker = if i == s.graph_target { "►" } else { "" };
        let mut style = Style::new().fg(color);
        if focused && i == s.selected {
            style = style.bg(Color::Rgb(40, 40, 55)).add_modifier(Modifier::BOLD);
        }
        Row::new(vec![
            Cell::from(Span::styled(marker, Style::new().fg(Color::Cyan))),
            Cell::from(t.label.clone()),
            Cell::from(t.addr.to_string()),
            Cell::from(fmt_ms(t.last_rtt_ms)),
            Cell::from(fmt_ms(st.mean)),
            Cell::from(fmt_ms(st.p95)),
            Cell::from(fmt_ms(st.max)),
            Cell::from(format!("{loss:.0}%")),
        ])
        .style(style)
    });
    let widths = [
        Constraint::Length(2),
        Constraint::Length(13),
        Constraint::Length(16),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(6),
    ];
    f.render_widget(Table::new(rows, widths).header(header), parts[1]);

    if let Some(t) = s.targets.get(s.graph_target) {
        let data = t.history.tail_u64(parts[2].width as usize);
        let spark = Sparkline::default()
            .data(data)
            .style(Style::new().fg(Color::Cyan))
            .block(Block::new().title(Span::styled(
                format!(" latency · {} ", t.label),
                Style::new().fg(Color::DarkGray),
            )));
        f.render_widget(spark, parts[2]);
    }
}

/// One-line summary above the table: stats window, and jitter / stddev /
/// bufferbloat for the graphed target.
fn quality_summary(f: &mut Frame, s: &AppState, n: usize, area: Rect) {
    let mut spans = vec![
        Span::styled(format!("window {}s ", s.window_secs), Style::new().fg(Color::Gray)),
        Span::styled("[w]", Style::new().fg(Color::Cyan)),
        Span::raw("  "),
    ];
    if let Some(t) = s.targets.get(s.graph_target) {
        let st = t.stats(n);
        spans.push(Span::styled(
            format!("{}: ", t.label),
            Style::new().fg(Color::DarkGray),
        ));
        spans.push(Span::styled(
            format!("jitter {:.1} · stddev {:.1}  ", t.jitter_ms, st.stddev),
            Style::new().fg(Color::Gray),
        ));
        if let Some(bloat) = t.bufferbloat_ms(n) {
            let (grade, color) = bufferbloat_grade(bloat);
            spans.push(Span::styled("bufferbloat ", Style::new().fg(Color::DarkGray)));
            spans.push(Span::styled(
                format!("+{bloat:.0}ms ({grade})"),
                Style::new().fg(color).bold(),
            ));
        }
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Grade latency inflation under load, à la the Waveform/Cloudflare scale.
fn bufferbloat_grade(bloat_ms: f64) -> (&'static str, Color) {
    match bloat_ms {
        b if b < 5.0 => ("excellent", Color::Green),
        b if b < 30.0 => ("good", Color::Green),
        b if b < 60.0 => ("moderate", Color::Yellow),
        b if b < 200.0 => ("poor", Color::Red),
        _ => ("bad", Color::Red),
    }
}

fn bandwidth_panel(f: &mut Frame, s: &AppState, area: Rect) {
    let tp = &s.throughput;
    let b = block(
        &format!("Bandwidth · {}", if tp.iface.is_empty() { "…" } else { &tp.iface }),
        s.focus == Panel::Bandwidth,
    );
    let inner = b.inner(area);
    f.render_widget(b, area);

    // Split view shows 5 talkers, full-screen shows 10; the graphs take the rest.
    let talkers = if s.fullscreen { 10 } else { 5 };
    let talker_h = talkers as u16 + 1; // +1 for the section title
    let rows = Layout::vertical([
        Constraint::Length(1),        // speedtest status / progress
        Constraint::Min(6),           // throughput graphs (given the most room)
        Constraint::Length(talker_h), // top talkers pinned to the bottom
    ])
    .split(inner);

    render_speedtest(f, s, rows[0]);

    let graphs = Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).split(rows[1]);
    let down = Sparkline::default()
        .data(tp.down_hist.tail_u64(graphs[0].width as usize))
        .style(Style::new().fg(Color::Green))
        .block(Block::new().title(Span::styled(
            format!(" ↓ down  {}", fmt_rate(tp.down_bps)),
            Style::new().fg(Color::Green).bold(),
        )));
    f.render_widget(down, graphs[0]);

    let up = Sparkline::default()
        .data(tp.up_hist.tail_u64(graphs[1].width as usize))
        .style(Style::new().fg(Color::Magenta))
        .block(Block::new().title(Span::styled(
            format!(" ↑ up    {}", fmt_rate(tp.up_bps)),
            Style::new().fg(Color::Magenta).bold(),
        )));
    f.render_widget(up, graphs[1]);

    top_talkers(f, s, rows[2], talkers);
}

/// The speed-test row: a live progress gauge while running, else a status line.
fn render_speedtest(f: &mut Frame, s: &AppState, area: Rect) {
    let st = &s.speedtest;
    if s.speedtest_enabled && matches!(st.status, SpeedStatus::Running) {
        let label = format!(
            "speedtest · {} {:.0}%  {:.1} Mbps",
            st.phase,
            st.progress * 100.0,
            st.live_mbps
        );
        let color = if st.phase == "upload" { Color::Magenta } else { Color::Green };
        f.render_widget(
            Gauge::default()
                .ratio(st.progress.clamp(0.0, 1.0))
                .label(label)
                .gauge_style(Style::new().fg(color)),
            area,
        );
    } else {
        f.render_widget(Paragraph::new(speedtest_line(s)), area);
    }
}

/// Compact "top processes by bandwidth" list beneath the throughput sparklines.
fn top_talkers(f: &mut Frame, s: &AppState, area: Rect, limit: usize) {
    let outer = Block::new().title(Span::styled(" top talkers ", Style::new().fg(Color::DarkGray)));
    let inner = outer.inner(area);
    f.render_widget(outer, area);

    if !s.proc_supported {
        f.render_widget(
            Paragraph::new(Span::styled(
                "per-process bandwidth unavailable on this platform",
                Style::new().fg(Color::DarkGray),
            )),
            inner,
        );
        return;
    }
    if s.processes.is_empty() {
        f.render_widget(
            Paragraph::new(Span::styled("…", Style::new().fg(Color::DarkGray))),
            inner,
        );
        return;
    }

    let rows = s.processes.iter().take(limit).map(|p| {
        let name: String = p.name.chars().take(18).collect();
        Row::new(vec![
            Cell::from(name),
            Cell::from(Span::styled(format!("↓{}", fmt_rate(p.down_bps)), Style::new().fg(Color::Green))),
            Cell::from(Span::styled(format!("↑{}", fmt_rate(p.up_bps)), Style::new().fg(Color::Magenta))),
        ])
    });
    let widths = [Constraint::Length(19), Constraint::Length(13), Constraint::Length(13)];
    f.render_widget(Table::new(rows, widths), inner);
}

/// Centered modal listing all keyboard shortcuts.
fn help_overlay(f: &mut Frame, area: Rect) {
    let w = 54u16.min(area.width);
    let h = 20u16.min(area.height);
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };
    let row = |k: &str, d: &str| {
        Line::from(vec![
            Span::styled(format!("  {k:<10}"), Style::new().fg(Color::Cyan)),
            Span::styled(d.to_string(), Style::new().fg(Color::Gray)),
        ])
    };
    let lines = vec![
        Line::from(Span::styled("  Global", Style::new().fg(Color::White).bold())),
        row("Tab", "cycle panel focus"),
        row("f", "toggle full-screen of focused panel"),
        row("s", "run speed test"),
        row("p", "pause / resume auto-refresh"),
        row("r", "re-probe network info"),
        row("w", "cycle stats window (30/60/300s)"),
        row("?", "toggle this help"),
        row("q / Esc", "quit"),
        Line::from(""),
        Line::from(Span::styled("  Connection Quality", Style::new().fg(Color::White).bold())),
        row("a", "add a target (IP or DNS name)"),
        row("↑/↓ or j/k", "select a target"),
        row("Enter", "graph the selected target's latency"),
        Line::from(""),
        Line::from(Span::styled("  press ? or Esc to close", Style::new().fg(Color::DarkGray))),
    ];
    f.render_widget(Clear, rect);
    f.render_widget(
        Paragraph::new(lines).block(
            Block::bordered()
                .title(Span::styled(" Keyboard Shortcuts ", Style::new().bold()))
                .border_style(Style::new().fg(Color::Cyan)),
        ),
        rect,
    );
}

fn netinfo_panel(f: &mut Frame, s: &AppState, area: Rect) {
    let n = &s.netinfo;
    let b = block("Network", s.focus == Panel::NetInfo);
    let inner = b.inner(area);
    f.render_widget(b, area);

    let kv = |k: &str, v: String| {
        Line::from(vec![
            Span::styled(format!("{k:<9}"), Style::new().fg(Color::DarkGray)),
            Span::raw(v),
        ])
    };
    let dash = |v: &str| if v.is_empty() { "-".to_string() } else { v.to_string() };

    let mut lines = vec![
        kv("iface", dash(&n.iface)),
        kv("link", dash(&n.link_kind)),
        kv("ipv4", if n.ipv4.is_empty() { "-".into() } else { n.ipv4.join(", ") }),
        kv("ipv6", if n.ipv6.is_empty() { "-".into() } else { n.ipv6.join(", ") }),
        kv("mac", dash(&n.mac)),
        kv("gateway", format!("{}  ({})", dash(&n.gateway_ip), dash(&n.gateway_mac))),
    ];
    if let Some(w) = &n.wifi {
        lines.push(kv("ssid", dash(&w.ssid)));
        lines.push(kv("wifi", format!("{}  ch {}", dash(&w.phy), dash(&w.channel))));
        lines.push(kv("signal", dash(&w.rssi)));
        lines.push(kv("tx rate", dash(&w.tx_rate)));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn vitals_panel(f: &mut Frame, s: &AppState, area: Rect) {
    let v = &s.vitals;
    let b = block("Machine", s.focus == Panel::Vitals);
    let inner = b.inner(area);
    f.render_widget(b, area);

    let parts = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
    ])
    .split(inner);

    let cpu = v.cpu_pct.clamp(0.0, 100.0);
    f.render_widget(
        Gauge::default()
            .ratio((cpu / 100.0) as f64)
            .label(format!("CPU {cpu:.0}%"))
            .gauge_style(Style::new().fg(usage_color(cpu))),
        parts[0],
    );

    let mem_pct = if v.mem_total > 0 {
        v.mem_used as f32 / v.mem_total as f32 * 100.0
    } else {
        0.0
    };
    f.render_widget(
        Gauge::default()
            .ratio((mem_pct / 100.0).clamp(0.0, 1.0) as f64)
            .label(format!("MEM {}/{}", fmt_bytes(v.mem_used), fmt_bytes(v.mem_total)))
            .gauge_style(Style::new().fg(usage_color(mem_pct))),
        parts[1],
    );

    // CPU history sparkline (uses the remaining space).
    let spark = Sparkline::default()
        .max(100)
        .data(v.cpu_hist.tail_u64(parts[3].width as usize))
        .style(Style::new().fg(Color::Yellow))
        .block(Block::new().title(Span::styled(" cpu history ", Style::new().fg(Color::DarkGray))));
    f.render_widget(spark, parts[3]);
}

/// One-line speed-test status/results shown atop the bandwidth panel.
fn speedtest_line(s: &AppState) -> Line<'static> {
    let st = &s.speedtest;
    let label = Span::styled("speedtest ", Style::new().fg(Color::DarkGray));
    if !s.speedtest_enabled {
        return Line::from(vec![
            label,
            Span::styled("disabled", Style::new().fg(Color::DarkGray)),
        ]);
    }
    match &st.status {
        SpeedStatus::Idle => Line::from(vec![
            label,
            Span::styled("[s]", Style::new().fg(Color::Cyan)),
            Span::raw(" run"),
        ]),
        SpeedStatus::Running => Line::from(vec![
            label,
            Span::styled("running…", Style::new().fg(Color::Yellow).bold()),
        ]),
        SpeedStatus::Done => {
            let ago = st
                .last_run
                .map(|t| format!("  ({}s ago)", t.elapsed().as_secs()))
                .unwrap_or_default();
            Line::from(vec![
                label,
                Span::styled(
                    format!("↓ {}", fmt_mbps(st.down_mbps)),
                    Style::new().fg(Color::Green).bold(),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("↑ {}", fmt_mbps(st.up_mbps)),
                    Style::new().fg(Color::Magenta).bold(),
                ),
                Span::styled(ago, Style::new().fg(Color::DarkGray)),
                Span::styled("  [s] rerun", Style::new().fg(Color::DarkGray)),
            ])
        }
        SpeedStatus::Failed(_) => Line::from(vec![
            label,
            Span::styled("failed", Style::new().fg(Color::Red).bold()),
            Span::styled("  [s] retry", Style::new().fg(Color::DarkGray)),
        ]),
    }
}

// --- formatting & color helpers -------------------------------------------

fn fmt_ms(v: Option<f64>) -> String {
    match v {
        Some(ms) => format!("{ms:.1}ms"),
        None => "—".to_string(),
    }
}

fn fmt_mbps(v: Option<f64>) -> String {
    match v {
        Some(m) => format!("{m:.1} Mbps"),
        None => "—".to_string(),
    }
}

fn fmt_rate(bps: f64) -> String {
    if bps >= 1_000_000.0 {
        format!("{:.1} MB/s", bps / 1_000_000.0)
    } else if bps >= 1_000.0 {
        format!("{:.1} KB/s", bps / 1_000.0)
    } else {
        format!("{bps:.0} B/s")
    }
}

fn fmt_bytes(n: u64) -> String {
    let f = n as f64;
    const G: f64 = 1_073_741_824.0;
    const M: f64 = 1_048_576.0;
    if f >= G {
        format!("{:.1}G", f / G)
    } else if f >= M {
        format!("{:.0}M", f / M)
    } else {
        format!("{:.0}K", f / 1024.0)
    }
}

fn latency_color(last: Option<f64>, loss: f64) -> Color {
    if loss >= 5.0 || last.is_none() {
        return Color::Red;
    }
    if loss >= 1.0 {
        return Color::Yellow;
    }
    match last {
        Some(ms) if ms < 50.0 => Color::Green,
        Some(ms) if ms < 150.0 => Color::Yellow,
        _ => Color::Red,
    }
}

fn usage_color(pct: f32) -> Color {
    if pct >= 85.0 {
        Color::Red
    } else if pct >= 60.0 {
        Color::Yellow
    } else {
        Color::Green
    }
}
