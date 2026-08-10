//! Rendering. A single [`render`] entry point draws the four panels from an
//! immutable snapshot of [`AppState`]. No data collection happens here.

use ratatui::layout::Alignment;
use ratatui::prelude::*;
use ratatui::style::Modifier;
use ratatui::symbols::Marker;
use ratatui::widgets::{
    Axis, Block, Cell, Chart, Clear, Dataset, Gauge, GraphType, LineGauge, Paragraph, Row,
    Sparkline, Table,
};

use crate::app::{AppState, InputMode, Panel, ProcStatus, SpeedStatus};

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
        let rows = Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(root[1]);
        let top = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(rows[0]);
        let bottom = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(rows[1]);
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
    let cols =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).split(area);

    let up = s.started.elapsed().as_secs();
    let mut left = vec![
        Span::styled(
            " octomon ",
            Style::new().fg(Color::Black).bg(Color::Cyan).bold(),
        ),
        Span::raw(format!(
            "  {:02}:{:02}:{:02}",
            up / 3600,
            (up % 3600) / 60,
            up % 60
        )),
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
            key("[a]"),
            txt("dd "),
            key("[d]"),
            txt("el "),
            key("[↑↓]"),
            txt("sel "),
            key("[g]"),
            txt("raph "),
            key("[t]"),
            txt("race "),
            key("[←→↵]"),
            txt("sort "),
            key("[R]"),
            txt("eset "),
        ],
        Panel::Bandwidth => {
            let p = s
                .speedtest_provider_names
                .get(s.speedtest_provider_idx)
                .map(String::as_str)
                .unwrap_or("—");
            vec![
                key("[s]"),
                txt("peed "),
                key("[v]"),
                txt(p),
                Span::raw(" "),
                key("[R]"),
                txt("eset "),
                key("[f]"),
                txt("ull "),
            ]
        }
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
            Span::styled(
                " add target (IP or DNS): ",
                Style::new().fg(Color::Yellow).bold(),
            ),
            Span::styled(s.input_buffer.clone(), Style::new().fg(Color::White)),
            Span::styled("▏", Style::new().fg(Color::Yellow)),
            Span::styled(
                "   [Enter] add  [Esc] cancel",
                Style::new().fg(Color::DarkGray),
            ),
        ])
    } else if let Some(n) = &s.notice {
        Line::from(Span::styled(
            format!(" {n}"),
            Style::new().fg(Color::Yellow),
        ))
    } else {
        Line::from(Span::styled(
            " [Tab] focus  [f] full  [p] pause  [r] refresh  [w] window  [s] speedtest  [?] help  [q] quit",
            Style::new().fg(Color::DarkGray),
        ))
    };
    f.render_widget(Paragraph::new(line), area);
}

fn block(title: &str, focused: bool) -> Block<'static> {
    let border = if focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };
    Block::bordered()
        .title(Span::styled(format!(" {title} "), Style::new().bold()))
        .border_style(Style::new().fg(border))
}

fn quality_panel(f: &mut Frame, s: &AppState, area: Rect) {
    let b = block("Connection Quality", s.focus == Panel::Quality);
    let inner = b.inner(area);
    f.render_widget(b, area);

    // When showing traceroute, shrink the table so hops get the room.
    let bottom_h = if s.fullscreen { 12 } else { 6 };
    let parts = if s.show_traceroute {
        let table_h = (s.targets.len() as u16 + 2).min(9);
        Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(table_h),
            Constraint::Min(0),
        ])
        .split(inner)
    } else {
        Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(bottom_h),
        ])
        .split(inner)
    };

    let n = s.window_samples();
    quality_summary(f, s, n, parts[0]);

    let focused = s.focus == Panel::Quality;
    // Sortable header: highlight the column cursor, mark the active sort ▲/▼.
    let hcell = |sort_col: usize, label: &str| {
        let mut txt = label.to_string();
        if let Some((c, desc)) = s.q_sort
            && c == sort_col
        {
            txt.push(if desc { '▼' } else { '▲' });
        }
        let style = if focused && s.q_col == sort_col {
            Style::new()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            Style::new().fg(Color::Gray).bold()
        };
        Cell::from(Span::styled(txt, style))
    };
    let header = Row::new(vec![
        Cell::from(""),
        hcell(0, "Target"),
        Cell::from(Span::styled("Address", Style::new().fg(Color::Gray).bold())),
        hcell(1, "last"),
        hcell(2, "avg"),
        hcell(3, "p95"),
        hcell(4, "max"),
        hcell(5, "loss"),
    ]);

    let order = s.quality_order();
    let rows = order.iter().map(|&i| {
        let t = &s.targets[i];
        let loss = t.loss_pct();
        let st = t.stats(n);
        let color = latency_color(t.last_rtt_ms, loss);
        let marker = if i == s.graph_target { "►" } else { "" };
        let mut style = Style::new().fg(color);
        if focused && i == s.selected {
            style = style
                .bg(Color::Rgb(40, 40, 55))
                .add_modifier(Modifier::BOLD);
        }
        // '⇢' marks auto-discovered (gateway / hop) targets.
        let label = if t.discovered {
            format!("⇢ {}", t.label)
        } else {
            t.label.clone()
        };
        Row::new(vec![
            Cell::from(Span::styled(marker, Style::new().fg(Color::Cyan))),
            Cell::from(label),
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

    if s.show_traceroute {
        traceroute_view(f, s, parts[2]);
    } else {
        latency_graph(f, s, n, parts[2]);
    }
}

/// Live traceroute hop list for the current target.
fn traceroute_view(f: &mut Frame, s: &AppState, area: Rect) {
    let Some(tr) = &s.traceroute else {
        return;
    };
    let status = if tr.running { "running…" } else { "done" };
    let outer = Block::new().title(Span::styled(
        format!(" traceroute · {}  ({status})  [g] graph ", tr.target),
        Style::new().fg(Color::DarkGray),
    ));
    let inner = outer.inner(area);
    f.render_widget(outer, area);

    let hop_line = |h: &crate::app::Hop| {
        let addr = h.addr.clone().unwrap_or_else(|| "*".to_string());
        let color = match h.rtt_ms {
            Some(v) if v >= 150.0 => Color::Red,
            Some(v) if v >= 60.0 => Color::Yellow,
            Some(_) => Color::Green,
            None => Color::DarkGray,
        };
        let rtt = h.rtt_ms.map(|v| format!("{v:.1}ms")).unwrap_or_default();
        Line::from(vec![
            Span::styled(format!("{:>2}  ", h.ttl), Style::new().fg(Color::DarkGray)),
            Span::styled(format!("{addr:<18}"), Style::new().fg(color)),
            Span::styled(rtt, Style::new().fg(color)),
        ])
    };

    let rows = inner.height as usize;
    let body: Vec<Line> = if tr.hops.is_empty() {
        vec![Line::from(Span::styled(
            "probing…",
            Style::new().fg(Color::DarkGray),
        ))]
    } else if tr.hops.len() > rows {
        // Not enough room: show what fits, then point to full-screen.
        let mut v: Vec<Line> = tr
            .hops
            .iter()
            .take(rows.saturating_sub(1))
            .map(hop_line)
            .collect();
        let remaining = tr.hops.len() - rows.saturating_sub(1);
        v.push(Line::from(Span::styled(
            format!("… +{remaining} more — press [f] for full screen"),
            Style::new().fg(Color::Yellow),
        )));
        v
    } else {
        tr.hops.iter().map(hop_line).collect()
    };
    f.render_widget(Paragraph::new(body), inner);
}

/// Latency line chart for the graphed target, with a p95 reference line.
fn latency_graph(f: &mut Frame, s: &AppState, n: usize, area: Rect) {
    let Some(t) = s.targets.get(s.graph_target) else {
        return;
    };
    // Braille markers double horizontal resolution.
    let want = (area.width as usize).saturating_mul(2).max(20);
    let raw: Vec<f64> = {
        let mut v: Vec<f64> = t.history.data.iter().rev().take(want).copied().collect();
        v.reverse();
        v
    };
    if raw.is_empty() {
        f.render_widget(
            Paragraph::new(Span::styled(
                format!(" latency · {} — collecting…", t.label),
                Style::new().fg(Color::DarkGray),
            )),
            area,
        );
        return;
    }

    let series: Vec<(f64, f64)> = raw
        .iter()
        .enumerate()
        .map(|(i, &v)| (i as f64, v))
        .collect();
    let xmax = (series.len().saturating_sub(1)).max(1) as f64;
    let p95 = t.stats(n).p95.unwrap_or(0.0);
    let ymax = raw.iter().copied().fold(0.0_f64, f64::max).max(p95) * 1.15 + 1.0;
    let p95_line = [(0.0, p95), (xmax, p95)];

    let datasets = vec![
        Dataset::default()
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::new().fg(Color::Cyan))
            .data(&series),
        Dataset::default()
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::new().fg(Color::Yellow))
            .data(&p95_line),
    ];

    let chart = Chart::new(datasets)
        .block(Block::new().title(Span::styled(
            format!(" latency · {}   p95 {p95:.0}ms ", t.label),
            Style::new().fg(Color::DarkGray),
        )))
        .x_axis(Axis::default().bounds([0.0, xmax]))
        .y_axis(
            Axis::default()
                .bounds([0.0, ymax])
                .labels([Line::from("0"), Line::from(format!("{ymax:.0}ms"))]),
        );
    f.render_widget(chart, area);
}

/// One-line summary above the table: stats window, and jitter / stddev /
/// bufferbloat for the graphed target.
fn quality_summary(f: &mut Frame, s: &AppState, n: usize, area: Rect) {
    let mut spans = vec![
        Span::styled(
            format!("window {}s ", s.window_secs),
            Style::new().fg(Color::Gray),
        ),
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
            spans.push(Span::styled(
                "bufferbloat ",
                Style::new().fg(Color::DarkGray),
            ));
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
        &format!(
            "Bandwidth · {}",
            if tp.iface.is_empty() {
                "…"
            } else {
                &tp.iface
            }
        ),
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

    let graphs =
        Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).split(rows[1]);
    let (ddata, dmax) = spark_floor(&tp.down_hist, graphs[0].width, graphs[0].height);
    let down = Sparkline::default()
        .data(ddata)
        .max(dmax)
        .style(Style::new().fg(Color::Green))
        .block(Block::new().title(Span::styled(
            format!(" ↓ down  {}", fmt_rate(tp.down_bps)),
            Style::new().fg(Color::Green).bold(),
        )));
    f.render_widget(down, graphs[0]);

    let (udata, umax) = spark_floor(&tp.up_hist, graphs[1].width, graphs[1].height);
    let up = Sparkline::default()
        .data(udata)
        .max(umax)
        .style(Style::new().fg(Color::Magenta))
        .block(Block::new().title(Span::styled(
            format!(" ↑ up    {}", fmt_rate(tp.up_bps)),
            Style::new().fg(Color::Magenta).bold(),
        )));
    f.render_widget(up, graphs[1]);

    // Full-screen: processes and speed-test history each get their own panel.
    if s.fullscreen {
        let cols = Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(rows[2]);

        let pblock = block("Processes", false);
        let pinner = pblock.inner(cols[0]);
        f.render_widget(pblock, cols[0]);
        top_talkers(f, s, pinner, talkers);

        let sblock = block("Speed Test History", false);
        let sinner = sblock.inner(cols[1]);
        f.render_widget(sblock, cols[1]);
        speedtest_results(f, s, sinner);
    } else {
        top_talkers(f, s, rows[2], talkers);
    }
}

/// Table of recent speed-test results (full-screen only).
fn speedtest_results(f: &mut Frame, s: &AppState, area: Rect) {
    if s.speed_history.is_empty() {
        f.render_widget(
            Paragraph::new(Span::styled(
                "no speed tests yet — [s] to run",
                Style::new().fg(Color::DarkGray),
            )),
            area,
        );
        return;
    }

    let header = Row::new(["time", "provider", "↓Mbps", "↑Mbps", "bloat"])
        .style(Style::new().fg(Color::DarkGray));
    let n = (area.height.saturating_sub(1)) as usize;
    let rows = s.speed_history.iter().rev().take(n).map(|r| {
        let bloat = match (r.idle_ms, r.loaded_ms) {
            (Some(i), Some(l)) => format!("+{:.0}ms", (l - i).max(0.0)),
            _ => "—".to_string(),
        };
        Row::new(vec![
            Cell::from(r.when()),
            Cell::from(r.provider.clone()),
            Cell::from(Span::styled(
                format!("{:.0}", r.down_mbps),
                Style::new().fg(Color::Green),
            )),
            Cell::from(Span::styled(
                format!("{:.0}", r.up_mbps),
                Style::new().fg(Color::Magenta),
            )),
            Cell::from(bloat),
        ])
    });
    let widths = [
        Constraint::Length(12),
        Constraint::Length(11),
        Constraint::Length(7),
        Constraint::Length(7),
        Constraint::Length(8),
    ];
    f.render_widget(Table::new(rows, widths).header(header), area);
}

/// Sparkline data that guarantees any non-zero sample renders at least one
/// sub-cell (▁), so low-but-present bandwidth is always visible. Returns the
/// data plus the explicit max to scale against.
fn spark_floor(hist: &crate::app::History, width: u16, height: u16) -> (Vec<u64>, u64) {
    let data = hist.tail_u64(width as usize);
    let max = data.iter().copied().max().unwrap_or(0);
    if max == 0 {
        return (data, 1); // no activity → nothing to show
    }
    // A sparkline cell has 8 vertical levels; the smallest visible value is
    // max / (rows*8). Floor non-zero samples to that so they show a pixel.
    let levels = (height as u64).saturating_mul(8).max(8);
    let floor = (max / levels).max(1);
    let data = data
        .iter()
        .map(|&v| if v > 0 { v.max(floor) } else { 0 })
        .collect();
    (data, max)
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
        let color = if st.phase == "upload" {
            Color::Magenta
        } else {
            Color::Green
        };
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

/// Compact "top processes by bandwidth" list beneath the throughput sparklines,
/// with per-process rtt and retransmit-rate for connection health.
fn top_talkers(f: &mut Frame, s: &AppState, area: Rect, limit: usize) {
    // No section title (the column header makes the list self-explanatory),
    // reclaiming a row for data.
    let inner = area;
    let dim = |f: &mut Frame, msg: &str| {
        f.render_widget(
            Paragraph::new(Span::styled(
                msg.to_string(),
                Style::new().fg(Color::DarkGray),
            )),
            inner,
        );
    };
    match s.proc_status {
        ProcStatus::Unsupported => {
            return dim(f, "per-process bandwidth unavailable on this platform");
        }
        ProcStatus::Probing => return dim(f, "detecting per-process bandwidth… (~5s)"),
        ProcStatus::Supported if s.processes.is_empty() => return dim(f, "sampling processes…"),
        ProcStatus::Supported => {}
    }

    // Header with the column cursor highlighted and a sort-direction arrow.
    let focused = s.focus == Panel::Bandwidth;
    let labels = ["process", "↓", "↑", "total", "retx"];
    let header = Row::new(labels.iter().enumerate().map(|(i, l)| {
        let mut txt = (*l).to_string();
        if let Some((c, desc)) = s.bw_sort
            && c == i
        {
            txt.push(if desc { '▼' } else { '▲' });
        }
        let style = if focused && i == s.bw_col {
            Style::new()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            Style::new().fg(Color::DarkGray)
        };
        Cell::from(Span::styled(txt, style))
    }));

    // Apply the active sort (a copy — the collector keeps its own order).
    let mut procs: Vec<&crate::app::ProcBandwidth> = s.processes.iter().collect();
    if let Some((col, desc)) = s.bw_sort {
        procs.sort_by(|a, b| {
            let o = match col {
                0 => a.name.cmp(&b.name),
                2 => a.up_bps.total_cmp(&b.up_bps),
                3 => a.total_bytes.cmp(&b.total_bytes),
                4 => a.retx_per_sec.total_cmp(&b.retx_per_sec),
                _ => a.down_bps.total_cmp(&b.down_bps),
            };
            if desc { o.reverse() } else { o }
        });
    }

    let rows = procs.into_iter().take(limit).map(|p| {
        let name: String = p.name.chars().take(36).collect();
        let (retx, retx_style) = if p.retx_per_sec >= 1.0 {
            (
                format!("{:.0}/s", p.retx_per_sec),
                Style::new().fg(Color::Red),
            )
        } else {
            ("·".to_string(), Style::new().fg(Color::DarkGray))
        };
        Row::new(vec![
            Cell::from(name),
            Cell::from(Span::styled(
                fmt_rate(p.down_bps),
                Style::new().fg(Color::Green),
            )),
            Cell::from(Span::styled(
                fmt_rate(p.up_bps),
                Style::new().fg(Color::Magenta),
            )),
            Cell::from(Span::styled(
                fmt_bytes(p.total_bytes),
                Style::new().fg(Color::Gray),
            )),
            Cell::from(Span::styled(retx, retx_style)),
        ])
    });
    let widths = [
        Constraint::Length(38),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(8),
        Constraint::Length(8),
    ];
    f.render_widget(Table::new(rows, widths).header(header), inner);
}

/// Centered modal listing all keyboard shortcuts.
fn help_overlay(f: &mut Frame, area: Rect) {
    let w = 60u16.min(area.width);
    let h = 22u16.min(area.height);
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };
    let row = |k: &str, d: &str| {
        // Pad generously so long key combos keep a gap before the description.
        Line::from(vec![
            Span::styled(format!("  {k:<15}"), Style::new().fg(Color::Cyan)),
            Span::styled(format!("  {d}"), Style::new().fg(Color::Gray)),
        ])
    };
    let lines = vec![
        Line::from(Span::styled(
            "  Global",
            Style::new().fg(Color::White).bold(),
        )),
        row("Tab / ⇧Tab", "cycle panel focus (fwd / back)"),
        row("f", "toggle full-screen of focused panel"),
        row("s", "run speed test"),
        row("p", "pause / resume auto-refresh"),
        row("r", "re-probe network info"),
        row("w", "cycle stats window (30/60/300s)"),
        row("?", "toggle this help"),
        row("q / Esc", "quit"),
        Line::from(""),
        Line::from(Span::styled(
            "  Connection Quality",
            Style::new().fg(Color::White).bold(),
        )),
        row("a", "add a target (IP or DNS name)"),
        row("d / Del", "delete the selected target"),
        row("g", "graph selected target (exits traceroute)"),
        row("t", "traceroute the selected target"),
        row("↑/↓ or j/k", "select a target"),
        row("←/→", "move sort-column cursor"),
        row("Enter", "sort by the cursor column"),
        row("Space", "toggle sort direction"),
        row("Shift+R", "reset this panel's data"),
        Line::from(""),
        Line::from(Span::styled(
            "  Bandwidth",
            Style::new().fg(Color::White).bold(),
        )),
        row("v", "cycle speed-test provider (saved)"),
        row("←/→", "move top-talkers column cursor"),
        row("Enter / Space", "sort by column / toggle direction"),
        row("Shift+R", "reset this panel's data"),
        Line::from(""),
        Line::from(Span::styled(
            "  press ? or Esc to close",
            Style::new().fg(Color::DarkGray),
        )),
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
    let dash = |v: &str| {
        if v.is_empty() {
            "-".to_string()
        } else {
            v.to_string()
        }
    };

    // Before the first netinfo sample lands.
    if n.iface.is_empty() {
        f.render_widget(
            Paragraph::new(Span::styled(
                "detecting network…",
                Style::new().fg(Color::DarkGray),
            )),
            inner,
        );
        return;
    }

    let mut lines = vec![
        kv("iface", dash(&n.iface)),
        kv("link", dash(&n.link_kind)),
        kv(
            "ipv4",
            if n.ipv4.is_empty() {
                "-".into()
            } else {
                n.ipv4.join(", ")
            },
        ),
        kv(
            "ipv6",
            if n.ipv6.is_empty() {
                "-".into()
            } else {
                n.ipv6.join(", ")
            },
        ),
        kv("mac", dash(&n.mac)),
        kv(
            "gateway",
            format!("{}  ({})", dash(&n.gateway_ip), dash(&n.gateway_mac)),
        ),
        kv(
            "dns",
            if n.dns.is_empty() {
                "-".into()
            } else {
                n.dns.join(", ")
            },
        ),
    ];
    if let Some(w) = &n.wifi {
        // Live signal/tx come from the CoreWLAN graph below; keep the slower
        // system_profiler details (SSID / PHY / channel) here.
        lines.push(kv("ssid", dash(&w.ssid)));
        lines.push(kv(
            "wifi",
            format!("{}  ch {}", dash(&w.phy), dash(&w.channel)),
        ));
    } else if n.link_kind.contains("Wi-Fi") || n.link_kind.contains("Wireless") {
        lines.push(Line::from(Span::styled(
            "gathering Wi-Fi details…",
            Style::new().fg(Color::DarkGray),
        )));
    }

    // Reserve space at the bottom for the live signal graph when on Wi-Fi.
    let (info_area, graph_area) = if s.signal.present {
        let p = Layout::vertical([Constraint::Min(4), Constraint::Length(5)]).split(inner);
        (p[0], Some(p[1]))
    } else {
        (inner, None)
    };

    f.render_widget(Paragraph::new(lines), info_area);
    if let Some(ga) = graph_area {
        signal_graph(f, s, ga);
    }

    // Transient "re-probing" note pinned to the bottom of the info area.
    if s.refresh_at.is_some_and(|t| t.elapsed().as_secs() < 3) {
        let bottom = Rect {
            x: info_area.x,
            y: info_area.y + info_area.height.saturating_sub(1),
            width: info_area.width,
            height: 1,
        };
        f.render_widget(
            Paragraph::new(Span::styled(
                "re-probing network info…",
                Style::new().fg(Color::Yellow),
            )),
            bottom,
        );
    }
}

/// Live Wi-Fi signal sparkline (RSSI, higher = better) with current tx rate.
fn signal_graph(f: &mut Frame, s: &AppState, area: Rect) {
    let sig = &s.signal;
    let sig_color = match sig.rssi_dbm {
        r if r >= -60 => Color::Green,
        r if r >= -72 => Color::Yellow,
        _ => Color::Red,
    };
    let title = format!(
        " signal {} dBm ({}) · tx {:.0} Mbps (cyan) ",
        sig.rssi_dbm,
        match sig_color {
            Color::Green => "green",
            Color::Yellow => "yellow",
            _ => "red",
        },
        sig.tx_rate_mbps,
    );

    // Both series share a normalised 0..1 y-axis so their trends overlay: RSSI
    // as signal quality (−30 best … −100 worst); tx-rate against its own peak.
    let want = (area.width as usize).saturating_mul(2).max(20);
    let tail = |h: &crate::app::History| -> Vec<f64> {
        let skip = h.data.len().saturating_sub(want);
        h.data.iter().skip(skip).copied().collect()
    };
    let rssi = tail(&sig.rssi_hist);
    let tx = tail(&sig.tx_hist);
    let len = rssi.len().min(tx.len());
    if len == 0 {
        return;
    }
    let tx_max = tx.iter().copied().fold(1.0_f64, f64::max);
    let sig_pts: Vec<(f64, f64)> = (0..len)
        .map(|i| (i as f64, ((rssi[i] + 100.0) / 70.0).clamp(0.0, 1.0)))
        .collect();
    let tx_pts: Vec<(f64, f64)> = (0..len)
        .map(|i| (i as f64, (tx[i] / tx_max).clamp(0.0, 1.0)))
        .collect();
    let xmax = (len - 1).max(1) as f64;

    let datasets = vec![
        Dataset::default()
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::new().fg(sig_color))
            .data(&sig_pts),
        Dataset::default()
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::new().fg(Color::Cyan))
            .data(&tx_pts),
    ];
    let chart = Chart::new(datasets)
        .block(Block::new().title(Span::styled(title, Style::new().fg(Color::DarkGray))))
        .x_axis(Axis::default().bounds([0.0, xmax]))
        .y_axis(Axis::default().bounds([0.0, 1.05]));
    f.render_widget(chart, area);
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

    // LineGauge keeps the label to the left of the bar, so it stays legible
    // (a Gauge draws the label over the fill, which is unreadable on yellow).
    let cpu = v.cpu_pct.clamp(0.0, 100.0);
    f.render_widget(
        LineGauge::default()
            .ratio((cpu / 100.0) as f64)
            .label(format!("CPU {cpu:>3.0}%"))
            .filled_style(Style::new().fg(usage_color(cpu)))
            .unfilled_style(Style::new().fg(Color::DarkGray)),
        parts[0],
    );

    let mem_pct = if v.mem_total > 0 {
        v.mem_used as f32 / v.mem_total as f32 * 100.0
    } else {
        0.0
    };
    f.render_widget(
        LineGauge::default()
            .ratio((mem_pct / 100.0).clamp(0.0, 1.0) as f64)
            .label(format!(
                "MEM {}/{}",
                fmt_bytes(v.mem_used),
                fmt_bytes(v.mem_total)
            ))
            .filled_style(Style::new().fg(usage_color(mem_pct)))
            .unfilled_style(Style::new().fg(Color::DarkGray)),
        parts[1],
    );

    // CPU history sparkline (uses the remaining space).
    let spark = Sparkline::default()
        .max(100)
        .data(v.cpu_hist.tail_u64(parts[3].width as usize))
        .style(Style::new().fg(Color::Yellow))
        .block(Block::new().title(Span::styled(
            " cpu history ",
            Style::new().fg(Color::DarkGray),
        )));
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
            let mut spans = vec![
                label,
                Span::styled(format!("{} ", st.provider), Style::new().fg(Color::Cyan)),
                Span::styled(
                    format!("↓ {}", fmt_mbps(st.down_mbps)),
                    Style::new().fg(Color::Green).bold(),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("↑ {}", fmt_mbps(st.up_mbps)),
                    Style::new().fg(Color::Magenta).bold(),
                ),
            ];
            // Loaded-latency bufferbloat, if measured.
            if let (Some(idle), Some(loaded)) = (st.idle_latency_ms, st.loaded_latency_ms) {
                let bloat = (loaded - idle).max(0.0);
                let (grade, color) = bufferbloat_grade(bloat);
                spans.push(Span::styled(
                    format!("  bloat +{bloat:.0}ms ({grade})"),
                    Style::new().fg(color),
                ));
            }
            spans.push(Span::styled(ago, Style::new().fg(Color::DarkGray)));
            spans.push(Span::styled(
                "  [s] rerun",
                Style::new().fg(Color::DarkGray),
            ));
            Line::from(spans)
        }
        SpeedStatus::Failed(e) => {
            // Surface the reason; flag rate limiting explicitly.
            let msg = if e.contains("rate-limit") || e.contains("429") {
                "rate-limited — wait a moment".to_string()
            } else {
                e.chars().take(48).collect()
            };
            Line::from(vec![
                label,
                Span::styled("failed: ", Style::new().fg(Color::Red).bold()),
                Span::styled(msg, Style::new().fg(Color::Red)),
                Span::styled("  [s] retry", Style::new().fg(Color::DarkGray)),
            ])
        }
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
