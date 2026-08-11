//! Rendering. A single [`render`] entry point draws the four panels from an
//! immutable snapshot of [`AppState`]. No data collection happens here.

use ratatui::layout::Alignment;
use ratatui::prelude::*;
use ratatui::style::Modifier;
use ratatui::symbols::Marker;
use ratatui::widgets::{
    Axis, Block, Cell, Chart, Clear, Dataset, Gauge, GraphType, LineGauge, Paragraph, Row,
    Sparkline, Table, Wrap,
};

use crate::app::{
    AppState, InputMode, LinkMedium, Panel, ProcStatus, QualityView, SpeedStatus, SubPane,
};

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
        help_overlay(f, s, f.area());
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
    // Recording is a background side effect that writes to disk, so it stays
    // visible for as long as it is running.
    match &s.log {
        Some(log) => {
            let secs = log.started.elapsed().as_secs();
            // Gap goes outside the styled span, or it renders as a red block
            // hanging off the left of the dot.
            left.push(Span::raw("  "));
            left.push(Span::styled(
                "● REC",
                Style::new().fg(Color::White).bg(Color::Red).bold(),
            ));
            left.push(Span::styled(
                format!(" {}:{:02}  {} rows", secs / 60, secs % 60, log.rows),
                Style::new().fg(Color::Red),
            ));
        }
        // Asked for, but the file is not open yet (or failed to open).
        None if s.logging_requested => left.push(Span::styled(
            "  ● starting…",
            Style::new().fg(Color::Yellow),
        )),
        None => {}
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
            key("[m]"),
            txt("onitor "),
            key("[n]"),
            txt("pane "),
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
            " [Tab] focus  [f] full  [p] pause  [r] refresh  [w] window  [s] speedtest  [l] log  [?] help  [q] quit",
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

    // The path views need the room, so the target table shrinks to a summary.
    let bottom_h = if s.fullscreen { 12 } else { 6 };
    let parts = if s.quality_view == QualityView::Graph {
        Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(bottom_h),
        ])
        .split(inner)
    } else {
        let table_h = (s.targets.len() as u16 + 2).min(9);
        Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(table_h),
            Constraint::Min(0),
        ])
        .split(inner)
    };

    let n = s.window_samples();
    quality_summary(f, s, n, parts[0]);

    let focused = s.focus == Panel::Quality && s.sub_pane == SubPane::Primary;
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

    match s.quality_view {
        QualityView::Graph => latency_graph(f, s, n, parts[2]),
        QualityView::Traceroute => traceroute_view(f, s, parts[2]),
        QualityView::HopMonitor => hop_monitor_view(f, s, n, parts[2]),
    }
}

/// A row of the rendered hop list: either a real hop, or a collapsed run of
/// consecutive hops that never answered.
enum HopRow<'a> {
    Hop(usize, &'a crate::app::MonitoredHop),
    /// (first ttl, last ttl, how many) — a run of silent hops worth one line.
    Silent(u8, u8, usize),
}

/// Collapse runs of unresponsive hops. A single silent hop between two
/// responders is genuinely informative and stays; a run of six is just noise
/// pushing the useful rows off the screen.
fn hop_rows(hops: &[crate::app::MonitoredHop]) -> Vec<HopRow<'_>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < hops.len() {
        if hops[i].addr.is_some() {
            out.push(HopRow::Hop(i, &hops[i]));
            i += 1;
            continue;
        }
        let start = i;
        while i < hops.len() && hops[i].addr.is_none() {
            i += 1;
        }
        let run = i - start;
        if run == 1 {
            out.push(HopRow::Hop(start, &hops[start]));
        } else {
            out.push(HopRow::Silent(hops[start].ttl, hops[i - 1].ttl, run));
        }
    }
    out
}

/// Continuous per-hop statistics with an inline sparkline for every hop — the
/// MTR-style view. Loss appearing at one hop and persisting past it points at
/// that hop; loss *only* at a hop is usually just ICMP deprioritised there, so
/// both columns are shown and coloured differently.
fn hop_monitor_view(f: &mut Frame, s: &AppState, n: usize, area: Rect) {
    let Some(m) = &s.hop_monitor else {
        return;
    };
    let status = if m.discovering {
        "walking path…"
    } else {
        "live"
    };
    let active = s.focus == Panel::Quality && s.sub_pane == SubPane::Secondary;

    // Full-screen has room to give the selected hop its own chart beneath the
    // table; the split view does not.
    let (list_area, chart_area) = if s.fullscreen && area.height >= 12 {
        let p = Layout::vertical([Constraint::Min(5), Constraint::Length(8)]).split(area);
        (p[0], Some(p[1]))
    } else {
        (area, None)
    };

    let b = block(&format!("Path · {}  ({status})", m.target), active);
    let inner = b.inner(list_area);
    f.render_widget(b, list_area);

    if inner.height == 0 || m.hops.is_empty() {
        f.render_widget(
            Paragraph::new(Span::styled(
                "discovering path…",
                Style::new().fg(Color::DarkGray),
            )),
            inner,
        );
        return;
    }

    // Column widths are fixed, so the sparklines start right after the last
    // column rather than being flung to the far right of a wide terminal.
    const COLS: [u16; 7] = [4, 17, 6, 8, 8, 8, 7];
    // Table adds one cell of spacing between columns; leaving it out squeezes
    // the columns and silently truncates the address cell.
    let table_w: u16 = COLS.iter().sum::<u16>() + COLS.len() as u16 - 1;
    let spark_w = inner.width.saturating_sub(table_w + 1);
    let show_sparks = spark_w >= 8;

    let header = Row::new(["ttl", "address", "loss", "last", "avg", "p95", "jitter"])
        .style(Style::new().fg(Color::Gray).bold());
    let rows_avail = inner.height.saturating_sub(1) as usize;
    let all_rows = hop_rows(&m.hops);
    let visible: Vec<&HopRow> = all_rows.iter().take(rows_avail).collect();

    let rows = visible.iter().map(|row| match row {
        // Left blank here and drawn afterwards across the whole row, since the
        // message is wider than the address column and a Table cannot span.
        HopRow::Silent(..) => Row::new(vec![Cell::from("")]),
        HopRow::Hop(idx, h) => {
            let selected = active && *idx == m.selected;
            let Some(stat) = &h.stat else {
                let mut style = Style::new().fg(Color::DarkGray);
                if selected {
                    style = style.bg(Color::Rgb(40, 40, 55));
                }
                return Row::new(vec![
                    Cell::from(format!("{:>2}", h.ttl)),
                    Cell::from("*"),
                    Cell::from("—"),
                    Cell::from("—"),
                    Cell::from("—"),
                    Cell::from("—"),
                    Cell::from("—"),
                ])
                .style(style);
            };
            let loss = stat.loss_pct();
            let st = stat.stats(n);
            let mut style = Style::new().fg(latency_color(stat.last_rtt_ms, loss));
            if selected {
                style = style
                    .bg(Color::Rgb(40, 40, 55))
                    .add_modifier(Modifier::BOLD);
            }
            Row::new(vec![
                Cell::from(format!("{:>2}", h.ttl)),
                Cell::from(
                    h.addr
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "*".to_string()),
                ),
                Cell::from(Span::styled(
                    format!("{loss:.0}%"),
                    Style::new().fg(loss_color(loss)),
                )),
                Cell::from(fmt_ms(stat.last_rtt_ms)),
                Cell::from(fmt_ms(st.mean)),
                Cell::from(fmt_ms(st.p95)),
                Cell::from(format!("{:.1}", stat.jitter_ms)),
            ])
            .style(style)
        }
    });
    let widths: Vec<Constraint> = COLS.iter().map(|w| Constraint::Length(*w)).collect();
    f.render_widget(
        Table::new(rows, widths).header(header),
        Rect {
            width: table_w.min(inner.width),
            ..inner
        },
    );

    for (i, row) in visible.iter().enumerate() {
        let y = inner.y + 1 + i as u16; // +1 skips the header row
        if y >= inner.y + inner.height {
            break;
        }
        match row {
            HopRow::Silent(from, to, count) => {
                f.render_widget(
                    Paragraph::new(Line::from(vec![
                        Span::styled(format!("{from:>2}-{to} "), Style::new().fg(Color::DarkGray)),
                        Span::styled(
                            format!("{count} hops not responsive"),
                            Style::new().fg(Color::DarkGray).italic(),
                        ),
                    ])),
                    Rect {
                        x: inner.x,
                        y,
                        width: inner.width,
                        height: 1,
                    },
                );
            }
            HopRow::Hop(_, h) => {
                if !show_sparks {
                    continue;
                }
                let Some(stat) = &h.stat else { continue };
                let data = stat.history.tail_u64(spark_w as usize);
                if data.is_empty() {
                    continue;
                }
                // Every hop is probed on the same interval, so one cell is the
                // same slice of time on every row. A hop discovered late has
                // fewer samples, so its trace is drawn narrower and pinned to
                // the right edge — that keeps "now" aligned down the column
                // instead of stretching a short history across the full width.
                let width = (data.len() as u16).min(spark_w);
                let max = data.iter().copied().max().unwrap_or(1).max(1);
                f.render_widget(
                    Sparkline::default()
                        .data(data)
                        .max(max)
                        .style(Style::new().fg(latency_color(stat.last_rtt_ms, stat.loss_pct()))),
                    Rect {
                        x: inner.x + table_w + 1 + (spark_w - width),
                        y,
                        width,
                        height: 1,
                    },
                );
            }
        }
    }

    if let Some(chart_area) = chart_area {
        hop_chart(f, m, n, chart_area);
    }
}

/// Latency history for the hop under the cursor, in its own panel.
fn hop_chart(f: &mut Frame, m: &crate::app::HopMonitor, n: usize, area: Rect) {
    let hop = m.hops.get(m.selected);
    let label = match hop {
        Some(h) => match h.addr {
            Some(a) => format!("hop {} · {a}", h.ttl),
            None => format!("hop {} · no reply", h.ttl),
        },
        None => "hop".to_string(),
    };
    let b = block(&label, false);
    let inner = b.inner(area);
    f.render_widget(b, area);

    let Some(stat) = hop.and_then(|h| h.stat.as_ref()) else {
        f.render_widget(
            Paragraph::new(Span::styled(
                "this hop does not answer — nothing to chart",
                Style::new().fg(Color::DarkGray),
            )),
            inner,
        );
        return;
    };

    let want = (inner.width as usize).saturating_mul(2).max(20);
    let raw: Vec<f64> = {
        let mut v: Vec<f64> = stat.history.data.iter().rev().take(want).copied().collect();
        v.reverse();
        v
    };
    if raw.is_empty() {
        f.render_widget(
            Paragraph::new(Span::styled(
                "collecting…",
                Style::new().fg(Color::DarkGray),
            )),
            inner,
        );
        return;
    }

    let series: Vec<(f64, f64)> = raw
        .iter()
        .enumerate()
        .map(|(i, &v)| (i as f64, v))
        .collect();
    let xmax = (series.len().saturating_sub(1)).max(1) as f64;
    let st = stat.stats(n);
    let p95 = st.p95.unwrap_or(0.0);
    let ymax = raw.iter().copied().fold(0.0_f64, f64::max).max(p95) * 1.15 + 1.0;
    let p95_line = [(0.0, p95), (xmax, p95)];

    let datasets = vec![
        Dataset::default()
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::new().fg(latency_color(stat.last_rtt_ms, stat.loss_pct())))
            .data(&series),
        Dataset::default()
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::new().fg(Color::Yellow))
            .data(&p95_line),
    ];
    let chart = Chart::new(datasets)
        .block(Block::new().title(Span::styled(
            format!(
                " p95 {p95:.0}ms · loss {:.0}% · jitter {:.1} ",
                stat.loss_pct(),
                stat.jitter_ms
            ),
            Style::new().fg(Color::DarkGray),
        )))
        .x_axis(Axis::default().bounds([0.0, xmax]))
        .y_axis(
            Axis::default()
                .bounds([0.0, ymax])
                .labels([Line::from("0"), Line::from(format!("{ymax:.0}ms"))]),
        );
    f.render_widget(chart, inner);
}

/// Loss deserves its own scale: any sustained loss matters, unlike latency where
/// tens of milliseconds are unremarkable.
fn loss_color(pct: f64) -> Color {
    match pct {
        p if p >= 5.0 => Color::Red,
        p if p >= 1.0 => Color::Yellow,
        p if p > 0.0 => Color::Rgb(200, 200, 120),
        _ => Color::Green,
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

    // A tunnelled default route swallows the intermediate hops, so keep a row
    // for the explanation rather than leaving a wall of '*' unexplained.
    let note = tunnel_note(s);
    let rows = (inner.height as usize).saturating_sub(note.len());
    let mut body: Vec<Line> = if tr.hops.is_empty() {
        vec![Line::from(Span::styled(
            if tr.running { "probing…" } else { "no hops" },
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
    body.extend(note);
    f.render_widget(Paragraph::new(body), inner);
}

/// One-line explanation, shown only when the default route is a tunnel, for why
/// hops go missing and the gateway looks dead.
fn tunnel_note(s: &AppState) -> Vec<Line<'static>> {
    let Some(vendor) = s.netinfo.tunnel_label() else {
        return Vec::new();
    };
    vec![Line::from(Span::styled(
        format!("⚠ default route is a tunnel ({vendor}) — hops inside it don't answer"),
        Style::new().fg(Color::Yellow),
    ))]
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
        Constraint::Length(speedtest_height(s, inner.width)), // status / progress
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

    // Full-screen: processes and speed-test history each get their own panel,
    // and 'n' moves the cursor between them.
    if s.fullscreen {
        let cols = Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(rows[2]);
        let on_history = s.focus == Panel::Bandwidth && s.sub_pane == SubPane::Secondary;

        let pblock = block("Processes", s.focus == Panel::Bandwidth && !on_history);
        let pinner = pblock.inner(cols[0]);
        f.render_widget(pblock, cols[0]);
        top_talkers(f, s, pinner, talkers);

        let sblock = block("Speed Test History", on_history);
        let sinner = sblock.inner(cols[1]);
        f.render_widget(sblock, cols[1]);
        speedtest_results(f, s, sinner, on_history);
    } else {
        top_talkers(f, s, rows[2], talkers);
    }
}

/// Table of recent speed-test results (full-screen only). Scrolls to keep the
/// cursor visible, so a long history can be paged through rather than clipped.
fn speedtest_results(f: &mut Frame, s: &AppState, area: Rect, focused: bool) {
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
    // Newest first; the cursor indexes this reversed order.
    let ordered: Vec<&crate::store::SpeedRecord> = s.speed_history.iter().rev().collect();
    let sel = s.speed_sel.min(ordered.len().saturating_sub(1));
    // Scroll only as far as needed to bring the cursor into view.
    let first = if n == 0 { 0 } else { sel.saturating_sub(n - 1) };

    let rows = ordered
        .iter()
        .skip(first)
        .take(n)
        .enumerate()
        .map(|(i, r)| {
            let selected = focused && first + i == sel;
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
            .style(if selected {
                Style::new()
                    .bg(Color::Rgb(40, 40, 55))
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::new()
            })
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

/// Rows to reserve for the speed-test status. A failure gets as many rows as the
/// message needs to wrap into, so the whole error is readable — more of it in
/// full-screen, where there is room to spare.
fn speedtest_height(s: &AppState, width: u16) -> u16 {
    let SpeedStatus::Failed(e) = &s.speedtest.status else {
        return 1;
    };
    if !s.speedtest_enabled {
        return 1;
    }
    // "speedtest failed: " prefix + message + "  [s] retry" suffix.
    let chars = 18 + e.chars().count() + 11;
    let w = width.max(1) as usize;
    let lines = chars.div_ceil(w) as u16;
    let cap = if s.fullscreen { 6 } else { 3 };
    lines.clamp(1, cap)
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
        // Wrap so a long failure reason uses the panel's full width rather than
        // being clipped at the right edge.
        f.render_widget(
            Paragraph::new(speedtest_line(s)).wrap(Wrap { trim: false }),
            area,
        );
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
            // Distinguish "this OS has no unprivileged source" from "the tool
            // that provides it simply isn't installed" — the second is fixable.
            let tool = if cfg!(target_os = "linux") {
                "ss"
            } else {
                "nettop"
            };
            let msg = match s.missing_tools.iter().find(|(n, _, _)| *n == tool) {
                Some((n, _, pkg)) => format!("per-process bandwidth needs {n} — {pkg}"),
                None => "per-process bandwidth unavailable on this platform".to_string(),
            };
            return dim(f, &msg);
        }
        ProcStatus::Probing => return dim(f, "detecting per-process bandwidth… (~5s)"),
        ProcStatus::Supported if s.processes.is_empty() => return dim(f, "sampling processes…"),
        ProcStatus::Supported => {}
    }

    // Header with the column cursor highlighted and a sort-direction arrow.
    let focused = s.focus == Panel::Bandwidth;
    let labels = ["name", "↓", "↑", "total", "retx"];
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

/// Centered modal listing all keyboard shortcuts, titled with the running
/// version so users can report what they're actually on.
fn help_overlay(f: &mut Frame, s: &AppState, area: Rect) {
    let row = |k: &str, d: &str| {
        Line::from(vec![
            Span::styled(format!(" {k:<11}"), Style::new().fg(Color::Cyan)),
            Span::styled(d.to_string(), Style::new().fg(Color::Gray)),
        ])
    };
    let head = |t: &str| {
        Line::from(Span::styled(
            format!(" {t}"),
            Style::new().fg(Color::White).bold(),
        ))
    };

    // Two columns, so the whole key set fits an 80x24 terminal without
    // scrolling. Descriptions are kept short enough for a half-width column.
    let mut left = vec![
        head("Global"),
        row("Tab / ⇧Tab", "cycle panels"),
        row("f", "full-screen focused panel"),
        row("n", "next sub-pane in panel"),
        row("Esc", "back / exit full-screen"),
        row("s", "run speed test"),
        row("p", "pause / resume refresh"),
        row("r", "re-probe network info"),
        row("w", "stats window 30/60/300s"),
        row("l", "start / stop CSV recording"),
        row("?", "toggle this help"),
        row("q / Ctrl+C", "quit"),
        Line::from(""),
        head("Navigation"),
        row("↑/↓ or j/k", "move the cursor"),
        row("PgUp/PgDn", "move by ten"),
        row("←/→", "move sort-column cursor"),
        row("Enter", "sort by that column"),
        row("Space", "reverse sort direction"),
        row("Shift+R", "reset this panel's data"),
    ];

    let mut right = vec![
        head("Connection Quality"),
        row("a", "add target (pre-fills hop)"),
        row("d / Del", "delete selected target"),
        row("g", "graph selected target"),
        row("t", "traceroute once"),
        row("m", "monitor every hop (MTR)"),
        Line::from(""),
        head("Bandwidth"),
        row("v", "cycle speed-test provider"),
        row("n", "processes ⇄ speed history"),
        Line::from(""),
        head("Network"),
        row("r", "re-probe"),
        row("f", "full-screen for DNS graphs"),
    ];

    // Only shown when something is actually absent, with the package that
    // provides it — which tools ship by default varies a lot by distribution.
    if !s.missing_tools.is_empty() {
        right.push(Line::from(""));
        right.push(Line::from(Span::styled(
            " Missing tools",
            Style::new().fg(Color::Yellow).bold(),
        )));
        for (name, _provides, package) in &s.missing_tools {
            right.push(Line::from(vec![
                Span::styled(format!(" {name:<11}"), Style::new().fg(Color::Yellow)),
                Span::styled(package.to_string(), Style::new().fg(Color::DarkGray)),
            ]));
        }
    }

    // Below this width the columns would truncate descriptions, so stack them
    // and accept scrolling on a very narrow terminal.
    let two_col = area.width >= 76;
    let body_h = if two_col {
        left.len().max(right.len())
    } else {
        left.push(Line::from(""));
        left.append(&mut right);
        left.len()
    } as u16;

    let w = if two_col { 78 } else { 40 }.min(area.width);
    let h = (body_h + 3).min(area.height); // +2 border, +1 footer
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };

    f.render_widget(Clear, rect);
    let outer = Block::bordered()
        .title(Span::styled(
            format!(" octomon v{} · Shortcuts ", env!("CARGO_PKG_VERSION")),
            Style::new().bold(),
        ))
        .title_bottom(Span::styled(
            " press ? or Esc to close ",
            Style::new().fg(Color::DarkGray),
        ))
        .border_style(Style::new().fg(Color::Cyan));
    let inner = outer.inner(rect);
    f.render_widget(outer, rect);

    if two_col {
        let cols = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(inner);
        f.render_widget(Paragraph::new(left), cols[0]);
        f.render_widget(Paragraph::new(right), cols[1]);
    } else {
        f.render_widget(Paragraph::new(left), inner);
    }
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

    // The OS's own name for the interface ("Wi-Fi", "Thunderbolt Ethernet") is
    // useful context but only when it isn't just the device name again.
    let iface = if n.iface_label.is_empty() || n.iface_label == n.iface {
        n.iface.clone()
    } else {
        format!("{}  ({})", n.iface, n.iface_label)
    };
    // Medium first, since it decides how everything below should be read; the
    // OS's extra facts (speed, DHCP) trail behind it, dimmed.
    let mut type_row = vec![
        Span::styled(format!("{:<9}", "type"), Style::new().fg(Color::DarkGray)),
        Span::styled(n.medium.label(), Style::new().fg(medium_color(n.medium))),
    ];
    if !n.link_detail.is_empty() {
        type_row.push(Span::styled(
            format!(" · {}", n.link_detail),
            Style::new().fg(Color::Gray),
        ));
    }

    let mut lines = vec![
        kv("iface", iface),
        Line::from(type_row),
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
    ];

    // A tunnel hides the real path: the encapsulated hops never answer ICMP, so
    // an empty traceroute is expected rather than a fault. Say so instead of
    // leaving a bare red gateway unexplained.
    if let Some(vendor) = n.tunnel_label() {
        let mut row = vec![
            Span::styled(format!("{:<9}", "tunnel"), Style::new().fg(Color::DarkGray)),
            Span::styled(vendor, Style::new().fg(Color::Yellow).bold()),
        ];
        if !n.tunnel_iface.is_empty() {
            row.push(Span::styled(
                format!("  ({})", n.tunnel_iface),
                Style::new().fg(Color::Gray),
            ));
        }
        lines.push(Line::from(row));
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:<9}", "gateway"),
                Style::new().fg(Color::DarkGray),
            ),
            Span::raw(format!(
                "{}  ({})",
                dash(&n.gateway_ip),
                dash(&n.gateway_mac)
            )),
        ]));
        // A split tunnel leaves the default route on the physical NIC, so the
        // gateway above is the real, reachable LAN gateway — internet traffic
        // simply never uses it. Don't mislabel it as the tunnel endpoint.
        lines.push(Line::from(Span::styled(
            if n.tunnel_is_split {
                "         LAN gateway — internet traffic bypasses it via the tunnel"
            } else {
                "         tunnel endpoint — hops beyond it are encapsulated"
            },
            Style::new().fg(Color::DarkGray),
        )));
    } else {
        lines.push(kv(
            "gateway",
            format!("{}  ({})", dash(&n.gateway_ip), dash(&n.gateway_mac)),
        ));
    }

    lines.push(dns_line(s));

    if let Some(w) = &n.wifi {
        // Live signal/tx come from the CoreWLAN graph below; keep the slower
        // system_profiler details (SSID / PHY / channel) here.
        lines.push(kv("ssid", dash(&w.ssid)));
        lines.push(kv(
            "wifi",
            format!("{}  ch {}", dash(&w.phy), dash(&w.channel)),
        ));
        // How crowded our channel is. Overlap matters as much as an exact
        // match, which is why both are counted separately.
        if let Some(c) = w.congestion().filter(|c| c.total > 0) {
            let busy = c.co_channel + c.overlapping;
            let color = match busy {
                0..=2 => Color::Green,
                3..=6 => Color::Yellow,
                _ => Color::Red,
            };
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{:<9}", "airspace"),
                    Style::new().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("{} co-ch · {} overlap", c.co_channel, c.overlapping),
                    Style::new().fg(color),
                ),
                Span::styled(
                    format!(" · {} nearby", c.total),
                    Style::new().fg(Color::DarkGray),
                ),
            ]));
        }
    } else if n.medium == LinkMedium::WiFi {
        lines.push(Line::from(Span::styled(
            "gathering Wi-Fi details…",
            Style::new().fg(Color::DarkGray),
        )));
    }

    // The radio can be associated while traffic goes elsewhere; say so, because
    // the signal graph below is deliberately suppressed in that case.
    if s.signal.present && matches!(n.medium, LinkMedium::Ethernet | LinkMedium::Bridge) {
        lines.push(Line::from(Span::styled(
            format!(
                "         Wi-Fi associated ({} dBm) but not the primary route",
                s.signal.rssi_dbm
            ),
            Style::new().fg(Color::DarkGray),
        )));
    }

    let graph = link_graph(s);
    let graph_h = if graph == LinkGraph::None { 0 } else { 5 };

    // Full-screen charts each resolver's response time, which is where slow DNS
    // actually becomes visible. The text block shrinks to its content so the
    // charts get the leftover space rather than sitting under a large void.
    let (info_area, graph_area, dns_area) = if s.fullscreen && !s.dns.is_empty() {
        let parts = Layout::vertical([
            Constraint::Length(lines.len() as u16),
            Constraint::Length(graph_h),
            Constraint::Min(3),
        ])
        .split(inner);
        (parts[0], (graph_h > 0).then_some(parts[1]), Some(parts[2]))
    } else if graph_h > 0 {
        let p = Layout::vertical([Constraint::Min(4), Constraint::Length(graph_h)]).split(inner);
        (p[0], Some(p[1]), None)
    } else {
        (inner, None, None)
    };

    f.render_widget(Paragraph::new(lines), info_area);
    if let Some(ga) = graph_area {
        match graph {
            LinkGraph::Signal => signal_graph(f, s, ga),
            LinkGraph::Utilisation => link_util_graph(f, s, ga),
            LinkGraph::None => {}
        }
    }
    if let Some(da) = dns_area {
        dns_graphs(f, s, da);
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

/// A machine can list a lot of resolvers (a VPN proxy, IPv6 duplicates, search
/// domains); charting all of them would crowd out the panel.
const MAX_DNS_GRAPHS: usize = 5;

/// One response-time sparkline per resolver, in its own panel. Each is scaled to
/// its own peak: the question is whether *this* resolver is degrading, and a
/// shared scale would flatten a fast one next to a slow one.
fn dns_graphs(f: &mut Frame, s: &AppState, area: Rect) {
    let shown = s.dns.len().min(MAX_DNS_GRAPHS);
    let hidden = s.dns.len().saturating_sub(shown);
    let title = if hidden > 0 {
        format!("DNS response time  (+{hidden} more)")
    } else {
        "DNS response time".to_string()
    };
    let b = block(&title, false);
    let inner = b.inner(area);
    f.render_widget(b, area);
    if inner.height == 0 {
        return;
    }

    // Split the panel evenly between resolvers, so a couple of them get tall
    // readable traces rather than a one-row squiggle each.
    let strip_h = (inner.height / shown as u16).max(1);
    const LABEL_W: u16 = 26;
    let spark_x = inner.x + LABEL_W;
    let spark_w = inner.width.saturating_sub(LABEL_W);

    for (i, probe) in s.dns.iter().take(shown).enumerate() {
        let top = inner.y + i as u16 * strip_h;
        if top >= inner.y + inner.height {
            break;
        }
        let h = strip_h.min(inner.y + inner.height - top);
        let color = probe.last_ms.map(dns_color).unwrap_or(Color::Red);

        // Label sits on the strip's first row; mean gives context the instant
        // reading cannot.
        let last = match probe.last_ms {
            Some(ms) => format!("{ms:.0}ms"),
            None if !probe.status.is_empty() => probe.status.clone(),
            None => "—".to_string(),
        };
        let mean = probe
            .mean_ms()
            .map(|v| format!("avg {v:.0}"))
            .unwrap_or_default();
        f.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    probe.server.to_string(),
                    Style::new().fg(Color::Gray),
                )),
                Line::from(vec![
                    Span::styled(format!("{last:<10}"), Style::new().fg(color).bold()),
                    Span::styled(mean, Style::new().fg(Color::DarkGray)),
                ]),
            ]),
            Rect {
                x: inner.x,
                y: top,
                width: LABEL_W.min(inner.width),
                height: h,
            },
        );

        if spark_w < 4 {
            continue;
        }
        let data = probe.hist.tail_u64(spark_w as usize);
        if data.is_empty() {
            continue;
        }
        let max = data.iter().copied().max().unwrap_or(1).max(1);
        f.render_widget(
            Sparkline::default()
                .data(data)
                .max(max)
                .style(Style::new().fg(color)),
            Rect {
                x: spark_x,
                y: top,
                width: spark_w,
                height: h,
            },
        );
    }
}

/// The `dns` row, annotated with each resolver's measured response time. A
/// resolver can answer pings in 2ms while taking 800ms to resolve, so the
/// address alone tells you nothing about whether it is the problem.
fn dns_line(s: &AppState) -> Line<'static> {
    let mut spans = vec![Span::styled(
        format!("{:<9}", "dns"),
        Style::new().fg(Color::DarkGray),
    )];
    if s.netinfo.dns.is_empty() {
        spans.push(Span::raw("-"));
        return Line::from(spans);
    }

    for (i, server) in s.netinfo.dns.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("  ", Style::new()));
        }
        spans.push(Span::raw(server.clone()));
        let probe = s.dns.iter().find(|p| p.server.to_string() == *server);
        match probe {
            // A failing resolver is the headline, not its latency.
            Some(p) if !p.status.is_empty() && p.last_ms.is_none() => {
                spans.push(Span::styled(
                    format!(" ({})", p.status),
                    Style::new().fg(Color::Red).bold(),
                ));
            }
            Some(p) => match p.last_ms {
                Some(ms) => spans.push(Span::styled(
                    format!(" ({ms:.0}ms)"),
                    Style::new().fg(dns_color(ms)),
                )),
                None => spans.push(Span::styled(" (…)", Style::new().fg(Color::DarkGray))),
            },
            None => spans.push(Span::styled(" (…)", Style::new().fg(Color::DarkGray))),
        }
    }
    Line::from(spans)
}

/// Resolver latency thresholds: a cached answer should be near the RTT to the
/// resolver, so tens of ms is fine and hundreds is not.
fn dns_color(ms: f64) -> Color {
    match ms {
        v if v < 30.0 => Color::Green,
        v if v < 120.0 => Color::Yellow,
        _ => Color::Red,
    }
}

/// Which link chart the Network panel should draw for the current medium.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum LinkGraph {
    /// Wi-Fi RSSI + tx rate.
    Signal,
    /// Wired link utilisation against negotiated capacity.
    Utilisation,
    None,
}

/// Radio metrics only make sense when the radio actually carries the traffic:
/// an associated Wi-Fi card is irrelevant while the default route is a cable.
/// A tunnel is layered over some physical link, so the radio (if associated) is
/// still the real bottleneck and its graph stays useful.
fn link_graph(s: &AppState) -> LinkGraph {
    match s.netinfo.medium {
        LinkMedium::WiFi | LinkMedium::Unknown if s.signal.present => LinkGraph::Signal,
        LinkMedium::Tunnel if s.signal.present => LinkGraph::Signal,
        m if m.is_wired() => LinkGraph::Utilisation,
        _ => LinkGraph::None,
    }
}

/// The wired counterpart to the Wi-Fi signal graph: how much of the negotiated
/// link capacity is in use. There is no RSSI on copper — headroom against line
/// rate is the equivalent "how healthy is this link" signal, and it is what
/// tells you whether the cable or something upstream is the limit.
fn link_util_graph(f: &mut Frame, s: &AppState, area: Rect) {
    let tp = &s.throughput;
    let want = (area.width as usize).saturating_mul(2).max(20);
    let tail = |h: &crate::app::History| -> Vec<f64> {
        let skip = h.data.len().saturating_sub(want);
        h.data.iter().skip(skip).copied().collect()
    };
    let down = tail(&tp.down_hist);
    let up = tail(&tp.up_hist);
    let len = down.len().min(up.len());
    if len == 0 {
        f.render_widget(
            Paragraph::new(Span::styled(
                " link utilisation — collecting…",
                Style::new().fg(Color::DarkGray),
            )),
            area,
        );
        return;
    }

    // Byte counters → percent of line rate. Without a reported line rate, fall
    // back to scaling against the observed peak and say so in the title.
    let cap_bps = s.netinfo.link_speed_bps.filter(|b| *b > 0);
    let peak = down
        .iter()
        .chain(up.iter())
        .copied()
        .fold(1.0_f64, f64::max)
        * 8.0;
    let scale = cap_bps.map(|b| b as f64).unwrap_or(peak);
    let pct = |bytes_per_sec: f64| (bytes_per_sec * 8.0 / scale * 100.0).clamp(0.0, 100.0);

    let dpts: Vec<(f64, f64)> = (0..len).map(|i| (i as f64, pct(down[i]))).collect();
    let upts: Vec<(f64, f64)> = (0..len).map(|i| (i as f64, pct(up[i]))).collect();
    let xmax = (len - 1).max(1) as f64;

    let (dnow, unow) = (pct(tp.down_bps), pct(tp.up_bps));
    let title = match cap_bps {
        Some(b) => format!(
            " link {} Mb · ↓ {dnow:.1}% ↑ {unow:.1}% of capacity ",
            b / 1_000_000
        ),
        None => format!(" link load (line rate unknown) · ↓ {dnow:.0}% ↑ {unow:.0}% of peak "),
    };

    let datasets = vec![
        Dataset::default()
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::new().fg(Color::Green))
            .data(&dpts),
        Dataset::default()
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::new().fg(Color::Magenta))
            .data(&upts),
    ];
    let chart = Chart::new(datasets)
        .block(Block::new().title(Span::styled(title, Style::new().fg(Color::DarkGray))))
        .x_axis(Axis::default().bounds([0.0, xmax]))
        .y_axis(
            Axis::default()
                .bounds([0.0, 100.0])
                .labels([Line::from("0"), Line::from("100%")]),
        );
    f.render_widget(chart, area);
}

/// Live Wi-Fi signal sparkline (RSSI, higher = better) with current tx rate.
fn signal_graph(f: &mut Frame, s: &AppState, area: Rect) {
    let sig = &s.signal;
    let sig_color = match sig.rssi_dbm {
        r if r >= -60 => Color::Green,
        r if r >= -72 => Color::Yellow,
        _ => Color::Red,
    };
    let band = match sig_color {
        Color::Green => "green",
        Color::Yellow => "yellow",
        _ => "red",
    };

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
    // Not every platform reports a bitrate — Linux's /proc/net/wireless has no
    // such field. Drawing a flat zero line and a "tx 0 Mbps" title would read as
    // a dead link rather than a missing measurement, so the series is dropped.
    let tx_max = tx.iter().copied().fold(0.0_f64, f64::max);
    let has_tx = tx_max > 0.0;
    let title = if has_tx {
        format!(
            " signal {} dBm ({band}) · tx {:.0} Mbps (cyan) ",
            sig.rssi_dbm, sig.tx_rate_mbps,
        )
    } else {
        format!(" signal {} dBm ({band}) ", sig.rssi_dbm)
    };

    let sig_pts: Vec<(f64, f64)> = (0..len)
        .map(|i| (i as f64, ((rssi[i] + 100.0) / 70.0).clamp(0.0, 1.0)))
        .collect();
    let tx_pts: Vec<(f64, f64)> = (0..len)
        .map(|i| (i as f64, (tx[i] / tx_max.max(1.0)).clamp(0.0, 1.0)))
        .collect();
    let xmax = (len - 1).max(1) as f64;

    let mut datasets = vec![
        Dataset::default()
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::new().fg(sig_color))
            .data(&sig_pts),
    ];
    if has_tx {
        datasets.push(
            Dataset::default()
                .marker(Marker::Braille)
                .graph_type(GraphType::Line)
                .style(Style::new().fg(Color::Cyan))
                .data(&tx_pts),
        );
    }
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
            // Surface the reason in full (the paragraph wraps to the panel
            // width); flag rate limiting explicitly.
            let msg = if e.contains("rate-limit") || e.contains("429") {
                "rate-limited — wait a moment".to_string()
            } else {
                e.clone()
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

/// Colour the link type so a tunnelled default route stands out — it changes how
/// every other reading on the panel should be read.
fn medium_color(m: LinkMedium) -> Color {
    match m {
        LinkMedium::Tunnel => Color::Yellow,
        LinkMedium::Unknown => Color::DarkGray,
        _ => Color::White,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::LinkMedium;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    /// Render into an off-screen buffer and return it as one searchable string.
    fn draw(s: &AppState, w: u16, h: u16) -> String {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| render(f, s)).unwrap();
        t.backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect()
    }

    fn state_with_medium(medium: LinkMedium) -> AppState {
        let mut s = AppState::new(vec![]);
        s.netinfo.iface = "en0".to_string();
        s.netinfo.medium = medium;
        s
    }

    #[test]
    fn network_panel_names_the_connection_type() {
        let s = state_with_medium(LinkMedium::Ethernet);
        assert!(draw(&s, 200, 60).contains("Ethernet (wired)"));
    }

    #[test]
    fn signal_graph_only_when_the_radio_carries_traffic() {
        // Wired primary with the radio still associated: no signal graph, but a
        // utilisation graph instead.
        let mut wired = state_with_medium(LinkMedium::Ethernet);
        wired.signal.present = true;
        wired.signal.rssi_dbm = -55;
        assert_eq!(link_graph(&wired), LinkGraph::Utilisation);
        let out = draw(&wired, 200, 60);
        assert!(!out.contains("signal -55 dBm"));
        assert!(out.contains("not the primary route"));

        // Wi-Fi primary: the signal graph is the right one.
        let mut wifi = state_with_medium(LinkMedium::WiFi);
        wifi.signal.present = true;
        assert_eq!(link_graph(&wifi), LinkGraph::Signal);

        // No radio and no wired capacity to chart: no graph at all.
        assert_eq!(
            link_graph(&state_with_medium(LinkMedium::WiFi)),
            LinkGraph::None
        );
    }

    #[test]
    fn hop_monitor_lists_every_hop_with_its_stats() {
        use crate::app::{HopMonitor, MonitoredHop, QualityView};
        use std::net::{IpAddr, Ipv4Addr};

        let hop = |ttl: u8, last: u8, samples: &[f64], losses: usize| {
            let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, last));
            let mut st = crate::app::TargetStat::new(format!("hop {ttl}"), addr);
            for &v in samples {
                st.record_reply(v);
            }
            for _ in 0..losses {
                st.record_loss();
            }
            MonitoredHop {
                ttl,
                addr: Some(addr),
                stat: Some(st),
            }
        };

        let silent = |ttl: u8| MonitoredHop {
            ttl,
            addr: None,
            stat: None,
        };

        let mut s = AppState::new(vec![]);
        s.quality_view = QualityView::HopMonitor;
        s.focus = Panel::Quality;
        s.fullscreen = true;
        s.hop_monitor = Some(HopMonitor {
            target: "Cloudflare (1.1.1.1)".into(),
            dest: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            hops: vec![
                hop(1, 1, &[3.0, 3.2, 3.1], 0),
                // A hop that answered discovery but is now dropping probes.
                hop(2, 2, &[20.0, 21.0], 6),
                silent(3), // lone gap — kept, it is informative
                hop(4, 4, &[30.0], 0),
                silent(5), // run of three — collapsed to one line
                silent(6),
                silent(7),
                hop(8, 8, &[40.0], 0),
            ],
            discovering: false,
            generation: 1,
            selected: 0,
        });

        let out = draw(&s, 120, 40);
        assert!(out.contains("Path ·"));
        assert!(out.contains("Cloudflare (1.1.1.1)"));
        assert!(out.contains("10.0.0.1"));
        assert!(out.contains("10.0.0.8"));
        // The lossy hop reports its loss rather than being hidden.
        assert!(out.contains("75%"));
        // A run of silent hops collapses; a lone one does not.
        assert!(out.contains("3 hops not responsive"));
        assert!(out.contains(" 5-7"));
    }

    #[test]
    fn silent_hop_runs_collapse_but_lone_gaps_survive() {
        use crate::app::MonitoredHop;
        use std::net::{IpAddr, Ipv4Addr};

        let live = |ttl: u8| MonitoredHop {
            ttl,
            addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, ttl))),
            stat: None,
        };
        let silent = |ttl: u8| MonitoredHop {
            ttl,
            addr: None,
            stat: None,
        };

        // live, gap, live, run-of-3, live
        let hops = vec![
            live(1),
            silent(2),
            live(3),
            silent(4),
            silent(5),
            silent(6),
            live(7),
        ];
        let rows = hop_rows(&hops);
        let shapes: Vec<String> = rows
            .iter()
            .map(|r| match r {
                HopRow::Hop(_, h) => format!("hop{}", h.ttl),
                HopRow::Silent(a, b, n) => format!("silent{a}-{b}x{n}"),
            })
            .collect();
        assert_eq!(
            shapes,
            vec!["hop1", "hop2", "hop3", "silent4-6x3", "hop7"],
            "a lone gap stays a row; a run collapses"
        );

        // A path that is entirely silent still collapses to one row.
        let all_silent = vec![silent(1), silent(2), silent(3)];
        assert_eq!(hop_rows(&all_silent).len(), 1);
        // And an empty path produces nothing rather than panicking.
        assert!(hop_rows(&[]).is_empty());
    }

    #[test]
    fn dns_row_annotates_each_resolver() {
        use crate::app::DnsProbe;
        use std::net::{IpAddr, Ipv4Addr};

        let mut s = state_with_medium(LinkMedium::WiFi);
        s.netinfo.dns = vec!["192.168.1.4".into(), "1.1.1.1".into(), "9.9.9.9".into()];

        let mut slow = DnsProbe::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4)));
        slow.last_ms = Some(410.0);
        slow.sent = 4;
        slow.ok = 4;

        let mut fast = DnsProbe::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        fast.last_ms = Some(9.0);
        fast.sent = 4;
        fast.ok = 4;

        // A resolver that stopped answering reports why, not a latency.
        let mut dead = DnsProbe::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
        dead.sent = 4;
        dead.status = "timeout".into();

        s.dns = vec![slow, fast, dead];
        let out = draw(&s, 200, 60);
        assert!(out.contains("192.168.1.4 (410ms)"));
        assert!(out.contains("1.1.1.1 (9ms)"));
        assert!(out.contains("9.9.9.9 (timeout)"));
    }

    #[test]
    fn airspace_row_appears_only_with_scan_results() {
        use crate::app::{Neighbour, WifiInfo};

        let mut s = state_with_medium(LinkMedium::WiFi);
        s.netinfo.wifi = Some(WifiInfo {
            ssid: "home".into(),
            phy: "802.11ax".into(),
            channel: "161 (5GHz, 80MHz)".into(),
            neighbours: vec![
                Neighbour {
                    channel: 161,
                    band_ghz: 5,
                    width_mhz: 80,
                },
                Neighbour {
                    channel: 157,
                    band_ghz: 5,
                    width_mhz: 20,
                },
            ],
            ..Default::default()
        });
        let out = draw(&s, 200, 60);
        assert!(out.contains("airspace"));
        assert!(out.contains("1 co-ch"));
        assert!(out.contains("2 nearby"));

        // A radio with no scan data shows no airspace row at all, rather than
        // claiming an empty airspace.
        s.netinfo.wifi = Some(WifiInfo {
            channel: "161 (5GHz, 80MHz)".into(),
            ..Default::default()
        });
        assert!(!draw(&s, 200, 60).contains("airspace"));
    }

    /// Every key the app binds should be discoverable from the help overlay,
    /// and the overlay has to fit a standard 80x24 terminal without clipping.
    #[test]
    fn help_lists_every_key_and_fits_a_standard_terminal() {
        let mut s = AppState::new(vec![]);
        s.show_help = true;
        let out = draw(&s, 80, 24);
        for c in out.as_bytes().chunks(80) {
            println!("{}", String::from_utf8_lossy(c).trim_end());
        }

        for key in [
            "Tab",
            "f",
            "n",
            "Esc",
            "s",
            "p",
            "r",
            "w",
            "l",
            "?",
            "q / Ctrl+C",
            "PgUp/PgDn",
            "Enter",
            "Space",
            "Shift+R",
            "a",
            "d / Del",
            "g",
            "t",
            "m",
            "v",
        ] {
            assert!(out.contains(key), "help is missing a binding for {key:?}");
        }
        // The closing hint sits in the bottom border; if the box overflowed the
        // terminal it would be the first thing lost.
        assert!(out.contains("press ? or Esc to close"));
        assert!(out.contains(&format!("octomon v{}", env!("CARGO_PKG_VERSION"))));

        // The column split must not clip descriptions. These are the longest
        // in each column and were truncated before the key field was narrowed.
        for desc in [
            "cycle panels",
            "add target (pre-fills hop)",
            "full-screen focused panel",
            "back / exit full-screen",
            "start / stop CSV recording",
            "monitor every hop (MTR)",
            "cycle speed-test provider",
            "processes ⇄ speed history",
            "full-screen for DNS graphs",
        ] {
            assert!(
                out.contains(desc),
                "truncated in the help overlay: {desc:?}"
            );
        }
    }

    /// A narrow terminal stacks the columns rather than truncating them.
    #[test]
    fn help_falls_back_to_one_column_when_narrow() {
        let mut s = AppState::new(vec![]);
        s.show_help = true;
        let out = draw(&s, 50, 40);
        assert!(out.contains("Connection Quality"));
        assert!(out.contains("cycle panels"));
    }

    #[test]
    fn help_shows_the_version_and_fits_its_content() {
        let mut s = AppState::new(vec![]);
        s.show_help = true;
        let out = draw(&s, 200, 60);
        assert!(out.contains(&format!("octomon v{}", env!("CARGO_PKG_VERSION"))));
        // The last section used to fall off the bottom of a fixed 22-row box.
        assert!(out.contains("press ? or Esc to close"));
    }

    #[test]
    fn tunnel_is_called_out() {
        let mut s = state_with_medium(LinkMedium::Tunnel);
        s.netinfo.tunnel = Some("Cloudflare WARP".to_string());
        s.netinfo.tunnel_iface = "utun0".to_string();
        s.netinfo.gateway_ip = "172.16.0.1".to_string();
        let out = draw(&s, 200, 60);
        assert!(out.contains("Cloudflare WARP"));
        assert!(out.contains("Tunnel (VPN)"));
        assert!(out.contains("encapsulated"));
    }

    /// WARP's usual shape: `default` still points at Wi-Fi, but 0.0.0.0/1 sends
    /// internet traffic down utun0. The LAN gateway is real and reachable, so it
    /// must not be described as the tunnel endpoint.
    #[test]
    fn split_tunnel_keeps_the_lan_gateway_honest() {
        let mut s = state_with_medium(LinkMedium::WiFi);
        s.netinfo.tunnel = Some("Cloudflare WARP".to_string());
        s.netinfo.tunnel_iface = "utun0".to_string();
        s.netinfo.tunnel_is_split = true;
        s.netinfo.gateway_ip = "192.168.1.1".to_string();
        let out = draw(&s, 200, 60);
        assert!(out.contains("Cloudflare WARP"));
        assert!(out.contains("(utun0)"));
        assert!(out.contains("bypasses it via the tunnel"));
        assert!(!out.contains("tunnel endpoint"));
        // The physical medium is still Wi-Fi, so the signal graph stays useful.
        assert!(out.contains("Wi-Fi (wireless)"));
    }

    #[test]
    fn failed_speedtest_gets_rows_for_the_whole_message() {
        let msg = "Cloudflare download failed: error sending request for url \
                   (https://speed.cloudflare.com/__down): connection closed before message completed";
        let mut s = AppState::new(vec![]);
        s.speedtest.status = SpeedStatus::Failed(msg.to_string());
        // A narrow panel needs several rows; a wide one needs fewer.
        assert!(speedtest_height(&s, 40) > speedtest_height(&s, 160));
        assert!(speedtest_height(&s, 40) > 1);
        // The tail of the message survives rather than being clipped at 48 chars.
        assert!(draw(&s, 200, 60).contains("connection closed before message completed"));
    }
}
