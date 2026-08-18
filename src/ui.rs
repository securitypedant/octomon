//! Rendering. A single [`render`] entry point draws the four panels from an
//! immutable snapshot of [`AppState`]. No data collection happens here.

use ratatui::layout::Alignment;
use ratatui::prelude::*;
use ratatui::style::Modifier;
use ratatui::symbols::Marker;
use ratatui::widgets::{
    Axis, Block, Cell, Chart, Clear, Dataset, Gauge, GraphType, LineGauge, Padding, Paragraph, Row,
    Scrollbar, ScrollbarOrientation, ScrollbarState, Sparkline, SparklineBar, Table, Wrap,
};

use crate::app::{
    AppState, BwView, InputMode, LinkMedium, Overlay, Panel, ProcStatus, QualityView, SpeedStatus,
    SubPane,
};
use crate::verdict::{RungStatus, Severity, Verdict, thresholds as th};

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

    // Setup problems come first: with ICMP unavailable most of the dashboard is
    // dead, and a one-line footer notice is far too easy to miss.
    match s.overlay {
        Overlay::Startup => startup_notice(f, s, f.area()),
        Overlay::Help => help_overlay(f, s, f.area()),
        Overlay::Triage => triage_overlay(f, s, f.area()),
        Overlay::Events => events_overlay(f, s, f.area()),
        Overlay::Explainer => explainer_overlay(f, f.area()),
        Overlay::Locations => locations_overlay(f, s, f.area()),
        Overlay::Whois => whois_overlay(f, s, f.area()),
        Overlay::None => {}
    }
}

/// Who owns the selected address: the registry's answer, so a bad hop can be
/// pinned on an organisation. Structured fields from RDAP; raw text when the
/// system `whois` had to answer instead.
fn whois_overlay(f: &mut Frame, s: &AppState, area: Rect) {
    let Some(w) = s.whois.as_ref() else {
        return;
    };
    let width = 84u16.min(area.width);

    let mut lines: Vec<Line> = Vec::new();
    let key = |k: &str| Span::styled(format!("{k:<12}"), Style::new().fg(Color::Cyan));
    lines.push(Line::from(vec![
        key("address"),
        Span::styled(w.addr.to_string(), Style::new().fg(Color::White).bold()),
    ]));
    if w.running {
        lines.push(Line::from(Span::styled(
            "looking up…",
            Style::new().fg(Color::DarkGray),
        )));
    } else if let Some(e) = &w.error {
        lines.push(Line::from(Span::styled(
            format!("lookup failed — {e}"),
            Style::new().fg(Color::Red),
        )));
    } else if !w.fields.is_empty() {
        // Wrap long values (remarks, ranges) under the key column rather than
        // letting the paragraph wrap them back to column zero.
        let val_w = (width as usize).saturating_sub(4 + 12).max(20);
        for (k, v) in &w.fields {
            let mut first = true;
            for chunk in wrap_words(v, val_w) {
                lines.push(Line::from(vec![
                    if first { key(k) } else { key("") },
                    Span::styled(chunk, Style::new().fg(Color::White)),
                ]));
                first = false;
            }
        }
    } else if !w.raw.is_empty() {
        for l in &w.raw {
            lines.push(Line::from(Span::styled(
                l.clone(),
                Style::new().fg(Color::Gray),
            )));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "the registry had nothing to say about this address",
            Style::new().fg(Color::DarkGray),
        )));
    }
    if !w.source.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("source: {}", w.source),
            Style::new().fg(Color::DarkGray),
        )));
    }

    let h = ((lines.len() as u16) + 2)
        .clamp(5, area.height * 4 / 5)
        .min(area.height);
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width,
        height: h,
    };
    let visible = rect.height.saturating_sub(2) as usize;
    let first = s.whois_scroll.min(lines.len().saturating_sub(visible));
    let shown: Vec<Line> = lines.into_iter().skip(first).collect();

    f.render_widget(Clear, rect);
    let outer = Block::bordered()
        .padding(Padding::new(1, 1, 0, 0))
        .title(Span::styled(
            " octomon · who owns this address ",
            Style::new().bold(),
        ))
        .title_bottom(Span::styled(
            " ↑↓ scroll · press W or Esc to close ",
            Style::new().fg(Color::DarkGray),
        ))
        .border_style(Style::new().fg(Color::Cyan));
    let inner = outer.inner(rect);
    f.render_widget(outer, rect);
    f.render_widget(Paragraph::new(shown), inner);
}

/// Greedy word wrap to `width` columns; a single over-long word stands alone.
fn wrap_words(text: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if !cur.is_empty() && cur.chars().count() + 1 + word.chars().count() > width {
            out.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if !cur.is_empty() || out.is_empty() {
        out.push(cur);
    }
    out
}

/// Every stored network location with its learned baseline: what "normal"
/// means at each place this machine has been.
fn locations_overlay(f: &mut Frame, s: &AppState, area: Rect) {
    let w = 84u16.min(area.width);
    let h = (area.height * 4 / 5).max(8.min(area.height));
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };
    // Three lines per location (name, stats, spacer).
    let visible = (rect.height.saturating_sub(2) as usize) / 3;

    let mut lines: Vec<Line> = Vec::new();
    match &s.locations {
        None => lines.push(Line::from(Span::styled(
            "loading…",
            Style::new().fg(Color::DarkGray),
        ))),
        Some(all) if all.is_empty() => {
            lines.push(Line::from(Span::styled(
                "no locations learned yet — baselines build up during healthy minutes",
                Style::new().fg(Color::DarkGray),
            )));
        }
        Some(all) => {
            // Scroll only when there is somewhere to scroll to: with the list
            // fully visible the offset stays pinned at zero.
            let max_first = all.len().saturating_sub(visible.max(1));
            let first = s.locations_sel.min(max_first);
            let ms = |v: Option<f64>| {
                v.map(|x| format!("~{x:.0}ms"))
                    .unwrap_or_else(|| "—".into())
            };
            for (key, b) in all.iter().skip(first).take(visible.max(1)) {
                let current = s.baseline_key.as_deref() == Some(key.as_str());
                let mut name_row = vec![Span::styled(
                    b.display_name().to_string(),
                    Style::new().fg(Color::White).bold(),
                )];
                if b.name.is_some() && b.name.as_deref() != Some(&b.label) {
                    name_row.push(Span::styled(
                        format!("  ({})", b.label),
                        Style::new().fg(Color::DarkGray),
                    ));
                }
                if current {
                    name_row.push(Span::styled(
                        "  ● current",
                        Style::new().fg(Color::Cyan).bold(),
                    ));
                }
                lines.push(Line::from(name_row));
                let speed = match (b.down_mbps, b.up_mbps) {
                    (Some(d), Some(u)) => format!(" · speed {d:.0}↓/{u:.0}↑"),
                    _ => String::new(),
                };
                let rssi = b
                    .rssi_dbm
                    .map(|r| format!(" · rssi ~{r:.0}dBm"))
                    .unwrap_or_default();
                lines.push(Line::from(Span::styled(
                    format!(
                        "  gateway {} · internet {} · DNS {}{rssi}{speed} · {} healthy min",
                        ms(b.gateway_ms),
                        ms(b.anchor_ms),
                        ms(b.dns_ms),
                        b.samples
                    ),
                    Style::new().fg(Color::Gray),
                )));
                lines.push(Line::from(""));
            }
        }
    }

    let total = s.locations.as_ref().map(Vec::len).unwrap_or(0);
    f.render_widget(Clear, rect);
    let outer = Block::bordered()
        .padding(Padding::new(1, 1, 0, 0))
        .title(Span::styled(
            format!(" octomon · locations ({total}) "),
            Style::new().bold(),
        ))
        .title_bottom(Span::styled(
            " ↑↓ scroll · [N] names the current network · press L or Esc to close ",
            Style::new().fg(Color::DarkGray),
        ))
        .border_style(Style::new().fg(Color::Cyan));
    let inner = outer.inner(rect);
    f.render_widget(outer, rect);
    f.render_widget(Paragraph::new(lines), inner);
}

/// First-run welcome: what the tool answers, and that it learns each network's
/// normal. Shown once, then persisted away.
fn explainer_overlay(f: &mut Frame, area: Rect) {
    let head = |t: &str| Line::from(Span::styled(format!(" {t}"), Style::new().bold()));
    let bullet = |t: &str| {
        Line::from(vec![
            Span::styled(" ● ", Style::new().fg(Color::Cyan)),
            Span::styled(t.to_string(), Style::new().fg(Color::Gray)),
        ])
    };
    let dim = |t: &str| {
        Line::from(Span::styled(
            format!("   {t}"),
            Style::new().fg(Color::DarkGray),
        ))
    };

    let lines = vec![
        head("this tool helps you diagnose internet connectivity issues:"),
        Line::from(Span::styled(
            " \"Is it my machine, my local network, my ISP — or the internet?\"",
            Style::new().fg(Color::Cyan).bold(),
        )),
        Line::from(""),
        bullet("a live analysis at the bottom left of the screen"),
        dim("press [y] anytime to see details"),
        bullet("[e] shows a timeline of what changed and when"),
        bullet("octomon learns what normal looks like on each network you use"),
        dim("(gateway latency, DNS, signal — saved and judged per location,"),
        dim("Name this network with [N], e.g. \"Home\"."),
        bullet("everything stays on this machine"),
        Line::from(""),
        Line::from(Span::styled(
            " give it a minute or two to learn before trusting comparisons",
            Style::new().fg(Color::DarkGray).italic(),
        )),
    ];

    // Breathing room inside the border: 1 column each side, 1 row above and
    // below.
    let pad = Padding::new(1, 1, 1, 1);
    let w = (78u16 + 2).min(area.width);
    let h = (lines.len() as u16 + 2 + 2).min(area.height);
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, rect);
    let outer = Block::bordered()
        .padding(pad)
        .title(Span::styled(" octomon · welcome ", Style::new().bold()))
        .title_bottom(Span::styled(
            " press any key to start ",
            Style::new().fg(Color::DarkGray),
        ))
        .border_style(Style::new().fg(Color::Cyan));
    let inner = outer.inner(rect);
    f.render_widget(outer, rect);
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

/// The session timeline, newest first: what changed and when. This is the
/// retroactive answer to "what happened during that call ten minutes ago?"
fn events_overlay(f: &mut Frame, s: &AppState, area: Rect) {
    // Big but not modal-window-pretending-to-be-a-screen: 80% each way.
    let w = (area.width * 4 / 5).max(40.min(area.width));
    let h = (area.height * 4 / 5).max(6.min(area.height));
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };
    let visible = rect.height.saturating_sub(2) as usize;

    let mut lines: Vec<Line> = Vec::new();
    if s.events.is_empty() {
        lines.push(Line::from(Span::styled(
            " no events yet — network changes and analysis findings land here",
            Style::new().fg(Color::DarkGray),
        )));
    }
    for e in s.events.iter().rev().skip(s.events_scroll).take(visible) {
        lines.push(Line::from(vec![
            Span::styled(format!(" {}  ", e.when()), Style::new().fg(Color::DarkGray)),
            Span::styled(
                format!("{:<9} ", e.category.label()),
                Style::new().fg(Color::Cyan),
            ),
            Span::styled(
                e.message.clone(),
                Style::new().fg(severity_color(e.severity)),
            ),
        ]));
    }

    let older = s
        .events
        .len()
        .saturating_sub(s.events_scroll)
        .saturating_sub(visible);
    let title = format!(
        " octomon · events ({} this session{}) ",
        s.events_total,
        if older > 0 {
            format!(", ↓{older} older")
        } else {
            String::new()
        }
    );
    f.render_widget(Clear, rect);
    let outer = Block::bordered()
        .padding(Padding::new(1, 1, 0, 0))
        .title(Span::styled(title, Style::new().bold()))
        .title_bottom(Span::styled(
            " ↑↓ scroll · press e or Esc to close ",
            Style::new().fg(Color::DarkGray),
        ))
        .border_style(Style::new().fg(Color::Cyan));
    let inner = outer.inner(rect);
    f.render_widget(outer, rect);
    f.render_widget(Paragraph::new(lines), inner);
}

/// Modal shown once at startup when something will visibly not work. Dismissed
/// by any key; the same detail stays available in `[?]` help afterwards.
fn startup_notice(f: &mut Frame, s: &AppState, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    if let Some(err) = &s.icmp_error {
        lines.push(Line::from(Span::styled(
            " ⚠ Latency features are disabled",
            Style::new().fg(Color::Red).bold(),
        )));
        for part in err.split('\n') {
            lines.push(Line::from(Span::styled(
                format!(" {}", part.trim_end()),
                Style::new().fg(Color::Gray),
            )));
        }
        lines.push(Line::from(""));
    }

    if !s.missing_tools.is_empty() {
        lines.push(Line::from(Span::styled(
            " ⚠ Missing tools",
            Style::new().fg(Color::Yellow).bold(),
        )));
        for (name, provides, package) in &s.missing_tools {
            lines.push(Line::from(vec![
                Span::styled(format!(" {name:<13}"), Style::new().fg(Color::Yellow)),
                Span::styled((*provides).to_string(), Style::new().fg(Color::Gray)),
            ]));
            lines.push(Line::from(Span::styled(
                format!("               {package}"),
                Style::new().fg(Color::DarkGray),
            )));
        }
        lines.push(Line::from(""));
    }

    // Always worth stating, since it silently narrows per-process bandwidth.
    if let Some(note) = &s.privilege_notice {
        lines.push(Line::from(Span::styled(
            " ℹ Privileges",
            Style::new().fg(Color::Cyan).bold(),
        )));
        lines.push(Line::from(Span::styled(
            format!(" {note}"),
            Style::new().fg(Color::Gray),
        )));
        lines.push(Line::from(""));
    }

    if lines.is_empty() {
        return;
    }

    let w = 78u16.min(area.width);
    // Long guidance wraps, so counting logical lines under-measures and clips
    // the bottom of the modal — which is where the least-obvious advice sits.
    // Width available to text: border + 1-column padding each side.
    let text_w = w.saturating_sub(4).max(1) as usize;
    let wrapped: usize = lines
        .iter()
        .map(|l| l.width().max(1).div_ceil(text_w))
        .sum();
    let h = (wrapped as u16 + 3).min(area.height);
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, rect);
    let outer = Block::bordered()
        .padding(Padding::new(1, 1, 0, 0))
        .title(Span::styled(" octomon · setup ", Style::new().bold()))
        .title_bottom(Span::styled(
            " press any key to continue ",
            Style::new().fg(Color::DarkGray),
        ))
        .border_style(Style::new().fg(Color::Yellow));
    let inner = outer.inner(rect);
    f.render_widget(outer, rect);
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn header(f: &mut Frame, s: &AppState, area: Rect) {
    let cols =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).split(area);

    let up = s.started.elapsed().as_secs();
    let mut left = vec![
        // Badges carry a space of their own colour either side, so the text
        // sits centred in its block; a plain space keeps the first one off
        // the terminal's left edge.
        Span::raw(" "),
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
        left.push(Span::raw("  "));
        left.push(Span::styled(
            " PAUSED ",
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
            left.push(Span::raw("  "));
            left.push(Span::styled(
                " ● REC ",
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

/// A vertical scrollbar down the right edge of `area` when `total` rows do not
/// all fit in `visible`; nothing when they do. Purely a cue — there is no mouse
/// to drag it — so it is drawn only when there is somewhere to scroll to.
/// Returns the area left for the content: one column narrower when drawn.
fn scroll_cue(f: &mut Frame, area: Rect, total: usize, first: usize, visible: usize) -> Rect {
    if total <= visible || area.width < 2 || area.height == 0 {
        return area;
    }
    let mut state = ScrollbarState::new(total.saturating_sub(visible))
        .position(first)
        .viewport_content_length(visible);
    let bar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(None)
        .end_symbol(None)
        .track_symbol(Some("│"))
        .thumb_symbol("┃")
        .track_style(Style::new().fg(Color::DarkGray))
        .thumb_style(Style::new().fg(Color::Gray));
    f.render_stateful_widget(bar, area, &mut state);
    Rect {
        width: area.width - 1,
        ..area
    }
}

/// The ttl column: the number, or "dest" for the endpoint row a walk that
/// stopped short still gets.
fn hop_ttl(h: &crate::app::MonitoredHop) -> String {
    if h.is_dest_placeholder() {
        "dest".to_string()
    } else {
        format!("{:>2}", h.ttl)
    }
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
            key("[W]"),
            txt("hois "),
            key("[n]"),
            txt("pane "),
            key("[←→ ↵]"),
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
            let mut v = vec![
                key("[s]"),
                txt("peed "),
                key("[v]"),
                txt(p),
                Span::raw(" "),
                key("[n]"),
                txt(match (s.bw_view, s.sub_pane) {
                    (BwView::Processes, SubPane::Primary) => "ext: remotes ",
                    (BwView::Remotes, SubPane::Primary) if s.fullscreen => "ext: history ",
                    _ => "ext: processes ",
                }),
            ];
            if s.bw_view == BwView::Remotes && s.sub_pane == SubPane::Primary {
                v.extend([key("[W]"), txt("hois "), key("[a]"), txt("dd ")]);
            }
            v.extend([key("[R]"), txt("eset "), key("[f]"), txt("ull ")]);
            v
        }
        Panel::NetInfo => vec![
            key("[r]"),
            txt("efresh "),
            key("[N]"),
            txt("ame "),
            key("[L]"),
            txt("ocations "),
        ],
        Panel::Vitals => vec![],
    };
    spans.push(key("[?]"));
    spans.push(txt("help "));
    Line::from(spans)
}

fn footer(f: &mut Frame, s: &AppState, area: Rect) {
    let input_line = |prompt: &str, buffer: &str, hint: &str| {
        Line::from(vec![
            Span::styled(format!(" {prompt}"), Style::new().fg(Color::Yellow).bold()),
            Span::styled(buffer.to_string(), Style::new().fg(Color::White)),
            Span::styled("▏", Style::new().fg(Color::Yellow)),
            Span::styled(format!("   {hint}"), Style::new().fg(Color::DarkGray)),
        ])
    };
    let line = if s.input_mode == InputMode::AddTarget {
        input_line(
            "add target (IP or DNS): ",
            &s.input_buffer,
            "[Enter] add  [Esc] cancel",
        )
    } else if s.input_mode == InputMode::NameNetwork {
        input_line(
            "name this network (Home, Office…): ",
            &s.input_buffer,
            "[Enter] save  [Esc] cancel",
        )
    } else if let Some(n) = &s.notice {
        Line::from(Span::styled(
            format!(" {n}"),
            Style::new().fg(Color::Yellow),
        ))
    } else {
        verdict_line(s)
    };

    // While recording, the destination sits bottom-right so the analysis line
    // keeps the left. Suppressed during text entry, which needs the width.
    let rec = if s.input_mode == InputMode::Normal {
        s.log.as_ref().map(|log| {
            let name = log
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            format!("● rec → {name} ({} rows) ", log.rows)
        })
    } else {
        None
    };
    match rec {
        Some(r) => {
            let cols = Layout::horizontal([Constraint::Min(0), Constraint::Length(r.len() as u16)])
                .split(area);
            f.render_widget(Paragraph::new(line), cols[0]);
            f.render_widget(
                Paragraph::new(Span::styled(r, Style::new().fg(Color::Red)))
                    .alignment(Alignment::Right),
                cols[1],
            );
        }
        None => f.render_widget(Paragraph::new(line), area),
    }
}

/// The always-visible one-liner: the verdict engine's headline. Full detail —
/// every rung and finding — is one keypress away on [y], so this stays terse.
fn verdict_line(s: &AppState) -> Line<'static> {
    let hint = Span::styled("  [y] analysis", Style::new().fg(Color::DarkGray));
    match &s.verdict.current {
        Verdict::Insufficient(reason) => Line::from(vec![
            Span::styled(format!(" ● {reason}"), Style::new().fg(Color::DarkGray)),
            hint,
        ]),
        Verdict::Healthy => Line::from(vec![
            Span::styled(" ● connection healthy", Style::new().fg(Color::Green)),
            hint,
        ]),
        Verdict::Problems(findings) => {
            let top = &findings[0];
            // Info-class findings are notes, not problems: the line stays green
            // rather than crying wolf over a busy CPU or a weak-but-working radio.
            if top.severity == Severity::Info {
                let n = findings.len();
                return Line::from(vec![
                    Span::styled(" ● connection healthy", Style::new().fg(Color::Green)),
                    Span::styled(
                        format!(
                            " · {n} note{}: {}",
                            if n == 1 { "" } else { "s" },
                            top.summary
                        ),
                        Style::new().fg(Color::Gray),
                    ),
                    hint,
                ]);
            }
            // Confidence wording lives in the [y] analysis overlay; the
            // headline keeps just the claim.
            let color = severity_color(top.severity);
            let mut spans = vec![Span::styled(
                format!(" ▲ {}", top.summary),
                Style::new().fg(color).bold(),
            )];
            if findings.len() > 1 {
                spans.push(Span::styled(
                    format!("  (+{} more)", findings.len() - 1),
                    Style::new().fg(Color::Yellow),
                ));
            }
            spans.push(hint);
            Line::from(spans)
        }
    }
}

fn severity_color(sev: Severity) -> Color {
    match sev {
        Severity::Down => Color::Red,
        Severity::Degraded => Color::Yellow,
        Severity::Info => Color::Gray,
    }
}

/// The triage ladder: every subsystem's status with its data — healthy rungs
/// included, so the verdict is auditable rather than oracular — then the active
/// findings with their evidence.
fn triage_overlay(f: &mut Frame, s: &AppState, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    for r in &s.verdict.triage.rungs {
        let (glyph, color) = match r.status {
            RungStatus::Ok => ("✓", Color::Green),
            RungStatus::Warn => ("~", Color::Yellow),
            RungStatus::Bad => ("✗", Color::Red),
            RungStatus::Unknown => ("?", Color::DarkGray),
        };
        lines.push(Line::from(vec![
            Span::styled(format!(" {glyph} "), Style::new().fg(color).bold()),
            Span::styled(
                format!("{:<13}", r.area.label()),
                Style::new().fg(Color::White),
            ),
            Span::styled(r.detail.clone(), Style::new().fg(Color::Gray)),
        ]));
    }

    lines.push(Line::from(""));
    match &s.verdict.current {
        Verdict::Insufficient(reason) => {
            lines.push(Line::from(Span::styled(
                format!(" {reason}"),
                Style::new().fg(Color::DarkGray),
            )));
        }
        Verdict::Healthy => {
            lines.push(Line::from(Span::styled(
                " no findings — connection looks healthy",
                Style::new().fg(Color::Green),
            )));
        }
        Verdict::Problems(findings) => {
            lines.push(Line::from(Span::styled(
                " Findings",
                Style::new().fg(Color::White).bold(),
            )));
            for finding in findings {
                // Confidence stays internal (it drives the ranking); the
                // evidence lines below make the case in words instead.
                lines.push(Line::from(Span::styled(
                    format!(" ▲ {}", finding.summary),
                    Style::new().fg(severity_color(finding.severity)).bold(),
                )));
                for e in &finding.evidence {
                    lines.push(Line::from(Span::styled(
                        format!("     {e}"),
                        Style::new().fg(Color::DarkGray),
                    )));
                }
            }
        }
    }

    let w = 78u16.min(area.width);
    // Border + 1-column padding each side.
    let text_w = w.saturating_sub(4).max(1) as usize;
    let wrapped: usize = lines
        .iter()
        .map(|l| l.width().max(1).div_ceil(text_w))
        .sum();
    let h = (wrapped as u16 + 2).min(area.height);
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, rect);
    let outer = Block::bordered()
        .padding(Padding::new(1, 1, 0, 0))
        .title(Span::styled(" octomon · analysis ", Style::new().bold()))
        .title_bottom(Span::styled(
            " press y or Esc to close, e for past events ",
            Style::new().fg(Color::DarkGray),
        ))
        .border_style(Style::new().fg(Color::Cyan));
    let inner = outer.inner(rect);
    f.render_widget(outer, rect);
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
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
    // The border is a fixed inset, so the inner rect is known before the title
    // is — and the title needs the scroll counts, which depend on the layout.
    let inner = block("", false).inner(area);

    // The web (HTTP) strip: hidden while a path view owns the bottom of a
    // split panel, but full-screen has room for both; in split view it also
    // needs a tall enough panel to not squeeze the latency chart.
    let show_web = has_web_data(s)
        && (s.fullscreen || (s.quality_view == QualityView::Graph && inner.height >= 13));
    let web_h: u16 = match (show_web, s.fullscreen) {
        (false, _) => 0,
        (true, true) => 6,
        (true, false) => 4,
    };

    let parts = if s.quality_view == QualityView::Graph {
        // Full-screen: the target list takes only what it needs and the chart
        // fills the rest, since three overlaid series need the vertical room.
        // Split view keeps a fixed slice so the table is not squeezed away.
        let (list, graph) = if s.fullscreen {
            (
                Constraint::Length((s.targets.len() as u16 + 1).min(14)),
                Constraint::Min(6),
            )
        } else {
            (Constraint::Min(3), Constraint::Length(6))
        };
        Layout::vertical([list, graph, Constraint::Length(web_h)]).split(inner)
    } else {
        let table_h = (s.targets.len() as u16 + 2).min(9);
        Layout::vertical([
            Constraint::Length(table_h),
            Constraint::Min(0),
            Constraint::Length(web_h),
        ])
        .split(inner)
    };

    let n = s.window_samples();

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
    // Scroll so the cursor stays visible: with a path monitor open below, the
    // target list gets few rows and the selection would otherwise fall off it.
    let rows_avail = (parts[0].height.saturating_sub(1)) as usize;
    let cursor = order.iter().position(|&i| i == s.selected).unwrap_or(0);
    let first = if rows_avail == 0 {
        0
    } else {
        cursor.saturating_sub(rows_avail - 1)
    };
    let hidden_above = first;
    let hidden_below = order.len().saturating_sub(first + rows_avail);

    let rows = order.iter().skip(first).take(rows_avail).map(|&i| {
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
    // The metric columns are fixed; the name and address split whatever the
    // panel has left, so a long hostname is not clipped at 13 characters while
    // the right-hand side of the panel sits empty.
    let widths = [
        Constraint::Length(2),
        Constraint::Min(14),
        Constraint::Min(16),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(6),
    ];
    // Scroll counts live in the title: overlaying them on the header row
    // clobbered whichever column happened to sit under them. They come before
    // the stats so a narrow panel clips the stats, never the scroll cue.
    let mut title = "Connection Quality".to_string();
    if hidden_above > 0 || hidden_below > 0 {
        title.push_str(" · ");
        if hidden_above > 0 {
            title.push_str(&format!("↑{hidden_above} "));
        }
        if hidden_below > 0 {
            title.push_str(&format!("↓{hidden_below} "));
        }
        title.push_str("more");
    }
    // The stats that used to have their own row ride in the title now, buying
    // the panel body an extra line of graph space.
    title.push_str(&format!(" ({}", s.window_label()));
    if s.window_is_capped() {
        title.push_str(&format!(" capped at {}", s.window_samples()));
    }
    if let Some(t) = s.targets.get(s.graph_target) {
        let st = t.stats(n);
        title.push_str(&format!(
            " · {}: jit {:.1} · sd {:.1}",
            t.label, t.jitter_ms, st.stddev
        ));
        if let Some(bloat) = t.bufferbloat_ms(n) {
            let (grade, _) = bufferbloat_grade(bloat);
            title.push_str(&format!(" · bloat +{bloat:.0}ms {grade}"));
        }
    }
    title.push(')');
    f.render_widget(block(&title, s.focus == Panel::Quality), area);
    // The scroll cue runs beside the rows, under the header.
    let body = Rect {
        y: parts[0].y + 1,
        height: parts[0].height.saturating_sub(1),
        ..parts[0]
    };
    let body = scroll_cue(f, body, order.len(), first, rows_avail);
    let table_area = Rect {
        width: body.width,
        ..parts[0]
    };
    f.render_widget(Table::new(rows, widths).header(header), table_area);

    match s.quality_view {
        QualityView::Graph => latency_graph(f, s, n, parts[1]),
        QualityView::Traceroute => traceroute_view(f, s, parts[1]),
        QualityView::HopMonitor => hop_monitor_view(f, s, n, parts[1]),
    }
    if show_web {
        web_graph(f, s, parts[2]);
    }
}

/// Whether the web strip has a target to describe.
fn has_web_data(s: &AppState) -> bool {
    s.targets.get(s.graph_target).is_some()
}

/// The web (HTTP) strip under the latency graph: the *graphed target's* web
/// service, not the general internet (that check lives in the Network panel).
/// A target that never served HTTP says so quietly — absence of a web server
/// is a fact, not a fault.
fn web_graph(f: &mut Frame, s: &AppState, area: Rect) {
    if area.height < 2 {
        return;
    }
    let Some(t) = s.targets.get(s.graph_target) else {
        return;
    };
    use crate::app::WebStatus;
    let rows = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).split(area);

    let head = Span::styled(
        format!(" web · {}  ", t.label),
        Style::new().fg(Color::DarkGray),
    );
    // Mid-path hops are never probed — routers aren't web destinations, and
    // "checking…" would be a promise that never resolves.
    if t.is_path_hop() {
        f.render_widget(
            Paragraph::new(Line::from(vec![
                head,
                Span::styled(
                    "mid-path router — not a web destination".to_string(),
                    Style::new().fg(Color::DarkGray),
                ),
            ])),
            rows[0],
        );
        return;
    }
    let detail = match t.web.status {
        WebStatus::Web if t.web.fails > 0 => Span::styled(
            format!("not answering ({} probes) — ping still fine", t.web.fails),
            Style::new().fg(Color::Red).bold(),
        ),
        WebStatus::Web => Span::styled(
            t.web
                .last_ttfb_ms
                .map(|ms| format!("ttfb {ms:.0}ms"))
                .unwrap_or_else(|| "…".into()),
            Style::new().fg(Color::Green),
        ),
        WebStatus::NoService => Span::styled(
            "no web service (connection refused)".to_string(),
            Style::new().fg(Color::DarkGray),
        ),
        WebStatus::Filtered => Span::styled(
            "TCP filtered — ping answers, web dropped".to_string(),
            Style::new().fg(Color::Yellow),
        ),
        WebStatus::Unknown => {
            Span::styled("checking…".to_string(), Style::new().fg(Color::DarkGray))
        }
    };
    f.render_widget(Paragraph::new(Line::from(vec![head, detail])), rows[0]);

    let data = t.web.hist.tail_u64(rows[1].width as usize);
    if !data.is_empty() {
        f.render_widget(
            Sparkline::default()
                .data(
                    data.iter()
                        .map(|v| SparklineBar::from(*v))
                        .collect::<Vec<_>>(),
                )
                .style(Style::new().fg(SERIES_COLOR)),
            rows[1],
        );
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
        // Three overlaid series need the vertical room to be told apart.
        let p = Layout::vertical([Constraint::Min(5), Constraint::Length(11)]).split(area);
        (p[0], Some(p[1]))
    } else {
        (area, None)
    };

    let title = format!("Path · {}  ({status})", m.target);
    let b = block(&title, active);
    let inner = b.inner(list_area);

    if inner.height == 0 || m.hops.is_empty() {
        f.render_widget(b, list_area);
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

    let header = Row::new(["ttl", "address", "loss", "last", "avg", "p95", "jitter"])
        .style(Style::new().fg(Color::Gray).bold());
    // Scroll so the selected hop stays on screen. Rows are not one-to-one with
    // hops — a run of silent ones collapses to a single row — so the cursor is
    // located by hop index rather than by counting rows.
    let rows_avail = inner.height.saturating_sub(1) as usize;
    let all_rows = hop_rows(&m.hops);
    let cursor = all_rows
        .iter()
        .position(|r| matches!(r, HopRow::Hop(i, _) if *i == m.selected))
        .unwrap_or(0);
    let first = if rows_avail == 0 {
        0
    } else {
        cursor.saturating_sub(rows_avail - 1)
    };
    let visible: Vec<&HopRow> = all_rows.iter().skip(first).take(rows_avail).collect();
    let hidden_above = first;
    let hidden_below = all_rows.len().saturating_sub(first + visible.len());
    // The scroll cue takes the last column when the list overflows; the
    // sparklines give it up. Drawn last, so nothing paints over it.
    let body = Rect {
        y: inner.y + 1,
        height: inner.height.saturating_sub(1),
        ..inner
    };
    let overflow = all_rows.len() > rows_avail;
    let inner_w = inner.width.saturating_sub(overflow as u16);
    let spark_w = inner_w.saturating_sub(table_w + 1);
    let show_sparks = spark_w >= 8;

    // Counts belong in the title, the way the target list does it. A footer row
    // costs one of the rows it is complaining about, and it used to tell the
    // reader to press [f] for full screen even when they were already in it.
    let mut title = title;
    if hidden_above > 0 || hidden_below > 0 {
        title.push_str(" · ");
        if hidden_above > 0 {
            title.push_str(&format!("↑{hidden_above} "));
        }
        if hidden_below > 0 {
            title.push_str(&format!("↓{hidden_below} "));
        }
        title.push_str("more");
    }
    f.render_widget(block(&title, active), list_area);

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
                    Cell::from(hop_ttl(h)),
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
                Cell::from(hop_ttl(h)),
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
                        width: inner_w,
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
                // Floor to a visible baseline, but colour from the *raw* sample:
                // a fast hop under a spiky peak must still read as green, not as
                // whatever its floored height happens to be.
                let (heights, max) = floor_to_visible(&data, 1);
                // Colour each bar by how bad that individual sample was, not by
                // the hop's current state: a row that is green throughout except
                // for a red patch tells you the trouble was transient, which
                // height alone makes you squint to work out.
                let bars: Vec<SparklineBar> = heights
                    .iter()
                    .zip(data.iter())
                    .map(|(&h, &raw)| {
                        SparklineBar::from(h).style(Style::new().fg(rtt_color(raw as f64)))
                    })
                    .collect();
                f.render_widget(
                    Sparkline::default().data(bars).max(max),
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
    scroll_cue(f, body, all_rows.len(), first, rows_avail);

    if let Some(chart_area) = chart_area {
        hop_chart(f, m, n, chart_area, s.graph_marker);
    }
}

/// Latency history for the hop under the cursor, in its own panel.
fn hop_chart(f: &mut Frame, m: &crate::app::HopMonitor, n: usize, area: Rect, marker: Marker) {
    let hop = m.hops.get(m.selected);
    let label = match hop {
        Some(h) if h.is_dest_placeholder() => match h.addr {
            Some(a) => format!("dest · {a}"),
            None => "dest".to_string(),
        },
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
    let jitter_line = [(0.0, stat.jitter_ms), (xmax, stat.jitter_ms)];

    let datasets = vec![
        Dataset::default()
            .marker(marker)
            .graph_type(GraphType::Line)
            .style(Style::new().fg(SERIES_COLOR))
            .data(&series),
        Dataset::default()
            .marker(marker)
            .graph_type(GraphType::Line)
            .style(Style::new().fg(P95_COLOR))
            .data(&p95_line),
        Dataset::default()
            .marker(marker)
            .graph_type(GraphType::Line)
            .style(Style::new().fg(JITTER_COLOR))
            .data(&jitter_line),
    ];
    let chart = Chart::new(datasets)
        .block(Block::new().title(Line::from(vec![
            Span::styled(" latency ", Style::new().fg(SERIES_COLOR)),
            Span::styled("· p95 ", Style::new().fg(Color::DarkGray)),
            Span::styled(format!("{p95:.0}ms"), Style::new().fg(P95_COLOR)),
            Span::styled(" · jitter ", Style::new().fg(Color::DarkGray)),
            Span::styled(
                format!("{:.1}ms", stat.jitter_ms),
                Style::new().fg(JITTER_COLOR),
            ),
            Span::styled(
                format!(" · loss {:.0}% ", stat.loss_pct()),
                Style::new().fg(Color::DarkGray),
            ),
        ])))
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
        p if p >= th::LOSS_BAD_PCT => Color::Red,
        p if p >= th::LOSS_WARN_PCT => Color::Yellow,
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
        // Unlike the path monitor this list has no cursor, so there is nothing
        // to scroll with — in full screen the hint has nothing left to offer
        // and saying "press [f] for full screen" to someone already there is
        // just confusing.
        let hint = if s.fullscreen {
            ""
        } else {
            " — press [f] for full screen"
        };
        v.push(Line::from(Span::styled(
            format!("… +{remaining} more{hint}"),
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
    // Jitter as a reference line rather than a series: it is a single smoothed
    // figure, so plotting it per-sample would just redraw the same value.
    let jitter_line = [(0.0, t.jitter_ms), (xmax, t.jitter_ms)];

    let datasets = vec![
        Dataset::default()
            .marker(s.graph_marker)
            .graph_type(GraphType::Line)
            .style(Style::new().fg(SERIES_COLOR))
            .data(&series),
        Dataset::default()
            .marker(s.graph_marker)
            .graph_type(GraphType::Line)
            .style(Style::new().fg(P95_COLOR))
            .data(&p95_line),
        Dataset::default()
            .marker(s.graph_marker)
            .graph_type(GraphType::Line)
            .style(Style::new().fg(JITTER_COLOR))
            .data(&jitter_line),
    ];

    // Each label is drawn in its series' colour, so the legend needs no key.
    let chart = Chart::new(datasets)
        .block(Block::new().title(Line::from(vec![
            Span::styled(" latency ", Style::new().fg(Color::DarkGray)),
            Span::styled(t.label.clone(), Style::new().fg(SERIES_COLOR)),
            Span::styled("   p95 ", Style::new().fg(Color::DarkGray)),
            Span::styled(format!("{p95:.0}ms"), Style::new().fg(P95_COLOR)),
            Span::styled("   jitter ", Style::new().fg(Color::DarkGray)),
            Span::styled(
                format!("{:.1}ms ", t.jitter_ms),
                Style::new().fg(JITTER_COLOR),
            ),
        ])))
        .x_axis(Axis::default().bounds([0.0, xmax]))
        .y_axis(
            Axis::default()
                .bounds([0.0, ymax])
                .labels([Line::from("0"), Line::from(format!("{ymax:.0}ms"))]),
        );
    f.render_widget(chart, area);
}

// (The one-line stats summary that used to sit above the target table now
// rides in the panel title, buying a line of graph space.)

/// Grade latency inflation under load, à la the Waveform/Cloudflare scale.
/// Steps live in the verdict rulebook so grading here and findings there agree.
fn bufferbloat_grade(bloat_ms: f64) -> (&'static str, Color) {
    let [excellent, good, moderate, poor] = th::BLOAT_STEPS_MS;
    match bloat_ms {
        b if b < excellent => ("excellent", Color::Green),
        b if b < good => ("good", Color::Green),
        b if b < moderate => ("moderate", Color::Yellow),
        b if b < poor => ("poor", Color::Red),
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

    // Split view shows 5 talkers under a header. Full screen gives the tables
    // half the height (never less than a 10-row pane, borders included) and
    // the graphs the rest; the tables scroll for anything beyond that.
    let speed_h = speedtest_height(s, inner.width);
    let talker_h = if s.fullscreen {
        (inner.height.saturating_sub(speed_h) / 2).max(13)
    } else {
        6
    };
    let rows = Layout::vertical([
        Constraint::Length(speed_h),  // status / progress
        Constraint::Min(6),           // throughput graphs (given the most room)
        Constraint::Length(talker_h), // top talkers pinned to the bottom
    ])
    .split(inner);

    render_speedtest(f, s, rows[0]);

    let graphs =
        Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).split(rows[1]);
    // The title line inside each Sparkline's block costs a row, so the trace is
    // scaled against one row fewer than the area it is given.
    let spark_h = |r: Rect| r.height.saturating_sub(1);
    let (ddata, dmax) = spark_floor(&tp.down_hist, graphs[0].width, spark_h(graphs[0]));
    let down = Sparkline::default()
        .data(ddata)
        .max(dmax)
        .style(Style::new().fg(Color::Green))
        .block(Block::new().title(Span::styled(
            format!(" ↓ down  {}", fmt_rate(tp.down_bps)),
            Style::new().fg(Color::Green).bold(),
        )));
    f.render_widget(down, graphs[0]);

    let (udata, umax) = spark_floor(&tp.up_hist, graphs[1].width, spark_h(graphs[1]));
    let up = Sparkline::default()
        .data(udata)
        .max(umax)
        .style(Style::new().fg(Color::Magenta))
        .block(Block::new().title(Span::styled(
            format!(" ↑ up    {}", fmt_rate(tp.up_bps)),
            Style::new().fg(Color::Magenta).bold(),
        )));
    f.render_widget(up, graphs[1]);

    // Full-screen: the talkers and speed-test history each get their own panel,
    // and 'n' moves the cursor between them. Given the width, processes and
    // remote addresses sit side by side and 'b' picks which one the sort and
    // row cursor belong to; otherwise 'b' switches which of the two is shown.
    if s.fullscreen {
        let on_history = s.focus == Panel::Bandwidth && s.sub_pane == SubPane::Secondary;
        let on_talkers = s.focus == Panel::Bandwidth && !on_history;
        let both = both_talker_tables_fit(rows[2].width);
        let cols = if both {
            Layout::horizontal([
                Constraint::Fill(1),
                Constraint::Fill(1),
                Constraint::Length(SPEED_HISTORY_W),
            ])
            .split(rows[2])
        } else {
            Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)])
                .split(rows[2])
        };

        // Say how to get to the other list: a second view behind a key that
        // is not otherwise hinted at in the title is a view nobody finds.
        let views: &[BwView] = if both {
            &[BwView::Processes, BwView::Remotes]
        } else {
            std::slice::from_ref(&s.bw_view)
        };
        for (i, view) in views.iter().enumerate() {
            let active = *view == s.bw_view;
            let name = match view {
                BwView::Processes => "Processes",
                BwView::Remotes => "Remote addresses",
            };
            let title = if both {
                name.to_string()
            } else {
                format!("{name} · n for next")
            };
            let tblock = block(&title, on_talkers && active);
            let tinner = tblock.inner(cols[i]);
            f.render_widget(tblock, cols[i]);
            top_talkers_view(f, s, tinner, *view);
        }
        let hist_area = cols[views.len()];

        // The saved count is the point of a history; when it outgrows what is
        // held in memory, say so rather than implying the rest is gone.
        let title = match s.speed_total {
            0 => "Speed Test History".to_string(),
            total if total > s.speed_history.len() => {
                format!(
                    "Speed Test History · {} of {total} saved",
                    s.speed_history.len()
                )
            }
            total => format!("Speed Test History · {total} saved"),
        };
        let sblock = block(&title, on_history);
        let sinner = sblock.inner(hist_area);
        f.render_widget(sblock, hist_area);
        speedtest_results(f, s, sinner, on_history);
    } else {
        top_talkers_view(f, s, rows[2], s.bw_view);
    }
}

/// Width of the speed-test history pane in full screen: its five fixed columns
/// plus borders.
const SPEED_HISTORY_W: u16 = 12 + 11 + 7 + 7 + 8 + 4 + 2;

/// Whether the full-screen talkers row is wide enough to show processes and
/// remote addresses at once, beside the speed history. The bar is set where
/// each table still gets the columns that make it worth having: the process
/// table its name/total/↓/↑, the remotes its address/process/total. Trailing
/// columns come back as the terminal widens.
fn both_talker_tables_fit(width: u16) -> bool {
    width >= SPEED_HISTORY_W + 2 * (52 + 2)
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
    floor_to_visible(&hist.tail_u64(width as usize), height)
}

/// Raise every sample to at least one rendered sub-cell, returning the data and
/// the scale to draw it against.
///
/// A sparkline cell has 8 vertical levels, so in a one-row trace anything below
/// `max / 8` renders as an empty column. With spiky data — a 240ms latency spike
/// among 14ms samples — that blanks nearly the whole row, which reads as missing
/// data rather than as a low value.
fn floor_to_visible(data: &[u64], height: u16) -> (Vec<u64>, u64) {
    let levels = (height as u64).saturating_mul(8).max(8);
    let max = data.iter().copied().max().unwrap_or(0);
    if max == 0 {
        // All zero: still draw the baseline, so the chart reads as "nothing
        // happening" rather than "no data" — an empty panel looks broken.
        return (vec![1; data.len()], levels);
    }
    // Rounded up: ratatui truncates `value * levels / max`, so a floor computed
    // by plain division lands just under one tick and renders nothing.
    let floor = max.div_ceil(levels).max(1);
    (data.iter().map(|&v| v.max(floor)).collect(), max)
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
        // The phase reads "Cloudflare · upload", so an equality test against
        // "upload" never matched and the bar stayed green for both directions.
        // Magenta matches the up-throughput series elsewhere in the UI.
        let color = if st.phase.contains("upload") {
            Color::Magenta
        } else {
            Color::Green
        };
        f.render_widget(
            Gauge::default()
                .ratio(st.progress.clamp(0.0, 1.0))
                .label(label)
                // An explicit background gives the label readable contrast on
                // both sides of the bar edge: ratatui swaps fg/bg for the cells
                // the bar covers, so without a bg set the text ends up as the
                // terminal's default foreground on a saturated fill.
                .gauge_style(Style::new().fg(color).bg(Color::Black)),
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

/// Compact "what has been using the link" table beneath the throughput
/// sparklines: processes ranked by bytes moved this session, with the current
/// rate and retransmits for connection health. As many rows as fit under the
/// header; the row cursor scrolls the rest into view.
fn top_talkers_view(f: &mut Frame, s: &AppState, area: Rect, view: BwView) {
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
            // Windows names no tool: its sources are in-process, and being
            // unable to reach them is a privilege problem, reported separately.
            let tool = if cfg!(target_os = "linux") {
                "ss"
            } else if cfg!(target_os = "macos") {
                "nettop"
            } else {
                ""
            };
            let msg = match s.missing_tools.iter().find(|(n, _, _)| *n == tool) {
                Some((n, _, pkg)) => format!("per-process bandwidth needs {n} — {pkg}"),
                None => "per-process bandwidth unavailable on this platform".to_string(),
            };
            return dim(f, &msg);
        }
        ProcStatus::NeedsPrivilege => {
            // Actionable, unlike Unsupported. Both routes are named because the
            // group is granted once where elevation is per-run.
            return dim(
                f,
                "per-process bandwidth needs an ETW session — run elevated, or join \
                 the \"Performance Log Users\" group",
            );
        }
        ProcStatus::Probing => return dim(f, "detecting per-process bandwidth… (~5s)"),
        ProcStatus::Supported if s.processes.is_empty() => return dim(f, "sampling processes…"),
        ProcStatus::Supported => {}
    }

    if view == BwView::Remotes {
        return top_remotes(f, s, inner);
    }
    // Only the active table (of the two shown side by side in full screen)
    // carries the column cursor and sort.
    let active = s.bw_view == BwView::Processes;

    // Session totals lead (that is what the table ranks by); the live rate and
    // health columns follow, and go first when the panel is narrow.
    // Sized so every column fits the full-screen pane of a 120-column terminal.
    const WIDTHS: [u16; 7] = [21, 7, 7, 7, 10, 5, 5];
    let ncols = fitting_columns(&WIDTHS, inner.width);
    let labels = ["name", "total", "↓", "↑", "now", "share", "retx"];
    let header = talkers_header(s, &labels[..ncols], active);

    // Rows as drawn (the sort, when one is active), scrolled to keep the
    // cursor in view, with a cue beside them when there is more.
    let order = s.process_order();
    let cursor_on = s.on_process_list();
    let (inner, first, visible) = talkers_scroll(f, inner, &order, s.proc_sel);

    let rows = order.iter().skip(first).take(visible).map(|&idx| {
        let p = &s.processes[idx];
        let name: String = p.name.chars().take(WIDTHS[0] as usize).collect();
        // Retransmits: red while they are happening, the session count once
        // they have, nothing when there were none.
        let (retx, retx_style) = if p.retx_per_sec >= 1.0 {
            (
                format!("{:.0}/s", p.retx_per_sec),
                Style::new().fg(Color::Red),
            )
        } else if p.retx > 0 {
            (p.retx.to_string(), Style::new().fg(Color::Gray))
        } else {
            ("·".to_string(), Style::new().fg(Color::DarkGray))
        };
        let mut cells = vec![
            Cell::from(name),
            Cell::from(Span::styled(
                fmt_bytes(p.total_bytes),
                Style::new().fg(Color::White),
            )),
            Cell::from(Span::styled(
                fmt_bytes(p.down_bytes),
                Style::new().fg(Color::Green),
            )),
            Cell::from(Span::styled(
                fmt_bytes(p.up_bytes),
                Style::new().fg(Color::Magenta),
            )),
            fmt_now(p.down_bps + p.up_bps),
            Cell::from(Span::styled(
                format!("{:.0}%", p.share * 100.0),
                Style::new().fg(Color::Gray),
            )),
            Cell::from(Span::styled(retx, retx_style)),
        ];
        cells.truncate(ncols);
        Row::new(cells).style(row_style(cursor_on && idx == s.proc_sel))
    });
    let widths: Vec<Constraint> = WIDTHS[..ncols]
        .iter()
        .map(|w| Constraint::Length(*w))
        .collect();
    f.render_widget(Table::new(rows, widths).header(header), inner);
}

/// Cursor-row highlight shared by the talkers tables.
fn row_style(selected: bool) -> Style {
    if selected {
        Style::new()
            .bg(Color::Rgb(40, 40, 55))
            .add_modifier(Modifier::BOLD)
    } else {
        Style::new()
    }
}

/// Scroll a talkers table so the cursor row stays visible, and draw the
/// scroll cue beside the rows (under the header) when they overflow. Returns
/// the area left for the table, the first row to draw, and how many.
fn talkers_scroll(
    f: &mut Frame,
    area: Rect,
    order: &[usize],
    cursor: usize,
) -> (Rect, usize, usize) {
    let visible = area.height.saturating_sub(1) as usize; // header row
    let pos = order.iter().position(|&i| i == cursor).unwrap_or(0);
    let first = if visible == 0 {
        0
    } else {
        pos.saturating_sub(visible - 1)
    };
    let body = Rect {
        y: area.y + 1,
        height: area.height.saturating_sub(1),
        ..area
    };
    let body = scroll_cue(f, body, order.len(), first, visible);
    (
        Rect {
            width: body.width,
            ..area
        },
        first,
        visible,
    )
}

/// How many leading columns of the given widths (plus one-cell gaps) fit in
/// `width`. Fixed widths, and when the panel is narrower than the lot (the
/// split view is), the trailing columns go rather than every column squeezing.
/// Always at least one.
fn fitting_columns(widths: &[u16], width: u16) -> usize {
    let mut ncols = 0;
    let mut used = 0u16;
    for w in widths {
        let next = used + w + if ncols > 0 { 1 } else { 0 };
        if next > width {
            break;
        }
        used = next;
        ncols += 1;
    }
    ncols.max(1)
}

/// The "now" column: the current combined rate, or a dim dot when idle so a
/// quiet row reads as quiet rather than as "0 B/s".
fn fmt_now(bps: f64) -> Cell<'static> {
    if bps > 0.0 {
        Cell::from(Span::styled(fmt_rate(bps), Style::new().fg(Color::Cyan)))
    } else {
        Cell::from(Span::styled("·", Style::new().fg(Color::DarkGray)))
    }
}

/// Sortable header row for a talkers table: the column under the cursor is
/// highlighted, the sorted column carries a direction arrow.
fn talkers_header<'a>(s: &AppState, labels: &[&'a str], active: bool) -> Row<'a> {
    let focused = active && s.focus == Panel::Bandwidth;
    Row::new(labels.iter().enumerate().map(|(i, l)| {
        let mut txt = (*l).to_string();
        if let Some((c, desc)) = s.bw_sort
            && active
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
    }))
}

/// `addr:port`, bracketing v6, with a `+` when more than one port was in use.
fn fmt_remote(r: &crate::app::RemoteBandwidth) -> String {
    let more = if r.ports > 1 { "+" } else { "" };
    match r.addr {
        std::net::IpAddr::V4(a) => format!("{a}:{}{more}", r.port),
        std::net::IpAddr::V6(a) => format!("[{a}]:{}{more}", r.port),
    }
}

/// "Which address is eating my link": the top remotes by bandwidth, with the
/// process talking to each. Its row cursor is one to act on — [W] asks who
/// owns the address, [a] pings it — as well as what scrolls the list.
fn top_remotes(f: &mut Frame, s: &AppState, area: Rect) {
    if s.remotes.is_empty() {
        f.render_widget(
            Paragraph::new(Span::styled(
                "no traffic to remote addresses yet",
                Style::new().fg(Color::DarkGray),
            )),
            area,
        );
        return;
    }
    // A squeezed address column is the one thing this table must not have, so
    // trailing columns are dropped instead when the panel is narrow.
    const WIDTHS: [u16; 7] = [24, 12, 7, 7, 7, 10, 5];
    let ncols = fitting_columns(&WIDTHS, area.width);
    let labels = ["remote", "process", "total", "↓", "↑", "now", "share"];
    let active = s.bw_view == BwView::Remotes;
    let header = talkers_header(s, &labels[..ncols], active);

    let order = s.remote_order();
    let cursor_on = s.selected_remote().is_some();
    let (area, first, visible) = talkers_scroll(f, area, &order, s.remote_sel);

    let rows = order.iter().skip(first).take(visible).map(|&idx| {
        let r = &s.remotes[idx];
        let selected = cursor_on && idx == s.remote_sel;
        // v6 with a port can outrun the column; keep the tail, which is the
        // distinctive part of the address.
        let remote: String = {
            let full = fmt_remote(r);
            let n = full.chars().count();
            if n > 24 {
                format!("…{}", full.chars().skip(n - 23).collect::<String>())
            } else {
                full
            }
        };
        let process: String = r.process.chars().take(WIDTHS[1] as usize).collect();
        let mut cells = vec![
            Cell::from(remote),
            Cell::from(Span::styled(process, Style::new().fg(Color::Gray))),
            Cell::from(Span::styled(
                fmt_bytes(r.total_bytes),
                Style::new().fg(Color::White),
            )),
            Cell::from(Span::styled(
                fmt_bytes(r.down_bytes),
                Style::new().fg(Color::Green),
            )),
            Cell::from(Span::styled(
                fmt_bytes(r.up_bytes),
                Style::new().fg(Color::Magenta),
            )),
            fmt_now(r.down_bps + r.up_bps),
            Cell::from(Span::styled(
                format!("{:.0}%", r.share * 100.0),
                Style::new().fg(Color::Gray),
            )),
        ];
        cells.truncate(ncols);
        Row::new(cells).style(row_style(selected))
    });
    let widths: Vec<Constraint> = WIDTHS[..ncols]
        .iter()
        .map(|w| Constraint::Length(*w))
        .collect();
    f.render_widget(Table::new(rows, widths).header(header), area);
}

/// Centered modal listing all keyboard shortcuts, titled with the running
/// version so users can report what they're actually on.
fn help_overlay(f: &mut Frame, s: &AppState, area: Rect) {
    let row = |k: &str, d: &str| {
        Line::from(vec![
            Span::styled(format!("{k:<11}"), Style::new().fg(Color::Cyan)),
            Span::styled(d.to_string(), Style::new().fg(Color::Gray)),
        ])
    };
    let head = |t: &str| {
        Line::from(Span::styled(
            t.to_string(),
            Style::new().fg(Color::White).bold(),
        ))
    };

    // Two columns, so the whole key set fits an 80x24 terminal without
    // scrolling. Descriptions are kept short enough for a half-width column.
    // Leading indent comes from the block's padding, not the lines.
    let mut left = vec![
        head("Global"),
        row("Tab / ⇧Tab", "cycle panels"),
        row("f", "full-screen focused panel"),
        row("n", "next sub-pane in panel"),
        row("Esc", "back / exit full-screen"),
        row("s", "run speed test"),
        row("p", "pause / resume the display"),
        row("r", "re-probe network info"),
        row("w", "stats window 1m/5m/15m"),
        row("l", "start / stop CSV recording"),
        row("y", "connection analysis"),
        row("e", "event timeline"),
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
        row("W", "whois: who owns address"),
        Line::from(""),
        head("Bandwidth"),
        row("v", "cycle speed-test provider"),
        row("n", "procs → remotes → history"),
        row("W / a", "whois / add sel. remote"),
        Line::from(""),
        head("Network"),
        row("r", "re-probe"),
        row("N", "name this network"),
        row("L", "saved network locations"),
        row("f", "full-screen for DNS graphs"),
    ];

    // Only shown when something is actually absent, with the package that
    // provides it — which tools ship by default varies a lot by distribution.
    if !s.missing_tools.is_empty() {
        right.push(Line::from(""));
        right.push(Line::from(Span::styled(
            "Missing tools",
            Style::new().fg(Color::Yellow).bold(),
        )));
        for (name, _provides, package) in &s.missing_tools {
            right.push(Line::from(vec![
                Span::styled(format!("{name:<11}"), Style::new().fg(Color::Yellow)),
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

    let w = if two_col { 80 } else { 42 }.min(area.width);
    let h = (body_h + 3).min(area.height); // +2 border, +1 footer
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };

    f.render_widget(Clear, rect);
    let outer = Block::bordered()
        .padding(Padding::new(1, 1, 0, 0))
        .title(Span::styled(
            format!(" octomon v{} · Shortcuts ", crate::util::VERSION),
            Style::new().bold(),
        ))
        .title_bottom(Span::styled(
            " press ? or Esc to close ",
            Style::new().fg(Color::DarkGray),
        ))
        .border_style(Style::new().fg(Color::Cyan));
    let inner = outer.inner(rect);
    f.render_widget(outer, rect);

    // A trailing column of padding, so the longest description does not sit
    // flush against the border.
    let pad = |r: Rect| Rect {
        width: r.width.saturating_sub(1),
        ..r
    };
    if two_col {
        let cols = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(inner);
        f.render_widget(Paragraph::new(left), pad(cols[0]));
        f.render_widget(Paragraph::new(right), pad(cols[1]));
    } else {
        f.render_widget(Paragraph::new(left), pad(inner));
    }
}

fn netinfo_panel(f: &mut Frame, s: &AppState, area: Rect) {
    let n = &s.netinfo;
    // The location name rides in the title, like the Bandwidth panel's iface:
    // "Network · Home". Until a baseline exists there is nothing to say.
    let title = match &s.baseline {
        Some(b) => format!("Network · {}", b.display_name()),
        None => "Network".to_string(),
    };
    let b = block(&title, s.focus == Panel::NetInfo);
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
    if let Some(l) = http_line(s) {
        lines.push(l);
    }

    if let Some(w) = &n.wifi {
        // Live signal/tx come from the CoreWLAN graph below; keep the slower
        // system_profiler details (SSID / PHY / channel) here.
        // macOS returns the literal string "<redacted>" for the network name
        // unless the caller holds Location Services authorisation — Apple treats
        // an SSID as location-revealing. Say why, rather than showing a bare
        // placeholder that reads like an octomon bug.
        if w.ssid.contains("redacted") {
            lines.push(Line::from(vec![
                Span::styled(format!("{:<9}", "ssid"), Style::new().fg(Color::DarkGray)),
                Span::styled(
                    "hidden — needs Location Services",
                    Style::new().fg(Color::DarkGray).italic(),
                ),
            ]));
        } else {
            lines.push(kv("ssid", dash(&w.ssid)));
        }
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
    // Full-screen has room for a signal trace worth reading; five rows in a
    // split panel is all that fits, but it is cramped when the panel is large.
    let graph_h = match (graph, s.fullscreen) {
        (LinkGraph::None, _) => 0,
        (_, true) => 10,
        (_, false) => 5,
    };

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

/// The internet-level HTTP check ("can I reach the internet the way a browser
/// does"), one Network-panel line — a property of the network, unlike the
/// per-target web strip in Connection Quality. Absent until a probe lands.
fn http_line(s: &AppState) -> Option<Line<'static>> {
    use crate::app::FamilyProbe as FP;
    if matches!(s.http.v4, FP::NotRun) && matches!(s.http.v6, FP::NotRun) {
        return None;
    }
    let span = |f: &FP, name: &str| match f {
        FP::NotRun => Span::styled(format!("{name} …"), Style::new().fg(Color::DarkGray)),
        FP::NotApplicable => Span::styled(format!("{name} n/a"), Style::new().fg(Color::DarkGray)),
        FP::Ok(ms) => Span::styled(
            format!("{name} ok {ms:.0}ms"),
            Style::new().fg(Color::Green),
        ),
        FP::Captive(_) => Span::styled(
            "CAPTIVE PORTAL".to_string(),
            Style::new().fg(Color::Red).bold(),
        ),
        FP::Fail(r) => Span::styled(format!("{name} {r}"), Style::new().fg(Color::Red)),
    };
    Some(Line::from(vec![
        Span::styled(format!("{:<9}", "http"), Style::new().fg(Color::DarkGray)),
        span(&s.http.v4, "v4"),
        Span::styled(" · ", Style::new().fg(Color::DarkGray)),
        span(&s.http.v6, "v6"),
        Span::styled(
            format!("  ({})", s.http.provider),
            Style::new().fg(Color::DarkGray),
        ),
    ]))
}

/// Resolver latency thresholds: a cached answer should be near the RTT to the
/// resolver, so tens of ms is fine and hundreds is not.
fn dns_color(ms: f64) -> Color {
    match ms {
        v if v < th::DNS_WARN_MS => Color::Green,
        v if v < th::DNS_BAD_MS => Color::Yellow,
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
            .marker(s.graph_marker)
            .graph_type(GraphType::Line)
            .style(Style::new().fg(Color::Green))
            .data(&dpts),
        Dataset::default()
            .marker(s.graph_marker)
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
    // Each figure is drawn in its own series' colour, so naming the colour in
    // the text ("(cyan)") is redundant — and wrong if the palette ever changes.
    let mut title = vec![
        Span::styled(" signal ", Style::new().fg(Color::DarkGray)),
        Span::styled(
            format!("{} dBm", sig.rssi_dbm),
            Style::new().fg(sig_color).bold(),
        ),
    ];
    if has_tx {
        title.push(Span::styled(" · tx ", Style::new().fg(Color::DarkGray)));
        title.push(Span::styled(
            format!("{:.0} Mbps ", sig.tx_rate_mbps),
            Style::new().fg(Color::Cyan).bold(),
        ));
    } else {
        title.push(Span::raw(" "));
    }

    let sig_pts: Vec<(f64, f64)> = (0..len)
        .map(|i| (i as f64, ((rssi[i] + 100.0) / 70.0).clamp(0.0, 1.0)))
        .collect();
    let tx_pts: Vec<(f64, f64)> = (0..len)
        .map(|i| (i as f64, (tx[i] / tx_max.max(1.0)).clamp(0.0, 1.0)))
        .collect();
    let xmax = (len - 1).max(1) as f64;

    let mut datasets = vec![
        Dataset::default()
            .marker(s.graph_marker)
            .graph_type(GraphType::Line)
            .style(Style::new().fg(sig_color))
            .data(&sig_pts),
    ];
    if has_tx {
        datasets.push(
            Dataset::default()
                .marker(s.graph_marker)
                .graph_type(GraphType::Line)
                .style(Style::new().fg(Color::Cyan))
                .data(&tx_pts),
        );
    }
    let chart = Chart::new(datasets)
        .block(Block::new().title(Line::from(title)))
        .x_axis(Axis::default().bounds([0.0, xmax]))
        .y_axis(Axis::default().bounds([0.0, 1.05]));
    f.render_widget(chart, area);
}

fn vitals_panel(f: &mut Frame, s: &AppState, area: Rect) {
    let v = &s.vitals;
    let b = block("Machine", s.focus == Panel::Vitals);
    let inner = b.inner(area);
    f.render_widget(b, area);

    // Per-core detail only earns its space full-screen; the split view keeps to
    // the summary plus history.
    let core_rows = if s.fullscreen && !v.cores.is_empty() {
        v.cores.len().div_ceil(CORES_PER_ROW) as u16 + 1
    } else {
        0
    };
    let parts = Layout::vertical([
        Constraint::Length(1), // cpu
        Constraint::Length(1), // memory pressure
        Constraint::Length(1), // load average
        Constraint::Length(1), // link errors
        Constraint::Length(1), // thermal / power
        Constraint::Length(core_rows),
        Constraint::Min(0), // history
    ])
    .split(inner);

    // LineGauge keeps the label to the left of the bar, so it stays legible
    // (a Gauge draws the label over the fill, which is unreadable on yellow).
    let cpu = v.cpu_pct.clamp(0.0, 100.0);
    let hottest = v
        .hottest_core()
        .map(|(i, pct)| format!(" (core {} {pct:.0}%)", i + 1))
        .unwrap_or_default();
    f.render_widget(
        LineGauge::default()
            .ratio((cpu / 100.0) as f64)
            .label(format!("CPU {cpu:>3.0}%{hottest}"))
            .filled_style(Style::new().fg(usage_color(cpu)))
            .unfilled_style(Style::new().fg(Color::DarkGray)),
        parts[0],
    );

    // Pressure, not used/total: caches make "used" sit near total on a healthy
    // machine, so the old bar was alarming and uninformative.
    let pressure = v.mem_pressure_pct.clamp(0.0, 100.0);
    f.render_widget(
        LineGauge::default()
            .ratio((pressure / 100.0) as f64)
            .label(format!(
                "MEM {pressure:>3.0}% used of {}",
                fmt_bytes(v.mem_total)
            ))
            .filled_style(Style::new().fg(usage_color(pressure)))
            .unfilled_style(Style::new().fg(Color::DarkGray)),
        parts[1],
    );

    // Load average, plus swap — swap activity is what actually correlates with
    // "everything feels slow".
    let (l1, l5, l15) = v.load;
    let cores = v.core_count().max(1) as f64;
    // Windows has no load-average concept and sysinfo reports zeros for it,
    // which would render as a measured, permanently idle machine rather than as
    // a figure the platform does not have. Swap still means something there.
    let mut load_spans = if cfg!(windows) {
        Vec::new()
    } else {
        vec![
            Span::styled("load ", Style::new().fg(Color::DarkGray)),
            Span::styled(
                format!("{l1:.2} {l5:.2} {l15:.2}"),
                // Load beyond core count means work is queueing for CPU.
                Style::new().fg(if l1 > cores {
                    Color::Red
                } else if l1 > cores * 0.7 {
                    Color::Yellow
                } else {
                    Color::Green
                }),
            ),
        ]
    };
    if v.swap_used > 0 {
        // Only separated from the load figures when there are any.
        let label = if load_spans.is_empty() {
            "swap "
        } else {
            "  swap "
        };
        load_spans.push(Span::styled(label, Style::new().fg(Color::DarkGray)));
        load_spans.push(Span::styled(
            fmt_bytes(v.swap_used),
            Style::new().fg(Color::Yellow),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(load_spans)), parts[2]);

    f.render_widget(Paragraph::new(link_error_line(&s.link_errors)), parts[3]);

    // Thermal state, when the platform reports it.
    if !v.thermal.is_empty() || !v.power_source.is_empty() {
        let mut spans = vec![Span::styled("power ", Style::new().fg(Color::DarkGray))];
        if !v.thermal.is_empty() {
            spans.push(Span::styled(
                v.thermal.clone(),
                Style::new().fg(if v.throttled {
                    Color::Red
                } else {
                    Color::Green
                }),
            ));
        }
        if !v.power_source.is_empty() {
            spans.push(Span::styled(
                format!("  {}", v.power_source),
                Style::new().fg(Color::Gray),
            ));
        }
        f.render_widget(Paragraph::new(Line::from(spans)), parts[4]);
    }

    if core_rows > 0 {
        core_grid(f, &v.cores, parts[5]);
    }

    // CPU history sparkline (uses the remaining space).
    let spark = Sparkline::default()
        .max(100)
        .data(v.cpu_hist.tail_u64(parts[6].width as usize))
        .style(Style::new().fg(Color::Yellow))
        .block(Block::new().title(Span::styled(
            " cpu history ",
            Style::new().fg(Color::DarkGray),
        )));
    f.render_widget(spark, parts[6]);
}

/// How many per-core meters sit on one row.
const CORES_PER_ROW: usize = 4;

/// Compact per-core meters. A single saturated core stalls a network path while
/// the global average looks idle, which the summary line cannot show.
fn core_grid(f: &mut Frame, cores: &[f32], area: Rect) {
    if area.height == 0 {
        return;
    }
    f.render_widget(
        Paragraph::new(Span::styled(
            format!(" per-core ({} cores) ", cores.len()),
            Style::new().fg(Color::DarkGray),
        )),
        Rect { height: 1, ..area },
    );

    let cell_w = area.width / CORES_PER_ROW as u16;
    if cell_w < 8 {
        return;
    }
    for (i, pct) in cores.iter().enumerate() {
        let row = (i / CORES_PER_ROW) as u16;
        let col = (i % CORES_PER_ROW) as u16;
        let y = area.y + 1 + row;
        if y >= area.y + area.height {
            break;
        }
        let pct = pct.clamp(0.0, 100.0);
        f.render_widget(
            LineGauge::default()
                .ratio((pct / 100.0) as f64)
                .label(format!("{:>2} {pct:>3.0}%", i + 1))
                .filled_style(Style::new().fg(usage_color(pct)))
                .unfilled_style(Style::new().fg(Color::DarkGray)),
            Rect {
                x: area.x + col * cell_w,
                y,
                width: cell_w.saturating_sub(1),
                height: 1,
            },
        );
    }
}

/// Interface error/drop summary. Silence here is the expected state, so a clean
/// link says so rather than showing nothing.
fn link_error_line(e: &crate::app::LinkErrors) -> Line<'static> {
    let total = e.rx_err_total + e.tx_err_total;
    let mut spans = vec![Span::styled("errs ", Style::new().fg(Color::DarkGray))];
    if total == 0 {
        spans.push(Span::styled("none", Style::new().fg(Color::Green)));
        return Line::from(spans);
    }
    let pct = e.error_pct();
    spans.push(Span::styled(
        format!("rx {} tx {}", e.rx_err_total, e.tx_err_total),
        Style::new().fg(if pct >= 1.0 {
            Color::Red
        } else {
            Color::Yellow
        }),
    ));
    // A rate means nothing without knowing whether the link was busy.
    spans.push(Span::styled(
        format!("  {pct:.2}% of packets"),
        Style::new().fg(Color::DarkGray),
    ));
    Line::from(spans)
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

/// Colour a single round-trip sample. Unlike [`latency_color`] this judges one
/// measurement in isolation, so a trace can show what each moment looked like.
fn rtt_color(ms: f64) -> Color {
    match ms {
        v if v < th::RTT_WARN_MS => Color::Green,
        v if v < th::RTT_BAD_MS => Color::Yellow,
        _ => Color::Red,
    }
}

/// Series colours for the latency charts. Deliberately outside the
/// green/yellow/red scale, which means "how bad is this" everywhere else — a
/// green trace line would read as a verdict rather than as a series.
const SERIES_COLOR: Color = Color::Cyan;
const P95_COLOR: Color = Color::Magenta;
const JITTER_COLOR: Color = Color::LightBlue;

fn latency_color(last: Option<f64>, loss: f64) -> Color {
    if loss >= th::LOSS_BAD_PCT || last.is_none() {
        return Color::Red;
    }
    if loss >= th::LOSS_WARN_PCT {
        return Color::Yellow;
    }
    match last {
        Some(ms) => rtt_color(ms),
        None => Color::Red,
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
    if pct >= th::USAGE_BAD_PCT {
        Color::Red
    } else if pct >= th::USAGE_WARN_PCT {
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

    fn finding(severity: Severity) -> crate::verdict::Finding {
        crate::verdict::Finding {
            cause: crate::verdict::Cause::GatewayLan,
            severity,
            confidence: crate::verdict::Confidence::Likely,
            summary: "gateway unresponsive (100% loss)".into(),
            evidence: vec!["gateway 192.168.1.1: 100% loss".into()],
            subject: String::new(),
        }
    }

    #[test]
    fn footer_carries_the_verdict_headline() {
        // Fresh state: measuring, never "healthy" from ignorance.
        let s = AppState::new(vec![]);
        let out = draw(&s, 120, 24);
        assert!(out.contains("measuring"));
        assert!(out.contains("[y] analysis"));

        let mut s = AppState::new(vec![]);
        s.verdict.current = Verdict::Healthy;
        assert!(draw(&s, 120, 24).contains("connection healthy"));

        s.verdict.current =
            Verdict::Problems(vec![finding(Severity::Down), finding(Severity::Degraded)]);
        let out = draw(&s, 120, 24);
        assert!(out.contains("gateway unresponsive"));
        // Confidence wording stays in the [y] overlay, off the headline.
        assert!(!out.contains("— likely"));
        assert!(out.contains("+1 more"), "co-causes must stay visible");

        // Info-class findings are notes, not a red headline.
        s.verdict.current = Verdict::Problems(vec![finding(Severity::Info)]);
        let out = draw(&s, 120, 24);
        assert!(out.contains("connection healthy"));
        assert!(out.contains("1 note"));
    }

    #[test]
    fn transient_notice_still_outranks_the_verdict_line() {
        let mut s = AppState::new(vec![]);
        s.verdict.current = Verdict::Healthy;
        s.notice = Some("network changed → en7".into());
        let out = draw(&s, 120, 24);
        assert!(out.contains("network changed"));
        assert!(!out.contains("connection healthy"));
    }

    #[test]
    fn triage_overlay_shows_the_whole_ladder_with_its_data() {
        let mut s = AppState::new(vec![crate::app::TargetStat::new(
            "Cloudflare".into(),
            "1.1.1.1".parse().unwrap(),
        )]);
        for _ in 0..20 {
            s.targets[0].record_reply(12.0);
        }
        s.vitals.cores = vec![10.0; 4];
        s.vitals.cpu_pct = 8.0;
        s.overlay = Overlay::Triage;
        let triage = crate::verdict::evaluate(&s);
        s.verdict.triage = triage;
        s.verdict.current = Verdict::Healthy;

        let out = draw(&s, 100, 30);
        // Every rung, healthy ones included — the exonerating evidence is the
        // difference between a verdict and an assertion.
        for label in [
            "machine",
            "gateway",
            "DNS",
            "ISP path",
            "internet",
            "destinations",
        ] {
            assert!(out.contains(label), "ladder is missing {label:?}");
        }
        assert!(out.contains("cpu 8%"), "healthy rungs carry their data");
        assert!(
            out.contains("[m] to watch"),
            "unknown rungs say how to fill them"
        );
        assert!(out.contains("no findings"));
        assert!(out.contains("press y or Esc to close"));
    }

    #[test]
    fn explainer_overlay_reads_as_a_welcome() {
        let mut s = AppState::new(vec![]);
        s.overlay = Overlay::Explainer;
        let out = draw(&s, 100, 30);
        assert!(out.contains("diagnose internet connectivity"));
        assert!(out.contains("my machine, my local network, my ISP"));
        assert!(out.contains("learns what normal looks like"));
        assert!(out.contains("press any key to start"));
    }

    #[test]
    fn network_panel_title_carries_the_location_name() {
        let mut s = state_with_medium(LinkMedium::WiFi);
        // No baseline yet: plain title.
        let out = draw(&s, 200, 60);
        assert!(out.contains(" Network "));
        assert!(!out.contains("Network · "));

        s.baseline = Some(crate::baseline::Baseline {
            label: "HomeNet".into(),
            samples: 0,
            ..Default::default()
        });
        assert!(draw(&s, 200, 60).contains("Network · HomeNet"));

        // A user-chosen name wins over the auto label.
        s.baseline.as_mut().unwrap().name = Some("Home".into());
        assert!(draw(&s, 200, 60).contains("Network · Home"));
    }

    #[test]
    fn locations_overlay_lists_stored_baselines() {
        let mut s = AppState::new(vec![]);
        s.overlay = Overlay::Locations;
        assert!(draw(&s, 120, 30).contains("loading…"));

        s.baseline_key = Some("k2".into());
        s.locations = Some(vec![
            (
                "k1".into(),
                crate::baseline::Baseline {
                    label: "CoffeeNet".into(),
                    name: Some("Cafe".into()),
                    samples: 40,
                    gateway_ms: Some(4.2),
                    down_mbps: Some(310.0),
                    up_mbps: Some(28.0),
                    ..Default::default()
                },
            ),
            (
                "k2".into(),
                crate::baseline::Baseline {
                    label: "HomeNet".into(),
                    samples: 2,
                    ..Default::default()
                },
            ),
        ]);
        let out = draw(&s, 120, 30);
        assert!(out.contains("locations (2)"));
        assert!(out.contains("Cafe"));
        assert!(
            out.contains("(CoffeeNet)"),
            "auto label shown next to the name"
        );
        assert!(out.contains("gateway ~4ms"));
        assert!(out.contains("speed 310↓/28↑"));
        assert!(out.contains("40 healthy min"));
        assert!(out.contains("● current"), "the active network is marked");
        assert!(out.contains("press L or Esc to close"));
    }

    #[test]
    fn naming_prompt_takes_over_the_footer() {
        let mut s = AppState::new(vec![]);
        s.input_mode = InputMode::NameNetwork;
        s.input_buffer = "Home".into();
        let out = draw(&s, 120, 24);
        assert!(out.contains("name this network"));
        assert!(out.contains("Home"));
        assert!(out.contains("[Enter] save"));
    }

    #[test]
    fn events_overlay_lists_newest_first_with_times() {
        let mut s = AppState::new(vec![]);
        s.overlay = Overlay::Events;
        let out = draw(&s, 120, 30);
        assert!(out.contains("no events yet"));

        s.push_event(
            Severity::Degraded,
            crate::app::EventCategory::Analysis,
            "▲ gateway unresponsive".into(),
        );
        s.push_event(
            Severity::Info,
            crate::app::EventCategory::Network,
            "VPN down".into(),
        );
        let out = draw(&s, 120, 30);
        assert!(out.contains("events (2 this session)"));
        assert!(out.contains("▲ gateway unresponsive"));
        assert!(out.contains("VPN down"));
        assert!(out.contains("analysis"), "category label says analysis");
        assert!(
            !out.contains("verdict"),
            "the word verdict is out of the UX"
        );
        assert!(out.contains("network"));
        // Newest (VPN down) renders above the older analysis event.
        assert!(out.find("VPN down").unwrap() < out.find("▲ gateway unresponsive").unwrap());
        assert!(out.contains("press e or Esc to close"));
    }

    /// A graphed mid-path hop must not promise a web check that never comes.
    #[test]
    fn web_strip_names_hops_as_non_destinations() {
        let mut s = AppState::new(vec![]);
        let mut hop =
            crate::app::TargetStat::new("hop 2→1.1.1.1".into(), "192.184.208.23".parse().unwrap());
        hop.discovered = true;
        for _ in 0..10 {
            hop.record_reply(4.0);
        }
        s.targets.push(hop);
        s.graph_target = 0;
        s.fullscreen = true; // guarantees the web strip is drawn
        let out = draw(&s, 120, 40);
        assert!(out.contains("mid-path router — not a web destination"));
        assert!(!out.contains("checking…"));
    }

    #[test]
    fn triage_overlay_lists_findings_with_evidence() {
        let mut s = AppState::new(vec![]);
        s.overlay = Overlay::Triage;
        s.verdict.triage = crate::verdict::evaluate(&s);
        s.verdict.current = Verdict::Problems(vec![finding(Severity::Down)]);
        let out = draw(&s, 100, 30);
        assert!(out.contains("gateway unresponsive"));
        assert!(
            !out.contains("likely"),
            "confidence words stay out of the UX"
        );
        assert!(out.contains("gateway 192.168.1.1: 100% loss"));
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
    /// The throughput trace must keep a visible baseline even at zero, so an
    /// idle link reads as "nothing flowing" rather than "the panel is broken".
    #[test]
    fn bandwidth_sparkline_always_shows_a_baseline() {
        let mut h = crate::app::History::new(64);

        // Completely idle.
        for _ in 0..10 {
            h.push(0.0);
        }
        let (data, max) = spark_floor(&h, 10, 3);
        assert!(data.iter().all(|&v| v > 0), "every cell must render");
        assert!(
            data.iter().all(|&v| v * 8 * 3 / max >= 1),
            "each must reach at least the lowest of the 8 sub-cell levels"
        );
        assert!(
            data.iter().all(|&v| v * 8 * 3 / max == 1),
            "and no more than one, so idle stays visually flat"
        );

        // A quiet stretch inside real traffic keeps its baseline too.
        let mut h2 = crate::app::History::new(64);
        for v in [0.0, 5_000_000.0, 0.0, 0.0, 1_000_000.0] {
            h2.push(v);
        }
        let (data, max) = spark_floor(&h2, 5, 3);
        assert_eq!(max, 5_000_000, "scale still comes from the real peak");
        assert!(
            data.iter().all(|&v| v * 8 * 3 / max >= 1),
            "zero samples still occupy the bottom row"
        );
        // The peak still reaches the top.
        assert_eq!(data.iter().copied().max().unwrap(), 5_000_000);
    }

    /// The gauge label must stay legible where the fill runs underneath it.
    #[test]
    fn speedtest_gauge_labels_upload_and_stays_readable() {
        use crate::app::SpeedStatus;

        let mut s = AppState::new(vec![]);
        s.focus = Panel::Bandwidth;
        s.speedtest.status = SpeedStatus::Running;
        s.speedtest.progress = 0.5;
        s.speedtest.live_mbps = 42.0;

        // Real phase strings are qualified by provider, which is why an equality
        // test against "upload" silently never fired.
        s.speedtest.phase = "Cloudflare · upload".into();
        let out = draw(&s, 120, 30);
        assert!(out.contains("upload"));

        s.speedtest.phase = "Cloudflare · download".into();
        assert!(draw(&s, 120, 30).contains("download"));
    }

    #[test]
    fn machine_panel_surfaces_the_new_signals() {
        let mut s = AppState::new(vec![]);
        s.focus = Panel::Vitals;
        s.vitals.cpu_pct = 9.0;
        s.vitals.cores = vec![12.0, 4.0, 88.0, 3.0];
        s.vitals.mem_total = 24 * 1024 * 1024 * 1024;
        s.vitals.mem_pressure_pct = 68.0;
        s.vitals.load = (2.8, 2.9, 2.9);
        s.vitals.thermal = "CPU limited to 70%".into();
        s.vitals.throttled = true;
        s.vitals.power_source = "Battery Power".into();

        let out = draw(&s, 120, 30);
        // A saturated core is invisible in a 9% average, so it is called out.
        // Cores are numbered from 1 for display; index 2 is core 3.
        assert!(out.contains("core 3 88%"));
        assert!(out.contains("68% used"), "pressure, not used/total");
        // Windows has no load-average concept and sysinfo reports zeros there,
        // so the row is suppressed rather than rendered as a measured idle.
        if cfg!(windows) {
            assert!(
                !out.contains("load "),
                "Windows has no load average to show"
            );
        } else {
            assert!(out.contains("2.80 2.90 2.90"));
        }
        assert!(out.contains("CPU limited to 70%"));
        assert!(out.contains("Battery Power"));

        // Per-core detail is full-screen only; the split view stays a summary.
        assert!(!out.contains("per-core"));
        s.fullscreen = true;
        assert!(draw(&s, 120, 30).contains("per-core (4 cores)"));
    }

    #[test]
    fn link_errors_read_as_a_share_of_traffic() {
        use crate::app::LinkErrors;

        // A clean link says so rather than showing nothing.
        let mut s = AppState::new(vec![]);
        s.focus = Panel::Vitals;
        assert!(draw(&s, 120, 30).contains("errs none"));

        s.link_errors = LinkErrors {
            iface: "en0".into(),
            rx_err_total: 12,
            tx_err_total: 3,
            rx_err_per_sec: 1.0,
            tx_err_per_sec: 0.0,
            rx_packets_per_sec: 900.0,
            tx_packets_per_sec: 1100.0,
        };
        let out = draw(&s, 120, 30);
        assert!(out.contains("rx 12 tx 3"));
        // A raw rate means nothing without knowing how busy the link was.
        assert!(out.contains("% of packets"));
        assert!((s.link_errors.error_pct() - 0.04998).abs() < 0.001);

        // An idle link must not divide by zero.
        assert_eq!(LinkErrors::default().error_pct(), 0.0);
    }

    /// Spiky latency must not blank the trace: a single 240ms outlier among
    /// 14ms samples would otherwise push every normal sample below one tick.
    #[test]
    fn path_sparkline_keeps_a_baseline_under_a_spike() {
        let samples: Vec<u64> = vec![14, 12, 15, 240, 13, 14, 0, 12];
        let (heights, max) = floor_to_visible(&samples, 1);
        assert_eq!(max, 240, "scale still comes from the real peak");
        for (h, raw) in heights.iter().zip(samples.iter()) {
            assert!(
                h * 8 / max >= 1,
                "sample {raw} rendered nothing (height {h}, max {max})"
            );
        }
        // The spike still tops out, and colour comes from the raw value so a
        // floored-up sample is not miscoloured as slow.
        assert_eq!(heights.iter().copied().max().unwrap(), 240);
        assert_eq!(rtt_color(14.0), Color::Green);
        assert_eq!(rtt_color(240.0), Color::Red);
    }

    /// A long target list must stay navigable when the path monitor squeezes it.
    #[test]
    fn target_list_scrolls_to_keep_the_cursor_visible() {
        use crate::app::{QualityView, TargetStat};
        use std::net::{IpAddr, Ipv4Addr};

        let targets: Vec<TargetStat> = (1..=30)
            .map(|i| {
                TargetStat::new(
                    format!("target-{i}"),
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8)),
                )
            })
            .collect();
        let mut s = AppState::new(targets);
        s.focus = Panel::Quality;
        s.quality_view = QualityView::Graph;

        // Cursor at the top: the first entries are on screen.
        s.selected = 0;
        let out = draw(&s, 100, 24);
        assert!(out.contains("target-1"));

        // Cursor near the end: the view has scrolled to it, and says so.
        s.selected = 29;
        let out = draw(&s, 100, 24);
        assert!(out.contains("target-30"), "cursor row must be visible");
        assert!(out.contains("more"), "should indicate the list continues");
    }

    /// A long hostname should use the panel, not be clipped at a fixed width.
    #[test]
    fn long_target_names_use_the_available_width() {
        use crate::app::TargetStat;
        use std::net::{IpAddr, Ipv4Addr};

        let name = "a-very-long-host.example.com";
        let s = AppState::new(vec![TargetStat::new(
            name.into(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        )]);
        assert!(draw(&s, 120, 24).contains(name));
    }

    /// The whois overlay shows the address while the query is in flight, the
    /// registry's fields once it lands, and the failure when it doesn't.
    #[test]
    fn whois_overlay_renders_each_state() {
        use crate::app::{Overlay, Whois};
        use std::net::{IpAddr, Ipv4Addr};

        let addr = IpAddr::V4(Ipv4Addr::new(75, 101, 33, 185));
        let mut s = AppState::new(vec![]);
        s.overlay = Overlay::Whois;
        s.whois = Some(Whois {
            addr,
            running: true,
            fields: Vec::new(),
            raw: Vec::new(),
            source: String::new(),
            error: None,
        });
        let out = draw(&s, 100, 30);
        assert!(out.contains("75.101.33.185"));
        assert!(out.contains("looking up"));

        let w = s.whois.as_mut().unwrap();
        w.running = false;
        w.source = "rdap.arin.net".into();
        w.fields = vec![
            (
                "network".into(),
                "75.101.0.0 – 75.101.63.255  (75.101.0.0/18)".into(),
            ),
            ("registrant".into(), "Sonic.net, LLC".into()),
            ("remarks".into(), "word ".repeat(40).trim().into()),
        ];
        let out = draw(&s, 100, 30);
        assert!(out.contains("Sonic.net, LLC"));
        assert!(out.contains("75.101.0.0/18"));
        assert!(out.contains("rdap.arin.net"));

        s.whois.as_mut().unwrap().error = Some("timed out".into());
        let out = draw(&s, 100, 30);
        assert!(out.contains("lookup failed"));
    }

    /// The remotes view lists addresses with their busiest port and process,
    /// marks a multi-port address, and highlights the cursor row.
    #[test]
    fn remotes_view_lists_addresses_with_port_and_process() {
        use crate::app::{BwView, ProcStatus, RemoteBandwidth};
        use std::net::{IpAddr, Ipv4Addr};

        let mut s = AppState::new(vec![]);
        s.focus = Panel::Bandwidth;
        s.proc_status = ProcStatus::Supported;
        s.processes = vec![
            crate::app::ProcBandwidth {
                name: "firefox".into(),
                pid: 1,
                down_bytes: 4_000_000,
                up_bytes: 1_000_000,
                total_bytes: 5_000_000,
                share: 0.8,
                retx: 3,
                down_bps: 900_000.0,
                up_bps: 10_000.0,
                retx_per_sec: 0.0,
            },
            // Idle now, but keeps its row with its session totals.
            crate::app::ProcBandwidth {
                name: "rsync".into(),
                pid: 2,
                down_bytes: 0,
                up_bytes: 1_250_000,
                total_bytes: 1_250_000,
                share: 0.2,
                ..Default::default()
            },
        ];
        s.remotes = vec![
            RemoteBandwidth {
                addr: IpAddr::V4(Ipv4Addr::new(151, 101, 193, 111)),
                port: 443,
                ports: 2,
                process: "firefox".into(),
                down_bytes: 4_000_000,
                up_bytes: 1_000_000,
                total_bytes: 5_000_000,
                share: 0.8,
                down_bps: 900_000.0,
                up_bps: 10_000.0,
            },
            RemoteBandwidth {
                addr: "2606:4700:4700::1111".parse().unwrap(),
                port: 53,
                ports: 1,
                process: "mDNSResponder".into(),
                down_bytes: 500,
                up_bytes: 500,
                total_bytes: 1_000,
                share: 0.2,
                down_bps: 0.0,
                up_bps: 0.0,
            },
        ];
        // Process view by default: no addresses shown.
        let out = draw(&s, 120, 30);
        assert!(out.contains("firefox"));
        assert!(out.contains("rsync"), "idle processes keep their row");
        assert!(!out.contains("151.101.193.111"));
        // Full screen has room for every column: session bytes, the live rate
        // and the retransmit count.
        s.fullscreen = true;
        let out = draw(&s, 120, 30);
        assert!(out.contains("now"), "{out}");
        assert!(out.contains("910.0 KB/s"), "{out}");
        assert!(out.contains("80%"), "{out}");
        s.fullscreen = false;

        s.bw_view = BwView::Remotes;
        s.remote_sel = 1;
        let out = draw(&s, 120, 30);
        assert!(
            out.contains("151.101.193.111:443+"),
            "busiest port, + for more"
        );
        // A long v6 keeps its distinctive tail rather than being squeezed.
        assert!(out.contains("…606:4700:4700::1111]:53"));
        assert!(out.contains("mDNSRespond"));
        assert!(out.contains("remote"));
        // The split view is too narrow for every column: the byte columns go,
        // the address does not get squeezed.
        assert!(!out.contains("977K"), "{out}");
        s.fullscreen = true;
        let out = draw(&s, 120, 30);
        assert!(out.contains("977K"), "{out}");
        assert!(out.contains("Remote addresses · n for next"));
        assert_eq!(
            s.selected_addr(),
            Some("2606:4700:4700::1111".parse().unwrap()),
            "the cursor row is what W and a act on"
        );
        s.bw_view = BwView::Processes;
        assert!(draw(&s, 120, 30).contains("Processes · n for next"));

        // Wide enough, full screen shows both tables at once beside the
        // history; 'n' then moves the focus (sort/cursor) between them, and
        // the focused one carries the highlighted border rather than a hint.
        let out = draw(&s, 200, 30);
        assert!(out.contains("Processes ─"), "{out}");
        assert!(out.contains("Remote addresses ─"), "{out}");
        assert!(!out.contains("n for next"), "{out}");
        assert!(out.contains("rsync") && out.contains("151.101.193.111:443+"));
        assert!(out.contains("Speed Test History"));
    }

    /// The talkers tables scroll with their row cursor and show the cue only
    /// when there is more than fits; ↑/↓ walk the rows as drawn under a sort.
    #[test]
    fn talkers_tables_scroll_with_the_cursor_in_display_order() {
        use crate::app::{BwView, ProcStatus};
        let mut s = AppState::new(vec![]);
        s.focus = Panel::Bandwidth;
        s.fullscreen = true;
        s.proc_status = ProcStatus::Supported;
        // 30 processes; the pane at 30 rows tall shows about ten.
        s.processes = (0..30)
            .map(|i| crate::app::ProcBandwidth {
                name: format!("proc{i:02}"),
                pid: i,
                total_bytes: (30 - i) as u64 * 1_000_000,
                ..Default::default()
            })
            .collect();
        let out = draw(&s, 120, 30);
        assert!(out.contains("proc00") && !out.contains("proc29"), "{out}");
        assert!(out.contains('┃'), "scroll cue when rows overflow: {out}");

        // Cursor to the last row in display order: the list scrolls to it.
        let order = s.process_order();
        s.proc_sel = *order.last().unwrap();
        let out = draw(&s, 120, 30);
        assert!(out.contains("proc29") && !out.contains("proc00"), "{out}");

        // Under an ascending name sort the cursor steps through names, not
        // collector indices.
        s.bw_view = BwView::Processes;
        s.bw_sort = Some((0, false));
        s.proc_sel = 0;
        let order = s.process_order();
        assert_eq!(&s.processes[order[0]].name, "proc00");
        let next = AppState::step_in_order(&order, s.proc_sel, 1);
        assert_eq!(&s.processes[next].name, "proc01");
        // Reverse it: stepping "down" from proc00 goes nowhere (it is last).
        s.bw_sort = Some((0, true));
        let order = s.process_order();
        assert_eq!(AppState::step_in_order(&order, 0, 1), 0);
        assert_eq!(
            &s.processes[AppState::step_in_order(&order, 0, -1)].name,
            "proc01"
        );

        // A short list draws no cue.
        s.processes.truncate(3);
        s.bw_sort = None;
        s.proc_sel = 0;
        assert!(!draw(&s, 120, 30).contains('┃'));
    }

    /// While paused the screen is drawn from a snapshot; what the user drives
    /// is copied across, what is measured is not.
    #[test]
    fn paused_snapshot_takes_navigation_but_not_measurements() {
        use crate::app::{BwView, Whois};
        let mut live = AppState::new(vec![]);
        let mut frozen = live.clone();
        live.throughput.down_bps = 12345.0;
        live.bw_view = BwView::Remotes;
        live.remote_sel = 3;
        live.fullscreen = true;
        live.notice = Some("hello".into());
        live.whois = Some(Whois {
            addr: "1.1.1.1".parse().unwrap(),
            running: true,
            fields: vec![],
            raw: vec![],
            source: String::new(),
            error: None,
        });
        frozen.sync_interactive_from(&live);
        assert_eq!(frozen.throughput.down_bps, 0.0, "measurement stays put");
        assert_eq!(frozen.bw_view, BwView::Remotes);
        assert_eq!(frozen.remote_sel, 3);
        assert!(frozen.fullscreen);
        assert_eq!(frozen.notice.as_deref(), Some("hello"));
        assert!(frozen.whois.is_some(), "a whois the user asked for arrives");
    }

    #[test]
    fn long_values_wrap_under_the_key_column() {
        let lines = wrap_words("aa bb cc dd", 5);
        assert_eq!(lines, vec!["aa bb", "cc dd"]);
        assert_eq!(wrap_words("", 5), vec![""]);
        assert_eq!(wrap_words("abcdefghij", 5), vec!["abcdefghij"]);
    }

    /// The scroll cue is a visual only — no mouse — so it appears only when
    /// there is somewhere to scroll to, on both lists.
    #[test]
    fn scroll_cue_appears_only_when_a_list_overflows() {
        use crate::app::{HopMonitor, MonitoredHop, QualityView, TargetStat};
        use std::net::{IpAddr, Ipv4Addr};

        // Three targets in a tall terminal: everything fits, no cue.
        let targets: Vec<TargetStat> = (1..=3)
            .map(|i| TargetStat::new(format!("t{i}"), IpAddr::V4(Ipv4Addr::new(10, 0, 0, i))))
            .collect();
        let s = AppState::new(targets);
        let out = draw(&s, 120, 40);
        assert!(!out.contains('┃'), "no cue when the list fits");

        // Thirty targets in a short terminal: the cue's thumb shows.
        let targets: Vec<TargetStat> = (1..=30)
            .map(|i| TargetStat::new(format!("t{i}"), IpAddr::V4(Ipv4Addr::new(10, 0, 0, i))))
            .collect();
        let s = AppState::new(targets);
        let out = draw(&s, 120, 24);
        assert!(out.contains('┃'), "cue when the target list overflows");

        // Same for the hop list.
        let hops: Vec<MonitoredHop> = (1..=25)
            .map(|ttl| {
                let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, ttl));
                MonitoredHop {
                    ttl,
                    addr: Some(addr),
                    stat: Some(TargetStat::new(format!("hop {ttl}"), addr)),
                }
            })
            .collect();
        let mut s = AppState::new(vec![]);
        s.focus = Panel::Quality;
        s.quality_view = QualityView::HopMonitor;
        s.hop_monitor = Some(HopMonitor {
            target: "dest".into(),
            dest: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            hops,
            discovering: false,
            generation: 1,
            selected: 0,
        });
        let out = draw(&s, 120, 24);
        assert!(out.contains('┃'), "cue when the hop list overflows");
        s.fullscreen = true;
        let out = draw(&s, 120, 60);
        assert!(!out.contains('┃'), "no cue once every hop fits");
    }

    #[test]
    fn hop_list_scrolls_to_keep_the_selection_visible() {
        use crate::app::{HopMonitor, MonitoredHop, QualityView, TargetStat};
        use std::net::{IpAddr, Ipv4Addr};

        let hops: Vec<MonitoredHop> = (1..=25)
            .map(|ttl| {
                let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, ttl));
                let mut st = TargetStat::new(format!("hop {ttl}"), addr);
                st.record_reply(10.0);
                MonitoredHop {
                    ttl,
                    addr: Some(addr),
                    stat: Some(st),
                }
            })
            .collect();

        let mut s = AppState::new(vec![]);
        s.focus = Panel::Quality;
        s.quality_view = QualityView::HopMonitor;
        s.hop_monitor = Some(HopMonitor {
            target: "dest".into(),
            dest: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            hops,
            discovering: false,
            generation: 1,
            selected: 0,
        });

        // Cursor at the top: the near end of the path is on screen, the far end
        // is not, and the title says how much is below.
        let out = draw(&s, 120, 24);
        assert!(out.contains("10.0.0.1 "), "first hop visible");
        assert!(!out.contains("10.0.0.25"), "last hop is past the fold");
        assert!(out.contains("↓"), "title counts what is hidden below");
        // The old footer told the reader to press [f] for full screen, which is
        // unhelpful advice to someone already in full screen.
        assert!(!out.contains("press [f] for full screen"));

        // Moving the cursor to the far end scrolls the list to follow it.
        // Without this the selection walks off the bottom and disappears.
        s.hop_monitor.as_mut().unwrap().selected = 24;
        let out = draw(&s, 120, 24);
        assert!(
            out.contains("10.0.0.25"),
            "the selected hop must be on screen"
        );
        assert!(!out.contains("10.0.0.1 "), "the top has scrolled away");
        assert!(out.contains("↑"), "title counts what is hidden above");
    }

    #[test]
    fn speed_history_reports_how_many_are_saved() {
        let record = |at: i64| crate::store::SpeedRecord {
            at,
            provider: "Cloudflare".into(),
            down_mbps: 100.0,
            up_mbps: 10.0,
            idle_ms: None,
            loaded_ms: None,
        };

        let mut s = AppState::new(vec![]);
        s.focus = Panel::Bandwidth;
        s.fullscreen = true;
        s.speed_history = (0..3).map(record).collect();
        s.speed_total = 3;
        assert!(draw(&s, 160, 40).contains("3 saved"));

        // When the file holds more than is loaded, both numbers are shown so
        // the older results do not look lost.
        s.speed_total = 812;
        assert!(draw(&s, 160, 40).contains("3 of 812 saved"));

        // Nothing recorded yet: no misleading zero.
        s.speed_history.clear();
        s.speed_total = 0;
        let out = draw(&s, 160, 40);
        assert!(out.contains("Speed Test History"));
        assert!(!out.contains("saved"));
    }

    #[test]
    fn help_lists_every_key_and_fits_a_standard_terminal() {
        let mut s = AppState::new(vec![]);
        s.overlay = Overlay::Help;
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
            "y",
            "e",
            "N",
            "W",
            "W / a",
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
            "whois: who owns address",
            "cycle speed-test provider",
            "procs → remotes → history",
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
        s.overlay = Overlay::Help;
        let out = draw(&s, 50, 40);
        assert!(out.contains("Connection Quality"));
        assert!(out.contains("cycle panels"));
    }

    #[test]
    fn help_shows_the_version_and_fits_its_content() {
        let mut s = AppState::new(vec![]);
        s.overlay = Overlay::Help;
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
