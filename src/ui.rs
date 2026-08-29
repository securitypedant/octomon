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
use crate::theme;
use crate::verdict::{RungStatus, Severity, Verdict, thresholds as th};

/// Draw the whole dashboard.
pub fn render(f: &mut Frame, s: &AppState) {
    // The session strip sits against the footer: the footer says how the
    // connection is *now*, the strip is that same judgement all session. It
    // lives in the root layout rather than in a panel so it spans the full
    // width and survives full-screen, where a long session is most likely to
    // be watched. A short terminal spends the row on data instead.
    let strip_h: u16 = u16::from(session_strip_fits(s, f.area()));
    let root = Layout::vertical([
        Constraint::Length(1),       // header
        Constraint::Min(0),          // body
        Constraint::Length(strip_h), // session strip
        Constraint::Length(1),       // footer (input / notice / hints)
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

    if strip_h > 0 {
        session_strip(f, s, root[2]);
    }
    footer(f, s, root[3]);

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
        Overlay::Routes => routes_overlay(f, s, f.area()),
        Overlay::Egress => egress_overlay(f, s, f.area()),
        // Not a floating overlay: the zoom takes over the Bandwidth panel's
        // bottom band in place (see `zoom_band`), leaving the graphs visible.
        Overlay::Zoom => {}
        Overlay::None => {}
    }
}

/// The Bandwidth panel's bottom band as one full-width table ([z]): every
/// column, names and addresses untruncated, and — for processes — what the
/// OS knows about the selected one. Pure inspection: the question it answers
/// is "what is that thing using my bandwidth?", never process management.
fn zoom_band(f: &mut Frame, s: &AppState, area: Rect) {
    let mut title = match s.zoom_view {
        crate::app::ZoomView::Processes => format!(" Processes · zoom ({}) ", s.processes.len()),
        crate::app::ZoomView::Remotes => {
            format!(" Remote addresses · zoom ({}) ", s.remotes.len())
        }
        crate::app::ZoomView::Speedtests => {
            format!(" Speed Test History · zoom ({}) ", s.speed_history.len())
        }
    };
    if s.zoom_view != crate::app::ZoomView::Speedtests {
        if let Some(name) = follow_label(s) {
            title.push_str(&format!("· following {name} "));
        }
        if !s.bw_filter.trim().is_empty() {
            title.push_str(&format!("· ⌕ {} ", s.bw_filter.trim()));
        }
    }
    // The talkers sort, follow, and filter from the zoom too; the history is
    // curated from it.
    let hint = match s.zoom_view {
        crate::app::ZoomView::Speedtests => {
            " ↑↓ scroll · d delete · n next table · press z or Esc to close "
        }
        _ => " ↑↓ scroll · ←→ ↵ sort · / filter · o follow · p/u pin · n next table · z closes ",
    };
    let outer = Block::bordered()
        .padding(Padding::new(1, 1, 0, 0))
        .title(Span::styled(title, Style::new().bold()))
        .title_bottom(Span::styled(hint, Style::new().fg(theme::dim())))
        .border_style(Style::new().fg(theme::accent()));
    let inner = outer.inner(area);
    f.render_widget(outer, area);
    if inner.height < 2 {
        return;
    }
    match s.zoom_view {
        crate::app::ZoomView::Processes => zoom_processes(f, s, inner),
        crate::app::ZoomView::Remotes => zoom_remotes(f, s, inner),
        crate::app::ZoomView::Speedtests => zoom_speedtests(f, s, inner),
    }
}

/// Fixed column widths for the columns that fit, with the leftover pane
/// width (up to `cap`) handed to column `col` — the name or address column
/// that puts it to use; number columns would not. Returns the widths and
/// that column's final width, for truncation.
fn flex_col(widths: &[u16], ncols: usize, avail: u16, col: usize, cap: u16) -> (Vec<u16>, u16) {
    let mut v: Vec<u16> = widths[..ncols].to_vec();
    let used: u16 = v.iter().sum::<u16>() + ncols.saturating_sub(1) as u16;
    let extra = avail.saturating_sub(used).min(cap);
    let col = col.min(v.len() - 1);
    v[col] += extra;
    let flexed = v[col];
    (v, flexed)
}

/// Header for a zoomed talkers table. The zoom splits the compact "now" into
/// now↓ / now↑ / now↕ (the combined rate, under its compact sort key) and
/// adds informational columns (pid): `map[key]` names the zoomed column that
/// carries each sort key's cursor highlight and sort arrow — keys 7/8 are
/// the split rate columns, which only exist here.
fn zoom_header<'a>(s: &AppState, labels: &[&'a str], view: BwView, map: &[usize]) -> Row<'a> {
    let sort = s.sort_for(view);
    Row::new(labels.iter().enumerate().map(|(i, l)| {
        let base = map.iter().position(|&z| z == i);
        let mut txt = (*l).to_string();
        if let (Some(b), Some((c, desc))) = (base, sort)
            && c == b
        {
            txt.push(if desc { '▼' } else { '▲' });
        }
        let style = if base == Some(s.bw_col) {
            Style::new()
                .fg(theme::accent())
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            Style::new().fg(theme::dim())
        };
        Cell::from(Span::styled(txt, style))
    }))
}

/// What a talkers table shows when the '/' filter matches nothing: the filter
/// itself, so the empty table reads as "your filter", never as "no traffic".
fn no_filter_match(f: &mut Frame, area: Rect, what: &str, filter: &str) {
    f.render_widget(
        Paragraph::new(Span::styled(
            format!("no {what} match ⌕ {filter} — / edits, Esc clears"),
            Style::new().fg(theme::dim()),
        )),
        area,
    );
}

/// The "── selected ──…" rule above a detail block, bright enough that the
/// block below it is noticed at all.
fn selected_rule(width: usize) -> Line<'static> {
    let tail: String = "─".repeat(width.saturating_sub(12).max(2));
    Line::from(vec![
        Span::styled("── ", Style::new().fg(theme::dim())),
        Span::styled("selected", Style::new().fg(theme::bright()).bold()),
        Span::styled(format!(" {tail}"), Style::new().fg(theme::dim())),
    ])
}

fn zoom_processes(f: &mut Frame, s: &AppState, area: Rect) {
    // The detail block below the table: everything known about the selected
    // process. Reserved up front so the table scroll accounts for it; a
    // short band gives up the who/when line before the path, and the block
    // entirely before the table.
    let detail_h: u16 = if area.height >= 12 {
        6
    } else if area.height >= 9 {
        4
    } else {
        0
    };
    let (table_area, detail_area) = if detail_h > 0 {
        let parts =
            Layout::vertical([Constraint::Min(1), Constraint::Length(detail_h)]).split(area);
        (parts[0], Some(parts[1]))
    } else {
        (area, None)
    };

    const WIDTHS: [u16; 10] = [34, 7, 11, 11, 11, 8, 8, 8, 6, 6];
    let ncols = fitting_columns(&WIDTHS, table_area.width);
    let (flexed, name_w) = flex_col(&WIDTHS, ncols, table_area.width, 0, 40);
    let labels = [
        "name", "pid", "now↓", "now↑", "now↕", "total", "↓", "↑", "share", "retx",
    ];
    let header = zoom_header(
        s,
        &labels[..ncols],
        BwView::Processes,
        &[0, 4, 5, 6, 7, 8, 9, 2, 3],
    );
    let order = s.process_order();
    let filter = s.filter_for(BwView::Processes).trim();
    if order.is_empty() && !filter.is_empty() {
        return no_filter_match(f, table_area, "processes", filter);
    }
    let (pos, sel_idx) = s.proc_cursor();
    let (table_area, first, visible) = talkers_scroll(f, table_area, order.len(), pos);
    let rows = order.iter().skip(first).take(visible).map(|&idx| {
        let p = &s.processes[idx];
        let name: String = p.name.chars().take(name_w as usize).collect();
        let mut cells = vec![
            Cell::from(name),
            Cell::from(Span::styled(
                p.pid.to_string(),
                Style::new().fg(theme::text()),
            )),
            fmt_now(p.down_bps, s.bits_units),
            fmt_now(p.up_bps, s.bits_units),
            fmt_now(p.down_bps + p.up_bps, s.bits_units),
            Cell::from(Span::styled(
                fmt_bytes(p.total_bytes),
                Style::new().fg(theme::bright()),
            )),
            Cell::from(Span::styled(
                fmt_bytes(p.down_bytes),
                Style::new().fg(Color::Green),
            )),
            Cell::from(Span::styled(
                fmt_bytes(p.up_bytes),
                Style::new().fg(Color::Magenta),
            )),
            Cell::from(Span::styled(
                format!("{:.0}%", p.share * 100.0),
                Style::new().fg(theme::text()),
            )),
            Cell::from(Span::styled(
                p.retx.to_string(),
                Style::new().fg(if p.retx_per_sec >= 1.0 {
                    Color::Red
                } else {
                    theme::text()
                }),
            )),
        ];
        cells.truncate(ncols);
        Row::new(cells).style(row_style(
            Some(idx) == sel_idx,
            s.pinned_procs.contains(&p.name),
        ))
    });
    let widths: Vec<Constraint> = flexed.iter().map(|w| Constraint::Length(*w)).collect();
    f.render_widget(Table::new(rows, widths).header(header), table_area);

    let Some(da) = detail_area else { return };
    let Some(p) = sel_idx.and_then(|i| s.processes.get(i)) else {
        return;
    };
    let text_w = da.width as usize;
    let mut lines = vec![
        selected_rule(text_w),
        Line::from(vec![
            Span::styled(p.name.clone(), Style::new().fg(theme::bright()).bold()),
            Span::styled(format!("  pid {}", p.pid), Style::new().fg(theme::text())),
        ]),
    ];
    match s.proc_details.get(&p.pid) {
        Some(d) => {
            // Who runs it, what launched it, since when — often the whole
            // answer for an opaquely-named helper.
            let mut meta: Vec<Span> = Vec::new();
            for (label, value) in [
                ("user ", &d.user),
                ("parent ", &d.parent),
                ("started ", &d.started),
            ] {
                if value.is_empty() {
                    continue;
                }
                if !meta.is_empty() {
                    meta.push(Span::styled(" · ", Style::new().fg(theme::dim())));
                }
                meta.push(Span::styled(label, Style::new().fg(theme::dim())));
                meta.push(Span::styled(value.clone(), Style::new().fg(theme::text())));
            }
            if !meta.is_empty() {
                lines.push(Line::from(meta));
            }
            // Then the path — it answers "what is this?"; the command line
            // only when it says more than the path already did.
            let path = if d.exe.is_empty() {
                "path withheld by the OS".to_string()
            } else {
                d.exe.clone()
            };
            lines.extend(column_lines(
                vec![Span::styled("path ", Style::new().fg(theme::dim()))],
                &path,
                Style::new().fg(theme::text()),
                5,
                text_w,
            ));
            if !d.cmd.is_empty() && d.cmd != d.exe {
                lines.extend(column_lines(
                    vec![Span::styled("cmd  ", Style::new().fg(theme::dim()))],
                    &d.cmd,
                    Style::new().fg(theme::dim()),
                    5,
                    text_w,
                ));
            }
        }
        // The scan runs off the key path; gone means exited since.
        None => lines.push(Line::from(Span::styled(
            "looking up… (or the process has exited)",
            Style::new().fg(theme::dim()),
        ))),
    }
    lines.truncate(detail_h as usize);
    f.render_widget(Paragraph::new(lines), da);
}

fn zoom_remotes(f: &mut Frame, s: &AppState, area: Rect) {
    // The address column is already sized for the longest realistic v6+port;
    // the leftover width goes to the *process* column — that is the one the
    // compact view truncates ("com.apple.WebKit.Netwo…").
    const WIDTHS: [u16; 9] = [40, 22, 11, 11, 11, 8, 8, 8, 6];
    let ncols = fitting_columns(&WIDTHS, area.width);
    let (flexed, _) = flex_col(&WIDTHS, ncols, area.width, 1, 30);
    let labels = [
        "remote", "process", "now↓", "now↑", "now↕", "total", "↓", "↑", "share",
    ];
    let header = zoom_header(
        s,
        &labels[..ncols],
        BwView::Remotes,
        &[0, 1, 4, 5, 6, 7, 8, 2, 3],
    );
    let order = s.remote_order();
    let filter = s.filter_for(BwView::Remotes).trim();
    if order.is_empty() && !filter.is_empty() {
        return no_filter_match(f, area, "remote addresses", filter);
    }
    let (pos, sel_idx) = s.remote_cursor();
    let (area, first, visible) = talkers_scroll(f, area, order.len(), pos);
    let rows = order.iter().skip(first).take(visible).map(|&idx| {
        let r = &s.remotes[idx];
        let mut remote = fmt_remote(r);
        if r.ports > 1 {
            remote.push_str(&format!(" (+{} ports)", r.ports - 1));
        }
        let mut cells = vec![
            Cell::from(remote),
            Cell::from(Span::styled(
                r.process.clone(),
                Style::new().fg(theme::text()),
            )),
            fmt_now(r.down_bps, s.bits_units),
            fmt_now(r.up_bps, s.bits_units),
            fmt_now(r.down_bps + r.up_bps, s.bits_units),
            Cell::from(Span::styled(
                fmt_bytes(r.total_bytes),
                Style::new().fg(theme::bright()),
            )),
            Cell::from(Span::styled(
                fmt_bytes(r.down_bytes),
                Style::new().fg(Color::Green),
            )),
            Cell::from(Span::styled(
                fmt_bytes(r.up_bytes),
                Style::new().fg(Color::Magenta),
            )),
            Cell::from(Span::styled(
                format!("{:.0}%", r.share * 100.0),
                Style::new().fg(theme::text()),
            )),
        ];
        cells.truncate(ncols);
        Row::new(cells).style(row_style(
            Some(idx) == sel_idx,
            s.pinned_remotes.contains(&r.addr),
        ))
    });
    let widths: Vec<Constraint> = flexed.iter().map(|w| Constraint::Length(*w)).collect();
    f.render_widget(Table::new(rows, widths).header(header), area);
}

fn zoom_speedtests(f: &mut Frame, s: &AppState, area: Rect) {
    if s.speed_history.is_empty() {
        f.render_widget(
            Paragraph::new(Span::styled(
                "no speed tests yet — [s] to run",
                Style::new().fg(theme::dim()),
            )),
            area,
        );
        return;
    }
    // provider carries "iPerf3 · {user's name}" now, which 11 columns
    // truncated mid-word; the compact speed values gave four columns back
    // to pay for most of it.
    const WIDTHS: [u16; 9] = [12, 22, 6, 6, 8, 30, 20, 18, 12];
    let ncols = fitting_columns(&WIDTHS, area.width);
    // Server names (M-Lab sites, Ookla hosts) routinely outgrow 30 columns;
    // any width the pane has spare goes to that column rather than to air.
    let widths: Vec<u16> = if ncols > 5 {
        flex_col(&WIDTHS, ncols, area.width, 5, 30).0
    } else {
        WIDTHS[..ncols].to_vec()
    };
    let labels = [
        "time",
        "provider",
        "↓",
        "↑",
        "bloat",
        "server",
        "network",
        "medium",
        "idle/load",
    ];
    let header = Row::new(labels[..ncols].iter().map(|l| Cell::from(*l)))
        .style(Style::new().fg(theme::dim()));
    let ordered: Vec<&crate::store::SpeedRecord> = s.speed_history.iter().rev().collect();
    let sel = s.speed_sel.min(ordered.len().saturating_sub(1));
    let visible = area.height.saturating_sub(1) as usize;
    let first = if visible == 0 {
        0
    } else {
        sel.saturating_sub(visible - 1)
    };
    let body = Rect {
        y: area.y + 1,
        height: area.height.saturating_sub(1),
        ..area
    };
    let body = scroll_cue(f, body, ordered.len(), first, visible);
    let area = Rect {
        width: body.width,
        ..area
    };
    let dash = |v: &Option<String>| v.clone().unwrap_or_else(|| "—".to_string());
    let rows = ordered
        .iter()
        .skip(first)
        .take(visible)
        .enumerate()
        .map(|(i, r)| {
            let bloat = match (r.idle_ms, r.loaded_ms) {
                (Some(i), Some(l)) => format!("+{:.0}ms", (l - i).max(0.0)),
                _ => "—".to_string(),
            };
            let idle_load = match (r.idle_ms, r.loaded_ms) {
                (Some(i), Some(l)) => format!("{i:.0}/{l:.0}ms"),
                (Some(i), None) => format!("{i:.0}ms/—"),
                _ => "—".to_string(),
            };
            let mut cells = vec![
                Cell::from(r.when()),
                Cell::from(r.provider.clone()),
                Cell::from(Span::styled(
                    fmt_speed_compact(r.down_mbps),
                    Style::new().fg(Color::Green),
                )),
                Cell::from(Span::styled(
                    fmt_speed_compact(r.up_mbps),
                    Style::new().fg(Color::Magenta),
                )),
                Cell::from(bloat),
                Cell::from(Span::styled(
                    dash(&r.server),
                    Style::new().fg(theme::text()),
                )),
                Cell::from(Span::styled(
                    dash(&r.network),
                    Style::new().fg(theme::accent()),
                )),
                Cell::from(Span::styled(
                    dash(&r.medium),
                    Style::new().fg(theme::text()),
                )),
                Cell::from(Span::styled(idle_load, Style::new().fg(theme::text()))),
            ];
            cells.truncate(ncols);
            Row::new(cells).style(row_style(first + i == sel, false))
        });
    let widths: Vec<Constraint> = widths.iter().map(|w| Constraint::Length(*w)).collect();
    f.render_widget(Table::new(rows, widths).header(header), area);
}

/// Who owns the selected address: the registry's answer, so a bad hop can be
/// pinned on an organisation. Structured fields from RDAP; raw text when the
/// system `whois` had to answer instead.
/// The [c] scan: which protocols this network lets out, one row per check.
fn egress_overlay(f: &mut Frame, s: &AppState, area: Rect) {
    use crate::collectors::egress::Outcome;

    // Rows first, widths second: the result column is sized to the labels
    // actually on screen — padding it for the widest *possible* label left a
    // gulf between the results and the notes whenever everything was open.
    struct Row {
        name: String,
        target: String,
        label: String,
        color: Color,
        note: String,
    }
    let rows: Vec<Row> = match &s.egress {
        None => Vec::new(),
        Some(scan) => scan
            .results
            .iter()
            .map(|r| {
                // A timeout to a host that answers on some other port is the
                // network filtering that port, not the host being down.
                let host_up = matches!(r.outcome, Outcome::Blocked)
                    && scan.results.iter().any(|o| {
                        o.check.host == r.check.host
                            && o.check.port != r.check.port
                            && matches!(o.outcome, Outcome::Open(_) | Outcome::Refused)
                    });
                let (label, color) = match &r.outcome {
                    Outcome::Pending => (r.outcome.label(), theme::dim()),
                    Outcome::Open(_) => (r.outcome.label(), Color::Green),
                    Outcome::Refused => (r.outcome.label(), theme::warn()),
                    Outcome::Blocked if host_up => (
                        "FILTERED (host answers on other ports)".to_string(),
                        Color::Red,
                    ),
                    Outcome::Blocked => (r.outcome.label(), Color::Red),
                    Outcome::Error(_) => (r.outcome.label(), theme::warn()),
                };
                Row {
                    name: r.check.name.clone(),
                    target: format!("{}:{}/{}", r.check.host, r.check.port, r.check.proto),
                    label,
                    color,
                    note: r.check.note.clone(),
                }
            })
            .collect(),
    };

    let name_w = rows.iter().map(|r| r.name.len()).max().unwrap_or(5).max(5);
    let ref_w = rows
        .iter()
        .map(|r| r.target.len())
        .max()
        .unwrap_or(9)
        .max(9);
    let res_w = rows
        .iter()
        .map(|r| r.label.chars().count())
        .max()
        .unwrap_or(6)
        .max("result".len());
    let note_w = rows
        .iter()
        .map(|r| r.note.len())
        .max()
        .unwrap_or(0)
        .max("why it matters".len());

    // The box takes what the columns need, up to the terminal; when that is
    // not enough, the notes wrap inside their own column rather than spilling
    // to the left margin.
    let indent = 1 + name_w + 2 + ref_w + 2 + res_w + 2;
    let width = ((indent + note_w + 4) as u16)
        .min(area.width.saturating_sub(2))
        .max(40.min(area.width));
    // Border + 1-column padding each side.
    let text_w = width.saturating_sub(4) as usize;

    let dim = Style::new().fg(theme::dim());
    let mut lines: Vec<Line> = Vec::new();
    match &s.egress {
        None => lines.push(Line::from(Span::styled(" starting scan…", dim))),
        Some(scan) => {
            lines.push(Line::from(vec![
                Span::styled(format!(" {:<name_w$}  ", "check"), dim),
                Span::styled(format!("{:<ref_w$}  ", "reference"), dim),
                Span::styled(format!("{:<res_w$}  ", "result"), dim),
                Span::styled("why it matters", dim),
            ]));
            for r in &rows {
                lines.extend(column_lines(
                    vec![
                        Span::styled(
                            format!(" {:<name_w$}  ", r.name),
                            Style::new().fg(theme::bright()),
                        ),
                        Span::styled(
                            format!("{:<ref_w$}  ", r.target),
                            Style::new().fg(theme::text()),
                        ),
                        Span::styled(
                            format!("{:<res_w$}  ", r.label),
                            Style::new().fg(r.color).bold(),
                        ),
                    ],
                    &r.note,
                    dim,
                    indent,
                    text_w,
                ));
            }
            lines.push(Line::from(""));
            let summary = if scan.running {
                "scanning… each row updates as it answers".to_string()
            } else {
                match scan.blocked() {
                    0 => "nothing filtered — every protocol tried gets out".to_string(),
                    n => format!(
                        "{n} filtered — this network blocks some outbound traffic (port 25 alone is normal on home ISPs)"
                    ),
                }
            };
            let style = Style::new().fg(if scan.running {
                theme::dim()
            } else {
                theme::bright()
            });
            for chunk in wrap_words(&summary, text_w.saturating_sub(1)) {
                lines.push(Line::from(Span::styled(format!(" {chunk}"), style)));
            }
        }
    }
    let max_h = area.height.max(1);
    let h = ((lines.len() as u16) + 2).clamp(5.min(max_h), max_h);
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width,
        height: h,
    };
    f.render_widget(Clear, rect);
    let outer = Block::bordered()
        .padding(Padding::new(1, 1, 0, 0))
        .title(Span::styled(
            " octomon · outbound reachability ",
            Style::new().bold(),
        ))
        .title_bottom(Span::styled(
            " r rescan · press c or Esc to close ",
            Style::new().fg(theme::dim()),
        ))
        .border_style(Style::new().fg(theme::accent()));
    let inner = outer.inner(rect);
    f.render_widget(outer, rect);
    // Pre-wrapped into columns above; Paragraph wrap would break the indents.
    f.render_widget(Paragraph::new(lines), inner);
}

/// The whois overlay's content at a given box width — shared by the draw and
/// by the exact scroll clamp in the input handler.
fn whois_lines(w: &crate::app::Whois, width: u16) -> Vec<Line<'static>> {
    let mut lines: Vec<Line> = Vec::new();
    let key = |k: &str| Span::styled(format!("{k:<12}"), Style::new().fg(theme::accent()));
    lines.push(Line::from(vec![
        key("address"),
        Span::styled(w.addr.to_string(), Style::new().fg(theme::bright()).bold()),
    ]));
    if w.running {
        lines.push(Line::from(Span::styled(
            "looking up…",
            Style::new().fg(theme::dim()),
        )));
    } else if let Some(e) = &w.error {
        // Wrapped: the reason is the useful part and it can be long.
        let text_w = (width as usize).saturating_sub(4).max(20);
        for chunk in wrap_words(&format!("lookup failed — {e}"), text_w) {
            lines.push(Line::from(Span::styled(chunk, Style::new().fg(Color::Red))));
        }
    } else if !w.fields.is_empty() {
        // Wrap long values (remarks, ranges) under the key column rather than
        // letting the paragraph wrap them back to column zero.
        let val_w = (width as usize).saturating_sub(4 + 12).max(20);
        for (k, v) in &w.fields {
            let mut first = true;
            for chunk in wrap_words(v, val_w) {
                lines.push(Line::from(vec![
                    if first { key(k) } else { key("") },
                    Span::styled(chunk, Style::new().fg(theme::bright())),
                ]));
                first = false;
            }
        }
    } else if !w.raw.is_empty() {
        for l in &w.raw {
            lines.push(Line::from(Span::styled(
                l.clone(),
                Style::new().fg(theme::text()),
            )));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "the registry had nothing to say about this address",
            Style::new().fg(theme::dim()),
        )));
    }
    if !w.source.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("source: {}", w.source),
            Style::new().fg(theme::dim()),
        )));
    }
    lines
}

fn whois_overlay(f: &mut Frame, s: &AppState, area: Rect) {
    let Some(w) = s.whois.as_ref() else {
        return;
    };
    let width = 84u16.min(area.width);
    let lines = whois_lines(w, width);

    let max_h = (area.height * 4 / 5).max(1);
    let h = ((lines.len() as u16) + 2)
        .clamp(5.min(max_h), max_h)
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
            Style::new().fg(theme::dim()),
        ))
        .border_style(Style::new().fg(theme::accent()));
    let inner = outer.inner(rect);
    f.render_widget(outer, rect);
    f.render_widget(Paragraph::new(shown), inner);
}

/// Exact upper bounds for the scrollable overlays' offsets, computed with
/// the same geometry the draws use, so ↓ can never run the counter past the
/// real bottom (which used to demand as many ↑ presses to come back).
pub fn routes_scroll_cap(s: &AppState, term_h: u16) -> usize {
    let lines = s.routes.as_ref().map_or(1, |r| r.len().max(1));
    let max_h = (term_h * 4 / 5).max(1);
    let h = (lines as u16)
        .saturating_add(2)
        .clamp(5.min(max_h), max_h)
        .min(term_h);
    lines.saturating_sub(h.saturating_sub(2) as usize)
}

pub fn whois_scroll_cap(s: &AppState, term_w: u16, term_h: u16) -> usize {
    let Some(w) = s.whois.as_ref() else { return 0 };
    let lines = whois_lines(w, 84u16.min(term_w)).len();
    let max_h = (term_h * 4 / 5).max(1);
    let h = (lines as u16)
        .saturating_add(2)
        .clamp(5.min(max_h), max_h)
        .min(term_h);
    lines.saturating_sub(h.saturating_sub(2) as usize)
}

pub fn triage_scroll_cap(s: &AppState, term_w: u16, term_h: u16) -> usize {
    let widest = triage_lines(s, usize::MAX / 2)
        .iter()
        .map(|l| l.width())
        .max()
        .unwrap_or(60) as u16;
    let max_w = term_w.saturating_sub(2).max(1);
    let w = (widest + 4).clamp(78.min(max_w), max_w);
    let text_w = w.saturating_sub(4).max(1) as usize;
    let lines = triage_lines(s, text_w).len();
    let visible = (lines as u16 + 2).min(term_h).saturating_sub(2) as usize;
    lines.saturating_sub(visible)
}

/// The OS routing table, verbatim ([T]): what the kernel actually does with a
/// packet. Deliberately unparaphrased — split-tunnel 0.0.0.0/1 overrides, a
/// missing default, and interface-scoped routes are exactly the details a
/// summary would smooth away.
fn routes_overlay(f: &mut Frame, s: &AppState, area: Rect) {
    let raw: &[String] = match s.routes.as_deref() {
        Some(lines) => lines,
        None => &[],
    };
    let mut lines: Vec<Line> = Vec::new();
    if s.routes.is_none() {
        lines.push(Line::from(Span::styled(
            "reading the routing table…",
            Style::new().fg(theme::dim()),
        )));
    } else {
        for l in raw {
            // Column headers and section titles get the emphasis; entries the
            // body colour. `route print` (Windows) and netstat both start
            // sections with a non-indented word.
            let header = l.ends_with(':')
                || l.starts_with("Destination")
                || l.starts_with("Internet")
                || l.starts_with("Routing tables")
                || l.starts_with('=');
            lines.push(Line::from(Span::styled(
                l.clone(),
                if header {
                    Style::new().fg(theme::bright()).bold()
                } else {
                    Style::new().fg(theme::text())
                },
            )));
        }
    }

    let width = ((lines.iter().map(|l| l.width()).max().unwrap_or(60) as u16) + 4)
        .clamp(60.min(area.width), area.width);
    let max_h = (area.height * 4 / 5).max(1);
    let h = ((lines.len() as u16) + 2)
        .clamp(5.min(max_h), max_h)
        .min(area.height);
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width,
        height: h,
    };
    let visible = rect.height.saturating_sub(2) as usize;
    let first = s.routes_scroll.min(lines.len().saturating_sub(visible));
    let below = lines.len().saturating_sub(first + visible);
    let total = lines.len();
    let shown: Vec<Line> = lines.into_iter().skip(first).collect();

    f.render_widget(Clear, rect);
    let mut title = " octomon · routing table ".to_string();
    if first > 0 || below > 0 {
        title.push_str(&format!("(↑{first} ↓{below}) "));
    }
    let outer = Block::bordered()
        .padding(Padding::new(1, 1, 0, 0))
        .title(Span::styled(title, Style::new().bold()))
        .title_bottom(Span::styled(
            " ↑↓ scroll · r re-reads · press T or Esc to close ",
            Style::new().fg(theme::dim()),
        ))
        .border_style(Style::new().fg(theme::accent()));
    let inner = outer.inner(rect);
    f.render_widget(outer, rect);
    // The scrollbar earns its column only when there is somewhere to go.
    let body = scroll_cue(f, inner, total, first, visible);
    f.render_widget(Paragraph::new(shown), body);
}

/// Greedy word wrap to `width` columns. A word wider than a whole line — a
/// Windows path, a comma-joined address list — is split hard at the width:
/// these wrapped strings land in aligned columns, where one over-long token
/// overflowing its column would defeat the wrap entirely.
fn wrap_words(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut cur_w = 0usize;
    for word in text.split_whitespace() {
        let chars: Vec<char> = word.chars().collect();
        for piece in chars.chunks(width) {
            if cur_w != 0 && cur_w + 1 + piece.len() > width {
                out.push(std::mem::take(&mut cur));
                cur_w = 0;
            }
            if cur_w != 0 {
                cur.push(' ');
                cur_w += 1;
            }
            cur.extend(piece.iter());
            cur_w += piece.len();
        }
    }
    if !cur.is_empty() || out.is_empty() {
        out.push(cur);
    }
    out
}

/// Text wrapped into its own column: `prefix` spans open the first line, and
/// continuation lines are indented by `indent` so the text never wanders
/// under the label/timestamp columns to its left. `indent` should equal the
/// prefix's printed width; `width` is the whole line's budget.
fn column_lines(
    prefix: Vec<Span<'static>>,
    text: &str,
    style: Style,
    indent: usize,
    width: usize,
) -> Vec<Line<'static>> {
    let avail = width.saturating_sub(indent).max(8);
    let mut prefix = Some(prefix);
    // Text that fits is passed through untouched: wrapping goes via
    // split_whitespace, which would collapse deliberate alignment runs
    // ("after:  ch 149") even when no wrap was needed.
    let chunks = if text.chars().count() <= avail {
        vec![text.to_string()]
    } else {
        wrap_words(text, avail)
    };
    chunks
        .into_iter()
        .map(|chunk| match prefix.take() {
            Some(mut spans) => {
                spans.push(Span::styled(chunk, style));
                Line::from(spans)
            }
            None => Line::from(vec![
                Span::raw(" ".repeat(indent)),
                Span::styled(chunk, style),
            ]),
        })
        .collect()
}

/// Every stored network location with its learned baseline: what "normal"
/// means at each place this machine has been.
fn locations_overlay(f: &mut Frame, s: &AppState, area: Rect) {
    let h = (area.height * 4 / 5).max(8.min(area.height));
    // Four lines per location: name, stats, history, and a separating blank.
    let visible = (h.saturating_sub(2) as usize) / 4;

    let mut lines: Vec<Line> = Vec::new();
    // The list is what is on disk when the overlay opened, plus the network
    // we are on *now* if it isn't there yet — a baseline is only written
    // after its first healthy minute, and the overlay may be open across a
    // network change. Shown first, as "learning", rather than missing.
    let merged = s.locations_view();
    match &merged {
        None => lines.push(Line::from(Span::styled(
            "loading…",
            Style::new().fg(theme::dim()),
        ))),
        Some(all) if all.is_empty() => {
            lines.push(Line::from(Span::styled(
                "no locations learned yet — baselines build up during healthy minutes",
                Style::new().fg(theme::dim()),
            )));
        }
        Some(all) => {
            // `locations_sel` is the cursor; scroll just enough to keep it on
            // screen, and only when there is somewhere to scroll to.
            let sel = s.locations_sel.min(all.len().saturating_sub(1));
            let max_first = all.len().saturating_sub(visible.max(1));
            let first = sel.saturating_sub(visible.max(1) - 1).min(max_first);
            // A latency normal that never got a single reply is not "still
            // learning": when the learned loss for that path sits at ~100%
            // (Azure VMs and some hotel networks drop ICMP wholesale as
            // policy), say what is known instead of an eternal dash.
            let ms = |v: Option<f64>, loss: Option<f64>| match v {
                Some(x) => format!("~{x:.0}ms"),
                None if loss.is_some_and(|l| l >= 90.0) => "no ICMP".into(),
                None => "—".into(),
            };
            // The stats render in fixed-width slots (label dim, value plain)
            // so the entries line up into scannable columns instead of each
            // row being its own dot-separated ribbon.
            // The trailing space is part of the slot, so a value that fills
            // its width still can't press against whatever follows.
            let slot = |label: &str, val: String, w: usize| -> Vec<Span<'static>> {
                vec![
                    Span::styled(format!("{label} "), Style::new().fg(theme::dim())),
                    Span::styled(format!("{val:<w$} "), Style::new().fg(theme::text())),
                ]
            };
            for (i, (key, b)) in all.iter().enumerate().skip(first).take(visible.max(1)) {
                let current = s.baseline_key.as_deref() == Some(key.as_str());
                let selected = i == sel;
                let name_style = if selected {
                    Style::new().fg(Color::Black).bg(Color::Cyan).bold()
                } else {
                    Style::new().fg(theme::bright()).bold()
                };
                let mut name_row = vec![Span::styled(
                    format!("{}{}", if selected { "▶ " } else { "  " }, b.display_name()),
                    name_style,
                )];
                if b.name.is_some() && b.name.as_deref() != Some(&b.label) {
                    name_row.push(Span::styled(
                        format!("  ({})", b.label),
                        Style::new().fg(theme::dim()),
                    ));
                }
                // The same LAN over Wi-Fi and over a cable is two entries;
                // the medium is what tells them apart. The current network's
                // entry may not have folded a minute yet — use the live
                // medium for it rather than show nothing.
                let medium = if !b.medium.is_empty() {
                    b.medium.clone()
                } else if current && s.netinfo.medium != LinkMedium::Unknown {
                    s.netinfo.medium.label().to_string()
                } else {
                    String::new()
                };
                if !medium.is_empty() {
                    // "Wi-Fi (wireless)" earns its parenthetical elsewhere;
                    // here one word per entry keeps the name row quiet.
                    let short = medium.split(" (").next().unwrap_or(&medium);
                    name_row.push(Span::styled(
                        format!("  · {short}"),
                        Style::new().fg(theme::text()),
                    ));
                }
                if current {
                    name_row.push(Span::styled(
                        "  ● current",
                        Style::new().fg(theme::accent()).bold(),
                    ));
                } else if let Some(local) = b
                    .last_seen
                    .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
                    .map(|t| t.with_timezone(&chrono::Local))
                {
                    // The slot "● current" fills on the active network: for
                    // every other entry, when this machine last sat on it.
                    // (A baseline file from before the field existed simply
                    // has no date, and gets no slot.)
                    name_row.push(Span::styled(
                        format!("  · seen {}", local.format("%Y-%m-%d")),
                        Style::new().fg(theme::dim()),
                    ));
                }
                // Nothing folded in yet — freshly seen, or just deleted and
                // re-added blank. Said loudly: the dashes below look broken
                // otherwise.
                if b.samples == 0 {
                    name_row.push(Span::styled(
                        "  · learning from scratch",
                        Style::new().fg(theme::warn()).bold(),
                    ));
                }
                lines.push(Line::from(name_row));
                // Every slot appears in every row ("—" when unlearned), so
                // the numbers form columns the eye can walk vertically.
                let mut stats: Vec<Span> = vec![Span::raw("  ")];
                stats.extend(slot("gateway", ms(b.gateway_ms, b.gateway_loss_pct), 7));
                stats.extend(slot("internet", ms(b.anchor_ms, b.anchor_loss_pct), 7));
                stats.extend(slot("tcp", ms(b.anchor_tcp_ms, None), 6));
                stats.extend(slot("web", ms(b.web_ttfb_ms, None), 6));
                stats.extend(slot("DNS", ms(b.dns_ms, None), 6));
                stats.extend(slot(
                    "rssi",
                    b.rssi_dbm
                        .map(|r| format!("{r:.0}dBm"))
                        .unwrap_or_else(|| "—".into()),
                    6,
                ));
                stats.extend(slot(
                    "speed",
                    match (b.down_mbps, b.up_mbps) {
                        (Some(d), Some(u)) => {
                            format!("{}↓/{}↑", fmt_speed_compact(d), fmt_speed_compact(u))
                        }
                        _ => "—".into(),
                    },
                    11,
                ));
                stats.push(Span::styled(
                    format!("{} healthy", crate::util::fmt_minutes(b.samples as u64)),
                    Style::new().fg(theme::dim()),
                ));
                lines.push(Line::from(stats));
                // What has gone wrong here lately, if anything has.
                let h = crate::history::summarise(&s.history, key, crate::history::WINDOW_DAYS);
                lines.push(Line::from(Span::styled(
                    format!("  {}", h.line()),
                    Style::new().fg(if h.outages > 0 {
                        theme::warn()
                    } else {
                        theme::dim()
                    }),
                )));
                lines.push(Line::from(""));
            }
        }
    }

    // As wide as the widest line wants (the stats line carries a lot), up to
    // nearly the terminal; never narrower than the footer hint needs.
    let widest = lines.iter().map(|l| l.width()).max().unwrap_or(60) as u16;
    // Floor gives way below 86 columns — crossed clamp bounds panic.
    let max_w = area.width.saturating_sub(2).max(1);
    let w = (widest + 4).clamp(84.min(max_w), max_w);
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };

    let total = merged.as_ref().map(Vec::len).unwrap_or(0);
    f.render_widget(Clear, rect);
    let outer = Block::bordered()
        .padding(Padding::new(1, 1, 0, 0))
        .title(Span::styled(
            format!(" octomon · locations ({total}) "),
            Style::new().bold(),
        ))
        .title_bottom(Span::styled(
            " ↑↓ select · Enter renames · d deletes · press L or Esc to close ",
            Style::new().fg(theme::dim()),
        ))
        .border_style(Style::new().fg(theme::accent()));
    let inner = outer.inner(rect);
    f.render_widget(outer, rect);
    f.render_widget(Paragraph::new(lines), inner);
}

/// The octomon mark in half-block art, coloured like the logo: green dome and
/// legs, the sixth leg amber (the fault arm), red eyes. 18 columns, 10 rows.
fn welcome_art() -> Vec<Line<'static>> {
    let g = Style::new().fg(Color::Green);
    let a = Style::new().fg(theme::warn());
    let r = Style::new().fg(Color::Red);
    let eyes = || {
        Line::from(vec![
            Span::styled(" ████", g),
            Span::styled("██", r),
            Span::styled("████", g),
            Span::styled("██", r),
            Span::styled("████ ", g),
        ])
    };
    let legs_long = || {
        Line::from(vec![
            Span::styled(" █ █ █ █ █ ", g),
            Span::styled("█", a),
            Span::styled(" █ █  ", g),
        ])
    };
    vec![
        Line::from(Span::styled("     ▄▄▄▄▄▄▄▄     ", g)),
        Line::from(Span::styled("   ▄▄████████▄▄   ", g)),
        Line::from(Span::styled(" ▄██████████████▄ ", g)),
        eyes(),
        eyes(),
        Line::from(Span::styled(" ████████████████ ", g)),
        legs_long(),
        legs_long(),
        legs_long(),
        Line::from(vec![
            Span::styled("   █   █   ", g),
            Span::styled("█", a),
            Span::styled("   █  ", g),
        ]),
    ]
}

/// First-run welcome: what the tool answers, and that it learns each network's
/// normal. Shown once, then persisted away.
fn explainer_overlay(f: &mut Frame, area: Rect) {
    let head = |t: &str| Line::from(Span::styled(format!(" {t}"), Style::new().bold()));
    let bullet = |t: &str| {
        Line::from(vec![
            Span::styled(" ● ", Style::new().fg(theme::accent())),
            Span::styled(t.to_string(), Style::new().fg(theme::text())),
        ])
    };
    let dim = |t: &str| {
        Line::from(Span::styled(
            format!("   {t}"),
            Style::new().fg(theme::dim()),
        ))
    };

    let lines = vec![
        head("this tool helps you diagnose internet connectivity issues:"),
        Line::from(Span::styled(
            " \"Is it my machine, my local network, my ISP — or the internet?\"",
            Style::new().fg(theme::accent()).bold(),
        )),
        Line::from(""),
        bullet("a live analysis at the bottom left of the screen"),
        dim("press [y] anytime to see details"),
        bullet("the bar above it is the whole session, oldest left, now right"),
        dim("green fine, yellow degraded, red down; press [b] to walk it"),
        bullet("[e] shows a timeline of what changed and when"),
        bullet("octomon learns what normal looks like on each network you use"),
        dim("(gateway latency, DNS, signal — saved and judged per location,"),
        dim("Name this network with [N], e.g. \"Home\"."),
        bullet("everything stays on this machine"),
        Line::from(""),
        Line::from(Span::styled(
            " give it a minute or two to learn before trusting comparisons",
            Style::new().fg(theme::dim()).italic(),
        )),
    ];

    // Breathing room inside the border: 1 column each side, 1 row above and
    // below.
    let pad = Padding::new(1, 1, 1, 1);
    // With room to spare, the mark sits to the left of the text; on narrow
    // terminals the text keeps the whole box.
    const ART_W: u16 = 18;
    const ART_GAP: u16 = 2;
    let with_art = area.width >= 78 + 2 + ART_W + ART_GAP;
    let w = if with_art {
        78 + 2 + ART_W + ART_GAP
    } else {
        (78u16 + 2).min(area.width)
    };
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
            Style::new().fg(theme::dim()),
        ))
        .border_style(Style::new().fg(theme::accent()));
    let inner = outer.inner(rect);
    f.render_widget(outer, rect);
    if with_art {
        let cols = Layout::horizontal([
            Constraint::Length(ART_W),
            Constraint::Length(ART_GAP),
            Constraint::Min(0),
        ])
        .split(inner);
        let art = welcome_art();
        // The mark centres vertically against the text column.
        let pad_top = inner.height.saturating_sub(art.len() as u16) / 2;
        let mut padded: Vec<Line> = (0..pad_top).map(|_| Line::from("")).collect();
        padded.extend(art);
        f.render_widget(Paragraph::new(padded), cols[0]);
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), cols[2]);
    } else {
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }
}

/// The session timeline, newest first: what changed and when. This is the
/// retroactive answer to "what happened during that call ten minutes ago?"
fn events_overlay(f: &mut Frame, s: &AppState, area: Rect) {
    // Nearly the whole screen: event messages (paths, resolver lists) are the
    // longest text octomon shows, and the panel exists to read them.
    let w = (area.width * 19 / 20).max(40.min(area.width));
    let h = (area.height * 9 / 10).max(6.min(area.height));
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };
    let visible = rect.height.saturating_sub(2) as usize;
    // Border and padding cost 4 columns; messages wrap inside their own
    // column, indented clear of the timestamp and category.
    let text_w = rect.width.saturating_sub(4) as usize;
    const INDENT: usize = 27; // " MM-DD HH:MM:SS  " + "{:<9} "

    let mut lines: Vec<Line> = Vec::new();
    if s.events.is_empty() {
        lines.push(Line::from(Span::styled(
            " no events yet — network changes and analysis findings land here",
            Style::new().fg(theme::dim()),
        )));
    }
    // Entries vary in height once wrapped, so take rows until the panel is
    // full rather than a fixed count of events.
    let mut taken = 0usize;
    for e in s.events.iter().rev().skip(s.events_scroll) {
        if lines.len() >= visible {
            break;
        }
        // A cleared finding ("✓ … ended after …") is good news and reads as
        // such; a raise is a warning even when its class is only a note, so
        // ▲ never renders grey; plain events stay grey. User markers are
        // magenta — they exist to be found again while scanning this list.
        let marker = e.category == crate::app::EventCategory::Marker;
        let color = if marker {
            Color::Magenta
        } else if e.message.starts_with('✓') {
            Color::Green
        } else if e.message.starts_with('▲') && e.severity == Severity::Info {
            theme::warn()
        } else {
            severity_color(e.severity)
        };
        lines.extend(column_lines(
            vec![
                Span::styled(format!(" {}  ", e.when()), Style::new().fg(theme::dim())),
                Span::styled(
                    format!("{:<9} ", e.category.label()),
                    Style::new().fg(if marker {
                        Color::Magenta
                    } else {
                        theme::accent()
                    }),
                ),
            ],
            &e.message,
            Style::new().fg(color),
            INDENT,
            text_w,
        ));
        taken += 1;
    }

    let older = s
        .events
        .len()
        .saturating_sub(s.events_scroll)
        .saturating_sub(taken);
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
            " ↑↓ scroll · M mark · x export · C clear · press e or Esc to close ",
            Style::new().fg(theme::dim()),
        ))
        .border_style(Style::new().fg(theme::accent()));
    let inner = outer.inner(rect);
    f.render_widget(outer, rect);
    // The list is newest-first; the cue runs the same way (top = newest).
    let content = scroll_cue(f, inner, s.events.len(), s.events_scroll, taken.max(1));
    f.render_widget(Paragraph::new(lines), content);
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
                Style::new().fg(theme::text()),
            )));
        }
        lines.push(Line::from(""));
    }

    if !s.missing_tools.is_empty() {
        lines.push(Line::from(Span::styled(
            " ⚠ Missing tools",
            Style::new().fg(theme::warn()).bold(),
        )));
        for (name, provides, package) in &s.missing_tools {
            lines.push(Line::from(vec![
                Span::styled(format!(" {name:<13}"), Style::new().fg(theme::warn())),
                Span::styled((*provides).to_string(), Style::new().fg(theme::text())),
            ]));
            lines.push(Line::from(Span::styled(
                format!("               {package}"),
                Style::new().fg(theme::dim()),
            )));
        }
        lines.push(Line::from(""));
    }

    // Always worth stating, since it silently narrows per-process bandwidth.
    if let Some(note) = &s.privilege_notice {
        lines.push(Line::from(Span::styled(
            " ℹ Privileges",
            Style::new().fg(theme::accent()).bold(),
        )));
        lines.push(Line::from(Span::styled(
            format!(" {note}"),
            Style::new().fg(theme::text()),
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
            Style::new().fg(theme::dim()),
        ))
        .border_style(Style::new().fg(theme::warn()));
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
            // Fixed pair: black-on-yellow reads on either background.
            Style::new().fg(Color::Black).bg(Color::Yellow).bold(),
        ));
    }
    if s.fullscreen {
        left.push(Span::styled("  ⛶ full", Style::new().fg(theme::dim())));
    }
    // Recording is a background side effect that writes to disk, so it stays
    // visible for as long as it is running.
    match &s.log {
        Some(log) => {
            let secs = log.started.elapsed().as_secs();
            left.push(Span::raw("  "));
            left.push(Span::styled(
                " ● REC ",
                // Fixed pair: white-on-red reads on either background.
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
            Style::new().fg(theme::warn()),
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
        .track_style(Style::new().fg(theme::dim()))
        .thumb_style(Style::new().fg(theme::text()));
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
    let key = |k: &str| Span::styled(k.to_string(), Style::new().fg(theme::accent()));
    let txt = |t: &str| Span::styled(t.to_string(), Style::new().fg(theme::text()));
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
                key("[z]"),
                txt("oom "),
            ];
            if s.bw_view == BwView::Remotes && s.sub_pane == SubPane::Primary {
                v.extend([key("[W]"), txt("hois "), key("[a]"), txt("dd ")]);
            }
            if s.sub_pane == SubPane::Primary {
                v.extend([
                    key("[o]"),
                    txt(if follow_label(s).is_some() {
                        "unfollow "
                    } else {
                        "follow "
                    }),
                ]);
            }
            // Pin/unpin exist only where per-process attribution does.
            if s.sub_pane == SubPane::Primary && s.proc_status == ProcStatus::Supported {
                v.extend([key("[p]"), txt("in "), key("[u]"), txt("npin ")]);
            }
            // With the speed-test history under the cursor (the full-screen
            // pane or its zoom), curation is the action on offer.
            if s.sub_pane == SubPane::Secondary
                || (s.overlay == Overlay::Zoom && s.zoom_view == crate::app::ZoomView::Speedtests)
            {
                v.extend([key("[d]"), txt("elete ")]);
            }
            v.extend([key("[R]"), txt("eset "), key("[f]"), txt("ull ")]);
            v
        }
        Panel::NetInfo => {
            let mut v = vec![
                key("[r]"),
                txt("efresh "),
                key("[G]"),
                txt("rescan "),
                key("[N]"),
                txt("ame "),
                key("[L]"),
                txt("ocations "),
            ];
            // The address cursor only means something with addresses to
            // walk, and only while this pane (not the history) holds it.
            if s.sub_pane == SubPane::Primary && !s.netinfo_addrs().is_empty() {
                v.extend([key("[↑↓]"), txt("ip "), key("[W]"), txt("hois ")]);
            }
            v
        }
        Panel::Vitals => vec![],
    };
    spans.push(key("[?]"));
    spans.push(txt("help "));
    Line::from(spans)
}

fn footer(f: &mut Frame, s: &AppState, area: Rect) {
    let input_line = |prompt: &str, buffer: &str, hint: &str| {
        Line::from(vec![
            Span::styled(format!(" {prompt}"), Style::new().fg(theme::warn()).bold()),
            Span::styled(buffer.to_string(), Style::new().fg(theme::bright())),
            Span::styled("▏", Style::new().fg(theme::warn())),
            Span::styled(format!("   {hint}"), Style::new().fg(theme::dim())),
        ])
    };
    let line = if s.input_mode == InputMode::AddTarget {
        input_line(
            "add target (IP or DNS): ",
            &s.input_buffer,
            "[Enter] add  [Esc] cancel",
        )
    } else if s.input_mode == InputMode::AddIperf3 {
        input_line(
            "add iPerf3 server (Name=host[:port]): ",
            &s.input_buffer,
            "[Enter] save  [Esc] cancel",
        )
    } else if s.input_mode == InputMode::NameNetwork {
        input_line(
            "name this network (Home, Office…): ",
            &s.input_buffer,
            "[Enter] save  [Esc] cancel",
        )
    } else if s.input_mode == InputMode::RenameLocation {
        input_line(
            "rename location (blank clears): ",
            &s.input_buffer,
            "[Enter] save  [Esc] cancel",
        )
    } else if s.input_mode == InputMode::TalkersFilter {
        input_line(
            "filter talkers (name, pid, address): ",
            &s.input_buffer,
            "[Enter] keep  [Esc] clear",
        )
    } else if s.input_mode == InputMode::Marker {
        input_line(
            "mark event (what just happened?): ",
            &s.input_buffer,
            "[Enter] add  [Esc] cancel",
        )
    } else if s.input_mode == InputMode::ConfirmReset {
        // Red, not the usual yellow: this one deletes everything.
        Line::from(vec![
            Span::styled(
                " TOTAL RESET — deletes ALL config and stored data. type ERASE then Enter: ",
                Style::new().fg(Color::Red).bold(),
            ),
            Span::styled(s.input_buffer.clone(), Style::new().fg(theme::bright())),
            Span::styled("▏", Style::new().fg(Color::Red)),
            Span::styled("   [Esc] cancel", Style::new().fg(theme::dim())),
        ])
    } else if let Some(n) = &s.notice {
        Line::from(Span::styled(
            format!(" {n}"),
            Style::new().fg(theme::warn()),
        ))
    } else if let Some(line) = bar_readout(s, area.width) {
        // Walking the session bar takes over this line: while the cursor is
        // up, "how is it now" is not the question being asked.
        line
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

/// How a session cell is drawn: the verdict headline's own three colours, so
/// a red cell and a red footer mean the same thing, and a block that grows
/// taller as things get worse — the strip stays readable in a screenshot, on a
/// monochrome terminal, and to a reader who cannot separate red from green.
///
/// The glyphs come from the configured bar set, so a console without the
/// eighth-blocks gets the two levels it can draw rather than tofu.
fn session_cell(
    state: crate::session::SessionState,
    bars: &ratatui::symbols::bar::Set<'static>,
) -> (&'static str, Color) {
    use crate::session::SessionState as S;
    match state {
        S::Unknown => (bars.one_eighth, theme::dim()),
        S::Healthy => (bars.half, Color::Green),
        S::Degraded => (bars.three_quarters, theme::warn()),
        S::Down => (bars.full, Color::Red),
    }
}

/// Whether the session strip earns its row: there has to be a session to draw
/// and room to draw it in. A short terminal spends the row on data, and a
/// narrow one would be left with a handful of blocks that overstate whatever
/// they landed on.
fn session_strip_fits(s: &AppState, area: Rect) -> bool {
    !s.session.is_empty() && area.height >= 12 && area.width as usize >= MIN_STRIP_CELLS
}

/// Fewer cells than this and each one covers so much of the session that the
/// strip stops being a shape and becomes a rumour.
const MIN_STRIP_CELLS: usize = 16;

/// The whole session as one bar across the bottom of the screen, oldest at the
/// left, now at the right. Coarse on purpose: it answers "how has this
/// connection been?", a question none of the live panels can reach once their
/// buffers roll over.
///
/// It keeps its span rather than its resolution, so the bar covers the entire
/// run — five minutes or nine hours — without ever scrolling.
///
/// No label and no clock: it sits directly above the analysis line, in the
/// analysis line's own colours, and edge to edge it reads as what it is. The
/// header already counts how long the run has been.
fn session_strip(f: &mut Frame, s: &AppState, area: Rect) {
    let cells = session_slices(s, area.width);
    // A session younger than the terminal is wide grows leftward from the
    // right edge, the way the hop traces do: "now" stays put under the
    // analysis line it belongs to, instead of marching across the screen for
    // the first two minutes and stopping.
    let mut spans = Vec::new();
    let blank = (area.width as usize).saturating_sub(cells.len());
    if blank > 0 {
        spans.push(Span::raw(" ".repeat(blank)));
    }
    let cursor = s.bar_cursor.map(|c| c.min(cells.len().saturating_sub(1)));
    // Runs of one state merge into a single span: a whole-session bar is
    // mostly one state, and a span per cell would be hundreds of them. The
    // cursor breaks its run so the column under it can be picked out.
    for (state, start, len) in fold_runs(&cells) {
        let (glyph, color) = session_cell(state, &s.bar_set);
        let style = Style::new().fg(color);
        match cursor.filter(|c| (start..start + len).contains(c)) {
            Some(c) => {
                let (before, after) = (c - start, start + len - c - 1);
                if before > 0 {
                    spans.push(Span::styled(glyph.repeat(before), style));
                }
                spans.push(Span::styled(glyph, style.add_modifier(Modifier::REVERSED)));
                if after > 0 {
                    spans.push(Span::styled(glyph.repeat(after), style));
                }
            }
            None => spans.push(Span::styled(glyph.repeat(len), style)),
        }
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// The bar's columns at the width it is drawn at — one place, so the cursor
/// keys and the draw can never disagree about which column is which.
pub fn session_slices(s: &AppState, width: u16) -> Vec<crate::session::Slice> {
    s.session.slices(width as usize)
}

/// The rightmost column index the bar cursor can hold, or `None` when there
/// is no bar to walk.
pub fn bar_cursor_cap(s: &AppState, term_w: u16, term_h: u16) -> Option<usize> {
    let area = Rect {
        x: 0,
        y: 0,
        width: term_w,
        height: term_h,
    };
    if !session_strip_fits(s, area) {
        return None;
    }
    session_slices(s, term_w).len().checked_sub(1)
}

/// Consecutive columns of the same state as (state, first column, length).
fn fold_runs(cells: &[crate::session::Slice]) -> Vec<(crate::session::SessionState, usize, usize)> {
    let mut out: Vec<(crate::session::SessionState, usize, usize)> = Vec::new();
    for (i, c) in cells.iter().enumerate() {
        match out.last_mut() {
            Some((state, _, n)) if *state == c.state => *n += 1,
            _ => out.push((c.state, i, 1)),
        }
    }
    out
}

/// What the column under the bar cursor stands for: which minutes, how they
/// read, and what was wrong with them.
///
/// The bar on its own says *that* something happened and roughly when. This is
/// the answer to the question it provokes, and the way into the timeline for
/// the rest of the answer.
fn bar_readout(s: &AppState, width: u16) -> Option<Line<'static>> {
    let cursor = s.bar_cursor?;
    let slices = session_slices(s, width);
    let slice = slices.get(cursor.min(slices.len().saturating_sub(1)))?;

    let clock = |ts: i64| {
        use chrono::{Local, TimeZone};
        Local
            .timestamp_opt(ts, 0)
            .single()
            .map(|t| t.format("%H:%M:%S").to_string())
            .unwrap_or_else(|| "—".into())
    };
    let (word, color) = match slice.state {
        crate::session::SessionState::Unknown => ("not measured", theme::dim()),
        crate::session::SessionState::Healthy => ("healthy", Color::Green),
        crate::session::SessionState::Degraded => ("degraded", theme::warn()),
        crate::session::SessionState::Down => ("down", Color::Red),
    };
    let mut spans = vec![
        Span::styled(
            format!(" {} → {}  ", clock(slice.from), clock(slice.to)),
            Style::new().fg(theme::text()),
        ),
        Span::styled(word.to_string(), Style::new().fg(color).bold()),
    ];
    if let Some(cause) = slice.cause {
        spans.push(Span::styled(
            format!(" · {}", cause.label()),
            Style::new().fg(theme::text()),
        ));
    }
    spans.push(Span::styled(
        "   ←→ move · ↵ timeline · Esc back",
        Style::new().fg(theme::dim()),
    ));
    Some(Line::from(spans))
}

/// The absolute performance grade as a footer span — the counterweight to a
/// green headline: "healthy" grades against this location's normal, this word
/// says what that normal is worth anywhere.
fn perf_span(s: &AppState) -> Option<Span<'static>> {
    use crate::verdict::PerfGrade;
    let p = s.verdict.triage.performance.as_ref()?;
    let color = match p.grade {
        PerfGrade::Excellent | PerfGrade::Good => Color::Green,
        PerfGrade::Fair => theme::warn(),
        PerfGrade::Poor => Color::Red,
    };
    Some(Span::styled(
        format!(" · performance {}", p.grade.label()),
        Style::new().fg(color),
    ))
}

/// The always-visible one-liner: the verdict engine's headline. Full detail —
/// every rung and finding — is one keypress away on [y], so this stays terse.
fn verdict_line(s: &AppState) -> Line<'static> {
    let hint = Span::styled("  [y] analysis", Style::new().fg(theme::dim()));
    match &s.verdict.current {
        Verdict::Insufficient(reason) => Line::from(vec![
            Span::styled(format!(" ● {reason}"), Style::new().fg(theme::dim())),
            hint,
        ]),
        Verdict::Healthy => {
            let mut spans = vec![Span::styled(
                " ● connection healthy",
                Style::new().fg(Color::Green),
            )];
            spans.extend(perf_span(s));
            spans.push(hint);
            Line::from(spans)
        }
        Verdict::Problems(findings) => {
            let top = &findings[0];
            // "Degraded but usable" is note-class (so the baseline can learn)
            // but is the connection's real state, not a footnote — it gets a
            // yellow headline of its own instead of "connection healthy".
            if top.cause == crate::verdict::Cause::UsableDegraded {
                let mut spans = vec![Span::styled(
                    " ● degraded but usable",
                    Style::new().fg(theme::warn()),
                )];
                spans.push(Span::styled(
                    " · heavy loss, web traffic getting through".to_string(),
                    Style::new().fg(theme::text()),
                ));
                if let Some(d) = active_for(top) {
                    spans.push(Span::styled(
                        format!(" · {d}"),
                        Style::new().fg(theme::text()),
                    ));
                }
                spans.extend(perf_span(s));
                spans.push(hint);
                return Line::from(spans);
            }
            // Info-class findings are notes, not problems: the line stays green
            // rather than crying wolf over a busy CPU or a weak-but-working radio.
            if top.severity == Severity::Info {
                let n = findings.len();
                let mut spans = vec![
                    Span::styled(" ● connection healthy", Style::new().fg(Color::Green)),
                    Span::styled(
                        format!(
                            " · {n} note{}: {}",
                            if n == 1 { "" } else { "s" },
                            top.summary
                        ),
                        Style::new().fg(theme::text()),
                    ),
                ];
                spans.extend(perf_span(s));
                spans.push(hint);
                return Line::from(spans);
            }
            // Confidence wording lives in the [y] analysis overlay; the
            // headline keeps just the claim.
            let color = severity_color(top.severity);
            let mut spans = vec![Span::styled(
                format!(" ▲ {}", top.summary),
                Style::new().fg(color).bold(),
            )];
            // How long: the difference between a blip and an outage.
            if let Some(d) = active_for(top) {
                spans.push(Span::styled(
                    format!(" · {d}"),
                    Style::new().fg(theme::text()),
                ));
            }
            if findings.len() > 1 {
                spans.push(Span::styled(
                    format!("  (+{} more)", findings.len() - 1),
                    Style::new().fg(theme::warn()),
                ));
            }
            spans.push(hint);
            Line::from(spans)
        }
    }
}

/// "3m 12s" for a finding that has been active that long; `None` for the raw
/// (un-hysteresised) evaluation, which carries no start time — and for steady
/// findings (a tunnel in the path, an ICMP-dropping gateway), where the timer
/// would just count uptime.
fn active_for(f: &crate::verdict::Finding) -> Option<String> {
    if f.steady() {
        return None;
    }
    let since = f.since?;
    let d = since.elapsed();
    if d.as_secs() < 5 {
        return None; // just raised — "0s" adds nothing
    }
    Some(crate::verdict::fmt_duration(d))
}

fn severity_color(sev: Severity) -> Color {
    match sev {
        Severity::Down => Color::Red,
        Severity::Degraded => theme::warn(),
        Severity::Info => theme::text(),
    }
}

/// The triage ladder: every subsystem's status with its data — healthy rungs
/// included, so the verdict is auditable rather than oracular — then the active
/// findings with their evidence.
/// The analysis overlay's content at a given text width — shared by the
/// draw and by the exact scroll clamp in the input handler, so the offset
/// can never run past the real bottom.
fn triage_lines(s: &AppState, text_w: usize) -> Vec<Line<'static>> {
    let mut lines: Vec<Line> = Vec::new();

    let status_glyph = |st: RungStatus| match st {
        RungStatus::Ok => ("✓", Color::Green),
        RungStatus::Warn => ("~", theme::warn()),
        RungStatus::Bad => ("✗", Color::Red),
        RungStatus::Unknown => ("?", theme::dim()),
    };
    for r in &s.verdict.triage.rungs {
        let (glyph, color) = status_glyph(r.status);
        lines.extend(column_lines(
            vec![
                Span::styled(format!(" {glyph} "), Style::new().fg(color).bold()),
                Span::styled(
                    format!("{:<15}", r.area.label()),
                    Style::new().fg(theme::bright()),
                ),
            ],
            &r.detail,
            Style::new().fg(theme::text()),
            18,
            text_w,
        ));
    }

    // The background checks: things that are not a rung but a person wants
    // to see were done — clock, proxy, path MTU, NAT, DNS honesty.
    if !s.verdict.triage.checks.is_empty() {
        lines.push(Line::from(Span::styled(
            " checks",
            Style::new().fg(theme::bright()).bold(),
        )));
        for c in &s.verdict.triage.checks {
            let (glyph, color) = status_glyph(c.status);
            lines.extend(column_lines(
                vec![
                    Span::styled(format!(" {glyph} "), Style::new().fg(color).bold()),
                    Span::styled(format!("{:<15}", c.name), Style::new().fg(theme::bright())),
                ],
                &c.detail,
                Style::new().fg(theme::text()),
                18,
                text_w,
            ));
        }
    }

    // The absolute read, so "all green" cannot be mistaken for "fast":
    // the rungs grade against this location's normal, this line grades
    // the same numbers on a universal scale.
    if let Some(p) = &s.verdict.triage.performance {
        use crate::verdict::PerfGrade;
        let color = match p.grade {
            PerfGrade::Excellent | PerfGrade::Good => Color::Green,
            PerfGrade::Fair => theme::warn(),
            PerfGrade::Poor => Color::Red,
        };
        lines.push(Line::from(""));
        // Same column geometry as the rungs, so the readings line up.
        lines.extend(column_lines(
            vec![
                Span::styled(
                    format!("   {:<15}", "performance"),
                    Style::new().fg(theme::bright()).bold(),
                ),
                Span::styled(
                    format!("{} — ", p.grade.label()),
                    Style::new().fg(color).bold(),
                ),
            ],
            &p.detail,
            Style::new().fg(theme::text()),
            18,
            text_w,
        ));
    }

    lines.push(Line::from(""));
    // The record: is it always like this on this network? The summary packs
    // many segments; folded at its separators to a modest width so this one
    // line stops dictating how wide the whole box opens.
    if let Some(h) = s.history_summary()
        && h.episodes > 0
    {
        let mut rows: Vec<String> = vec![String::new()];
        for seg in h.line().split(" · ") {
            let cur = rows.last_mut().expect("starts non-empty");
            if !cur.is_empty() && cur.len() + 3 + seg.len() > 58 {
                rows.push(seg.to_string());
            } else {
                if !cur.is_empty() {
                    cur.push_str(" · ");
                }
                cur.push_str(seg);
            }
        }
        for (i, row) in rows.iter().enumerate() {
            let prefix = if i == 0 {
                vec![Span::styled(
                    " history ",
                    Style::new().fg(theme::bright()).bold(),
                )]
            } else {
                vec![Span::raw("         ")]
            };
            lines.extend(column_lines(
                prefix,
                row,
                Style::new().fg(theme::text()),
                9,
                text_w,
            ));
        }
        lines.push(Line::from(""));
    }
    match &s.verdict.current {
        Verdict::Insufficient(reason) => {
            lines.push(Line::from(Span::styled(
                format!(" {reason}"),
                Style::new().fg(theme::dim()),
            )));
        }
        Verdict::Healthy => {
            // On an ICMP-blackholed network "healthy" rests on web + DNS
            // evidence alone — say so, or the empty quality table and the
            // green verdict read as contradicting each other.
            let qualifier = if crate::verdict::icmp_blackholed(s) {
                " (judged on web + DNS — this network blocks ICMP)"
            } else {
                ""
            };
            lines.push(Line::from(Span::styled(
                format!(" no findings — connection looks healthy{qualifier}"),
                Style::new().fg(Color::Green),
            )));
        }
        Verdict::Problems(findings) => {
            lines.push(Line::from(Span::styled(
                " Findings",
                Style::new().fg(theme::bright()).bold(),
            )));
            for finding in findings {
                // Confidence stays internal (it drives the ranking); the
                // evidence lines below make the case in words instead.
                let mut head = column_lines(
                    vec![Span::styled(
                        " ▲ ",
                        Style::new().fg(severity_color(finding.severity)).bold(),
                    )],
                    &finding.summary,
                    Style::new().fg(severity_color(finding.severity)).bold(),
                    3,
                    text_w,
                );
                // Duration / symptom tags ride on the headline's last
                // line when they fit, and take their own line when not.
                let mut tags: Vec<Span> = Vec::new();
                if let Some(d) = active_for(finding) {
                    tags.push(Span::styled(
                        format!("  · for {d}"),
                        Style::new().fg(theme::text()),
                    ));
                }
                if finding.symptom {
                    tags.push(Span::styled(
                        "  · symptom of the above",
                        Style::new().fg(theme::dim()),
                    ));
                }
                if !tags.is_empty() {
                    let tags_w: usize = tags.iter().map(|t| t.width()).sum();
                    let last = head.last_mut().expect("column_lines is never empty");
                    if last.width() + tags_w <= text_w {
                        for t in tags {
                            last.push_span(t);
                        }
                    } else {
                        let mut spans = vec![Span::raw("   ")];
                        spans.extend(tags);
                        head.push(Line::from(spans));
                    }
                }
                lines.extend(head);
                for e in &finding.evidence {
                    lines.extend(column_lines(
                        vec![Span::raw("     ")],
                        e,
                        Style::new().fg(theme::dim()),
                        5,
                        text_w,
                    ));
                }
            }
        }
    }
    lines
}

fn triage_overlay(f: &mut Frame, s: &AppState, area: Rect) {
    // Built twice: once unwrapped to learn how wide the content wants to be,
    // then again wrapped to the width the box actually got — so every long
    // detail, headline and evidence line continues in its own column instead
    // of sliding under the glyph and label to its left.
    // As wide as the content wants, up to nearly the terminal: a finding's
    // headline with its duration should not wrap when there is room.
    let widest = triage_lines(s, usize::MAX / 2)
        .iter()
        .map(|l| l.width())
        .max()
        .unwrap_or(60) as u16;
    // The preferred floor gives way on a terminal too narrow to hold it —
    // clamp panics outright when its bounds cross.
    let max_w = area.width.saturating_sub(2).max(1);
    let w = (widest + 4).clamp(78.min(max_w), max_w);
    // Border + 1-column padding each side.
    let text_w = w.saturating_sub(4).max(1) as usize;
    let lines = triage_lines(s, text_w);
    let h = (lines.len() as u16 + 2).min(area.height);
    // Sit below centre rather than on it: the graphs the analysis is read
    // against live in the top half of the screen, and a centred box covers
    // exactly the part of them a person is looking at. Clamped so the box
    // never runs off the bottom.
    let centred_y = (area.height.saturating_sub(h)) / 2;
    let y = (centred_y + area.height / 5).min(area.height.saturating_sub(h));
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + y,
        width: w,
        height: h,
    };
    f.render_widget(Clear, rect);
    let overflows = lines.len() as u16 + 2 > area.height;
    let outer = Block::bordered()
        .padding(Padding::new(1, 1, 0, 0))
        .title(Span::styled(" octomon · analysis ", Style::new().bold()))
        .title_bottom(Span::styled(
            if overflows {
                " ↑↓ scroll · press y or Esc to close, e for past events "
            } else {
                " press y or Esc to close, e for past events "
            },
            Style::new().fg(theme::dim()),
        ))
        .border_style(Style::new().fg(theme::accent()));
    let inner = outer.inner(rect);
    f.render_widget(outer, rect);
    // Pre-wrapped above; Paragraph-level wrap would only mangle the indents.
    // More content than the box holds scrolls line-wise, cursor keys in the
    // handler, clamped here so the last page always fills the box.
    let total = lines.len();
    let visible = (inner.height as usize).max(1);
    let first = s.triage_scroll.min(total.saturating_sub(visible));
    let shown: Vec<Line> = lines.into_iter().skip(first).take(visible).collect();
    let content = scroll_cue(f, inner, total, first, shown.len().max(1));
    f.render_widget(Paragraph::new(shown), content);
}

fn block(title: &str, focused: bool) -> Block<'static> {
    let border = if focused {
        theme::accent()
    } else {
        theme::dim()
    };
    Block::bordered()
        .title(Span::styled(format!(" {title} "), Style::new().bold()))
        .border_style(Style::new().fg(border))
}

/// The numbers one probe family contributes to a quality-table row,
/// precomputed so ICMP (flat fields on `TargetStat`) and TCP (a
/// [`crate::app::Series`]) render through one code path with one set of
/// grading rules.
struct FamilyNums {
    last: Option<f64>,
    jitter: f64,
    st: crate::app::RttStats,
    loss: f64,
    now_loss: f64,
    stale: bool,
    rtt_ref: Option<f64>,
    loss_ref: Option<f64>,
    /// This family's wall of loss is the network's ICMP policy, not a fault
    /// (see `icmp_blackholed`) — excused readings render dim.
    excused: bool,
    /// False for a target this family never probes (TCP skips discovered
    /// hops): cells show a quiet placeholder instead of fake 0% loss.
    probed: bool,
}

/// The metric cells (`last avg p95 [max] jit loss`) for one family.
fn family_cells(v: &FamilyNums, dim_all: bool, with_max: bool) -> Vec<Cell<'static>> {
    let cell = |text: String, color: Color| {
        let c = if dim_all { theme::dim() } else { color };
        Cell::from(Span::styled(text, Style::new().fg(c)))
    };
    if !v.probed {
        let quiet = || cell("·".into(), theme::dim());
        let mut out = vec![quiet(), quiet(), quiet()];
        if with_max {
            out.push(quiet());
        }
        out.extend([quiet(), cell(String::new(), theme::dim())]);
        return out;
    }
    let excused_wall = v.excused && v.loss >= 99.0;
    let windowed = |x: Option<f64>| if v.stale { None } else { x };
    let stale_c = if excused_wall {
        theme::dim()
    } else {
        match crate::verdict::loss_grade(v.now_loss, v.loss_ref) {
            crate::verdict::RttGrade::Bad => Color::Red,
            crate::verdict::RttGrade::Warn => theme::warn(),
            crate::verdict::RttGrade::Good => theme::dim(),
        }
    };
    let rtt_c = |x: Option<f64>| match x {
        Some(ms) => rtt_color(ms, v.rtt_ref),
        None if v.stale => stale_c,
        None => theme::dim(),
    };
    let jit_color = if v.stale {
        stale_c
    } else if v.jitter < th::PERF_JITTER_STEPS_MS[1] {
        Color::Green
    } else if v.jitter < th::PERF_JITTER_STEPS_MS[2] {
        theme::warn()
    } else {
        Color::Red
    };
    let loss_color = if excused_wall {
        theme::dim()
    } else {
        match (
            crate::verdict::loss_grade(v.loss, v.loss_ref),
            crate::verdict::loss_grade(v.loss, None),
        ) {
            (crate::verdict::RttGrade::Good, crate::verdict::RttGrade::Good) => Color::Green,
            // "Good" only against this location's learned weather: usual,
            // not healthy. Dim says "expected here"; green would say
            // "fine", which 30% loss on a plane is not.
            (crate::verdict::RttGrade::Good, _) => theme::dim(),
            (crate::verdict::RttGrade::Warn, _) => theme::warn(),
            (crate::verdict::RttGrade::Bad, _) => Color::Red,
        }
    };
    // ↓ marks loss that is pure momentum: the recent probes are clean and
    // the figure is an ended incident draining out of the window.
    let aging = v.loss >= 0.5 && v.now_loss == 0.0;
    let mut out = vec![
        cell(
            fmt_ms(v.last),
            latency_color(v.last, 0.0, v.rtt_ref, v.loss_ref),
        ),
        cell(fmt_ms(windowed(v.st.mean)), rtt_c(windowed(v.st.mean))),
        cell(fmt_ms(windowed(v.st.p95)), rtt_c(windowed(v.st.p95))),
    ];
    if with_max {
        out.push(cell(fmt_ms(windowed(v.st.max)), rtt_c(windowed(v.st.max))));
    }
    out.push(cell(
        if v.stale {
            "—".into()
        } else {
            format!("{:.1}", v.jitter)
        },
        jit_color,
    ));
    out.push(cell(
        format!("{:.0}%{}", v.loss, if aging { "↓" } else { "" }),
        loss_color,
    ));
    out
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
        // Full-screen normally has room for the tall strip, but on a short
        // viewport those rows are better spent on the path views above,
        // which by then are rationing hop rows.
        (true, true) if inner.height < 40 => 4,
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
    // The whole network drops ICMP while the web answers (Azure VMs): every
    // ICMP row's 100% is the same non-signal, and neither red (nothing is
    // broken) nor green (nothing is *fine* — nothing is measured) tells the
    // truth. It also flips the split view's default family to TCP, so such a
    // network opens onto numbers instead of dashes.
    let blackholed = crate::verdict::icmp_blackholed(s);
    let family = s.quality_family.unwrap_or(if blackholed {
        crate::app::ProbeFamily::Tcp
    } else {
        crate::app::ProbeFamily::Icmp
    });
    // Full screen fits both families side by side; the max columns are the
    // least diagnostic (p95 already tells the tail story) and yield first on
    // narrower fullscreens — TCP's before ICMP's.
    let dual = s.fullscreen;
    let icmp_max = !dual || area.width >= 140;
    let tcp_max = dual && area.width >= 150;
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
                .fg(theme::accent())
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            Style::new().fg(theme::text()).bold()
        };
        Cell::from(Span::styled(txt, style))
    };
    let plain = |label: &str| {
        Cell::from(Span::styled(
            label.to_string(),
            Style::new().fg(theme::text()).bold(),
        ))
    };
    let divider = |label: &str| {
        Cell::from(Span::styled(
            label.to_string(),
            Style::new().fg(theme::accent()).bold(),
        ))
    };
    let mut header_cells = vec![Cell::from(""), hcell(0, "Target"), plain("Address")];
    // Split view: the metric headers describe whichever family is shown and
    // stay sortable. Dual (full screen): each family's group sits behind its
    // own labelled divider — the ICMP group keeps the sort; the tcp divider
    // carries a leading space so the groups don't run into each other.
    if dual {
        header_cells.push(divider("│ icmp"));
    }
    if dual || family == crate::app::ProbeFamily::Icmp {
        header_cells.extend([hcell(1, "last"), hcell(2, "avg"), hcell(3, "p95")]);
        if icmp_max {
            header_cells.push(hcell(4, "max"));
        }
        header_cells.extend([hcell(5, "jit"), hcell(6, "loss")]);
    } else {
        header_cells.extend([plain("last"), plain("avg"), plain("p95")]);
        if icmp_max {
            header_cells.push(plain("max"));
        }
        header_cells.extend([plain("jit"), plain("loss")]);
    }
    if dual {
        header_cells.push(divider("│ tcp"));
        header_cells.extend([hcell(7, "last"), hcell(8, "avg"), hcell(9, "p95")]);
        if tcp_max {
            header_cells.push(hcell(10, "max"));
        }
        header_cells.extend([hcell(11, "jit"), hcell(12, "loss")]);
    }
    let header = Row::new(header_cells);

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
        let icmp_loss = t.recent_loss_pct(n);
        // A mid-path router that never answers ICMP is not a fault — the
        // analysis already treats it that way — so it reads dim, not red.
        let dim_hop = t.is_path_hop() && icmp_loss >= th::LOSS_DOWN_PCT;
        // Every stat cell grades itself (see `family_cells`), so recovery
        // reads as the row greening from the left: `last` and the name turn
        // green the moment replies return, while p95/max/loss hold their
        // colour until the incident ages out of the window.
        let icmp = FamilyNums {
            last: t.last_rtt_ms,
            jitter: t.jitter_ms,
            st: t.stats(n),
            loss: icmp_loss,
            // Loss as it stands *right now*: the detection-sized slice of
            // the window, which lets the row start relaxing before the
            // windowed figures do.
            now_loss: t.recent_loss_pct(th::RECENT.min(n)),
            stale: t.stats_stale(n),
            rtt_ref: crate::verdict::rtt_reference(t, s),
            loss_ref: crate::verdict::loss_reference(t, s),
            excused: blackholed,
            probed: true,
        };
        let tcp = FamilyNums {
            last: t.tcp.last_ms,
            jitter: t.tcp.jitter_ms,
            st: t.tcp.stats(n),
            loss: t.tcp.recent_loss_pct(n),
            now_loss: t.tcp.recent_loss_pct(th::RECENT.min(n)),
            stale: t.tcp.stats_stale(n),
            rtt_ref: t.tcp.floor_ms(),
            loss_ref: None,
            excused: false,
            probed: !t.discovered,
        };
        // The identity columns wear the shown family's *current* condition —
        // last reply and fresh loss — not the windowed history beside them.
        let id_nums = if !dual && family == crate::app::ProbeFamily::Tcp {
            &tcp
        } else {
            &icmp
        };
        let identity = if (id_nums.excused && id_nums.loss >= 99.0) || !id_nums.probed {
            theme::dim()
        } else {
            latency_color(
                id_nums.last,
                id_nums.now_loss,
                id_nums.rtt_ref,
                id_nums.loss_ref,
            )
        };
        let marker = if i == s.graph_target { "►" } else { "" };
        let mut row_style = Style::new();
        if focused && i == s.selected {
            row_style = row_style.bg(theme::sel_bg()).add_modifier(Modifier::BOLD);
        }
        // '⇢' marks auto-discovered (gateway / hop) targets.
        let label = if t.discovered {
            format!("⇢ {}", t.label)
        } else {
            t.label.clone()
        };
        let idc = |text: String| {
            let c = if dim_hop { theme::dim() } else { identity };
            Cell::from(Span::styled(text, Style::new().fg(c)))
        };
        let mut cells = vec![
            Cell::from(Span::styled(marker, Style::new().fg(theme::accent()))),
            idc(label),
            idc(t.addr.to_string()),
        ];
        if dual {
            cells.push(Cell::from(Span::styled("│", Style::new().fg(theme::dim()))));
            cells.extend(family_cells(&icmp, dim_hop, icmp_max));
            cells.push(Cell::from(Span::styled("│", Style::new().fg(theme::dim()))));
            cells.extend(family_cells(&tcp, dim_hop, tcp_max));
        } else if family == crate::app::ProbeFamily::Tcp {
            cells.extend(family_cells(&tcp, dim_hop, icmp_max));
        } else {
            cells.extend(family_cells(&icmp, dim_hop, icmp_max));
        }
        Row::new(cells).style(row_style)
    });
    // The metric columns are fixed; the name and address split whatever the
    // panel has left, so a long hostname is not clipped at 13 characters while
    // the right-hand side of the panel sits empty.
    let mut widths = vec![
        Constraint::Length(2),
        Constraint::Min(14),
        Constraint::Min(16),
    ];
    if dual {
        widths.push(Constraint::Length(6)); // the "│ icmp" divider
    }
    widths.extend([
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(8),
    ]);
    if icmp_max {
        widths.push(Constraint::Length(8));
    }
    // loss needs five cells at most ("100%↓"); six left a ragged gap
    // between the icmp block and the tcp divider.
    widths.extend([Constraint::Length(6), Constraint::Length(5)]);
    if dual {
        widths.push(Constraint::Length(5)); // the "│ tcp" divider
        widths.extend([
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(8),
        ]);
        if tcp_max {
            widths.push(Constraint::Length(8));
        }
        widths.extend([Constraint::Length(6), Constraint::Length(6)]);
    }
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
    // Which family the split-view metric columns describe ([i] toggles);
    // full screen shows both, labelled by the │icmp and │tcp dividers.
    if !dual {
        title.push_str(if family == crate::app::ProbeFamily::Tcp {
            " · tcp :443"
        } else {
            " · icmp"
        });
    }
    if let Some(t) = s.targets.get(s.graph_target) {
        // Same staleness contract as the cells below: jit/sd/bloat are
        // computed from successes only, so with no reply inside the window
        // they would sit frozen in the title looking current.
        if t.stats_stale(n) {
            // Network-wide blackhole: the cue below explains every target at
            // once; per-target "not answering" would only crowd it out of
            // the panel's width.
            if !blackholed {
                title.push_str(&format!(" · {}: not answering", t.label));
            }
        } else {
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
    }
    // A speed test saturates the link on purpose; without a label, the loaded
    // readings — which stay in these stats until the window rolls past them —
    // look like the connection failing.
    if matches!(s.speedtest.status, SpeedStatus::Running) {
        title.push_str(" · under speed test load");
    } else if s
        .speedtest
        .last_run
        .is_some_and(|t| t.elapsed().as_secs() < s.window_secs)
    {
        title.push_str(" · includes speed test load");
    }
    // A wall of 100% loss with a working web check is a network that drops
    // ICMP as policy (Azure VMs, some hotels) — name that here, where the red
    // is, or the table reads as a total outage. Kept short: the title is
    // already long and this cue must survive a half-width panel.
    if blackholed {
        title.push_str(" · no ICMP here — web ok");
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
        Style::new().fg(theme::dim()),
    );
    // Mid-path hops are never probed — routers aren't web destinations, and
    // "checking…" would be a promise that never resolves.
    if t.is_path_hop() {
        f.render_widget(
            Paragraph::new(Line::from(vec![
                head,
                Span::styled(
                    "mid-path router — not a web destination".to_string(),
                    Style::new().fg(theme::dim()),
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
            "no web check — port 443 refused".to_string(),
            Style::new().fg(theme::dim()),
        ),
        WebStatus::Filtered => Span::styled(
            "TCP filtered — ping answers, web dropped".to_string(),
            Style::new().fg(theme::warn()),
        ),
        WebStatus::Unknown => Span::styled("checking…".to_string(), Style::new().fg(theme::dim())),
    };
    f.render_widget(Paragraph::new(Line::from(vec![head, detail])), rows[0]);

    let slots = t.web.hist.tail_slots(rows[1].width as usize);
    if !slots.is_empty() {
        let max = slots
            .iter()
            .filter_map(|v| v.map(|ms| ms.max(0.0) as u64))
            .max()
            .unwrap_or(1)
            .max(1);
        // A probe that never came back is red at full height; the TTFBs keep
        // the accent colour.
        let bars: Vec<SparklineBar> = slots
            .iter()
            .map(|slot| match slot {
                Some(ms) => {
                    SparklineBar::from(ms.max(0.0) as u64).style(Style::new().fg(theme::accent()))
                }
                None => SparklineBar::from(max).style(Style::new().fg(Color::Red)),
            })
            .collect();
        f.render_widget(
            Sparkline::default()
                .data(bars)
                .max(max)
                .bar_set(s.bar_set.clone()),
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

    let title = format!("Path · icmp · {}  ({status})", m.target);
    let b = block(&title, active);
    let inner = b.inner(list_area);

    if inner.height == 0 || m.hops.is_empty() {
        f.render_widget(b, list_area);
        f.render_widget(
            Paragraph::new(Span::styled(
                "discovering path…",
                Style::new().fg(theme::dim()),
            )),
            inner,
        );
        return;
    }

    // Column widths are fixed, so the sparklines start right after the last
    // column rather than being flung to the far right of a wide terminal.
    // Metric order mirrors the target table above (last · avg · p95 · max ·
    // jitter · loss), so the eye can drop between the two without re-mapping.
    // The split view hasn't the width for every metric: `max` is the one
    // that goes — ratatui would otherwise squeeze every column, and p95
    // still carries the spike story there.
    const COLS: [u16; 8] = [4, 17, 8, 8, 8, 8, 7, 6];
    const FULL_W: u16 = 4 + 17 + 8 + 8 + 8 + 8 + 7 + 6 + 7; // widths + gaps
    let show_max = inner.width >= FULL_W;
    let mut labels = vec!["ttl", "address", "last", "avg", "p95"];
    let mut widths_u: Vec<u16> = vec![COLS[0], COLS[1], COLS[2], COLS[3], COLS[4]];
    if show_max {
        labels.push("max");
        widths_u.push(COLS[5]);
    }
    labels.extend(["jitter", "loss"]);
    widths_u.extend([COLS[6], COLS[7]]);
    // Table adds one cell of spacing between columns; leaving it out squeezes
    // the columns and silently truncates the address cell.
    let table_w: u16 = widths_u.iter().sum::<u16>() + widths_u.len() as u16 - 1;

    let header = Row::new(labels).style(Style::new().fg(theme::text()).bold());
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
                let mut style = Style::new().fg(theme::dim());
                if selected {
                    style = style.bg(theme::sel_bg());
                }
                let mut cells = vec![Cell::from(hop_ttl(h)), Cell::from("*")];
                cells.extend((2..widths_u.len()).map(|_| Cell::from("—")));
                return Row::new(cells).style(style);
            };
            let loss = stat.recent_loss_pct(n);
            // The same per-cell grading the target table uses, so the two
            // tables read with one rulebook: each stat colours itself, and
            // recovery greens from the left. A lossy *middle* hop is a
            // router deprioritising ICMP, not a fault — it reads dim; the
            // destination's loss is real and keeps its colour.
            let mid_hop_policy = loss >= th::LOSS_DOWN_PCT && h.addr != Some(m.dest);
            let nums = FamilyNums {
                last: stat.last_rtt_ms,
                jitter: stat.jitter_ms,
                st: stat.stats(n),
                loss,
                now_loss: stat.recent_loss_pct(th::RECENT.min(n)),
                stale: stat.stats_stale(n),
                rtt_ref: stat.floor_ms(),
                loss_ref: None,
                excused: false,
                probed: true,
            };
            let identity = if mid_hop_policy {
                theme::dim()
            } else {
                latency_color(
                    stat.last_rtt_ms,
                    stat.recent_loss_pct(th::RECENT.min(n)),
                    stat.floor_ms(),
                    None,
                )
            };
            let mut style = Style::new();
            if selected {
                style = style.bg(theme::sel_bg()).add_modifier(Modifier::BOLD);
            }
            let mut cells = vec![
                Cell::from(Span::styled(hop_ttl(h), Style::new().fg(identity))),
                Cell::from(Span::styled(
                    h.addr
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "*".to_string()),
                    Style::new().fg(identity),
                )),
            ];
            cells.extend(family_cells(&nums, mid_hop_policy, show_max));
            Row::new(cells).style(style)
        }
    });
    let widths: Vec<Constraint> = widths_u.iter().map(|w| Constraint::Length(*w)).collect();
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
                        Span::styled(format!("{from:>2}-{to} "), Style::new().fg(theme::dim())),
                        Span::styled(
                            format!("{count} hops not responsive"),
                            Style::new().fg(theme::dim()).italic(),
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
                let slots = stat.history.tail_slots(spark_w as usize);
                let data: Vec<u64> = slots
                    .iter()
                    .map(|v| v.unwrap_or(0.0).max(0.0) as u64)
                    .collect();
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
                    .zip(slots.iter())
                    .map(|(&h, slot)| match slot {
                        Some(ms) => SparklineBar::from(h)
                            .style(Style::new().fg(rtt_color(*ms, stat.floor_ms()))),
                        // A probe that never came back is not a 0 ms reply —
                        // left to the floor-and-colour path it would draw as
                        // the fastest bar on the row. Full height, red.
                        None => SparklineBar::from(max).style(Style::new().fg(Color::Red)),
                    })
                    .collect();
                f.render_widget(
                    Sparkline::default()
                        .data(bars)
                        .max(max)
                        .bar_set(s.bar_set.clone()),
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
                Style::new().fg(theme::dim()),
            )),
            inner,
        );
        return;
    };

    let want = (inner.width as usize).saturating_mul(2).max(20);
    let runs = LatencyRuns::from_slots(&stat.history.tail_slots(want));
    if runs.len == 0 {
        f.render_widget(
            Paragraph::new(Span::styled("collecting…", Style::new().fg(theme::dim()))),
            inner,
        );
        return;
    }

    let xmax = runs.xmax();
    let st = stat.stats(n);
    let p95 = st.p95.unwrap_or(0.0);
    let ymax = if runs.has_samples() {
        runs.peak().max(p95) * 1.15 + 1.0
    } else {
        1.0
    };
    let gaps = runs.gap_bands();
    let mut datasets = latency_datasets(&runs.runs, &gaps, marker);
    let stale = stat.stats_stale(n);
    let p95_line = [(0.0, p95), (xmax, p95)];
    let jitter_line = [(0.0, stat.jitter_ms), (xmax, stat.jitter_ms)];
    if !stale {
        datasets.push(
            Dataset::default()
                .marker(marker)
                .graph_type(GraphType::Line)
                .style(Style::new().fg(P95_COLOR))
                .data(&p95_line),
        );
        datasets.push(
            Dataset::default()
                .marker(marker)
                .graph_type(GraphType::Line)
                .style(Style::new().fg(theme::jitter()))
                .data(&jitter_line),
        );
    }
    let mut title = vec![Span::styled(" latency ", Style::new().fg(theme::accent()))];
    if stale {
        title.push(Span::styled(
            "· not answering ",
            Style::new().fg(Color::Red).bold(),
        ));
    } else {
        title.extend([
            Span::styled("· p95 ", Style::new().fg(theme::dim())),
            Span::styled(format!("{p95:.0}ms"), Style::new().fg(P95_COLOR)),
            Span::styled(" · jitter ", Style::new().fg(theme::dim())),
            Span::styled(
                format!("{:.1}ms", stat.jitter_ms),
                Style::new().fg(theme::jitter()),
            ),
        ]);
    }
    title.push(Span::styled(
        format!(" · loss {:.0}% ", stat.recent_loss_pct(n)),
        Style::new().fg(theme::dim()),
    ));
    let top = if runs.has_samples() {
        format!("{ymax:.0}ms")
    } else {
        String::new()
    };
    let chart = Chart::new(datasets)
        .block(Block::new().title(Line::from(title)))
        .x_axis(Axis::default().bounds([0.0, xmax]))
        .y_axis(
            Axis::default()
                .bounds([0.0, ymax])
                .labels([Line::from("0"), Line::from(top)]),
        );
    f.render_widget(chart, inner);
}

/// Live traceroute hop list for the current target.
fn traceroute_view(f: &mut Frame, s: &AppState, area: Rect) {
    let Some(tr) = &s.traceroute else {
        return;
    };
    let status = if tr.running { "running…" } else { "done" };
    let outer = Block::new().title(Span::styled(
        format!(" traceroute · {}  ({status})  [g] graph ", tr.target),
        Style::new().fg(theme::dim()),
    ));
    let inner = outer.inner(area);
    f.render_widget(outer, area);

    let hop_line = |h: &crate::app::Hop| {
        let addr = h.addr.clone().unwrap_or_else(|| "*".to_string());
        let color = match h.rtt_ms {
            Some(v) if v >= 150.0 => Color::Red,
            Some(v) if v >= 60.0 => theme::warn(),
            Some(_) => Color::Green,
            None => theme::dim(),
        };
        let rtt = h.rtt_ms.map(|v| format!("{v:.1}ms")).unwrap_or_default();
        Line::from(vec![
            Span::styled(format!("{:>2}  ", h.ttl), Style::new().fg(theme::dim())),
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
            Style::new().fg(theme::dim()),
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
            Style::new().fg(theme::warn()),
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
        Style::new().fg(theme::warn()),
    ))]
}

/// Latency line chart for the graphed target, with a p95 reference line.
/// A latency chart's samples split at the misses: the answered probes as
/// unbroken runs, and every unanswered stretch as its own span.
///
/// Losses hold their slot on the x axis, so a chart drawn from this cannot do
/// what the old success-only series did — freeze on the last good reading and
/// then, once replies returned, splice the two sides of an outage together
/// until the gap had no width at all.
struct LatencyRuns {
    /// Unbroken runs of answered probes as (x, ms) points.
    runs: Vec<Vec<(f64, f64)>>,
    /// Each unanswered stretch as (first x, last x).
    gaps: Vec<(f64, f64)>,
    /// Slots in the window, answered or not.
    len: usize,
    /// Unanswered probes at the right-hand edge: the outage still running.
    trailing: usize,
}

impl LatencyRuns {
    fn from_slots(slots: &[Option<f64>]) -> Self {
        let mut runs: Vec<Vec<(f64, f64)>> = Vec::new();
        let mut gaps = Vec::new();
        let mut gap_start: Option<usize> = None;
        for (i, slot) in slots.iter().enumerate() {
            match slot {
                Some(ms) => {
                    if let Some(start) = gap_start.take() {
                        gaps.push(((start as f64), ((i - 1) as f64)));
                    }
                    match runs.last_mut() {
                        // Consecutive replies join up; one that follows a gap
                        // starts a fresh run so the line is not drawn across it.
                        Some(run) if run.last().is_some_and(|(x, _)| *x == (i - 1) as f64) => {
                            run.push((i as f64, *ms))
                        }
                        _ => runs.push(vec![(i as f64, *ms)]),
                    }
                }
                None => {
                    gap_start.get_or_insert(i);
                }
            }
        }
        let trailing = match gap_start {
            Some(start) => {
                gaps.push((start as f64, (slots.len().saturating_sub(1)) as f64));
                slots.len() - start
            }
            None => 0,
        };
        Self {
            runs,
            gaps,
            len: slots.len(),
            trailing,
        }
    }

    /// Every miss as a segment pinned to the axis floor. Deliberately not
    /// plotted as a 0 ms sample: zero is a *value* in the same units as the
    /// data — it would read as an impossibly fast reply, join the real line
    /// with a diagonal, and drag the y scale. A red bar along the floor says
    /// "nothing answered through here", which is what actually happened.
    fn gap_bands(&self) -> Vec<[(f64, f64); 2]> {
        self.gaps
            .iter()
            .map(|(a, b)| [(*a, 0.0), (*b, 0.0)])
            .collect()
    }

    fn xmax(&self) -> f64 {
        (self.len.saturating_sub(1)).max(1) as f64
    }

    /// Whether anything answered in this window — the difference between a
    /// chart with a gap in it and a chart of nothing at all.
    fn has_samples(&self) -> bool {
        !self.runs.is_empty()
    }

    /// The tallest reply in the window; zero when none answered.
    fn peak(&self) -> f64 {
        self.runs
            .iter()
            .flatten()
            .fold(0.0_f64, |m, (_, v)| m.max(*v))
    }
}

/// "no replies for 4m 12s" — how long the run of misses at the right-hand edge
/// has lasted, in wall time rather than probe count.
fn outage_note(runs: &LatencyRuns, samples_per_sec: f64) -> Option<String> {
    if runs.trailing == 0 {
        return None;
    }
    let rate = if samples_per_sec > 0.0 {
        samples_per_sec
    } else {
        1.0
    };
    let secs = (runs.trailing as f64 / rate).round() as u64;
    Some(format!(
        "no replies for {}",
        crate::verdict::fmt_duration(std::time::Duration::from_secs(secs.max(1)))
    ))
}

/// The datasets every latency chart shares: the answered runs in the accent
/// colour, then a red band along the floor for each stretch that went
/// unanswered.
fn latency_datasets<'a>(
    runs: &'a [Vec<(f64, f64)>],
    gaps: &'a [[(f64, f64); 2]],
    marker: Marker,
) -> Vec<Dataset<'a>> {
    let mut sets: Vec<Dataset<'a>> = runs
        .iter()
        .map(|run| {
            Dataset::default()
                .marker(marker)
                .graph_type(GraphType::Line)
                .style(Style::new().fg(theme::accent()))
                .data(run)
        })
        .collect();
    sets.extend(gaps.iter().map(|band| {
        Dataset::default()
            .marker(marker)
            .graph_type(GraphType::Line)
            .style(Style::new().fg(Color::Red))
            .data(band)
    }));
    sets
}

fn latency_graph(f: &mut Frame, s: &AppState, n: usize, area: Rect) {
    let Some(t) = s.targets.get(s.graph_target) else {
        return;
    };
    // Braille markers double horizontal resolution.
    let want = (area.width as usize).saturating_mul(2).max(20);
    let runs = LatencyRuns::from_slots(&t.history.tail_slots(want));
    // Nothing has ever answered here. Which *kind* of nothing matters: a
    // network that drops ICMP as policy is not an outage, and a floor-to-floor
    // red band would insist it was. Say it in words instead.
    if !runs.has_samples() && (runs.len == 0 || crate::verdict::icmp_blackholed(s)) {
        // "collecting…" is a promise; on a network that blackholes ICMP it
        // will never be kept — say what is actually happening and where the
        // real signal lives instead.
        let placeholder = if crate::verdict::icmp_blackholed(s) {
            format!(
                " latency · {} — no ICMP replies on this network; web probes still measure",
                t.label
            )
        } else {
            format!(" latency · {} — collecting…", t.label)
        };
        f.render_widget(
            Paragraph::new(Span::styled(placeholder, Style::new().fg(theme::dim()))),
            area,
        );
        return;
    }

    let xmax = runs.xmax();
    let p95 = t.stats(n).p95.unwrap_or(0.0);
    // A window with nothing but misses has no scale to draw — the axis top is
    // left blank rather than labelled with a millisecond figure describing a
    // measurement that never happened.
    let ymax = if runs.has_samples() {
        runs.peak().max(p95) * 1.15 + 1.0
    } else {
        1.0
    };
    let gaps = runs.gap_bands();
    let mut datasets = latency_datasets(&runs.runs, &gaps, s.graph_marker);

    // Nothing has answered lately: p95 and jitter describe a period that has
    // ended, and drawing them as reference lines across a dead chart is the
    // same frozen-figures lie the target table dashes out. The red floor and
    // the title carry the truth instead.
    let stale = t.stats_stale(n);
    let p95_line = [(0.0, p95), (xmax, p95)];
    // Jitter as a reference line rather than a series: it is a single smoothed
    // figure, so plotting it per-sample would just redraw the same value.
    let jitter_line = [(0.0, t.jitter_ms), (xmax, t.jitter_ms)];
    if !stale {
        datasets.push(
            Dataset::default()
                .marker(s.graph_marker)
                .graph_type(GraphType::Line)
                .style(Style::new().fg(P95_COLOR))
                .data(&p95_line),
        );
        datasets.push(
            Dataset::default()
                .marker(s.graph_marker)
                .graph_type(GraphType::Line)
                .style(Style::new().fg(theme::jitter()))
                .data(&jitter_line),
        );
    }

    // Each label is drawn in its series' colour, so the legend needs no key.
    let mut title = vec![
        Span::styled(" latency ", Style::new().fg(theme::dim())),
        Span::styled(t.label.clone(), Style::new().fg(theme::accent())),
    ];
    match outage_note(&runs, s.samples_per_sec) {
        // A stalled graph explains nothing on its own — say how long it has
        // been stalled, in the same red the floor band is drawn in.
        Some(note) => title.push(Span::styled(
            format!("   {note} "),
            Style::new().fg(Color::Red).bold(),
        )),
        None => title.extend([
            Span::styled("   p95 ", Style::new().fg(theme::dim())),
            Span::styled(format!("{p95:.0}ms"), Style::new().fg(P95_COLOR)),
            Span::styled("   jitter ", Style::new().fg(theme::dim())),
            Span::styled(
                format!("{:.1}ms ", t.jitter_ms),
                Style::new().fg(theme::jitter()),
            ),
        ]),
    }
    let top = if runs.has_samples() {
        format!("{ymax:.0}ms")
    } else {
        String::new()
    };
    let chart = Chart::new(datasets)
        .block(Block::new().title(Line::from(title)))
        .x_axis(Axis::default().bounds([0.0, xmax]))
        .y_axis(
            Axis::default()
                .bounds([0.0, ymax])
                .labels([Line::from("0"), Line::from(top)]),
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
        b if b < moderate => ("moderate", theme::warn()),
        b if b < poor => ("poor", Color::Red),
        _ => ("bad", Color::Red),
    }
}

/// "following firefox" — the [o] state for the active talkers table, shown
/// in the panel titles so the mode is never invisible.
fn follow_label(s: &AppState) -> Option<String> {
    match s.bw_view {
        BwView::Processes => s.follow_proc.clone(),
        BwView::Remotes => s.follow_remote.map(|a| a.to_string()),
    }
}

fn bandwidth_panel(f: &mut Frame, s: &AppState, area: Rect) {
    let tp = &s.throughput;
    let mut title = format!(
        "Bandwidth · {}",
        if tp.iface.is_empty() {
            "…"
        } else {
            &tp.iface
        }
    );
    if let Some(name) = follow_label(s) {
        title.push_str(&format!(" · following {name}"));
    }
    if !s.bw_filter.trim().is_empty() {
        title.push_str(&format!(" · ⌕ {}", s.bw_filter.trim()));
    }
    let b = block(&title, s.focus == Panel::Bandwidth);
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
        .bar_set(s.bar_set.clone())
        .style(Style::new().fg(Color::Green))
        .block(Block::new().title(Span::styled(
            format!(
                " ↓ down  {}{}",
                fmt_rate(tp.down_bps, s.bits_units),
                fmt_mbits(tp.down_bps, s.bits_units)
            ),
            Style::new().fg(Color::Green).bold(),
        )));
    f.render_widget(down, graphs[0]);

    let (udata, umax) = spark_floor(&tp.up_hist, graphs[1].width, spark_h(graphs[1]));
    let up = Sparkline::default()
        .data(udata)
        .max(umax)
        .bar_set(s.bar_set.clone())
        .style(Style::new().fg(Color::Magenta))
        .block(Block::new().title(Span::styled(
            format!(
                " ↑ up    {}{}",
                fmt_rate(tp.up_bps, s.bits_units),
                fmt_mbits(tp.up_bps, s.bits_units)
            ),
            Style::new().fg(Color::Magenta).bold(),
        )));
    f.render_widget(up, graphs[1]);

    // Full-screen: the talkers and speed-test history each get their own panel,
    // and 'n' moves the cursor between them. Given the width, processes and
    // remote addresses sit side by side and 'b' picks which one the sort and
    // row cursor belong to; otherwise 'b' switches which of the two is shown.
    if s.fullscreen {
        // Zoomed ([z]): the bottom band becomes one full-width table — the
        // graphs above stay where the eye already was. It stays drawn while
        // the [y] analysis or a [W]hois floats over it, so closing the
        // overlay lands back on the table instead of on a re-shuffled panel.
        if s.overlay == Overlay::Zoom || (s.zoom_behind && s.overlay != Overlay::None) {
            zoom_band(f, s, rows[2]);
            return;
        }
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
                Style::new().fg(theme::dim()),
            )),
            area,
        );
        return;
    }

    let header =
        Row::new(["time", "provider", "↓", "↑", "bloat"]).style(Style::new().fg(theme::dim()));
    // Newest first; the cursor indexes this reversed order.
    let ordered: Vec<&crate::store::SpeedRecord> = s.speed_history.iter().rev().collect();
    let sel = s.speed_sel.min(ordered.len().saturating_sub(1));

    // Detail block for the selected test at the bottom of the pane — the
    // table's five columns can't carry the whole record (idle/loaded split,
    // which server ran the test, which network it ran on), and "was that
    // 104 Mbps at home or on the hotel Wi-Fi?" is the question a history
    // exists to answer. Skipped on a pane too short to give the table room.
    let detail: Vec<Line> = {
        let r = ordered[sel];
        let bloat = match (r.idle_ms, r.loaded_ms) {
            (Some(i), Some(l)) => format!(" · bloat +{:.0}ms", (l - i).max(0.0)),
            _ => String::new(),
        };
        let latency = match (r.idle_ms, r.loaded_ms) {
            (Some(i), Some(l)) => format!("idle {i:.0}ms · loaded {l:.0}ms{bloat}"),
            (Some(i), None) => format!("idle {i:.0}ms"),
            _ => "latency not recorded".to_string(),
        };
        let network = match (&r.network, &r.medium) {
            (Some(n), Some(m)) => format!("{n} · {m}"),
            (Some(n), None) => n.clone(),
            // Records from before the field existed.
            (None, _) => "not recorded (older test)".to_string(),
        };
        // The rates ride on the identity line — the pane has the width, and
        // the row this saves goes to the test list above.
        let mut lines = vec![
            selected_rule(area.width as usize),
            Line::from(vec![
                Span::styled(
                    format!("{} · {}", r.when(), r.provider),
                    Style::new().fg(theme::text()),
                ),
                Span::styled(
                    format!("  ↓ {}", crate::util::fmt_mbps(r.down_mbps)),
                    Style::new().fg(Color::Green),
                ),
                Span::styled(
                    format!("  ↑ {}", crate::util::fmt_mbps(r.up_mbps)),
                    Style::new().fg(Color::Magenta),
                ),
            ]),
            Line::from(Span::styled(latency, Style::new().fg(theme::text()))),
        ];
        // Only when recorded: a blank "server" row on older entries is noise.
        if let Some(server) = &r.server {
            lines.push(Line::from(vec![
                Span::styled("server  ", Style::new().fg(theme::dim())),
                Span::styled(server.clone(), Style::new().fg(theme::text())),
            ]));
        }
        lines.push(Line::from(vec![
            Span::styled("network ", Style::new().fg(theme::dim())),
            Span::styled(network, Style::new().fg(theme::accent())),
        ]));
        lines
    };
    let detail_h: u16 = if area.height >= 10 {
        detail.len() as u16
    } else {
        0
    };
    let (table_area, detail_area) = if detail_h > 0 {
        let parts =
            Layout::vertical([Constraint::Min(1), Constraint::Length(detail_h)]).split(area);
        (parts[0], Some(parts[1]))
    } else {
        (area, None)
    };
    if let Some(da) = detail_area {
        f.render_widget(Paragraph::new(detail), da);
    }

    let n = (table_area.height.saturating_sub(1)) as usize;
    // Scroll only as far as needed to bring the cursor into view.
    let first = if n == 0 { 0 } else { sel.saturating_sub(n - 1) };
    // A cue on the right edge whenever more tests exist than fit — drawn only
    // then; the table narrows by one column to make room for it.
    let table_area = scroll_cue(f, table_area, ordered.len(), first, n);

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
                    fmt_speed_compact(r.down_mbps),
                    Style::new().fg(Color::Green),
                )),
                Cell::from(Span::styled(
                    fmt_speed_compact(r.up_mbps),
                    Style::new().fg(Color::Magenta),
                )),
                Cell::from(bloat),
            ])
            .style(if selected {
                Style::new()
                    .bg(theme::sel_bg())
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
    f.render_widget(Table::new(rows, widths).header(header), table_area);
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
            "speedtest · {} {:.0}%  {}",
            st.phase,
            st.progress * 100.0,
            crate::util::fmt_mbps(st.live_mbps)
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
            Paragraph::new(Span::styled(msg.to_string(), Style::new().fg(theme::dim()))),
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

    // Session totals lead (that is what the table ranks by); the live rate and
    // health columns follow, and go first when the panel is narrow.
    // Sized so every column fits the full-screen pane of a 120-column terminal.
    // "now" sits beside the name: "who is using the link right now" is the
    // question this table is opened for; session totals read second. Any
    // leftover pane width goes to the name — a truncated name in front of
    // blank columns answers nothing.
    const WIDTHS: [u16; 7] = [21, 10, 7, 7, 7, 5, 5];
    let ncols = fitting_columns(&WIDTHS, inner.width);
    let (widths, name_w) = flex_col(&WIDTHS, ncols, inner.width, 0, 24);
    let labels = ["name", "now", "total", "↓", "↑", "share", "retx"];
    let header = talkers_header(s, &labels[..ncols], BwView::Processes, 1);

    // Rows as drawn (the sort, when one is active), scrolled to keep the
    // cursor's position in view, with a cue beside them when there is more.
    let order = s.process_order();
    let filter = s.filter_for(BwView::Processes).trim();
    if order.is_empty() && !filter.is_empty() {
        return no_filter_match(f, inner, "processes", filter);
    }
    let cursor_on = s.on_process_list();
    let (pos, sel_idx) = s.proc_cursor();
    let (inner, first, visible) = talkers_scroll(f, inner, order.len(), pos);

    let rows = order.iter().skip(first).take(visible).map(|&idx| {
        let p = &s.processes[idx];
        let name: String = p.name.chars().take(name_w as usize).collect();
        // Retransmits: red while they are happening, the session count once
        // they have, nothing when there were none.
        let (retx, retx_style) = if p.retx_per_sec >= 1.0 {
            (
                format!("{:.0}/s", p.retx_per_sec),
                Style::new().fg(Color::Red),
            )
        } else if p.retx > 0 {
            (p.retx.to_string(), Style::new().fg(theme::text()))
        } else {
            ("·".to_string(), Style::new().fg(theme::dim()))
        };
        let mut cells = vec![
            Cell::from(name),
            fmt_now(p.down_bps + p.up_bps, s.bits_units),
            rcell(Span::styled(
                fmt_bytes(p.total_bytes),
                Style::new().fg(theme::bright()),
            )),
            rcell(Span::styled(
                fmt_bytes(p.down_bytes),
                Style::new().fg(Color::Green),
            )),
            rcell(Span::styled(
                fmt_bytes(p.up_bytes),
                Style::new().fg(Color::Magenta),
            )),
            rcell(Span::styled(
                format!("{:.0}%", p.share * 100.0),
                Style::new().fg(theme::text()),
            )),
            rcell(Span::styled(retx, retx_style)),
        ];
        cells.truncate(ncols);
        Row::new(cells).style(row_style(
            cursor_on && Some(idx) == sel_idx,
            s.pinned_procs.contains(&p.name),
        ))
    });
    let widths: Vec<Constraint> = widths.iter().map(|w| Constraint::Length(*w)).collect();
    f.render_widget(Table::new(rows, widths).header(header), inner);
}

/// Cursor-row and pinned-row backgrounds shared by the talkers tables. A pin
/// is a background wash, not a marker glyph — no column is spent on it — in a
/// cold teal so it can't be mistaken for the cursor's blue-grey; the cursor
/// on a pinned row lifts that teal and goes bold, so both facts stay visible
/// at once.
fn row_style(selected: bool, pinned: bool) -> Style {
    match (selected, pinned) {
        (true, true) => Style::new()
            .bg(theme::sel_pin_bg())
            .add_modifier(Modifier::BOLD),
        (true, false) => Style::new()
            .bg(theme::sel_bg())
            .add_modifier(Modifier::BOLD),
        (false, true) => Style::new().bg(theme::pin_bg()),
        (false, false) => Style::new(),
    }
}

/// Scroll a talkers table so the cursor's display position stays visible, and
/// draw the scroll cue beside the rows (under the header) when they overflow.
/// Returns the area left for the table, the first row to draw, and how many.
fn talkers_scroll(f: &mut Frame, area: Rect, total: usize, pos: usize) -> (Rect, usize, usize) {
    let visible = area.height.saturating_sub(1) as usize; // header row
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
    let body = scroll_cue(f, body, total, first, visible);
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

/// A right-aligned numeric cell: the units column stays put and magnitudes
/// compare down the column, the way number tables are read. Name columns
/// stay left-aligned.
fn rcell(span: Span<'_>) -> Cell<'_> {
    Cell::from(Line::from(span).right_aligned())
}

/// The "now" column: the current combined rate, or a dim dot when idle so a
/// quiet row reads as quiet rather than as "0 B/s".
fn fmt_now(bps: f64, bits: bool) -> Cell<'static> {
    if bps > 0.0 {
        rcell(Span::styled(
            fmt_rate(bps, bits),
            Style::new().fg(theme::accent()),
        ))
    } else {
        rcell(Span::styled("·", Style::new().fg(theme::dim())))
    }
}

/// Sortable header row for a talkers table: the column under the cursor is
/// highlighted, the sorted column carries a direction arrow. The first
/// `left_cols` labels head text columns and stay left-aligned; the rest head
/// numbers and right-align with them.
fn talkers_header<'a>(s: &AppState, labels: &[&'a str], view: BwView, left_cols: usize) -> Row<'a> {
    let active = s.bw_view == view;
    // The column cursor belongs to the table that holds the row cursor —
    // not while the speed-test history pane has it.
    let focused = active && s.focus == Panel::Bandwidth && s.sub_pane == SubPane::Primary;
    Row::new(labels.iter().enumerate().map(|(i, l)| {
        let mut txt = (*l).to_string();
        // The arrow shows whichever sort this table is drawn in — the parked
        // one too, when the other table is the active one. The zoom-only
        // now↓/now↑ keys have no compact column; their arrow lands on the
        // combined "now", which is what they refine.
        if let Some((c, desc)) = s.sort_for(view)
            && (if c > 6 { view.combined_now_key() } else { c }) == i
        {
            txt.push(if desc { '▼' } else { '▲' });
        }
        let style = if focused && i == s.bw_col {
            Style::new()
                .fg(theme::accent())
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            Style::new().fg(theme::dim())
        };
        let line = Line::from(Span::styled(txt, style));
        Cell::from(if i < left_cols {
            line
        } else {
            line.right_aligned()
        })
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
                Style::new().fg(theme::dim()),
            )),
            area,
        );
        return;
    }
    // A squeezed address column is the one thing this table must not have, so
    // trailing columns are dropped instead when the panel is narrow.
    const WIDTHS: [u16; 7] = [24, 12, 10, 7, 7, 7, 5];
    let ncols = fitting_columns(&WIDTHS, area.width);
    // Leftover width goes to the address — a squeezed v6 in front of blank
    // space answers nothing.
    let (flexed, addr_w) = flex_col(&WIDTHS, ncols, area.width, 0, 24);
    let labels = ["remote", "process", "now", "total", "↓", "↑", "share"];
    let header = talkers_header(s, &labels[..ncols], BwView::Remotes, 2);

    let order = s.remote_order();
    let filter = s.filter_for(BwView::Remotes).trim();
    if order.is_empty() && !filter.is_empty() {
        return no_filter_match(f, area, "remote addresses", filter);
    }
    let cursor_on = s.selected_remote().is_some();
    let (pos, sel_idx) = s.remote_cursor();
    let (area, first, visible) = talkers_scroll(f, area, order.len(), pos);

    let rows = order.iter().skip(first).take(visible).map(|&idx| {
        let r = &s.remotes[idx];
        let selected = cursor_on && Some(idx) == sel_idx;
        // v6 with a port can outrun the column; keep the tail, which is the
        // distinctive part of the address.
        let remote: String = {
            let full = fmt_remote(r);
            let n = full.chars().count();
            let w = addr_w as usize;
            if n > w {
                format!("…{}", full.chars().skip(n + 1 - w).collect::<String>())
            } else {
                full
            }
        };
        let process: String = r.process.chars().take(WIDTHS[1] as usize).collect();
        let mut cells = vec![
            Cell::from(remote),
            Cell::from(Span::styled(process, Style::new().fg(theme::text()))),
            fmt_now(r.down_bps + r.up_bps, s.bits_units),
            rcell(Span::styled(
                fmt_bytes(r.total_bytes),
                Style::new().fg(theme::bright()),
            )),
            rcell(Span::styled(
                fmt_bytes(r.down_bytes),
                Style::new().fg(Color::Green),
            )),
            rcell(Span::styled(
                fmt_bytes(r.up_bytes),
                Style::new().fg(Color::Magenta),
            )),
            rcell(Span::styled(
                format!("{:.0}%", r.share * 100.0),
                Style::new().fg(theme::text()),
            )),
        ];
        cells.truncate(ncols);
        Row::new(cells).style(row_style(selected, s.pinned_remotes.contains(&r.addr)))
    });
    let widths: Vec<Constraint> = flexed.iter().map(|w| Constraint::Length(*w)).collect();
    f.render_widget(Table::new(rows, widths).header(header), area);
}

/// Centered modal listing all keyboard shortcuts, titled with the running
/// version so users can report what they're actually on.
fn help_overlay(f: &mut Frame, s: &AppState, area: Rect) {
    let row = |k: &str, d: &str| {
        Line::from(vec![
            Span::styled(format!("{k:<11}"), Style::new().fg(theme::accent())),
            Span::styled(d.to_string(), Style::new().fg(theme::text())),
        ])
    };
    let head = |t: &str| {
        Line::from(Span::styled(
            t.to_string(),
            Style::new().fg(theme::bright()).bold(),
        ))
    };

    // Grouped by what the reader is looking for — the global keys, then
    // getting around, then each panel's own — and kept to a size that packs
    // into two columns of an 80x24 terminal, the smallest this dashboard is
    // designed for. Nothing here scrolls: a shortcut list you have to page
    // through to find a shortcut has failed at its one job. Descriptions stay
    // inside 28 columns for the same reason.
    // Leading indent comes from the block's padding, not the lines.
    let mut sections: Vec<Vec<Line>> = vec![
        vec![
            head("Global"),
            row("Tab / ⇧Tab", "cycle panels"),
            row("f", "full-screen focused panel"),
            row("n", "next sub-pane in panel"),
            row("Esc", "back / exit full-screen"),
            row("P", "pause / resume the display"),
            row("w", "stats window 30s→15m"),
            row("r / G", "re-probe / rescan the path"),
            row("? / q", "this help / quit (^C too)"),
        ],
        vec![
            head("Navigation"),
            row("↑/↓ or j/k", "move the cursor"),
            row("PgUp/PgDn", "move by ten"),
            row("←/→", "move sort-column cursor"),
            row("Enter", "sort / flip direction"),
            row("Shift+R/^R", "panel reset / ERASE ALL"),
        ],
        vec![
            head("Diagnose & record"),
            row("y / T", "analysis / routing table"),
            row("e / c / M", "events / ports / marker"),
            row("b", "walk the session bar"),
            row("l / D", "CSV recording / zip bundle"),
        ],
        vec![
            head("Connection Quality"),
            row("a", "add target (remembered)"),
            row("d / Del", "delete + forget target"),
            row("i", "stats: icmp ↔ tcp :443"),
            row("g", "graph selected target"),
            row("t", "traceroute once"),
            row("m", "monitor every hop (MTR)"),
            row("W", "whois: who owns address"),
        ],
        vec![
            head("Bandwidth"),
            row("s", "run a speed test"),
            row("v / I / V", "provider cycle · add · del"),
            row("n", "procs → remotes → history"),
            row("W / a", "whois / add sel. remote"),
            row("p / u", "pin / unpin row at the top"),
            row("o / /", "follow row / filter rows"),
            row("d / z", "del. speed test / zoom"),
        ],
        vec![
            head("Network"),
            row("N", "name this network"),
            row("L", "saved network locations"),
            row("f", "full-screen: DNS + history"),
        ],
    ];

    // Only shown when something is actually absent, with the package that
    // provides it — which tools ship by default varies a lot by distribution.
    if !s.missing_tools.is_empty() {
        let mut missing = vec![Line::from(Span::styled(
            "Missing tools",
            Style::new().fg(theme::warn()).bold(),
        ))];
        for (name, _provides, package) in &s.missing_tools {
            missing.push(Line::from(vec![
                Span::styled(format!("{name:<11}"), Style::new().fg(theme::warn())),
                Span::styled(package.to_string(), Style::new().fg(theme::dim())),
            ]));
        }
        sections.push(missing);
    }

    // Wider terminals get a third column rather than a taller box: columns
    // cost width, which there is plenty of, and save height, which is what
    // runs out. Below two columns' worth the sections stack and a very narrow
    // terminal simply cannot show them all.
    let (ncols, w) = match area.width {
        aw if aw >= 126 => (3, 126),
        aw if aw >= 96 => (2, 96),
        aw if aw >= 76 => (2, 80),
        aw => (1, 46.min(aw)),
    };
    let columns = pack_help(sections, ncols);
    let body_h = columns.iter().map(|c| c.len()).max().unwrap_or(0) as u16;

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
            match &s.update_available {
                Some(v) => format!(
                    " octomon v{} · v{v} available · Shortcuts ",
                    crate::util::VERSION
                ),
                None => format!(" octomon v{} · Shortcuts ", crate::util::VERSION),
            },
            Style::new().bold(),
        ))
        .title_bottom(Span::styled(
            " press ? or Esc to close ",
            Style::new().fg(theme::dim()),
        ))
        // Where to report a bug or read more — in the border, where it costs
        // no rows on a 24-line terminal.
        .title_bottom(
            Line::from(Span::styled(
                " github.com/securitypedant/octomon · octomon.dev ",
                Style::new().fg(theme::dim()),
            ))
            .right_aligned(),
        )
        .border_style(Style::new().fg(theme::accent()));
    let inner = outer.inner(rect);
    f.render_widget(outer, rect);

    // A trailing column of padding, so the longest description does not sit
    // flush against the border.
    let pad = |r: Rect| Rect {
        width: r.width.saturating_sub(1),
        ..r
    };
    let widths = vec![Constraint::Ratio(1, ncols as u32); ncols];
    let rects = Layout::horizontal(widths).split(inner);
    for (lines, rect) in columns.into_iter().zip(rects.iter()) {
        f.render_widget(Paragraph::new(lines), pad(*rect));
    }
}

/// Lay the help sections out in `ncols` columns, in order, with a blank line
/// between sections sharing a column.
///
/// The column height is the shortest one the sections actually fit in, so the
/// box is as short as it can be — height is the scarce dimension in a terminal
/// and the whole list has to be visible at once. A set too long for the
/// columns available packs into the last one and is clipped by the border,
/// which is only reachable on a terminal below the size this is designed for.
fn pack_help(sections: Vec<Vec<Line<'static>>>, ncols: usize) -> Vec<Vec<Line<'static>>> {
    let lens: Vec<usize> = sections.iter().map(|s| s.len()).collect();
    let total: usize = lens.iter().sum::<usize>() + lens.len();
    // Never shorter than the longest single section: one section is never
    // split across columns, so it sets the floor.
    let floor = lens.iter().copied().max().unwrap_or(0);
    let height = (floor..=total.max(floor))
        .find(|h| fits_columns(&lens, ncols, *h))
        .unwrap_or(total);

    let mut columns: Vec<Vec<Line>> = Vec::with_capacity(ncols);
    let mut current: Vec<Line> = Vec::new();
    for section in sections {
        let need = current.len() + 1 + section.len();
        if !current.is_empty() && (need > height && columns.len() + 1 < ncols) {
            columns.push(std::mem::take(&mut current));
        } else if !current.is_empty() {
            current.push(Line::from(""));
        }
        current.extend(section);
    }
    columns.push(current);
    columns
}

/// Whether the sections fit `ncols` columns of `height` lines, packed in
/// order with a blank line between neighbours.
fn fits_columns(lens: &[usize], ncols: usize, height: usize) -> bool {
    let mut used = 0usize;
    let mut cols = 1usize;
    for len in lens {
        let need = if used == 0 { *len } else { used + 1 + len };
        if used > 0 && need > height {
            cols += 1;
            used = *len;
            if cols > ncols || used > height {
                return false;
            }
        } else {
            used = need;
        }
    }
    true
}

fn netinfo_panel(f: &mut Frame, s: &AppState, area: Rect) {
    // Full-screen: the network history sits to the right of the details, and
    // 'n' moves the cursor over to it. It needs width to be readable; below
    // that the panel stays as it is in the split view.
    if s.fullscreen && area.width >= 100 {
        let cols = Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(area);
        let on_history = s.focus == Panel::NetInfo && s.sub_pane == SubPane::Secondary;
        netinfo_details(f, s, cols[0], s.focus == Panel::NetInfo && !on_history);
        net_history_pane(f, s, cols[1], on_history);
        return;
    }
    netinfo_details(f, s, area, s.focus == Panel::NetInfo);
}

/// The interface / network history: every change to how this machine is
/// attached, newest first, with the selected entry's before/after underneath.
fn net_history_pane(f: &mut Frame, s: &AppState, area: Rect, focused: bool) {
    let title = format!(
        "Network history ({}){}",
        s.net_history.len(),
        if focused { "" } else { " · n to browse" }
    );
    let b = block(&title, focused);
    let inner = b.inner(area);
    f.render_widget(b, area);
    if inner.height == 0 {
        return;
    }
    if s.net_history.is_empty() {
        f.render_widget(
            Paragraph::new(Span::styled(
                " no changes yet — joins, roams, address and route changes land here",
                Style::new().fg(theme::dim()),
            ))
            .wrap(Wrap { trim: false }),
            inner,
        );
        return;
    }
    // List on top, detail of the selected entry below; the detail gets what
    // it needs (its wrapped lines + a header), the list the rest.
    let sel = s.selected_net_change();
    let text_w = inner.width as usize;
    // The detail is wrapped up front — its before/after resolver lists are
    // exactly the lines that outgrow the pane — so the layout can size the
    // pane from what will actually be printed.
    let detail: Vec<Line> = match sel {
        None => Vec::new(),
        Some(c) => {
            let mut d = vec![Line::from(Span::styled(
                format!(" {} · {}", c.kind.label(), c.iface),
                Style::new().fg(theme::bright()).bold(),
            ))];
            for l in &c.detail {
                d.extend(column_lines(
                    vec![Span::raw("  ")],
                    l,
                    Style::new().fg(theme::text()),
                    2,
                    text_w,
                ));
            }
            d
        }
    };
    // A fixed slice of the pane, whatever the selected entry holds: sized per
    // entry, the list above grew and shrank as the cursor moved between a
    // one-line roam and a fifteen-line resolver change, and the whole pane
    // jumped. Kept modest so a short entry doesn't strand a screen of blank
    // rows. [Enter] expands the slice to the whole entry — the list yields
    // the rows, by explicit choice — leaving at least a few list rows for
    // context; Enter again collapses.
    let detail_h = if detail.is_empty() || inner.height < 8 {
        0
    } else if s.net_detail_expanded {
        (detail.len() as u16).min(inner.height.saturating_sub(4).max(inner.height / 2))
    } else {
        (inner.height / 4).clamp(4, 8).min(inner.height / 2)
    };
    let mut detail = detail;
    let h = detail_h as usize;
    if h > 0 && detail.len() > h {
        let hidden = detail.len() - (h - 1);
        detail.truncate(h - 1);
        detail.push(Line::from(Span::styled(
            if s.net_detail_expanded {
                // Even expanded, the pane can be too short for everything.
                format!("  … +{hidden} more lines — the pane is too short for the rest")
            } else {
                format!("  … +{hidden} more lines · ↵ to expand")
            },
            Style::new().fg(theme::dim()),
        )));
    }
    let parts = Layout::vertical([Constraint::Min(1), Constraint::Length(detail_h)]).split(inner);
    let list_area = parts[0];
    let visible = list_area.height as usize;

    // Each entry wrapped, summary continuing under its own column — which
    // makes entries vary in height, so the scroll window is chosen by rows.
    use chrono::TimeZone as _;
    let wrapped: Vec<Vec<Line>> = s
        .net_history
        .iter()
        .rev()
        .enumerate()
        .map(|(i, c)| {
            let selected = focused && i == s.net_history_sel;
            // Dated, not just timed: this history routinely spans days of
            // uptime, where "09:14:02" alone no longer says which morning.
            let when = chrono::Local
                .timestamp_opt(c.at, 0)
                .single()
                .map(|dt| dt.format("%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "—".to_string());
            let style = if selected {
                Style::new().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::new()
            };
            column_lines(
                vec![
                    Span::styled(
                        format!(" {when} "),
                        style.fg(if selected { Color::Black } else { theme::dim() }),
                    ),
                    Span::styled(
                        format!("{:<10} ", c.kind.label()),
                        style.fg(if selected {
                            Color::Black
                        } else {
                            theme::accent()
                        }),
                    ),
                ],
                &c.summary,
                style,
                27, // " MM-DD HH:MM:SS " + "{:<10} "
                text_w,
            )
        })
        .collect();
    // Walk back from the selection until the window is full, so the cursor
    // stays on screen however tall the wrapped entries above it are.
    let sel_i = s.net_history_sel.min(wrapped.len().saturating_sub(1));
    let mut first = sel_i;
    let mut used = wrapped[sel_i].len();
    while first > 0 && used + wrapped[first - 1].len() <= visible {
        first -= 1;
        used += wrapped[first].len();
    }
    let mut lines: Vec<Line> = Vec::new();
    let mut shown = 0usize;
    for entry in wrapped.iter().skip(first) {
        // Whole entries only — except one too tall for the pane by itself,
        // which is shown clipped rather than not at all.
        if !lines.is_empty() && lines.len() + entry.len() > visible {
            break;
        }
        lines.extend(entry.iter().cloned());
        shown += 1;
    }
    let content = scroll_cue(f, list_area, s.net_history.len(), first, shown.max(1));
    f.render_widget(Paragraph::new(lines), content);
    if detail_h > 0 {
        f.render_widget(Paragraph::new(detail), parts[1]);
    }
}

fn netinfo_details(f: &mut Frame, s: &AppState, area: Rect, focused: bool) {
    let n = &s.netinfo;
    // The location name rides in the title, like the Bandwidth panel's iface:
    // "Network · Home". Until a baseline exists there is nothing to say.
    // While one is still learning, the title says so with its progress —
    // otherwise "why is nothing relative here yet" is invisible until the
    // locations overlay is opened.
    let title = match &s.baseline {
        Some(b) if b.established() => format!("Network · {}", b.display_name()),
        Some(b) => format!(
            "Network · {} · learning {}/{}m",
            b.display_name(),
            b.samples,
            crate::baseline::MIN_SAMPLES
        ),
        None => "Network".to_string(),
    };
    let b = block(&title, focused);
    let inner = b.inner(area);
    f.render_widget(b, area);

    let kv = |k: &str, v: String| {
        Line::from(vec![
            Span::styled(format!("{k:<9}"), Style::new().fg(theme::dim())),
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

    // The address cursor: which of the panel's addresses [W] would ask about,
    // shown only while this pane holds it. Slots, not text, decide which
    // entry lights up — a gateway and a resolver are often the same
    // 192.168.1.1.
    use crate::app::NetSlot;
    let addrs = s.netinfo_addrs();
    let sel: Option<NetSlot> = (s.focus == Panel::NetInfo && s.sub_pane == SubPane::Primary)
        .then(|| {
            addrs
                .get(s.net_sel.min(addrs.len().saturating_sub(1)))
                .map(|a| a.slot)
        })
        .flatten();
    let hl = |slot: NetSlot, text: String| -> Span<'static> {
        if sel == Some(slot) {
            Span::styled(text, Style::new().fg(Color::Black).bg(Color::Cyan))
        } else {
            Span::raw(text)
        }
    };

    // Before the first netinfo sample lands.
    if n.iface.is_empty() {
        f.render_widget(
            Paragraph::new(Span::styled(
                "detecting network…",
                Style::new().fg(theme::dim()),
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
        Span::styled(format!("{:<9}", "type"), Style::new().fg(theme::dim())),
        Span::styled(n.medium.label(), Style::new().fg(medium_color(n.medium))),
    ];
    if !n.link_detail.is_empty() {
        type_row.push(Span::styled(
            format!(" · {}", n.link_detail),
            Style::new().fg(theme::text()),
        ));
    }
    if !n.dhcp_server.is_empty() {
        // A lease was found even when the OS didn't say "DHCP" — the lease
        // is the proof, so the word appears with it.
        if !n.link_detail.contains("DHCP") {
            type_row.push(Span::styled(" · DHCP", Style::new().fg(theme::text())));
        }
        type_row.push(Span::styled(" (", Style::new().fg(theme::text())));
        type_row.push(if sel == Some(NetSlot::Dhcp) {
            hl(NetSlot::Dhcp, n.dhcp_server.clone())
        } else {
            Span::styled(n.dhcp_server.clone(), Style::new().fg(theme::text()))
        });
        type_row.push(Span::styled(")", Style::new().fg(theme::text())));
    }

    let text_w = inner.width as usize;
    let label = |k: &str| Span::styled(format!("{k:<9}"), Style::new().fg(theme::dim()));

    // Interface addresses as individual spans (not one joined string), so
    // the address cursor can land on each; packed so multihomed lists still
    // wrap under their own column.
    let addr_list =
        |key: &str, list: &[String], slot: fn(usize) -> NetSlot| -> Vec<Line<'static>> {
            if list.is_empty() {
                return vec![Line::from(vec![label(key), Span::raw("-")])];
            }
            let groups = list
                .iter()
                .enumerate()
                .map(|(i, a)| vec![hl(slot(i), a.clone())])
                .collect();
            pack_groups(label(key), groups, text_w)
        };
    let mut lines = vec![kv("iface", iface), Line::from(type_row)];
    lines.extend(addr_list("ipv4", &n.ipv4, NetSlot::V4));
    lines.extend(addr_list("ipv6", &n.ipv6, NetSlot::V6));
    lines.push(kv("mac", dash(&n.mac)));

    // A tunnel hides the real path: the encapsulated hops never answer ICMP, so
    // an empty traceroute is expected rather than a fault. Say so instead of
    // leaving a bare red gateway unexplained.
    if let Some(vendor) = n.tunnel_label() {
        let mut row = vec![
            Span::styled(format!("{:<9}", "tunnel"), Style::new().fg(theme::dim())),
            Span::styled(vendor, Style::new().fg(theme::warn()).bold()),
        ];
        if !n.tunnel_iface.is_empty() {
            row.push(Span::styled(
                format!("  ({})", n.tunnel_iface),
                Style::new().fg(theme::text()),
            ));
        }
        lines.push(Line::from(row));
        lines.extend(pack_groups(
            label("gateway"),
            vec![vec![
                hl(NetSlot::Gateway, dash(&n.gateway_ip)),
                Span::raw(format!("  ({})", dash(&n.gateway_mac))),
            ]],
            text_w,
        ));
        // A split tunnel leaves the default route on the physical NIC, so the
        // gateway above is the real, reachable LAN gateway — internet traffic
        // simply never uses it. Don't mislabel it as the tunnel endpoint.
        lines.push(Line::from(Span::styled(
            if n.tunnel_is_split {
                "         LAN gateway — internet traffic bypasses it via the tunnel"
            } else {
                "         tunnel endpoint — hops beyond it are encapsulated"
            },
            Style::new().fg(theme::dim()),
        )));
    } else {
        let mut groups = vec![vec![
            hl(NetSlot::Gateway, dash(&n.gateway_ip)),
            Span::raw(format!("  ({})", dash(&n.gateway_mac))),
        ]];
        // Both families: name the v6 router too, so "IPv6 broken" has an
        // address to be checked against.
        if !n.gateway_ipv6.is_empty() && n.gateway_ipv6 != n.gateway_ip {
            groups.push(vec![
                Span::raw("· v6 "),
                hl(NetSlot::GatewayV6, n.gateway_ipv6.clone()),
            ]);
        }
        lines.extend(pack_groups(label("gateway"), groups, text_w));
    }

    // How the internet sees this machine — the address beyond the NAT. It is
    // discovered, not configured, so it appears once known.
    if let Some(t) = s
        .targets
        .iter()
        .find(|t| t.discovered && t.label.contains("public"))
    {
        lines.push(Line::from(vec![
            Span::styled(format!("{:<9}", "public"), Style::new().fg(theme::dim())),
            hl(NetSlot::Public, t.addr.to_string()),
        ]));
    }

    // The edge's view of this connection, when the /edge check is on and has
    // answered, split into what each fact is: the ISP is *whose network you
    // are on* — a first-class answer, not a clause — and the edge row is the
    // Cloudflare PoP serving you plus its own TCP measurement of this
    // machine (the far end saying how far away you are, no ICMP involved).
    if let Some(e) = &s.edge {
        if !e.isp.is_empty() {
            let mut spans = vec![
                Span::styled(format!("{:<9}", "isp"), Style::new().fg(theme::dim())),
                Span::styled(e.isp.clone(), Style::new().fg(theme::text())),
            ];
            if e.asn != 0 {
                spans.push(Span::styled(
                    format!(" (AS{})", e.asn),
                    Style::new().fg(theme::dim()),
                ));
            }
            lines.push(Line::from(spans));
        }
        let mut spans = vec![
            Span::styled(format!("{:<9}", "edge"), Style::new().fg(theme::dim())),
            Span::styled(e.colo_label(), Style::new().fg(theme::text())),
            Span::styled(" · nearest Cloudflare PoP", Style::new().fg(theme::dim())),
        ];
        if let Some(rtt) = e.tcp_rtt_ms {
            spans.push(Span::styled(
                format!(" · sees this machine at {rtt:.0}ms"),
                Style::new().fg(theme::text()),
            ));
        }
        lines.push(Line::from(spans));
    }

    // The clock, only when it is wrong: right is the expected state.
    if let Some(off) = s.clock.offset_ms()
        && off.abs() >= crate::verdict::thresholds::CLOCK_WARN_MS
    {
        lines.push(Line::from(vec![
            Span::styled(format!("{:<9}", "clock"), Style::new().fg(theme::dim())),
            Span::styled(
                crate::collectors::clock::describe_offset(off),
                Style::new().fg(if off.abs() >= crate::verdict::thresholds::CLOCK_BAD_MS {
                    Color::Red
                } else {
                    theme::warn()
                }),
            ),
            Span::styled(
                format!(" · via {}", s.clock.source()),
                Style::new().fg(theme::dim()),
            ),
        ]));
    }

    // A system proxy is worth knowing about whenever one is set: browsers take
    // it, octomon's checks don't.
    if let Some(p) = &s.proxy {
        use crate::app::FamilyProbe as FP;
        let mut row = vec![
            Span::styled(format!("{:<9}", "proxy"), Style::new().fg(theme::dim())),
            Span::styled(p.describe(), Style::new().fg(theme::warn())),
        ];
        match &s.http.via_proxy {
            FP::Ok(ms) => row.push(Span::styled(
                format!(" · web via proxy ok {ms:.0}ms"),
                Style::new().fg(Color::Green),
            )),
            FP::Fail(r) => row.push(Span::styled(
                format!(" · web via proxy FAILED ({r})"),
                Style::new().fg(Color::Red),
            )),
            _ => {}
        }
        lines.push(Line::from(row));
    }

    // Path MTU, only when it is narrower than the interface or broken. A
    // black-hole reading taken while the path drops most packets is loss
    // wearing a costume — same gate as the analysis, so the two never argue.
    if let Some(p) = &s.pmtu
        && (p.blackhole
            || p.path_mtu
                .zip(p.iface_mtu)
                .is_some_and(|(path, iface)| path < iface))
    {
        let (text, color) = match crate::verdict::pmtu_gated(s) {
            Some(reason) => (format!("not judged — {reason}"), theme::dim()),
            None => (
                crate::collectors::pmtu::describe(p),
                if p.blackhole {
                    Color::Red
                } else {
                    theme::warn()
                },
            ),
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{:<9}", "mtu"), Style::new().fg(theme::dim())),
            Span::styled(text, Style::new().fg(color)),
        ]));
    }

    // Only when there is something to say: ordinary NAT is not news.
    if let Some((kind, via)) = s.nat_kind() {
        lines.push(Line::from(vec![
            Span::styled(format!("{:<9}", "nat"), Style::new().fg(theme::dim())),
            Span::styled(kind.label(), Style::new().fg(theme::warn())),
            Span::styled(
                format!(" · hop 2 is {via} · {}", kind.advice()),
                Style::new().fg(theme::text()),
            ),
        ]));
    }

    lines.extend(dns_lines(s, text_w, sel));
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
                Span::styled(format!("{:<9}", "ssid"), Style::new().fg(theme::dim())),
                Span::styled(
                    "hidden — needs Location Services",
                    Style::new().fg(theme::dim()).italic(),
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
                3..=6 => theme::warn(),
                _ => Color::Red,
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{:<9}", "airspace"), Style::new().fg(theme::dim())),
                Span::styled(
                    format!("{} co-ch · {} overlap", c.co_channel, c.overlapping),
                    Style::new().fg(color),
                ),
                Span::styled(
                    format!(" · {} nearby", c.total),
                    Style::new().fg(theme::dim()),
                ),
            ]));
        }
    } else if n.medium == LinkMedium::WiFi {
        lines.push(Line::from(Span::styled(
            "gathering Wi-Fi details…",
            Style::new().fg(theme::dim()),
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
            Style::new().fg(theme::dim()),
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
                Style::new().fg(theme::warn()),
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
                    if probe.reference {
                        format!("{} (reference)", probe.server)
                    } else {
                        probe.server.to_string()
                    },
                    Style::new().fg(theme::text()),
                )),
                Line::from(vec![
                    Span::styled(format!("{last:<10}"), Style::new().fg(color).bold()),
                    Span::styled(mean, Style::new().fg(theme::dim())),
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
        let slots = probe.hist.tail_slots(spark_w as usize);
        if slots.is_empty() {
            continue;
        }
        let max = slots
            .iter()
            .filter_map(|v| v.map(|ms| ms.max(0.0) as u64))
            .max()
            .unwrap_or(1)
            .max(1);
        // Colour each bar by how slow that individual answer was, like the
        // quality sparklines — a graph tinted wholesale by the *latest*
        // reading repaints history it isn't entitled to. A query that timed
        // out is drawn red at full height rather than as a 0 ms answer.
        let bars: Vec<SparklineBar> = slots
            .iter()
            .map(|slot| match slot {
                Some(ms) => {
                    SparklineBar::from(ms.max(0.0) as u64).style(Style::new().fg(dns_color(*ms)))
                }
                None => SparklineBar::from(max).style(Style::new().fg(Color::Red)),
            })
            .collect();
        f.render_widget(
            Sparkline::default()
                .data(bars)
                .max(max)
                .bar_set(s.bar_set.clone()),
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
/// The `dns` rows: each resolver with its reading is one indivisible group —
/// a line break lands between resolvers, never between an address and its
/// reading — and continuation lines stay in the value column.
fn dns_lines(s: &AppState, width: usize, sel: Option<crate::app::NetSlot>) -> Vec<Line<'static>> {
    use crate::app::NetSlot;
    let label = Span::styled(format!("{:<9}", "dns"), Style::new().fg(theme::dim()));
    if s.netinfo.dns.is_empty() {
        return vec![Line::from(vec![label, Span::raw("-")])];
    }

    let mut groups: Vec<Vec<Span<'static>>> = Vec::new();
    for (i, server) in s.netinfo.dns.iter().enumerate() {
        // The address cursor, when it sits on this resolver — [W]'s subject.
        let mut g = vec![if sel == Some(NetSlot::Dns(i)) {
            Span::styled(
                server.clone(),
                Style::new().fg(Color::Black).bg(Color::Cyan),
            )
        } else {
            Span::raw(server.clone())
        }];
        let probe = s.dns.iter().find(|p| p.server.to_string() == *server);
        match probe {
            // A failing resolver is the headline, not its latency.
            Some(p) if !p.status.is_empty() && p.last_ms.is_none() => {
                g.push(Span::styled(
                    format!(" ({})", p.status),
                    Style::new().fg(Color::Red).bold(),
                ));
            }
            Some(p) => match p.last_ms {
                Some(ms) => g.push(Span::styled(
                    format!(" ({ms:.0}ms)"),
                    Style::new().fg(dns_color(ms)),
                )),
                None => g.push(Span::styled(" (…)", Style::new().fg(theme::dim()))),
            },
            None => g.push(Span::styled(" (…)", Style::new().fg(theme::dim()))),
        }
        if probe.is_some_and(|p| p.hijack == Some(true)) {
            g.push(Span::styled(
                " ⚠ redirects",
                Style::new().fg(Color::Red).bold(),
            ));
        }
        groups.push(g);
    }
    // The public reference resolver, for contrast — dimmed, it isn't ours.
    if let Some(r) = s.dns.iter().find(|p| p.reference) {
        let reading = match r.last_ms {
            Some(ms) => format!("{ms:.0}ms"),
            None if !r.status.is_empty() => r.status.clone(),
            None => "…".to_string(),
        };
        let color = if r.last_ms.is_none() && !r.status.is_empty() {
            theme::warn()
        } else {
            theme::dim()
        };
        // The server as its own span, so the address cursor can land on it.
        let mut g = vec![
            Span::styled("ref ", Style::new().fg(color)),
            if sel == Some(NetSlot::RefDns) {
                Span::styled(
                    r.server.to_string(),
                    Style::new().fg(Color::Black).bg(Color::Cyan),
                )
            } else {
                Span::styled(r.server.to_string(), Style::new().fg(color))
            },
            Span::styled(format!(" ({reading})"), Style::new().fg(color)),
        ];
        if r.hijack == Some(true) {
            g.push(Span::styled(
                " ⚠ redirects",
                Style::new().fg(Color::Red).bold(),
            ));
        }
        groups.push(g);
    }
    // The search domain: what "nas" expands to, and what only the LAN's own
    // resolver can answer — the thing a failing local resolver takes away.
    if !s.netinfo.dns_search.is_empty() {
        groups.push(vec![Span::styled(
            format!("search {}", s.netinfo.dns_search.join(", ")),
            Style::new().fg(theme::dim()),
        )]);
    }

    pack_groups(label, groups, width)
}

/// Pack span groups into lines under a 9-column label, continuing under the
/// value column; a break never splits a group. Shared by the dns row and the
/// Network panel's address lists, which highlight individual entries and so
/// cannot go through plain-text wrapping.
fn pack_groups(
    label: Span<'static>,
    groups: Vec<Vec<Span<'static>>>,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines: Vec<Line> = Vec::new();
    let mut cur: Vec<Span> = vec![label];
    let mut cur_w = 9usize;
    for g in groups {
        let g_w: usize = g.iter().map(|sp| sp.width()).sum();
        if cur_w > 9 && cur_w + 2 + g_w > width {
            lines.push(Line::from(std::mem::take(&mut cur)));
            cur = vec![Span::raw(" ".repeat(9))];
            cur_w = 9;
        }
        if cur_w > 9 {
            cur.push(Span::raw("  "));
            cur_w += 2;
        }
        cur_w += g_w;
        cur.extend(g);
    }
    lines.push(Line::from(cur));
    lines
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
        FP::NotRun => Span::styled(format!("{name} …"), Style::new().fg(theme::dim())),
        FP::NotApplicable => Span::styled(format!("{name} n/a"), Style::new().fg(theme::dim())),
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
        Span::styled(format!("{:<9}", "http"), Style::new().fg(theme::dim())),
        span(&s.http.v4, "v4"),
        Span::styled(" · ", Style::new().fg(theme::dim())),
        span(&s.http.v6, "v6"),
        Span::styled(
            format!("  ({})", s.http.provider),
            Style::new().fg(theme::dim()),
        ),
    ]))
}

/// Resolver latency thresholds: a cached answer should be near the RTT to the
/// resolver, so tens of ms is fine and hundreds is not.
fn dns_color(ms: f64) -> Color {
    match ms {
        v if v < th::DNS_WARN_MS => Color::Green,
        v if v < th::DNS_BAD_MS => theme::warn(),
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
        h.tail_slots(want).into_iter().flatten().collect()
    };
    let down = tail(&tp.down_hist);
    let up = tail(&tp.up_hist);
    let len = down.len().min(up.len());
    if len == 0 {
        f.render_widget(
            Paragraph::new(Span::styled(
                " link utilisation — collecting…",
                Style::new().fg(theme::dim()),
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
        .block(Block::new().title(Span::styled(title, Style::new().fg(theme::dim()))))
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
        r if r >= -72 => theme::warn(),
        _ => Color::Red,
    };
    // Both series share a normalised 0..1 y-axis so their trends overlay: RSSI
    // as signal quality (−30 best … −100 worst); tx-rate against its own peak.
    let want = (area.width as usize).saturating_mul(2).max(20);
    let tail = |h: &crate::app::History| -> Vec<f64> {
        h.tail_slots(want).into_iter().flatten().collect()
    };
    let rssi = tail(&sig.rssi_hist);
    let tx = tail(&sig.tx_hist);
    let len = rssi.len().min(tx.len());
    if len == 0 {
        return;
    }
    // Not every platform reports a bitrate — Linux's /proc/net/wireless has no
    // such field. Drawing a flat zero line and a "tx 0 Mb/s" title would read as
    // a dead link rather than a missing measurement, so the series is dropped.
    let tx_max = tx.iter().copied().fold(0.0_f64, f64::max);
    let has_tx = tx_max > 0.0;
    // Each figure is drawn in its own series' colour, so naming the colour in
    // the text ("(cyan)") is redundant — and wrong if the palette ever changes.
    let mut title = vec![
        Span::styled(" signal ", Style::new().fg(theme::dim())),
        Span::styled(
            format!("{} dBm", sig.rssi_dbm),
            Style::new().fg(sig_color).bold(),
        ),
    ];
    if has_tx {
        title.push(Span::styled(" · tx ", Style::new().fg(theme::dim())));
        title.push(Span::styled(
            format!("{:.0} Mb/s ", sig.tx_rate_mbps),
            Style::new().fg(theme::accent()).bold(),
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
                .style(Style::new().fg(theme::accent()))
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
            .unfilled_style(Style::new().fg(theme::dim())),
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
            .unfilled_style(Style::new().fg(theme::dim())),
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
            Span::styled("load ", Style::new().fg(theme::dim())),
            Span::styled(
                format!("{l1:.2} {l5:.2} {l15:.2}"),
                // Load beyond core count means work is queueing for CPU.
                Style::new().fg(if l1 > cores {
                    Color::Red
                } else if l1 > cores * 0.7 {
                    theme::warn()
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
        load_spans.push(Span::styled(label, Style::new().fg(theme::dim())));
        load_spans.push(Span::styled(
            fmt_bytes(v.swap_used),
            Style::new().fg(theme::warn()),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(load_spans)), parts[2]);

    f.render_widget(Paragraph::new(link_error_line(&s.link_errors)), parts[3]);

    // Thermal state, when the platform reports it.
    if !v.thermal.is_empty() || !v.power_source.is_empty() {
        let mut spans = vec![Span::styled("power ", Style::new().fg(theme::dim()))];
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
                Style::new().fg(theme::text()),
            ));
        }
        f.render_widget(Paragraph::new(Line::from(spans)), parts[4]);
    }

    if core_rows > 0 {
        core_grid(f, &v.cores, parts[5]);
    }

    // CPU history sparkline (uses the remaining space), with available
    // memory drawn over it as a line: the two starve a machine differently
    // (a pegged core vs. swap death) and reading them against each other is
    // the question — "did memory dive when the CPU spiked?".
    let spark = Sparkline::default()
        .max(100)
        .data(v.cpu_hist.tail_u64(parts[6].width as usize))
        .bar_set(s.bar_set.clone())
        .style(Style::new().fg(theme::warn()))
        .block(Block::new().title(Line::from(vec![
            Span::styled(" cpu history ", Style::new().fg(theme::dim())),
            Span::styled("· avail mem ", Style::new().fg(P95_COLOR)),
        ])));
    f.render_widget(spark, parts[6]);
    // The line rides the same rect: Chart plots only its dots, so the bars
    // stay visible everywhere the line isn't.
    let graph = Rect {
        y: parts[6].y + 1,
        height: parts[6].height.saturating_sub(1),
        ..parts[6]
    };
    if graph.height >= 1 && graph.width >= 4 {
        let want = graph.width as usize * 2;
        let avail: Vec<(f64, f64)> = {
            let mut vals: Vec<f64> = v
                .pressure_hist
                .successes()
                .rev()
                .take(want)
                .map(|p| (100.0 - p).clamp(0.0, 100.0))
                .collect();
            vals.reverse();
            vals.iter()
                .enumerate()
                .map(|(i, &m)| (i as f64, m))
                .collect()
        };
        if avail.len() >= 2 {
            let xmax = (avail.len() - 1) as f64;
            let ds = Dataset::default()
                .marker(s.graph_marker)
                .graph_type(GraphType::Line)
                .style(Style::new().fg(P95_COLOR))
                .data(&avail);
            let chart = Chart::new(vec![ds])
                .x_axis(Axis::default().bounds([0.0, xmax]))
                .y_axis(Axis::default().bounds([0.0, 100.0]));
            f.render_widget(chart, graph);
        }
    }
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
            Style::new().fg(theme::dim()),
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
                .unfilled_style(Style::new().fg(theme::dim())),
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
    let mut spans = vec![Span::styled("errs ", Style::new().fg(theme::dim()))];
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
            theme::warn()
        }),
    ));
    // A rate means nothing without knowing whether the link was busy.
    spans.push(Span::styled(
        format!("  {pct:.2}% of packets"),
        Style::new().fg(theme::dim()),
    ));
    Line::from(spans)
}

/// One-line speed-test status/results shown atop the bandwidth panel.
fn speedtest_line(s: &AppState) -> Line<'static> {
    let st = &s.speedtest;
    let label = Span::styled("speedtest ", Style::new().fg(theme::dim()));
    if !s.speedtest_enabled {
        return Line::from(vec![
            label,
            Span::styled("disabled", Style::new().fg(theme::dim())),
        ]);
    }
    match &st.status {
        SpeedStatus::Idle => Line::from(vec![
            label,
            Span::styled("[s]", Style::new().fg(theme::accent())),
            Span::raw(" run"),
        ]),
        SpeedStatus::Running => Line::from(vec![
            label,
            Span::styled("running…", Style::new().fg(theme::warn()).bold()),
        ]),
        SpeedStatus::Done => {
            let ago = st
                .last_run
                .map(|t| format!("  ({} ago)", fmt_ago(t.elapsed().as_secs())))
                .unwrap_or_default();
            let mut spans = vec![
                label,
                Span::styled(
                    format!("{} ", st.provider),
                    Style::new().fg(theme::accent()),
                ),
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
            spans.push(Span::styled(ago, Style::new().fg(theme::dim())));
            spans.push(Span::styled("  [s] rerun", Style::new().fg(theme::dim())));
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
                Span::styled("  [s] retry", Style::new().fg(theme::dim())),
            ])
        }
    }
}

// --- formatting & color helpers -------------------------------------------

/// A learned speed, compact enough for the locations overlay's columns:
/// "943M", "1.2G", "750K" — the arrows and slot label carry the rest.
fn fmt_speed_compact(mbps: f64) -> String {
    if mbps >= 10_000.0 {
        format!("{:.0}G", mbps / 1000.0)
    } else if mbps >= 1000.0 {
        format!("{:.1}G", mbps / 1000.0)
    } else if mbps >= 1.0 {
        format!("{mbps:.0}M")
    } else {
        format!("{:.0}K", mbps * 1000.0)
    }
}

/// An age as people read one: seconds only while they are still short,
/// then the minutes/hours/days ladder ("2m", "1h 5m").
fn fmt_ago(secs: u64) -> String {
    if secs < 100 {
        format!("{secs}s")
    } else {
        crate::util::fmt_minutes(secs / 60)
    }
}

fn fmt_ms(v: Option<f64>) -> String {
    match v {
        Some(ms) => format!("{ms:.1}ms"),
        None => "—".to_string(),
    }
}

fn fmt_mbps(v: Option<f64>) -> String {
    match v {
        Some(m) => crate::util::fmt_mbps(m),
        None => "—".to_string(),
    }
}

/// One live rate, in the configured unit family: bytes (KB/s, MB/s — what a
/// file transfer reads as) or bits (Kb/s, Mb/s — what speed tests and ISP
/// plans are sold in). `byte_rate` is always bytes/sec on the way in.
fn fmt_rate(byte_rate: f64, bits: bool) -> String {
    if bits {
        let bps = byte_rate * 8.0;
        if bps >= 1_000_000.0 {
            format!("{:.1} Mb/s", bps / 1_000_000.0)
        } else if bps >= 1_000.0 {
            format!("{:.1} Kb/s", bps / 1_000.0)
        } else {
            format!("{bps:.0} b/s")
        }
    } else if byte_rate >= 1_000_000.0 {
        format!("{:.1} MB/s", byte_rate / 1_000_000.0)
    } else if byte_rate >= 1_000.0 {
        format!("{:.1} KB/s", byte_rate / 1_000.0)
    } else {
        format!("{byte_rate:.0} B/s")
    }
}

/// The bits-per-second twin of a byte rate, so the live traffic reads against
/// the speed test's Mb/s ("am I using all of my 5.8?") without mental ×8.
/// Empty below 1 Mb/s, where the comparison isn't being made — and in bits
/// mode, where the main figure already says it.
fn fmt_mbits(byte_rate: f64, bits: bool) -> String {
    let mbps = byte_rate * 8.0 / 1e6;
    if !bits && mbps >= 1.0 {
        format!(" ({mbps:.1} Mb/s)")
    } else {
        String::new()
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

/// Colour a single round-trip sample against the path's reference floor (see
/// [`crate::verdict::rtt_grade`]). Unlike [`latency_color`] this judges one
/// measurement in isolation, so a trace can show what each moment looked like.
fn rtt_color(ms: f64, reference_ms: Option<f64>) -> Color {
    match crate::verdict::rtt_grade(ms, reference_ms) {
        crate::verdict::RttGrade::Good => Color::Green,
        crate::verdict::RttGrade::Warn => theme::warn(),
        crate::verdict::RttGrade::Bad => Color::Red,
    }
}

/// Series colours for the latency charts (the main line is [`theme::accent`]).
/// Deliberately outside the green/yellow/red scale, which means "how bad is
/// this" everywhere else — a green trace line would read as a verdict rather
/// than as a series.
const P95_COLOR: Color = Color::Magenta;

/// A target row's colour: loss first (absolute — packets have no "normal"),
/// then the latest round trip against the path's own reference floor.
/// `normal_loss` is the location's learned loss for this kind of path: on a
/// network whose weather is lossy (plane, hotel), only loss worse than usual
/// *here* reads as trouble — same contract as [`crate::verdict::loss_grade`].
fn latency_color(
    last: Option<f64>,
    loss: f64,
    reference_ms: Option<f64>,
    normal_loss: Option<f64>,
) -> Color {
    match crate::verdict::loss_grade(loss, normal_loss) {
        crate::verdict::RttGrade::Bad => return Color::Red,
        crate::verdict::RttGrade::Warn => return theme::warn(),
        crate::verdict::RttGrade::Good => {}
    }
    match last {
        Some(ms) => rtt_color(ms, reference_ms),
        // The very last probe went unanswered on a path whose loss is within
        // its (lossy) normal: a gap, not an alarm — red here would repaint
        // half the rows every tick on such a network.
        None if normal_loss.is_some_and(|n| n >= th::LOSS_BAD_PCT) => theme::text(),
        None => Color::Red,
    }
}

/// Colour the link type so a tunnelled default route stands out — it changes how
/// every other reading on the panel should be read.
fn medium_color(m: LinkMedium) -> Color {
    match m {
        LinkMedium::Tunnel => theme::warn(),
        LinkMedium::Unknown => theme::dim(),
        _ => theme::bright(),
    }
}

fn usage_color(pct: f32) -> Color {
    if pct >= th::USAGE_BAD_PCT {
        Color::Red
    } else if pct >= th::USAGE_WARN_PCT {
        theme::warn()
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
            symptom: false,
            since: None,
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

        // Degraded-but-usable is note-class but is the connection's real
        // state: its own headline, never "connection healthy".
        let mut usable = finding(Severity::Info);
        usable.cause = crate::verdict::Cause::UsableDegraded;
        usable.summary =
            "connection degraded but usable — heavy packet loss, web traffic still getting through"
                .into();
        s.verdict.current = Verdict::Problems(vec![usable]);
        let out = draw(&s, 120, 24);
        assert!(out.contains("degraded but usable"), "got: {out}");
        assert!(!out.contains("connection healthy"));
    }

    #[test]
    fn zoom_reveals_what_the_tables_truncate() {
        use crate::app::{ProcBandwidth, ProcDetail, ZoomView};
        let mut s = AppState::new(vec![]);
        s.focus = Panel::Bandwidth;
        s.processes = vec![ProcBandwidth {
            name: "com.apple.WebKit.Networking".into(),
            pid: 4242,
            down_bps: 900_000.0,
            down_bytes: 1_300_000_000,
            total_bytes: 1_300_000_000,
            ..Default::default()
        }];
        s.proc_details.insert(
            4242,
            ProcDetail {
                exe: "/System/Library/Frameworks/WebKit.framework/XPCServices/helper".into(),
                cmd: String::new(),
                user: "simon".into(),
                parent: "Safari (410)".into(),
                started: "08-24 07:12".into(),
            },
        );
        s.fullscreen = true;
        s.overlay = Overlay::Zoom;
        s.zoom_view = ZoomView::Processes;
        let out = draw(&s, 160, 40);
        // The name the split view showed as "com.apple.WebKit.Netw…".
        assert!(out.contains("com.apple.WebKit.Networking"), "{out}");
        assert!(out.contains("4242"), "pid: {out}");
        assert!(out.contains("WebKit.framework"), "path: {out}");
        // Who runs it, what launched it, since when.
        assert!(out.contains("Safari (410)"), "parent: {out}");
        assert!(out.contains("simon"), "user: {out}");
        assert!(out.contains("08-24 07:12"), "started: {out}");
        assert!(out.contains("Processes · zoom"));
        // The band replaces the tables, not the graphs: the throughput
        // strip's titles stay on screen.
        assert!(out.contains("↓ down"), "graphs stay: {out}");
        // The compact "now" splits three ways here: each direction and the
        // combined rate, all present as sortable headers.
        assert!(out.contains("now↓"), "{out}");
        assert!(out.contains("now↑"), "{out}");
        assert!(out.contains("now↕"), "{out}");
        // A sort on the zoom-only now↑ key puts its arrow on that column.
        s.bw_sort = Some((8, true));
        assert!(draw(&s, 160, 40).contains("now↑▼"));
        s.bw_sort = None;

        // The '/' filter names itself in the title, and a filter that
        // matches nothing says so rather than drawing an empty table.
        s.bw_filter = "webkit".into();
        let out = draw(&s, 160, 40);
        assert!(out.contains("⌕ webkit"), "{out}");
        assert!(out.contains("com.apple.WebKit.Networking"), "{out}");
        s.bw_filter = "zzz".into();
        let out = draw(&s, 160, 40);
        assert!(out.contains("no processes match ⌕ zzz"), "{out}");
        s.bw_filter.clear();

        // Speed tests zoomed: the server and network the compact table
        // has no room for become columns.
        s.zoom_view = ZoomView::Speedtests;
        s.speed_history.push(crate::store::SpeedRecord {
            at: 1_700_000_000,
            provider: "Cloudflare".into(),
            down_mbps: 5.8,
            up_mbps: 5.2,
            idle_ms: Some(32.0),
            loaded_ms: Some(156.0),
            network: Some("Sheraton Orlando".into()),
            medium: Some("Wi-Fi (wireless)".into()),
            server: Some("MIA (edge)".into()),
        });
        let out = draw(&s, 160, 40);
        assert!(out.contains("MIA (edge)"), "{out}");
        assert!(out.contains("Sheraton Orlando"), "{out}");
        assert!(out.contains("server"), "{out}");
        assert!(out.contains("Speed Test History · zoom"), "{out}");
    }

    /// The compact talkers table narrows under the '/' filter, announces it
    /// in the panel title, and explains an empty result instead of drawing a
    /// blank table.
    #[test]
    fn compact_talkers_filter_narrows_and_reports_no_match() {
        use crate::app::{ProcBandwidth, ProcStatus};
        let mut s = AppState::new(vec![]);
        s.focus = Panel::Bandwidth;
        s.proc_status = ProcStatus::Supported;
        s.processes = vec![
            ProcBandwidth {
                name: "firefox".into(),
                pid: 1,
                ..Default::default()
            },
            ProcBandwidth {
                name: "rsync".into(),
                pid: 2,
                ..Default::default()
            },
        ];
        s.bw_filter = "fire".into();
        let out = draw(&s, 120, 30);
        assert!(out.contains("firefox"));
        assert!(!out.contains("rsync"), "{out}");
        assert!(out.contains("⌕ fire"), "title carries the filter: {out}");
        s.bw_filter = "zzz".into();
        let out = draw(&s, 120, 30);
        assert!(out.contains("no processes match ⌕ zzz"), "{out}");
    }

    #[test]
    fn a_marker_lands_in_the_events_overlay_with_its_category() {
        let mut s = AppState::new(vec![]);
        s.push_event(
            Severity::Info,
            crate::app::EventCategory::Marker,
            "⚑ moved to the meeting room".into(),
        );
        s.overlay = Overlay::Events;
        let out = draw(&s, 120, 24);
        assert!(out.contains("marker"), "category column: {out}");
        assert!(out.contains("moved to the meeting room"));
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
        assert!(
            out.contains("cpu usage 8%") && out.contains("avail memory"),
            "healthy rungs carry their data"
        );
        assert!(
            out.contains("[m] to watch"),
            "unknown rungs say how to fill them"
        );
        // The absolute read rides along: green rungs say "normal for here",
        // this line says what that normal is worth anywhere.
        assert!(
            out.contains("performance") && out.contains("excellent"),
            "the absolute performance line is present"
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
        assert!(out.contains("speed 310M↓/28M↑"));
        assert!(out.contains("40m healthy"));
        assert!(out.contains("● current"), "the active network is marked");
        assert!(
            !out.contains("learning from scratch"),
            "both entries have learned something"
        );
        // A blank entry — just re-added after a delete — says so loudly.
        s.locations.as_mut().unwrap()[1].1.samples = 0;
        assert!(draw(&s, 120, 30).contains("learning from scratch"));
        assert!(out.contains("d deletes"), "delete hint in the footer");
        assert!(out.contains("press L or Esc to close"));

        // A non-current entry shows when it was last seen, in the slot
        // "● current" occupies on the active one — which never shows a date,
        // however fresh its own timestamp is.
        let ts = 1_756_000_000; // 2025-08-24 UTC
        for (_, b) in s.locations.as_mut().unwrap() {
            b.last_seen = Some(ts);
        }
        let expect = chrono::DateTime::from_timestamp(ts, 0)
            .unwrap()
            .with_timezone(&chrono::Local)
            .format("· seen %Y-%m-%d")
            .to_string();
        let out = draw(&s, 120, 30);
        assert!(out.contains(&expect), "{out}");
        assert_eq!(out.matches("· seen").count(), 1, "{out}");
        assert!(out.contains("● current"), "{out}");
    }

    /// After an outage ends, the windowed loss figure is momentum, not the
    /// present: once the recent probes are clean it carries a ↓ so the eye
    /// reads "draining out", not "still broken".
    #[test]
    fn recovered_loss_wears_the_aging_arrow() {
        let mut s = AppState::new(vec![]);
        s.window_secs = 60;
        let mut t = crate::app::TargetStat::new(
            "Cloudflare".into(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
        );
        // A 30 s outage, then 25 clean seconds: the 1m window still holds
        // the losses, the recent slice is spotless.
        for _ in 0..10 {
            t.record_reply(10.0);
        }
        for _ in 0..30 {
            t.record_loss();
        }
        for _ in 0..25 {
            t.record_reply(10.0);
        }
        s.targets.push(t);
        let out = draw(&s, 160, 40);
        assert!(out.contains("%↓"), "aging loss carries the arrow");

        // Mid-outage — recent probes still failing — no arrow: the loss is
        // current, not history.
        let mut s2 = AppState::new(vec![]);
        s2.window_secs = 60;
        let mut t2 = crate::app::TargetStat::new(
            "Cloudflare".into(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
        );
        for _ in 0..30 {
            t2.record_reply(10.0);
        }
        for _ in 0..10 {
            t2.record_loss();
        }
        s2.targets.push(t2);
        let out = draw(&s2, 160, 40);
        assert!(!out.contains("%↓"), "live loss has no arrow");
    }

    /// Total outage: the RTT columns must not keep serving frozen pre-outage
    /// figures as if they were current — they dash out, and the title stops
    /// quoting jit/sd for a target that is not answering.
    #[test]
    fn outage_dashes_out_the_frozen_stats() {
        let mut s = AppState::new(vec![]);
        s.window_secs = 30;
        let mut t = crate::app::TargetStat::new(
            "Cloudflare".into(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
        );
        for _ in 0..30 {
            t.record_reply(10.0);
        }
        for _ in 0..30 {
            t.record_loss();
        }
        s.targets.push(t);
        let out = draw(&s, 160, 40);
        assert!(
            !out.contains("10.0ms"),
            "pre-outage figures must not read as current"
        );
        assert!(out.contains("not answering"));

        // The same figures come back the moment the path answers again.
        s.targets[0].record_reply(10.0);
        let out = draw(&s, 160, 40);
        assert!(out.contains("10.0ms"));
        assert!(!out.contains("not answering"));
    }

    /// Losses hold their slot, so the line breaks where they are and a run of
    /// them has width — pre-outage samples cannot slide up against post-outage
    /// ones and hide the gap entirely.
    #[test]
    fn latency_runs_break_at_the_misses() {
        let runs =
            LatencyRuns::from_slots(&[Some(10.0), Some(11.0), None, None, None, Some(12.0), None]);
        assert_eq!(runs.len, 7);
        assert_eq!(runs.runs.len(), 2, "two unbroken runs of replies");
        assert_eq!(runs.runs[0].len(), 2);
        assert_eq!(runs.runs[1], vec![(5.0, 12.0)]);
        assert_eq!(runs.gaps, vec![(2.0, 4.0), (6.0, 6.0)]);
        assert_eq!(runs.trailing, 1, "the miss at the edge is still running");
        // Gaps ride the axis floor: never plotted as a 0 ms measurement.
        assert_eq!(runs.gap_bands()[0], [(2.0, 0.0), (4.0, 0.0)]);

        // A window that ends on a reply is not an outage.
        let ok = LatencyRuns::from_slots(&[None, Some(9.0)]);
        assert_eq!(ok.trailing, 0);
        assert_eq!(ok.gaps, vec![(0.0, 0.0)]);
        assert!(ok.has_samples());
        assert!(!LatencyRuns::from_slots(&[None, None]).has_samples());
    }

    /// The plane case: the graph must not sit there drawing a healthy line
    /// out of pre-outage samples. The floor goes red for the length of the
    /// outage and the title says how long it has been running.
    #[test]
    fn a_dead_path_paints_the_graph_floor_red() {
        let mut s = AppState::new(vec![crate::app::TargetStat::new(
            "Cloudflare".into(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
        )]);
        s.focus = Panel::Quality;
        s.fullscreen = true;
        for _ in 0..60 {
            s.targets[0].record_reply(20.0);
        }

        // Plotted braille cells of a given colour: the gap band is the only
        // red one, the p95 reference line the only one in its own colour.
        let marks = |s: &AppState, color: Color| -> usize {
            let mut t = Terminal::new(TestBackend::new(120, 30)).unwrap();
            t.draw(|f| render(f, s)).unwrap();
            let buf = t.backend().buffer();
            buf.content()
                .iter()
                .filter(|c| {
                    c.fg == color
                        && c.symbol()
                            .chars()
                            .next()
                            .is_some_and(|ch| ('\u{2801}'..='\u{28ff}').contains(&ch))
                })
                .count()
        };
        assert_eq!(marks(&s, Color::Red), 0, "a healthy path draws no gap band");
        assert!(marks(&s, P95_COLOR) > 0, "p95 rides across a live chart");

        for _ in 0..120 {
            s.targets[0].record_loss();
        }
        assert!(marks(&s, Color::Red) > 0, "the outage paints the floor red");
        // Frozen p95 / jitter reference lines describe a period that ended.
        assert_eq!(marks(&s, P95_COLOR), 0, "stale reference lines are dropped");
        let out = draw(&s, 120, 30);
        assert!(
            out.contains("no replies for 2m"),
            "the graph title says how long"
        );
    }

    /// The session strip: the whole run as one unlabelled bar above the
    /// footer, edge to edge, oldest left, now right, and a red block wherever
    /// the connection was down.
    #[test]
    fn session_strip_carries_the_whole_run_above_the_footer() {
        use crate::session::SessionState;
        let mut s = AppState::new(vec![]);
        // Ten minutes fine, one minute down, five minutes fine again.
        for _ in 0..600 {
            s.session.record(SessionState::Healthy, None);
        }
        for _ in 0..60 {
            s.session.record(SessionState::Down, None);
        }
        for _ in 0..300 {
            s.session.record(SessionState::Healthy, None);
        }

        let (w, h) = (120u16, 30u16);
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| render(f, &s)).unwrap();
        let buf = t.backend().buffer();
        let row = |y: u16| -> String { (0..w).map(|x| buf[(x, y)].symbol()).collect() };

        // Second from the bottom: the footer keeps the last row.
        let strip = row(h - 2);
        assert!(row(h - 1).contains("[y] analysis"), "footer still last");
        // Nothing but bar: no label, no clock (the header counts the run),
        // no gaps at either end.
        assert!(
            strip.chars().all(|c| "▁▄▆█".contains(c)),
            "the strip is bar and nothing else: {strip}"
        );
        assert_eq!(strip.chars().count(), w as usize, "edge to edge");
        // Down draws the full block, healthy the half one: the strip reads
        // without colour as well as with it.
        assert!(strip.contains('█') && strip.contains('▄'));

        let colored =
            |y: u16, c: Color| -> Vec<u16> { (0..w).filter(|x| buf[(*x, y)].fg == c).collect() };
        let green = colored(h - 2, Color::Green);
        let red = colored(h - 2, Color::Red);
        assert!(!green.is_empty() && !red.is_empty());
        // The outage sits where it happened: after the first stretch of green
        // and before the last.
        let (first_red, last_red) = (red[0], red[red.len() - 1]);
        assert!(green[0] < first_red, "the good start is left of the outage");
        assert!(
            green[green.len() - 1] > last_red,
            "and the recovery is right of it"
        );
    }

    /// The bar answers "what was that?" — the cursor picks a column, and the
    /// footer says which minutes it covers, how they read and what was wrong.
    #[test]
    fn the_bar_cursor_reads_out_the_column_it_is_on() {
        use crate::session::SessionState;
        use crate::verdict::Cause;
        let mut s = AppState::new(vec![]);
        for _ in 0..300 {
            s.session.record(SessionState::Healthy, None);
        }
        for _ in 0..120 {
            s.session
                .record(SessionState::Down, Some(Cause::GatewayLan));
        }
        for _ in 0..60 {
            s.session.record(SessionState::Healthy, None);
        }

        let (w, h) = (120u16, 30u16);
        // The footer row alone: "down" also appears in the Bandwidth panel,
        // and the question here is what the readout says.
        let readout = |s: &AppState| -> String {
            let out = draw(s, w, h);
            out.chars()
                .skip((h as usize - 1) * w as usize)
                .collect::<String>()
        };

        // With no cursor the footer is the analysis line, as ever.
        assert!(readout(&s).contains("[y] analysis"));

        // On the newest column: healthy again, and no cause to name.
        let cap = bar_cursor_cap(&s, w, h).expect("the bar is drawn");
        s.bar_cursor = Some(cap);
        let line = readout(&s);
        assert!(line.contains("healthy"), "state of the column: {line}");
        assert!(line.contains("←→ move · ↵ timeline · Esc back"));
        assert!(!line.contains("[y] analysis"), "the readout takes the line");

        // The outage is reachable by walking, and names its cause when found.
        let outage = (0..=cap)
            .find(|i| {
                s.bar_cursor = Some(*i);
                readout(&s).contains("down")
            })
            .expect("the outage is reachable with the cursor");
        s.bar_cursor = Some(outage);
        let line = readout(&s);
        assert!(
            line.contains("gateway"),
            "the column names its cause: {line}"
        );
        // And which minutes it stands for, as clock times.
        assert!(line.contains(" → "), "the readout carries the span");
        // The columns either side of the outage are not it: the cursor picks
        // out one column, not a mood.
        s.bar_cursor = Some(0);
        assert!(readout(&s).contains("healthy"), "the session opened clean");

        // The cursor marks its column: reversed, so it reads on any theme.
        s.bar_cursor = Some(outage);
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| render(f, &s)).unwrap();
        let buf = t.backend().buffer();
        let marked = (0..w)
            .filter(|x| buf[(*x, h - 2)].modifier.contains(Modifier::REVERSED))
            .count();
        assert_eq!(marked, 1, "exactly one column wears the cursor");
    }

    /// The cursor's range is the bar as drawn — which changes with the
    /// terminal. Every key press re-clamps against this, so a window resized
    /// while the cursor is up cannot leave it pointing off the end.
    #[test]
    fn the_cursor_range_follows_the_bar_it_is_drawn_on() {
        let mut s = AppState::new(vec![]);
        assert_eq!(
            bar_cursor_cap(&s, 120, 30),
            None,
            "no session yet, nothing to walk"
        );

        for _ in 0..40 {
            s.session
                .record(crate::session::SessionState::Healthy, None);
        }
        // A young session is only as wide as it is long.
        assert_eq!(bar_cursor_cap(&s, 120, 30), Some(39));
        for _ in 0..400 {
            s.session
                .record(crate::session::SessionState::Healthy, None);
        }
        assert_eq!(bar_cursor_cap(&s, 120, 30), Some(119), "one per column");
        assert_eq!(bar_cursor_cap(&s, 80, 30), Some(79), "narrower: fewer");
        assert_eq!(
            bar_cursor_cap(&s, 120, 10),
            None,
            "no bar on a short terminal, so no cursor either"
        );
    }

    /// A terminal too short to spare a row spends it on data instead.
    #[test]
    fn a_short_terminal_drops_the_session_strip() {
        let mut s = AppState::new(vec![]);
        for _ in 0..60 {
            s.session
                .record(crate::session::SessionState::Healthy, None);
        }
        // Rows that are nothing but bar (and blank where the young session
        // has not reached yet).
        let bar_rows = |s: &AppState, w: u16, h: u16| -> usize {
            let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
            t.draw(|f| render(f, s)).unwrap();
            let buf = t.backend().buffer();
            (0..h)
                .filter(|y| {
                    (0..w).any(|x| "▁▄▆█".contains(buf[(x, *y)].symbol()))
                        && (0..w).all(|x| " ▁▄▆█".contains(buf[(x, *y)].symbol()))
                })
                .count()
        };
        assert_eq!(bar_rows(&s, 120, 30), 1);
        assert_eq!(bar_rows(&s, 120, 10), 0, "a short terminal keeps the row");
        // And nothing to draw before the first verdict tick.
        assert_eq!(bar_rows(&AppState::new(vec![]), 120, 30), 0);

        // One minute of a session in a 120-column terminal: the bar is 60
        // cells wide and sits against the right edge, under "now".
        let mut t = Terminal::new(TestBackend::new(120, 30)).unwrap();
        t.draw(|f| render(f, &s)).unwrap();
        let buf = t.backend().buffer();
        let bar = |x: u16| "▁▄▆█".contains(buf[(x, 28)].symbol());
        assert!(bar(119), "the newest cell is flush right");
        assert!(!bar(0), "and a young session has not reached the left yet");
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
    fn egress_overlay_lists_checks_and_summarises() {
        use crate::collectors::egress::{CheckResult, EgressCheck, Outcome, Scan};
        let mut s = AppState::new(vec![]);
        s.overlay = Overlay::Egress;
        let out = draw(&s, 120, 30);
        assert!(out.contains("starting scan"));

        let check = |name: &str, port: u16, o: Outcome| CheckResult {
            check: EgressCheck {
                name: name.into(),
                host: "example.org".into(),
                port,
                proto: "tcp".into(),
                note: "why".into(),
            },
            outcome: o,
        };
        s.egress = Some(Scan {
            started: std::time::Instant::now(),
            running: false,
            results: vec![
                check("SSH", 22, Outcome::Open(12.0)),
                check("SMTP", 25, Outcome::Blocked),
                check("IMAPS", 993, Outcome::Refused),
            ],
        });
        let out = draw(&s, 120, 30);
        assert!(out.contains("outbound reachability"));
        assert!(out.contains("open 12ms"));
        assert!(out.contains("refused (reachable)"));
        assert!(out.contains("1 filtered"));
        assert!(
            out.contains("FILTERED (host answers on other ports)"),
            "25 timing out while 22/993 to the same host answer is filtering, not a dead host"
        );
        assert!(out.contains("r rescan"));

        // With nothing filtered, the result column shrinks to the labels on
        // screen — no gulf sized for the FILTERED label that never appears.
        s.egress = Some(Scan {
            started: std::time::Instant::now(),
            running: false,
            results: vec![
                check("SSH", 22, Outcome::Open(12.0)),
                check("IMAPS", 993, Outcome::Open(9.0)),
            ],
        });
        let out = draw(&s, 120, 30);
        assert!(
            out.contains("result     why it matters"),
            "5-space gap: the column fits 'open 12ms', not the widest possible label"
        );

        // A note longer than the box wraps inside its own column instead of
        // spilling to the left margin; its tail stays readable.
        let mut long = check("SSH", 22, Outcome::Open(12.0));
        long.check.note = "git over ssh, remote shells and captive portals live here".into();
        s.egress = Some(Scan {
            started: std::time::Instant::now(),
            running: false,
            results: vec![long],
        });
        let out = draw(&s, 70, 30);
        assert!(out.contains("live here"), "note tail survives the wrap");
    }

    /// Every overlay must survive a degenerate terminal. The analysis
    /// overlay's width clamp panicked below 80 columns (min > max), which
    /// poisoned the state lock and took the collectors down with it.
    #[test]
    fn overlays_survive_tiny_terminals() {
        use crate::app::TargetStat;
        use std::net::{IpAddr, Ipv4Addr};
        let mut s = AppState::new(vec![TargetStat::new(
            "Cloudflare".into(),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        )]);
        // Findings give the analysis overlay real content to size against.
        for _ in 0..10 {
            s.targets[0].record_loss();
        }
        s.verdict = crate::verdict::VerdictState::default();
        s.verdict.triage = crate::verdict::evaluate(&s);
        for overlay in [
            Overlay::Triage,
            Overlay::Events,
            Overlay::Egress,
            Overlay::Locations,
            Overlay::Help,
        ] {
            s.overlay = overlay;
            for (w, h) in [(20, 4), (40, 8), (79, 20)] {
                draw(&s, w, h); // not panicking is the assertion
            }
        }
    }

    /// Long event messages wrap inside the message column; the tail is
    /// readable instead of clipped at the border.
    #[test]
    fn events_overlay_wraps_long_messages() {
        let mut s = AppState::new(vec![]);
        s.overlay = Overlay::Events;
        s.push_event(
            Severity::Info,
            crate::app::EventCategory::Network,
            "DNS servers changed to 192.168.1.4 and 172.64.36.1 and 172.64.36.2 and finally omega"
                .into(),
        );
        let out = draw(&s, 80, 24);
        assert!(out.contains("DNS servers changed"));
        assert!(out.contains("omega"), "tail of the message survives");
        assert!(out.contains("C clear"), "clear shortcut in the footer");
    }

    /// The dns row wraps between resolvers — a reading never separates from
    /// its server — and continuations stay in the value column.
    #[test]
    fn dns_rows_wrap_between_resolvers() {
        use std::net::{IpAddr, Ipv4Addr};
        let mut s = AppState::new(vec![]);
        s.netinfo.dns = vec![
            "192.168.1.4".into(),
            "172.64.36.1".into(),
            "172.64.36.2".into(),
        ];
        for (a, ms) in [([192, 168, 1, 4], 2.0), ([172, 64, 36, 1], 6.0)] {
            let mut p = crate::app::DnsProbe::new(IpAddr::V4(Ipv4Addr::from(a)));
            p.record(Some(ms));
            s.dns.push(p);
        }
        let lines = dns_lines(&s, 40, None);
        assert!(lines.len() > 1, "three resolvers cannot fit in 40 columns");
        for l in &lines {
            assert!(l.width() <= 40, "line overflows: {l:?}");
        }
        let texts: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
        assert!(texts[0].starts_with("dns"));
        assert!(
            texts[1].starts_with("         "),
            "continuation is indented into the value column: {:?}",
            texts[1]
        );
        // The group is indivisible: each server's reading sits beside it.
        let with_reading = texts.iter().find(|t| t.contains("172.64.36.1")).unwrap();
        assert!(with_reading.contains("(6ms)"));

        // The search domain trails the resolvers when the OS has one.
        s.netinfo.dns_search = vec!["thorpevillage.local".into()];
        let all: String = dns_lines(&s, 200, None)
            .iter()
            .map(|l| l.to_string())
            .collect();
        assert!(all.contains("search thorpevillage.local"));
    }

    #[test]
    fn fullscreen_network_shows_the_history_pane_with_detail() {
        let mut s = AppState::new(vec![]);
        s.focus = Panel::NetInfo;
        s.fullscreen = true;
        s.netinfo.iface = "en0".into();
        s.netinfo.medium = crate::app::LinkMedium::WiFi;
        let out = draw(&s, 140, 40);
        assert!(out.contains("Network history (0)"));
        assert!(out.contains("no changes yet"));

        s.push_net_change(
            crate::app::NetChangeKind::WifiRoamed,
            "en0".into(),
            "Wi-Fi roamed — Home ch 36 → 149".into(),
            vec!["before: ch 36".into(), "after:  ch 149 · -58 dBm".into()],
        );
        s.push_net_change(
            crate::app::NetChangeKind::VpnUp,
            "utun4".into(),
            "VPN up — Tailscale".into(),
            vec!["before:".into(), "after:".into()],
        );
        // Cursor into the history pane: newest first, detail of the selection.
        s.sub_pane = SubPane::Secondary;
        let out = draw(&s, 140, 40);
        assert!(out.contains("Network history (2)"));
        assert!(out.contains("wifi roam"));
        assert!(out.contains("vpn up"));
        assert!(
            out.find("VPN up").unwrap() < out.find("Wi-Fi roamed").unwrap(),
            "newest first"
        );
        assert!(
            out.contains("vpn up · utun4"),
            "detail header for the selected (newest) entry"
        );
        s.net_history_sel = 1;
        let out = draw(&s, 140, 40);
        assert!(out.contains("wifi roam · en0"));
        assert!(out.contains("after:  ch 149"));

        // Long summaries and before/after details wrap inside the pane; the
        // tail is readable instead of clipped at the border.
        s.push_net_change(
            crate::app::NetChangeKind::AddressChanged,
            "en0".into(),
            "DNS servers changed → 192.168.1.4, 172.64.36.1, 172.64.36.2, fe80::dad5:b9ff:fe00:b601"
                .into(),
            vec![
                "before: 192.168.1.4, 172.64.36.1, 172.64.36.2, fe80::dad5:b9ff:fe00:b601"
                    .into(),
            ],
        );
        s.net_history_sel = 0;
        let out = draw(&s, 100, 40);
        assert!(
            out.contains("fe80::dad5:b9ff:fe00:b601"),
            "summary tail wraps into view"
        );
        assert!(out.contains("before:"), "detail present");
    }

    #[test]
    fn network_panel_flags_proxy_clock_mtu_and_nat_only_when_notable() {
        use crate::app::TargetStat;
        use std::net::{IpAddr, Ipv4Addr};
        let mut s = AppState::new(vec![]);
        s.netinfo.iface = "en0".into();
        s.netinfo.medium = crate::app::LinkMedium::Ethernet;
        s.focus = Panel::NetInfo;
        s.fullscreen = true;
        let quiet = draw(&s, 90, 40);
        for k in ["proxy", "clock", "mtu", "nat"] {
            assert!(
                !quiet.contains(&format!("{k:<9}")),
                "{k} row shown with nothing to say"
            );
        }
        s.proxy = Some(crate::app::ProxyConfig {
            kind: crate::app::ProxyKind::Manual {
                http: "proxy.corp:8080".into(),
                https: "proxy.corp:8080".into(),
            },
            source: "System Settings".into(),
            bypass: String::new(),
        });
        s.clock.ntp_offset_ms = Some(400_000.0);
        s.pmtu = Some(crate::app::PmtuResult {
            target: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            iface_mtu: Some(1500),
            path_mtu: Some(1400),
            blackhole: true,
            pmtud_works: false,
        });
        let mut gw = TargetStat::new("gateway".into(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        gw.discovered = true;
        let mut h2 = TargetStat::new(
            "hop 2→1.1.1.1".into(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
        );
        h2.discovered = true;
        s.targets.push(gw);
        s.targets.push(h2);
        let loud = draw(&s, 90, 40);
        assert!(loud.contains("proxy.corp:8080"));
        assert!(loud.contains("clock 6m 40s fast"));
        assert!(loud.contains("BLACK HOLE"));
        assert!(loud.contains("CGNAT"));
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
        assert!(out.contains("x export"), "the export key is advertised");
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

        // The per-hop trace draws misses red. They hold a slot now, and a
        // slot holding no reply must not be coloured as though it held the
        // fastest one on the row.
        let mut t = Terminal::new(TestBackend::new(120, 40)).unwrap();
        t.draw(|f| render(f, &s)).unwrap();
        let buf = t.backend().buffer();
        let bars = |c: Color| {
            buf.content()
                .iter()
                .filter(|cell| {
                    cell.fg == c
                        && cell
                            .symbol()
                            .chars()
                            .next()
                            .is_some_and(|ch| ('\u{2581}'..='\u{2588}').contains(&ch))
                })
                .count()
        };
        assert!(bars(Color::Red) > 0, "the misses draw as red bars");
        assert!(bars(Color::Green) > 0, "the healthy hops keep their own");
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

    /// The reds a speed test causes are real readings; the header has to say
    /// where they came from — while the test runs, and for as long as the
    /// loaded samples remain inside the stats window.
    #[test]
    fn quality_header_names_speed_test_load() {
        use crate::app::SpeedStatus;

        let mut s = AppState::new(vec![]);
        assert!(!draw(&s, 160, 40).contains("speed test load"));

        s.speedtest.status = SpeedStatus::Running;
        assert!(draw(&s, 160, 40).contains("under speed test load"));

        s.speedtest.status = SpeedStatus::Done;
        s.speedtest.last_run = Some(std::time::Instant::now());
        assert!(draw(&s, 160, 40).contains("includes speed test load"));
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
        assert_eq!(rtt_color(14.0, None), Color::Green);
        assert_eq!(rtt_color(240.0, None), Color::Red);
        // Against a 160 ms floor (a VPN exit on another continent) the same
        // 240 ms is within normal, and 600 ms is the problem.
        assert_eq!(rtt_color(240.0, Some(160.0)), Color::Green);
        assert_eq!(rtt_color(400.0, Some(160.0)), theme::warn());
        assert_eq!(rtt_color(600.0, Some(160.0)), Color::Red);
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

    /// The routing-table overlay: loading state first, then the tool's raw
    /// lines, scrolled by `routes_scroll` with the counts in the title.
    #[test]
    fn routes_overlay_shows_the_table_and_scrolls() {
        use crate::app::Overlay;

        let mut s = AppState::new(vec![]);
        s.overlay = Overlay::Routes;
        let out = draw(&s, 100, 30);
        assert!(out.contains("routing table"));
        assert!(out.contains("reading the routing table"));

        s.routes = Some(
            (0..60)
                .map(|i| format!("10.0.{i}.0/24        10.90.0.1        UGSc        en0"))
                .collect(),
        );
        let out = draw(&s, 100, 30);
        assert!(out.contains("10.0.0.0/24"));
        assert!(out.contains("press T or Esc to close"));

        // 60 rows into a 30-line terminal: scrolling reveals the tail.
        s.routes_scroll = 45;
        let out = draw(&s, 100, 30);
        assert!(out.contains("10.0.59.0/24"));
        assert!(!out.contains("10.0.0.0/24"));
    }

    /// A wall of 100% ICMP loss while the web probe succeeds is a network
    /// dropping ICMP as policy (an Azure VM): the quality panel must say so
    /// instead of presenting the red as an outage. Without the working web
    /// probe the wall stays an outage and earns no such excuse.
    #[test]
    fn quality_title_names_an_icmp_blackhole() {
        use crate::app::{FamilyProbe, TargetStat};
        use std::net::{IpAddr, Ipv4Addr};

        let mut s = AppState::new(vec![
            TargetStat::new("Cloudflare".into(), IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            TargetStat::new("Google".into(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        ]);
        for t in &mut s.targets {
            for _ in 0..15 {
                t.record_loss();
            }
        }
        s.http.v4 = FamilyProbe::Ok(30.0);
        // The split view's half-width panel is exactly where the cue used to
        // truncate, so that is where it is asserted.
        let out = draw(&s, 170, 40);
        assert!(
            out.contains("no ICMP here — web ok"),
            "expected the blackhole cue in the quality title"
        );
        // The per-target "not answering" clause yields to the network-wide
        // cue rather than crowding it out of the width.
        assert!(!out.contains("not answering"));
        // The latency graph stops promising "collecting…" — it never will.
        assert!(out.contains("web probes still measure"));
        assert!(!out.contains("collecting"));

        // The analysis names the condition and qualifies the green verdict.
        let checks = crate::verdict::checks(&s);
        let icmp = checks.iter().find(|c| c.name == "ICMP").expect("ICMP row");
        assert_eq!(icmp.status, crate::verdict::RungStatus::Warn);
        assert!(icmp.detail.contains("blocked on this network"));
        s.overlay = crate::app::Overlay::Triage;
        s.verdict.current = crate::verdict::Verdict::Healthy;
        let out = draw(&s, 170, 45);
        assert!(
            out.contains("judged on web + DNS"),
            "healthy line must admit it is judging without ICMP"
        );

        s.overlay = crate::app::Overlay::None;
        s.http.v4 = FamilyProbe::NotRun;
        let out = draw(&s, 170, 40);
        assert!(!out.contains("no ICMP here"));
        assert!(crate::verdict::checks(&s).iter().all(|c| c.name != "ICMP"));
    }

    /// The │ dividers of the dual view must sit in the same buffer column in
    /// the header and every data row — a stray pad space inside one cell
    /// once shifted the body's tcp divider a column right of its header.
    #[test]
    fn dual_view_dividers_align_between_header_and_rows() {
        use crate::app::TargetStat;
        use std::net::{IpAddr, Ipv4Addr};
        let mut s = AppState::new(vec![
            TargetStat::new("Cloudflare".into(), IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            TargetStat::new("Google".into(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        ]);
        for t in &mut s.targets {
            for _ in 0..20 {
                t.record_reply(10.0);
                t.tcp.record_reply(33.0);
            }
        }
        s.focus = Panel::Quality;
        s.fullscreen = true;
        let mut t = Terminal::new(TestBackend::new(170, 40)).unwrap();
        t.draw(|f| render(f, &s)).unwrap();
        let buf = t.backend().buffer();
        let dividers = |y: u16| -> Vec<u16> {
            // Interior columns only: x=0 and the panel edge are borders.
            (1..168u16)
                .filter(|x| buf[(*x, y)].symbol() == "│")
                .collect()
        };
        let header = dividers(2);
        assert_eq!(
            header.len(),
            2,
            "│ icmp and │ tcp in the header: {header:?}"
        );
        for y in 3..5 {
            assert_eq!(dividers(y), header, "row {y} out of column");
        }
    }
    /// The edge row names the PoP's city. Pinned by test because the label
    /// helper once made it into the analysis but not the Network panel.
    #[test]
    fn edge_row_names_the_colo_city() {
        let mut s = AppState::new(vec![]);
        // The panel says nothing at all without an interface.
        s.netinfo.iface = "en0".into();
        s.edge = Some(crate::app::EdgeInfo {
            ip: "203.0.113.9".into(),
            asn: 33363,
            isp: "Charter Communications, Inc".into(),
            colo: "MIA".into(),
            colo_city: "Miami".into(),
            tcp_rtt_ms: Some(13.0),
        });
        let out = draw(&s, 170, 45);
        assert!(
            out.contains("MIA (Miami)"),
            "colo city in the Network panel"
        );
        assert!(out.contains("Charter Communications"), "isp row present");
    }

    /// The quality table's second family: [i] flips the split view to the
    /// TCP connect series, an ICMP blackhole flips it automatically, and
    /// full screen shows both families behind the │tcp divider.
    #[test]
    fn quality_table_shows_the_tcp_family() {
        use crate::app::{FamilyProbe, ProbeFamily, TargetStat};
        use std::net::{IpAddr, Ipv4Addr};

        let mut s = AppState::new(vec![
            TargetStat::new("Cloudflare".into(), IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            TargetStat::new("Google".into(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        ]);
        for t in &mut s.targets {
            for _ in 0..20 {
                t.record_reply(10.0);
                t.tcp.record_reply(33.0);
            }
        }
        // Healthy ICMP: the split view defaults to it — no tcp marker.
        let out = draw(&s, 170, 40);
        assert!(!out.contains("tcp :443"));
        assert!(out.contains("· icmp"), "split view names its family");
        assert!(out.contains("10.0ms"));
        assert!(!out.contains("33.0ms"));

        // [i] flips to the TCP series: its numbers, and the title says so.
        s.quality_family = Some(ProbeFamily::Tcp);
        let out = draw(&s, 170, 40);
        assert!(out.contains("tcp :443"));
        assert!(out.contains("33.0ms"));

        // An ICMP blackhole flips the *default* (no user override needed).
        s.quality_family = None;
        for t in &mut s.targets {
            for _ in 0..20 {
                t.record_loss();
            }
        }
        s.http.v4 = FamilyProbe::Ok(30.0);
        let out = draw(&s, 170, 40);
        assert!(out.contains("tcp :443"));
        assert!(out.contains("33.0ms"));

        // Full screen: both families side by side behind the divider.
        s.focus = Panel::Quality;
        s.fullscreen = true;
        let out = draw(&s, 170, 45);
        assert!(out.contains("│ icmp"), "icmp group labelled in dual view");
        assert!(out.contains("│ tcp"));
        assert!(out.contains("33.0ms"), "tcp numbers in the dual view");

        // The performance grade rides the TCP series while ICMP is blind.
        let triage = crate::verdict::evaluate(&s);
        let perf = triage.performance.expect("graded");
        assert!(perf.detail.contains("(tcp)"), "got: {}", perf.detail);
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
        // bits mode: the same rate reads in the unit speed tests are sold in,
        // and never mixes families ("Mb/s", not "Mbps" or "MB/s").
        s.bits_units = true;
        let out = draw(&s, 120, 30);
        assert!(out.contains("7.3 Mb/s"), "{out}");
        assert!(!out.contains("910.0 KB/s"), "{out}");
        s.bits_units = false;
        s.fullscreen = false;

        s.bw_view = BwView::Remotes;
        s.remote_sel = 1;
        let out = draw(&s, 120, 30);
        assert!(
            out.contains("151.101.193.111:443+"),
            "busiest port, + for more"
        );
        // The address column takes the pane's leftover width: the long v6
        // fits whole here (a narrower pane would keep its distinctive tail).
        assert!(out.contains("[2606:4700:4700::1111]:53"), "{out}");
        assert!(out.contains("mDNSRespond"));
        assert!(out.contains("remote"));
        // The split view is too narrow for every column: the trailing byte
        // columns go, the address does not get squeezed.
        assert!(!out.contains("4M"), "{out}");
        s.fullscreen = true;
        let out = draw(&s, 120, 30);
        assert!(
            out.contains("4M"),
            "full screen brings the ↓ column back: {out}"
        );
        assert!(out.contains("Remote addresses · n for next"));
        // The cursor is a display position; park it on the v6 row wherever
        // the sort put that, and [W]/[a] act on it.
        s.remote_sel = s
            .remote_order()
            .iter()
            .position(|&i| s.remotes[i].addr.to_string() == "2606:4700:4700::1111")
            .unwrap();
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

        // Cursor to the last display position: the list scrolls to it.
        s.proc_sel = 29;
        let out = draw(&s, 120, 30);
        assert!(out.contains("proc29") && !out.contains("proc00"), "{out}");

        // The cursor is positional: under an ascending name sort row 1 is
        // proc01; flipping the sort leaves the cursor on row 1, which the
        // descending list now fills with proc28. Following ([o]) is what
        // glues it to an item instead.
        s.bw_view = BwView::Processes;
        s.bw_sort = Some((0, false));
        s.proc_sel = 0;
        assert_eq!(&s.processes[s.proc_cursor().1.unwrap()].name, "proc00");
        crate::move_proc_cursor(&mut s, 1);
        assert_eq!(&s.processes[s.proc_cursor().1.unwrap()].name, "proc01");
        s.bw_sort = Some((0, true));
        assert_eq!(&s.processes[s.proc_cursor().1.unwrap()].name, "proc28");
        // Follow proc01 through the same flip: the cursor rides along.
        s.follow_proc = Some("proc01".into());
        assert_eq!(&s.processes[s.proc_cursor().1.unwrap()].name, "proc01");
        assert_eq!(s.proc_cursor().0, 28, "proc01 sits near the bottom now");
        s.follow_proc = None;

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
        // Over-long single words split hard: these strings land in aligned
        // columns, where an unbroken path or address list would overflow.
        assert_eq!(wrap_words("abcdefghij", 5), vec!["abcde", "fghij"]);
        assert_eq!(
            wrap_words("x C:\\Users\\S\\file.csv", 8),
            vec!["x", "C:\\Users", "\\S\\file.", "csv"]
        );
    }

    /// Continuations stay in their own column, indented past the prefix.
    #[test]
    fn column_lines_keep_the_hanging_indent() {
        let lines = column_lines(
            vec![Span::raw("label:  ")],
            "one two three four",
            Style::new(),
            8,
            18,
        );
        let text: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
        assert_eq!(text[0], "label:  one two");
        assert_eq!(text[1], "        three four");
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
            network: Some("United WiFi".into()),
            medium: Some("Wi-Fi (wireless)".into()),
            server: Some("MIA (edge)".into()),
        };

        let mut s = AppState::new(vec![]);
        s.focus = Panel::Bandwidth;
        s.fullscreen = true;
        s.speed_history = (0..3).map(record).collect();
        s.speed_total = 3;
        let out = draw(&s, 160, 40);
        assert!(out.contains("3 saved"));
        // The detail block names the network the selected test ran on.
        assert!(out.contains("United WiFi"), "got: {out}");
        assert!(out.contains("Wi-Fi (wireless)"));

        // When the file holds more than is loaded, both numbers are shown so
        // the older results do not look lost.
        s.speed_total = 812;
        assert!(draw(&s, 160, 40).contains("3 of 812 saved"));

        // A record from before the field existed says so instead of lying.
        let mut old = record(99);
        old.network = None;
        old.medium = None;
        s.speed_history.push(old);
        s.speed_sel = 0; // newest-first: the legacy record is now selected
        assert!(draw(&s, 160, 40).contains("not recorded (older test)"));

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
            "r / G",
            "w",
            "? / q",
            "PgUp/PgDn",
            "Enter",
            "Shift+R",
            "a",
            "d / Del",
            "g",
            "t",
            "m",
            "v",
            "y / T",
            "e / c / M",
            "N",
            "W",
            "W / a",
            "l / D",
            "p / u",
            "o / /",
        ] {
            assert!(out.contains(key), "help is missing a binding for {key:?}");
        }
        // Every group survives the packing: the section that lands last is
        // the one a box one row too tall would swallow.
        for section in [
            "Global",
            "Navigation",
            "Diagnose & record",
            "Connection Quality",
            "Bandwidth",
            "Network",
        ] {
            assert!(
                out.contains(section),
                "help is missing the {section:?} group"
            );
        }
        // The closing hint sits in the bottom border; if the box overflowed the
        // terminal it would be the first thing lost.
        assert!(out.contains("press ? or Esc to close"));
        assert!(out.contains(&format!("octomon v{}", env!("CARGO_PKG_VERSION"))));

        // The column split must not clip descriptions. These are the longest
        // in each column and were truncated before the key field was narrowed.
        for desc in [
            "cycle panels",
            "add target (remembered)",
            "full-screen focused panel",
            "back / exit full-screen",
            "CSV recording / zip bundle",
            "monitor every hop (MTR)",
            "pin / unpin row at the top",
            "whois: who owns address",
            "provider cycle · add · del",
            "procs → remotes → history",
            "full-screen: DNS + history",
            "follow row / filter rows",
            "events / ports / marker",
            "del. speed test / zoom",
            "analysis / routing table",
            "re-probe / rescan the path",
            "this help / quit (^C too)",
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
