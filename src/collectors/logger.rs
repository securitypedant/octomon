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

use crate::app::{AppState, LogStatus};
use crate::config::Config;

const HEADER: &str = "timestamp,category,subject,metric,value,unit\n";

pub async fn run(state: Arc<Mutex<AppState>>, cfg: Config) {
    let mut ticker = tokio::time::interval(cfg.sample_interval());
    let mut file: Option<tokio::fs::File> = None;

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
                        s.log = Some(LogStatus {
                            path: path.clone(),
                            rows: 0,
                            started: std::time::Instant::now(),
                        });
                        s.notice = Some(format!("recording → {}", path.display()));
                    }
                    Err(e) => {
                        let mut s = state.lock().unwrap();
                        s.logging_requested = false;
                        s.notice = Some(format!("could not start recording: {e}"));
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
                    s.notice = Some(format!(
                        "recording stopped — {} rows → {}",
                        status.rows,
                        status.path.display()
                    ));
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
            let body = format_rows(&s, &stamp);
            let rows = body.lines().count() as u64;
            (body, rows)
        };

        if let Some(f) = file.as_mut() {
            if f.write_all(body.as_bytes()).await.is_err() {
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
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| e.to_string())?;
    }
    let mut f = tokio::fs::File::create(&path)
        .await
        .map_err(|e| e.to_string())?;
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
            format!("{:.2}", t.loss_pct()),
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
                format!("{:.2}", st.loss_pct()),
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

    // Per-process talkers.
    for p in &s.processes {
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

/// Quote a CSV field when it contains anything that would break parsing.
/// Target labels and process names are user- and system-supplied.
fn field(v: &str) -> String {
    if v.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_string()
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
