//! Per-process bandwidth. Platform sampling returns *cumulative* byte counters,
//! so this collector diffs successive samples to derive per-process rates and
//! keeps the top talkers. Exits early (marking unsupported) where the platform
//! has no unprivileged source.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::app::{AppState, ProcBandwidth, ProcStatus};
use crate::platform;

// Keep enough for the full-screen view (10); the split view shows fewer.
const TOP_N: usize = 10;

/// Map pid → full process name via `ps` (nettop truncates names to ~15 chars).
/// `comm` on macOS is the full executable path, so its basename is the name.
async fn full_names() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    let Ok(out) = tokio::process::Command::new("ps")
        .args(["-axo", "pid=,comm="])
        .output()
        .await
    else {
        return map;
    };
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let line = line.trim_start();
        if let Some((pid_s, comm)) = line.split_once(char::is_whitespace)
            && let Ok(pid) = pid_s.parse::<u32>()
        {
            let comm = comm.trim();
            let name = comm.rsplit('/').next().unwrap_or(comm).to_string();
            map.insert(pid, name);
        }
    }
    map
}

pub async fn run(state: Arc<Mutex<AppState>>) {
    // Probe support once; mark unsupported (not just "empty") if unavailable.
    if platform::proc_net_sample().await.is_none() {
        state.lock().unwrap().proc_status = ProcStatus::Unsupported;
        return;
    }
    state.lock().unwrap().proc_status = ProcStatus::Supported;

    // Counter key -> (bytes_in, bytes_out, retx) from the previous sample. Keyed
    // by the counter, not the process: on Linux each sample is one socket, and
    // diffing per socket is what makes a closing connection harmless.
    let mut prev: HashMap<u64, (u64, u64, u64)> = HashMap::new();
    // Bytes attributed to each pid since octomon started. Derived from deltas
    // rather than read from the sample, since a per-socket total is not a
    // process total.
    let mut totals: HashMap<u32, u64> = HashMap::new();
    let mut prev_at = Instant::now();
    let mut ticker = tokio::time::interval(Duration::from_secs(2));

    loop {
        ticker.tick().await;
        let Some(sample) = platform::proc_net_sample().await else {
            continue;
        };
        // nettop truncates process names to ~15 chars; enrich with full names.
        let full_names = full_names().await;
        let now = Instant::now();
        let secs = now.duration_since(prev_at).as_secs_f64().max(0.001);

        // Sum each counter's delta onto its owning process.
        let mut agg: HashMap<u32, (f64, f64, f64, String)> = HashMap::new();
        for s in &sample {
            let Some((pin, pout, pretx)) = prev.get(&s.key) else {
                // First sighting of this counter: nothing to diff against yet.
                // Counting its total here would report a socket's whole history
                // as one interval's traffic.
                continue;
            };
            let d_in = s.bytes_in.saturating_sub(*pin);
            let d_out = s.bytes_out.saturating_sub(*pout);
            let d_retx = s.retx.saturating_sub(*pretx);
            if d_in == 0 && d_out == 0 && d_retx == 0 {
                continue;
            }
            let e = agg
                .entry(s.pid)
                .or_insert_with(|| (0.0, 0.0, 0.0, s.name.clone()));
            e.0 += d_in as f64;
            e.1 += d_out as f64;
            e.2 += d_retx as f64;
            *totals.entry(s.pid).or_default() += d_in + d_out;
        }

        let mut list: Vec<ProcBandwidth> = agg
            .into_iter()
            .map(|(pid, (d_in, d_out, d_retx, name))| ProcBandwidth {
                name: full_names.get(&pid).cloned().unwrap_or(name),
                pid,
                down_bps: d_in / secs,
                up_bps: d_out / secs,
                total_bytes: totals.get(&pid).copied().unwrap_or_default(),
                retx_per_sec: d_retx / secs,
            })
            .collect();
        list.sort_by(|a, b| (b.down_bps + b.up_bps).total_cmp(&(a.down_bps + a.up_bps)));
        list.truncate(TOP_N);

        // Only remember counters still present; a socket that has gone away had
        // its final delta counted already.
        prev = sample
            .iter()
            .map(|s| (s.key, (s.bytes_in, s.bytes_out, s.retx)))
            .collect();
        prev_at = now;

        state.lock().unwrap().processes = list;
    }
}
