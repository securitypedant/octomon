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

    // pid -> (bytes_in, bytes_out, retx) from the previous sample.
    let mut prev: HashMap<u32, (u64, u64, u64)> = HashMap::new();
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

        let mut list: Vec<ProcBandwidth> = Vec::new();
        for s in &sample {
            if let Some((pin, pout, pretx)) = prev.get(&s.pid) {
                let down = s.bytes_in.saturating_sub(*pin) as f64 / secs;
                let up = s.bytes_out.saturating_sub(*pout) as f64 / secs;
                if down + up > 0.0 {
                    let name = full_names
                        .get(&s.pid)
                        .cloned()
                        .unwrap_or_else(|| s.name.clone());
                    list.push(ProcBandwidth {
                        name,
                        pid: s.pid,
                        down_bps: down,
                        up_bps: up,
                        total_bytes: s.bytes_in.saturating_add(s.bytes_out),
                        retx_per_sec: s.retx.saturating_sub(*pretx) as f64 / secs,
                    });
                }
            }
        }
        list.sort_by(|a, b| (b.down_bps + b.up_bps).total_cmp(&(a.down_bps + a.up_bps)));
        list.truncate(TOP_N);

        prev = sample
            .iter()
            .map(|s| (s.pid, (s.bytes_in, s.bytes_out, s.retx)))
            .collect();
        prev_at = now;

        state.lock().unwrap().processes = list;
    }
}
