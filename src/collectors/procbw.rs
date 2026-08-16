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

/// Map pid → process name.
///
/// On unix this *enriches* the sample, whose names nettop truncates to ~15
/// chars; `comm` is the full executable path, so its basename is the name. On
/// Windows it is the only source there is — ETW events carry a pid and nothing
/// else — so a miss here leaves a process unlabelled rather than abbreviated.
#[cfg(windows)]
async fn full_names() -> HashMap<u32, String> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

    tokio::task::spawn_blocking(|| {
        // Names only: the default refresh also reads command lines, environment
        // and disk usage for every process, which is a lot of work every 2s.
        let mut sys = System::new_with_specifics(
            RefreshKind::nothing().with_processes(ProcessRefreshKind::nothing()),
        );
        sys.refresh_processes(ProcessesToUpdate::All, true);
        sys.processes()
            .iter()
            .map(|(pid, proc)| (pid.as_u32(), proc.name().to_string_lossy().to_string()))
            .collect()
    })
    .await
    .unwrap_or_default()
}

#[cfg(not(windows))]
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
        state.lock().unwrap().proc_status = if platform::proc_needs_privilege() {
            ProcStatus::NeedsPrivilege
        } else {
            ProcStatus::Unsupported
        };
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
    // False until a baseline exists, so the first sample only records counters
    // rather than attributing their history to one interval.
    let mut primed = false;
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
            let (d_in, d_out, d_retx) = match prev.get(&s.key) {
                Some((pin, pout, pretx)) => (
                    s.bytes_in.saturating_sub(*pin),
                    s.bytes_out.saturating_sub(*pout),
                    s.retx.saturating_sub(*pretx),
                ),
                // A counter not seen before. Skipping it loses most real
                // traffic: an ordinary web request opens a socket, transfers,
                // and closes well inside one sampling interval, so it is only
                // ever observed once. Its counters start at zero when the
                // socket opens, so the whole total *is* recent traffic.
                //
                // Only from the second sample onward: on the first, every
                // socket is new and long-lived ones would dump their entire
                // history as one interval's worth.
                None if primed => (s.bytes_in, s.bytes_out, s.retx),
                None => continue,
            };
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
        primed = true;

        state.lock().unwrap().processes = list;
    }
}
