//! Per-process and per-remote bandwidth. Platform sampling returns *cumulative*
//! byte counters per socket, so this collector diffs successive samples to
//! derive rates, then sums them two ways: onto the owning process (who is using
//! the link) and onto the remote address (what they are talking to). Exits
//! early (marking unsupported) where the platform has no unprivileged source.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::app::{AppState, ProcBandwidth, ProcStatus, RemoteBandwidth};
use crate::platform;

// Keep enough for the full-screen view (10); the split view shows fewer.
const TOP_N: usize = 10;

/// Traffic that never touched the wire is not bandwidth: loopback and the
/// unspecified address (a socket bound but not yet connected).
fn on_the_wire(addr: IpAddr) -> bool {
    !(addr.is_loopback() || addr.is_unspecified())
}

/// Bytes moved to one remote this interval, and by whom.
#[derive(Default)]
struct RemoteAgg {
    d_in: f64,
    d_out: f64,
    /// Bytes per port, to name the busiest.
    ports: HashMap<u16, f64>,
    /// Bytes per process name, to name the busiest.
    procs: HashMap<String, f64>,
}

/// Turn the interval's per-remote sums into the ranked list the UI shows.
fn rank_remotes(
    agg: HashMap<IpAddr, RemoteAgg>,
    totals: &HashMap<IpAddr, u64>,
    secs: f64,
) -> Vec<RemoteBandwidth> {
    let all: f64 = agg.values().map(|a| a.d_in + a.d_out).sum();
    fn busiest<K: Clone>(m: &HashMap<K, f64>) -> Option<K> {
        m.iter()
            .max_by(|a, b| a.1.total_cmp(b.1))
            .map(|(k, _)| k.clone())
    }
    let mut list: Vec<RemoteBandwidth> = agg
        .into_iter()
        .map(|(addr, a)| RemoteBandwidth {
            addr,
            port: busiest(&a.ports).unwrap_or(0),
            ports: a.ports.len(),
            process: busiest(&a.procs).unwrap_or_default(),
            down_bps: a.d_in / secs,
            up_bps: a.d_out / secs,
            total_bytes: totals.get(&addr).copied().unwrap_or_default(),
            share: if all > 0.0 {
                (a.d_in + a.d_out) / all
            } else {
                0.0
            },
        })
        .collect();
    list.sort_by(|a, b| (b.down_bps + b.up_bps).total_cmp(&(a.down_bps + a.up_bps)));
    list.truncate(TOP_N);
    list
}

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
    // Likewise per remote address.
    let mut remote_totals: HashMap<IpAddr, u64> = HashMap::new();
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

        // Sum each counter's delta onto its owning process, and onto the
        // remote it was talking to.
        let mut agg: HashMap<u32, (f64, f64, f64, String)> = HashMap::new();
        let mut ragg: HashMap<IpAddr, RemoteAgg> = HashMap::new();
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

            if let Some((addr, port)) = s.remote
                && on_the_wire(addr)
                && d_in + d_out > 0
            {
                let r = ragg.entry(addr).or_default();
                r.d_in += d_in as f64;
                r.d_out += d_out as f64;
                *r.ports.entry(port).or_default() += (d_in + d_out) as f64;
                let name = full_names
                    .get(&s.pid)
                    .cloned()
                    .unwrap_or_else(|| s.name.clone());
                *r.procs.entry(name).or_default() += (d_in + d_out) as f64;
                *remote_totals.entry(addr).or_default() += d_in + d_out;
            }
        }
        let remotes = rank_remotes(ragg, &remote_totals, secs);

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

        let mut st = state.lock().unwrap();
        st.processes = list;
        // Keep the cursor on a row that still exists; the list reorders as
        // traffic shifts, which is unavoidable for a live ranking.
        st.remote_sel = st.remote_sel.min(remotes.len().saturating_sub(1));
        st.remotes = remotes;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    #[test]
    fn remotes_rank_by_rate_and_name_their_busiest_port_and_process() {
        let mut agg: HashMap<IpAddr, RemoteAgg> = HashMap::new();
        let a = agg.entry(ip(1)).or_default();
        a.d_in = 900.0;
        a.d_out = 100.0;
        a.ports.insert(443, 950.0);
        a.ports.insert(80, 50.0);
        a.procs.insert("firefox".into(), 700.0);
        a.procs.insert("curl".into(), 300.0);
        let b = agg.entry(ip(2)).or_default();
        b.d_in = 100.0;
        b.ports.insert(22, 100.0);
        b.procs.insert("ssh".into(), 100.0);

        let totals = HashMap::from([(ip(1), 5000u64), (ip(2), 300u64)]);
        let list = rank_remotes(agg, &totals, 2.0);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].addr, ip(1));
        assert_eq!((list[0].port, list[0].ports), (443, 2));
        assert_eq!(list[0].process, "firefox");
        assert!((list[0].down_bps - 450.0).abs() < 1e-9, "bytes / secs");
        assert!((list[0].share - 1000.0 / 1100.0).abs() < 1e-9);
        assert_eq!(list[0].total_bytes, 5000);
        assert_eq!(list[1].addr, ip(2));
        assert_eq!(list[1].ports, 1);
    }

    #[test]
    fn loopback_is_not_bandwidth() {
        assert!(!on_the_wire("127.0.0.1".parse().unwrap()));
        assert!(!on_the_wire("::1".parse().unwrap()));
        assert!(!on_the_wire("0.0.0.0".parse().unwrap()));
        // LAN traffic is: a NAS backup is exactly the kind of thing to find.
        assert!(on_the_wire("192.168.1.20".parse().unwrap()));
        assert!(on_the_wire("2606:4700::1111".parse().unwrap()));
    }
}
