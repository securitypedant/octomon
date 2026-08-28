//! Per-process and per-remote bandwidth. Platform sampling returns *cumulative*
//! byte counters per socket, so this collector diffs successive samples to
//! derive per-interval deltas, then accumulates them two ways: onto the owning
//! process (who is using the link) and onto the remote address (what they are
//! talking to). The tables it publishes are session totals — a process that
//! moved a gigabyte ten minutes ago still ranks above one trickling now — with
//! the current rate alongside. Exits early (marking unsupported) where the
//! platform has no unprivileged source.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::app::{AppState, ProcBandwidth, ProcStatus, RemoteBandwidth};
use crate::platform;

/// Rows published to the UI. More than any view shows, so a sort by a live
/// column (rate) can surface a small-total process that is busy right now.
const TOP_N: usize = 50;
/// Bound on remembered aggregates: a long session against a CDN sees a great
/// many addresses. Past this the smallest idle entries are dropped.
const MAX_AGG: usize = 2000;

/// Traffic that never touched the wire is not bandwidth: loopback and the
/// unspecified address (a socket bound but not yet connected).
fn on_the_wire(addr: IpAddr) -> bool {
    !(addr.is_loopback() || addr.is_unspecified())
}

/// One process's session so far, plus what it did this interval.
#[derive(Default)]
struct ProcAgg {
    name: String,
    down: u64,
    up: u64,
    retx: u64,
    /// This interval's deltas; zeroed at the start of every tick.
    d_in: u64,
    d_out: u64,
    d_retx: u64,
}

/// One remote address's session so far, and by whom.
#[derive(Default)]
struct RemoteAgg {
    down: u64,
    up: u64,
    /// Bytes per port, to name the busiest.
    ports: HashMap<u16, u64>,
    /// Bytes per process name, to name the busiest.
    procs: HashMap<String, u64>,
    d_in: u64,
    d_out: u64,
}

fn busiest<K: Clone>(m: &HashMap<K, u64>) -> Option<K> {
    m.iter().max_by_key(|(_, v)| **v).map(|(k, _)| k.clone())
}

/// Turn the session's per-process aggregates into the ranked list the UI shows.
fn rank_processes(
    agg: &HashMap<u32, ProcAgg>,
    names: &HashMap<u32, String>,
    secs: f64,
) -> Vec<ProcBandwidth> {
    let all: u64 = agg.values().map(|a| a.down + a.up).sum();
    let mut list: Vec<ProcBandwidth> = agg
        .iter()
        .map(|(&pid, a)| ProcBandwidth {
            name: names.get(&pid).cloned().unwrap_or_else(|| a.name.clone()),
            pid,
            down_bytes: a.down,
            up_bytes: a.up,
            total_bytes: a.down + a.up,
            share: if all > 0 {
                (a.down + a.up) as f64 / all as f64
            } else {
                0.0
            },
            retx: a.retx,
            down_bps: a.d_in as f64 / secs,
            up_bps: a.d_out as f64 / secs,
            retx_per_sec: a.d_retx as f64 / secs,
        })
        .collect();
    list.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes).then(a.pid.cmp(&b.pid)));
    list.truncate(TOP_N);
    list
}

/// Turn the session's per-remote aggregates into the ranked list the UI shows.
fn rank_remotes(agg: &HashMap<IpAddr, RemoteAgg>, secs: f64) -> Vec<RemoteBandwidth> {
    let all: u64 = agg.values().map(|a| a.down + a.up).sum();
    let mut list: Vec<RemoteBandwidth> = agg
        .iter()
        .map(|(&addr, a)| RemoteBandwidth {
            addr,
            port: busiest(&a.ports).unwrap_or(0),
            ports: a.ports.len(),
            process: busiest(&a.procs).unwrap_or_default(),
            down_bytes: a.down,
            up_bytes: a.up,
            total_bytes: a.down + a.up,
            share: if all > 0 {
                (a.down + a.up) as f64 / all as f64
            } else {
                0.0
            },
            down_bps: a.d_in as f64 / secs,
            up_bps: a.d_out as f64 / secs,
        })
        .collect();
    list.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes).then(a.addr.cmp(&b.addr)));
    list.truncate(TOP_N);
    list
}

/// Keep the aggregate maps bounded: once past `MAX_AGG`, drop the smallest
/// entries that did nothing this interval until half the room is free.
fn prune<K: Clone + Eq + std::hash::Hash, V>(
    m: &mut HashMap<K, V>,
    total: impl Fn(&V) -> u64,
    idle: impl Fn(&V) -> bool,
) {
    if m.len() <= MAX_AGG {
        return;
    }
    let mut idle_keys: Vec<(u64, K)> = m
        .iter()
        .filter(|(_, v)| idle(v))
        .map(|(k, v)| (total(v), k.clone()))
        .collect();
    idle_keys.sort_by_key(|(t, _)| *t);
    let drop = m.len() - MAX_AGG / 2;
    for (_, k) in idle_keys.into_iter().take(drop) {
        m.remove(&k);
    }
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
        let needs_privilege = platform::proc_needs_privilege();
        crate::errlog::log(
            "talkers",
            if needs_privilege {
                "per-process bandwidth needs elevated privileges — the talkers table stays empty"
            } else {
                "per-process bandwidth is unavailable on this platform — the talkers table stays empty"
            },
        );
        state.lock().unwrap().proc_status = if needs_privilege {
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
    // Session aggregates, built from deltas rather than read from the sample,
    // since a per-socket total is not a process total. The name in `ProcAgg`
    // is the last one seen, so an exited process keeps its label.
    let mut procs: HashMap<u32, ProcAgg> = HashMap::new();
    let mut remotes: HashMap<IpAddr, RemoteAgg> = HashMap::new();
    let mut prev_at = Instant::now();
    // False until a baseline exists, so the first sample only records counters
    // rather than attributing their history to one interval.
    let mut primed = false;
    let mut ticker = tokio::time::interval(Duration::from_secs(2));

    loop {
        ticker.tick().await;
        let Some(sample) = platform::proc_net_sample().await else {
            // Supported at startup and failing now: the table quietly freezes
            // on its last figures rather than going blank, so nothing on
            // screen distinguishes this from an idle machine.
            crate::errlog::log(
                "talkers",
                "a per-process sample failed — the tables are not advancing",
            );
            continue;
        };
        // nettop truncates process names to ~15 chars; enrich with full names.
        let full_names = full_names().await;
        let now = Instant::now();
        let secs = now.duration_since(prev_at).as_secs_f64().max(0.001);

        // A reset from the UI wipes the session, not just the tables.
        if state.lock().unwrap().bw_reset {
            procs.clear();
            remotes.clear();
        }

        // New interval: last tick's deltas are history.
        for a in procs.values_mut() {
            (a.d_in, a.d_out, a.d_retx) = (0, 0, 0);
        }
        for a in remotes.values_mut() {
            (a.d_in, a.d_out) = (0, 0);
        }

        // Add each counter's delta onto its owning process, and onto the
        // remote it was talking to.
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
            let name = full_names
                .get(&s.pid)
                .cloned()
                .unwrap_or_else(|| s.name.clone());
            let p = procs.entry(s.pid).or_default();
            p.name = name.clone();
            p.down += d_in;
            p.up += d_out;
            p.retx += d_retx;
            p.d_in += d_in;
            p.d_out += d_out;
            p.d_retx += d_retx;

            if let Some((addr, port)) = s.remote
                && on_the_wire(addr)
                && d_in + d_out > 0
            {
                let r = remotes.entry(addr).or_default();
                r.down += d_in;
                r.up += d_out;
                r.d_in += d_in;
                r.d_out += d_out;
                *r.ports.entry(port).or_default() += d_in + d_out;
                *r.procs.entry(name).or_default() += d_in + d_out;
            }
        }
        prune(&mut procs, |a| a.down + a.up, |a| a.d_in + a.d_out == 0);
        prune(&mut remotes, |a| a.down + a.up, |a| a.d_in + a.d_out == 0);

        let proc_list = rank_processes(&procs, &full_names, secs);
        let remote_list = rank_remotes(&remotes, secs);

        // Only remember counters still present; a socket that has gone away had
        // its final delta counted already.
        prev = sample
            .iter()
            .map(|s| (s.key, (s.bytes_in, s.bytes_out, s.retx)))
            .collect();
        prev_at = now;
        primed = true;

        let mut st = state.lock().unwrap();
        st.bw_reset = false;
        // Paused means the tables hold still. Aggregation carries on above,
        // so resuming shows the true totals. The screen is drawn from a
        // snapshot while paused, but the key handlers (W, a) act on the *live*
        // list by cursor index, so the live list must match what is shown.
        if st.paused {
            continue;
        }
        // Keep the cursors on rows that still exist. Rows are ordered by
        // session total, so the ranking settles rather than churning.
        st.proc_sel = st.proc_sel.min(proc_list.len().saturating_sub(1));
        st.processes = proc_list;
        st.remote_sel = st.remote_sel.min(remote_list.len().saturating_sub(1));
        st.remotes = remote_list;
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
    fn remotes_rank_by_session_total_and_name_their_busiest_port_and_process() {
        let mut agg: HashMap<IpAddr, RemoteAgg> = HashMap::new();
        let a = agg.entry(ip(1)).or_default();
        a.down = 4500;
        a.up = 500;
        a.d_in = 900;
        a.d_out = 100;
        a.ports.insert(443, 4750);
        a.ports.insert(80, 250);
        a.procs.insert("firefox".into(), 3500);
        a.procs.insert("curl".into(), 1500);
        // Busier right now, but has moved far less over the session: ranks
        // second, since the table answers "what has been using the link".
        let b = agg.entry(ip(2)).or_default();
        b.down = 300;
        b.d_in = 2000;
        b.ports.insert(22, 300);
        b.procs.insert("ssh".into(), 300);

        let list = rank_remotes(&agg, 2.0);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].addr, ip(1));
        assert_eq!((list[0].port, list[0].ports), (443, 2));
        assert_eq!(list[0].process, "firefox");
        assert_eq!((list[0].down_bytes, list[0].up_bytes), (4500, 500));
        assert_eq!(list[0].total_bytes, 5000);
        assert!((list[0].down_bps - 450.0).abs() < 1e-9, "bytes / secs");
        assert!((list[0].share - 5000.0 / 5300.0).abs() < 1e-9);
        assert_eq!(list[1].addr, ip(2));
        assert_eq!(list[1].ports, 1);
        assert!((list[1].down_bps - 1000.0).abs() < 1e-9);
    }

    #[test]
    fn processes_rank_by_session_total_and_keep_idle_rows() {
        let mut agg: HashMap<u32, ProcAgg> = HashMap::new();
        // Exited: no longer in the name map, nothing this interval, but it
        // moved the most bytes and stays at the top under its last name.
        agg.insert(
            7,
            ProcAgg {
                name: "rsync".into(),
                down: 100,
                up: 9_000,
                retx: 3,
                ..Default::default()
            },
        );
        agg.insert(
            8,
            ProcAgg {
                name: "Firefox".into(),
                down: 1_000,
                up: 100,
                d_in: 500,
                d_out: 20,
                d_retx: 2,
                ..Default::default()
            },
        );
        let names = HashMap::from([(8u32, "firefox".to_string())]);
        let list = rank_processes(&agg, &names, 2.0);
        assert_eq!(list.len(), 2);
        assert_eq!((list[0].pid, list[0].name.as_str()), (7, "rsync"));
        assert_eq!(list[0].total_bytes, 9_100);
        assert_eq!(list[0].down_bps, 0.0);
        assert_eq!(list[0].retx, 3);
        assert_eq!(list[1].name, "firefox", "live name wins over the sample's");
        assert!((list[1].down_bps - 250.0).abs() < 1e-9);
        assert!((list[1].retx_per_sec - 1.0).abs() < 1e-9);
        assert!((list[1].share - 1_100.0 / 10_200.0).abs() < 1e-9);
    }

    #[test]
    fn prune_drops_the_smallest_idle_entries_only_when_over_the_cap() {
        let mut m: HashMap<u32, ProcAgg> = HashMap::new();
        for i in 0..(MAX_AGG as u32 + 10) {
            m.insert(
                i,
                ProcAgg {
                    down: i as u64,
                    // The smallest one is busy right now, so it survives.
                    d_in: if i == 0 { 1 } else { 0 },
                    ..Default::default()
                },
            );
        }
        prune(&mut m, |a| a.down + a.up, |a| a.d_in + a.d_out == 0);
        assert_eq!(m.len(), MAX_AGG / 2);
        assert!(m.contains_key(&0), "busy entries are kept");
        assert!(m.contains_key(&(MAX_AGG as u32 + 9)), "biggest kept");
        assert!(!m.contains_key(&1), "smallest idle dropped");

        let mut small: HashMap<u32, ProcAgg> = HashMap::new();
        small.insert(1, ProcAgg::default());
        prune(&mut small, |a| a.down + a.up, |_| true);
        assert_eq!(small.len(), 1, "under the cap nothing goes");
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
