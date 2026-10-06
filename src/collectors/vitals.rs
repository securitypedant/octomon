//! Machine vitals via sysinfo, framed as "is the local machine the bottleneck?"
//!
//! Beyond CPU and memory this collects the signals that explain a slow network
//! when the obvious ones look fine: a single saturated core, memory pressure,
//! load average, and (on macOS) thermal throttling — which tanks throughput
//! while CPU sits idle.

use std::sync::{Arc, Mutex};

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

use crate::app::{AppState, TOP_PROCS, TopProc};
use crate::config::Config;

/// The thermal probe shells out, so it runs far less often than the counters.
const THERMAL_EVERY: u32 = 30;
/// Walking the process table costs tens of milliseconds on a busy machine;
/// every other sample is plenty for "what is eating the CPU".
const PROCS_EVERY: u32 = 2;

pub async fn run(state: Arc<Mutex<AppState>>, cfg: Config) {
    let mut sys = System::new();
    let mut ticker = tokio::time::interval(cfg.sample_interval());
    let mut tick: u32 = 0;

    loop {
        ticker.tick().await;
        // CPU usage is a delta between refreshes; the first reading reads ~0.
        sys.refresh_cpu_usage();
        sys.refresh_memory();

        let cpu = sys.global_cpu_usage();
        let cores: Vec<f32> = sys.cpus().iter().map(|c| c.cpu_usage()).collect();
        let used = sys.used_memory();
        let total = sys.total_memory();
        let available = sys.available_memory();
        let mem_pct = if total > 0 {
            used as f64 / total as f64 * 100.0
        } else {
            0.0
        };
        // Pressure is what is *unavailable*, not what is "used": caches count
        // as used but are handed back on demand, so used/total sits near 100%
        // on a healthy machine and tells you nothing.
        let pressure = if total > 0 {
            ((total.saturating_sub(available)) as f64 / total as f64 * 100.0) as f32
        } else {
            0.0
        };
        let load = System::load_average();

        // Thermal state changes slowly and costs a subprocess.
        let thermal = if tick.is_multiple_of(THERMAL_EVERY) {
            crate::platform::thermal_state().await
        } else {
            None
        };
        // The busiest processes. The cpu figure is per core, the convention
        // of Activity Monitor, top and htop: one fully busy core is 100%, a
        // multithreaded build can read 400%. The first cut divided by the
        // core count so the rows added up to the gauge above, and a
        // swift-frontend at 73% in Activity Monitor read 4% here — nobody
        // compares against the gauge, they compare against the tool they
        // know. The first refresh has no previous sample and reads every
        // process at zero, which the filter drops rather than showing ten
        // idle rows.
        let top = if tick.is_multiple_of(PROCS_EVERY) {
            sys.refresh_processes_specifics(
                ProcessesToUpdate::All,
                true,
                ProcessRefreshKind::nothing().with_cpu().with_memory(),
            );
            let row = |p: &sysinfo::Process| TopProc {
                pid: p.pid().as_u32(),
                name: p.name().to_string_lossy().into_owned(),
                cpu_pct: p.cpu_usage(),
                mem: p.memory(),
            };
            let mut all: Vec<TopProc> = sys.processes().values().map(row).collect();
            // The union of the top ten by CPU and the top ten by memory:
            // the panel sorts by whichever column is chosen, and either
            // answer has to be in the list for that to mean anything.
            all.sort_by(|a, b| b.cpu_pct.total_cmp(&a.cpu_pct));
            let mut top: Vec<TopProc> = all
                .iter()
                .filter(|p| p.cpu_pct > 0.0)
                .take(TOP_PROCS)
                .cloned()
                .collect();
            all.sort_by_key(|p| std::cmp::Reverse(p.mem));
            for p in all.iter().filter(|p| p.mem > 0).take(TOP_PROCS) {
                if !top.iter().any(|t| t.pid == p.pid) {
                    top.push(p.clone());
                }
            }
            let own = sys
                .process(sysinfo::Pid::from_u32(std::process::id()))
                .map(row);
            Some((top, own))
        } else {
            None
        };
        let uptime = System::uptime();
        tick = tick.wrapping_add(1);

        let mut s = state.lock().unwrap();
        if let Some((top, own)) = top {
            s.vitals.top_procs = top;
            s.vitals.own = own;
        }
        s.vitals.uptime_secs = uptime;
        s.vitals.cpu_pct = cpu;
        s.vitals.cores = cores;
        s.vitals.mem_used = used;
        s.vitals.mem_total = total;
        s.vitals.mem_pressure_pct = pressure;
        s.vitals.swap_used = sys.used_swap();
        s.vitals.swap_total = sys.total_swap();
        s.vitals.load = (load.one, load.five, load.fifteen);
        s.vitals.cpu_hist.push(cpu as f64);
        s.vitals.mem_hist.push(mem_pct);
        s.vitals.pressure_hist.push(pressure as f64);
        if let Some(t) = thermal {
            s.vitals.thermal = t.summary;
            s.vitals.throttled = t.throttled;
            s.vitals.power_source = t.power_source;
        }
    }
}
