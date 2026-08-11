//! Machine vitals via sysinfo, framed as "is the local machine the bottleneck?"
//!
//! Beyond CPU and memory this collects the signals that explain a slow network
//! when the obvious ones look fine: a single saturated core, memory pressure,
//! load average, and (on macOS) thermal throttling — which tanks throughput
//! while CPU sits idle.

use std::sync::{Arc, Mutex};

use sysinfo::System;

use crate::app::AppState;
use crate::config::Config;

/// The thermal probe shells out, so it runs far less often than the counters.
const THERMAL_EVERY: u32 = 30;

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
        tick = tick.wrapping_add(1);

        let mut s = state.lock().unwrap();
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
