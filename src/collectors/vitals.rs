//! Machine vitals (CPU + memory) via sysinfo. Deliberately minimal — just enough
//! to judge whether the local machine, not the network, is the bottleneck.

use std::sync::{Arc, Mutex};

use sysinfo::System;

use crate::app::AppState;
use crate::config::Config;

pub async fn run(state: Arc<Mutex<AppState>>, cfg: Config) {
    let mut sys = System::new();
    let mut ticker = tokio::time::interval(cfg.sample_interval());

    loop {
        ticker.tick().await;
        // CPU usage is a delta between refreshes; the first reading reads ~0.
        sys.refresh_cpu_usage();
        sys.refresh_memory();

        let cpu = sys.global_cpu_usage();
        let used = sys.used_memory();
        let total = sys.total_memory();
        let mem_pct = if total > 0 {
            used as f64 / total as f64 * 100.0
        } else {
            0.0
        };

        let mut s = state.lock().unwrap();
        s.vitals.cpu_pct = cpu;
        s.vitals.mem_used = used;
        s.vitals.mem_total = total;
        s.vitals.cpu_hist.push(cpu as f64);
        s.vitals.mem_hist.push(mem_pct);
    }
}
