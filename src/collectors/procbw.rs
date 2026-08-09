//! Per-process bandwidth. Platform sampling returns *cumulative* byte counters,
//! so this collector diffs successive samples to derive per-process rates and
//! keeps the top talkers. Exits early (marking unsupported) where the platform
//! has no unprivileged source.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::app::{AppState, ProcBandwidth};
use crate::platform;

const TOP_N: usize = 6;

pub async fn run(state: Arc<Mutex<AppState>>) {
    // Probe support once; bail (leaving proc_supported = false) if unavailable.
    if platform::proc_net_sample().await.is_none() {
        return;
    }
    state.lock().unwrap().proc_supported = true;

    let mut prev: HashMap<u32, (u64, u64)> = HashMap::new();
    let mut prev_at = Instant::now();
    let mut ticker = tokio::time::interval(Duration::from_secs(2));

    loop {
        ticker.tick().await;
        let Some(sample) = platform::proc_net_sample().await else {
            continue;
        };
        let now = Instant::now();
        let secs = now.duration_since(prev_at).as_secs_f64().max(0.001);

        let mut list: Vec<ProcBandwidth> = Vec::new();
        for s in &sample {
            if let Some((pin, pout)) = prev.get(&s.pid) {
                let down = s.bytes_in.saturating_sub(*pin) as f64 / secs;
                let up = s.bytes_out.saturating_sub(*pout) as f64 / secs;
                if down + up > 0.0 {
                    list.push(ProcBandwidth {
                        name: s.name.clone(),
                        pid: s.pid,
                        down_bps: down,
                        up_bps: up,
                    });
                }
            }
        }
        list.sort_by(|a, b| {
            (b.down_bps + b.up_bps)
                .total_cmp(&(a.down_bps + a.up_bps))
        });
        list.truncate(TOP_N);

        prev = sample
            .iter()
            .map(|s| (s.pid, (s.bytes_in, s.bytes_out)))
            .collect();
        prev_at = now;

        state.lock().unwrap().processes = list;
    }
}
