//! Aggregate throughput from OS interface byte counters (no privileges needed).
//! Focuses on the default-route interface when known, else sums non-loopback
//! interfaces.

use std::sync::{Arc, Mutex};

use sysinfo::Networks;

use crate::app::AppState;
use crate::config::Config;

pub async fn run(state: Arc<Mutex<AppState>>, cfg: Config) {
    let default_iface = netdev::get_default_interface().map(|i| i.name).ok();
    let mut networks = Networks::new_with_refreshed_list();

    let mut ticker = tokio::time::interval(cfg.sample_interval());
    ticker.tick().await; // consume the immediate first tick (baseline)

    loop {
        ticker.tick().await;
        // `received()` / `transmitted()` report bytes since the previous refresh.
        networks.refresh(true);
        let secs = cfg.sample_interval().as_secs_f64().max(0.001);

        let mut down = 0u64;
        let mut up = 0u64;
        let mut label = String::from("all");

        for (name, data) in &networks {
            match &default_iface {
                Some(di) if di == name => {
                    down = data.received();
                    up = data.transmitted();
                    label = di.clone();
                    break;
                }
                Some(_) => continue,
                None => {
                    if name.starts_with("lo") {
                        continue;
                    }
                    down += data.received();
                    up += data.transmitted();
                }
            }
        }

        let down_bps = down as f64 / secs;
        let up_bps = up as f64 / secs;

        let mut s = state.lock().unwrap();
        s.throughput.iface = label;
        s.throughput.down_bps = down_bps;
        s.throughput.up_bps = up_bps;
        s.throughput.down_hist.push(down_bps);
        s.throughput.up_hist.push(up_bps);
    }
}
