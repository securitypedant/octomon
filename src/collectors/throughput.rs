//! Aggregate throughput from OS interface byte counters (no privileges needed).
//! Focuses on the default-route interface when known, else sums non-loopback
//! interfaces.

use std::sync::{Arc, Mutex};

use sysinfo::Networks;

use crate::app::AppState;
use crate::config::Config;

pub async fn run(state: Arc<Mutex<AppState>>, cfg: Config) {
    let mut networks = Networks::new_with_refreshed_list();

    let mut ticker = tokio::time::interval(cfg.sample_interval());
    ticker.tick().await; // consume the immediate first tick (baseline)

    // Which interface the previous sample measured. A change means the counter
    // delta spans two different NICs, so that one sample has to be discarded.
    let mut prev_iface: Option<String> = None;

    loop {
        ticker.tick().await;
        // `received()` / `transmitted()` report bytes since the previous refresh.
        // `refresh(true)` also picks up interfaces that appeared since the last
        // call, so a VPN or a newly plugged NIC starts being counted.
        networks.refresh(true);
        let secs = cfg.sample_interval().as_secs_f64().max(0.001);

        // Follow the default route as netinfo re-probes it, rather than a name
        // captured at startup — otherwise switching Wi-Fi networks, plugging in
        // Ethernet, or a VPN coming up leaves this reading a dead interface.
        let want = {
            let s = state.lock().unwrap();
            Some(s.netinfo.iface.clone()).filter(|n| !n.is_empty())
        };

        let mut down = 0u64;
        let mut up = 0u64;
        let mut label = String::from("all");

        for (name, data) in &networks {
            match &want {
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

        // The first sample after a switch compares counters from the old NIC
        // against the new one, which would render as a huge phantom spike.
        let switched = prev_iface.as_deref() != Some(label.as_str());
        prev_iface = Some(label.clone());
        if switched {
            let mut s = state.lock().unwrap();
            s.throughput.iface = label;
            s.throughput.down_bps = 0.0;
            s.throughput.up_bps = 0.0;
            continue;
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
