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
    // The default-route name the counters could not find, logged once per
    // name rather than once per second.
    let mut missing_logged: Option<String> = None;

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
        let (want, underlay) = {
            let s = state.lock().unwrap();
            (
                Some(s.netinfo.iface.clone()).filter(|n| !n.is_empty()),
                Some(s.netinfo.underlay_iface.clone()).filter(|n| !n.is_empty()),
            )
        };

        let mut down = 0u64;
        let mut up = 0u64;
        let mut label = String::from("all");
        // Error and packet counters ride along with the byte counters — same
        // refresh, no extra syscalls. Rising errors while CPU looks fine point
        // at the link itself, which nothing else in octomon would reveal.
        let mut rx_err = 0u64;
        let mut tx_err = 0u64;
        let mut rx_pkt = 0u64;
        let mut tx_pkt = 0u64;

        // The default-route interface alone when its counters can be found.
        // Failing that, the physical adapter under a tunnel: the same bytes
        // pass through it, encrypted, so it is the right single reading
        // when the tunnel adapter itself has no counters (NordVPN's NordLynx
        // on Windows, found in the field: the default route named an adapter
        // sysinfo does not list, and a name that matched nothing used to
        // count nothing, so the graph drew its first few samples while the
        // default route was still unknown and then sat at zero for the rest
        // of the session). Failing both, every non-loopback adapter summed:
        // the honest reading when nothing can be singled out, at the cost
        // of counting a tunnel's traffic twice. Each step down is logged
        // once so it can be seen and fixed.
        let find = |n: &String| networks.iter().find(|(name, _)| *name == n);
        let matched = want
            .as_ref()
            .and_then(find)
            .or_else(|| underlay.as_ref().and_then(find));
        match matched {
            Some((name, data)) => {
                if let Some(di) = &want
                    && di != name
                    && missing_logged.as_deref() != Some(di.as_str())
                {
                    crate::errlog::log(
                        "throughput",
                        format!(
                            "default interface {di:?} has no counters under that name; reading its underlay {name:?}"
                        ),
                    );
                    missing_logged = Some(di.clone());
                }
                down = data.received();
                up = data.transmitted();
                rx_err = data.errors_on_received();
                tx_err = data.errors_on_transmitted();
                rx_pkt = data.packets_received();
                tx_pkt = data.packets_transmitted();
                label = name.clone();
            }
            None => {
                if let Some(di) = &want
                    && missing_logged.as_deref() != Some(di.as_str())
                {
                    let known: Vec<&str> = networks.keys().map(|n| n.as_str()).collect();
                    crate::errlog::log(
                        "throughput",
                        format!(
                            "default interface {di:?} has no counters under that name (sysinfo knows {known:?}); summing every adapter"
                        ),
                    );
                    missing_logged = Some(di.clone());
                }
                for (name, data) in &networks {
                    if name.starts_with("lo") {
                        continue;
                    }
                    down += data.received();
                    up += data.transmitted();
                    rx_err += data.errors_on_received();
                    tx_err += data.errors_on_transmitted();
                    rx_pkt += data.packets_received();
                    tx_pkt += data.packets_transmitted();
                }
            }
        }

        // The first sample after a switch compares counters from the old NIC
        // against the new one, which would render as a huge phantom spike.
        let switched = prev_iface.as_deref() != Some(label.as_str());
        prev_iface = Some(label.clone());
        if switched {
            let mut s = state.lock().unwrap();
            s.throughput.iface = label.clone();
            s.throughput.down_bps = 0.0;
            s.throughput.up_bps = 0.0;
            // Error totals belong to the interface that produced them.
            s.link_errors = crate::app::LinkErrors {
                iface: label,
                ..Default::default()
            };
            continue;
        }

        let down_bps = down as f64 / secs;
        let up_bps = up as f64 / secs;

        let mut s = state.lock().unwrap();
        s.throughput.iface = label.clone();
        s.throughput.down_bps = down_bps;
        s.throughput.up_bps = up_bps;
        s.throughput.down_hist.push(down_bps);
        s.throughput.up_hist.push(up_bps);

        let e = &mut s.link_errors;
        e.iface = label;
        e.rx_err_per_sec = rx_err as f64 / secs;
        e.tx_err_per_sec = tx_err as f64 / secs;
        // Kept cumulative so a brief burst stays visible after it stops.
        e.rx_err_total += rx_err;
        e.tx_err_total += tx_err;
        e.rx_packets_per_sec = rx_pkt as f64 / secs;
        e.tx_packets_per_sec = tx_pkt as f64 / secs;
    }
}
