//! Aggregate throughput from OS interface byte counters (no privileges needed).
//! Focuses on the default-route interface when known, else the physical
//! adapter under it, else sums the physical interfaces.

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

        let mut label = String::from("all");

        // The default-route interface alone when its counters can be found.
        // Failing that, the physical adapter under a tunnel: the same bytes
        // pass through it, encrypted, so it is the right single reading
        // when the tunnel adapter itself has no counters (NordVPN's NordLynx
        // on Windows, found in the field: the default route named an adapter
        // sysinfo does not list, and a name that matched nothing used to
        // count nothing, so the graph drew its first few samples while the
        // default route was still unknown and then sat at zero for the rest
        // of the session). Failing both, every physical adapter summed: the
        // honest reading when nothing can be singled out. Tunnels stay out
        // of that sum, because a VPN's bytes also cross the adapter under
        // it and would be counted twice (issue #19). Each step down is
        // logged once so it can be seen and fixed.
        let find = |n: &String| networks.iter().find(|(name, _)| *name == n);
        let matched = want
            .as_ref()
            .and_then(find)
            .or_else(|| underlay.as_ref().and_then(find));
        let c = match matched {
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
                label = name.clone();
                Counters::of(data)
            }
            None => {
                if let Some(di) = &want
                    && missing_logged.as_deref() != Some(di.as_str())
                {
                    let known: Vec<&str> = networks.keys().map(|n| n.as_str()).collect();
                    crate::errlog::log(
                        "throughput",
                        format!(
                            "default interface {di:?} has no counters under that name (sysinfo knows {known:?}); summing every physical adapter"
                        ),
                    );
                    missing_logged = Some(di.clone());
                }
                sum_physical(
                    networks
                        .iter()
                        .map(|(name, data)| (name.as_str(), Counters::of(data))),
                )
            }
        };
        let Counters {
            down,
            up,
            rx_err,
            tx_err,
            rx_pkt,
            tx_pkt,
        } = c;

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
        s.throughput.sampled_at = Some(std::time::Instant::now());

        let e = &mut s.link_errors;
        e.iface = label;
        e.rx_err_per_sec = rx_err as f64 / secs;
        e.tx_err_per_sec = tx_err as f64 / secs;
        // Kept cumulative so a brief burst stays visible after it stops.
        e.rx_err_total += rx_err;
        e.tx_err_total += tx_err;
        e.rx_packets_per_sec = rx_pkt as f64 / secs;
        e.tx_packets_per_sec = tx_pkt as f64 / secs;
        e.record(secs, rx_pkt + tx_pkt, rx_err + tx_err);
    }
}

/// One refresh's worth of an interface's counters: bytes, errors and packets
/// since the previous refresh, in each direction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Counters {
    down: u64,
    up: u64,
    rx_err: u64,
    tx_err: u64,
    rx_pkt: u64,
    tx_pkt: u64,
}

impl Counters {
    fn of(data: &sysinfo::NetworkData) -> Self {
        Self {
            down: data.received(),
            up: data.transmitted(),
            rx_err: data.errors_on_received(),
            tx_err: data.errors_on_transmitted(),
            rx_pkt: data.packets_received(),
            tx_pkt: data.packets_transmitted(),
        }
    }

    fn add(self, o: Self) -> Self {
        Self {
            down: self.down + o.down,
            up: self.up + o.up,
            rx_err: self.rx_err + o.rx_err,
            tx_err: self.tx_err + o.tx_err,
            rx_pkt: self.rx_pkt + o.rx_pkt,
            tx_pkt: self.tx_pkt + o.tx_pkt,
        }
    }
}

/// The last-resort reading: every adapter summed, except loopback and
/// anything named like a tunnel. With a VPN up, the tunnel adapter and the
/// physical adapter beneath it both report the same traffic, once in the
/// clear and once encrypted, so adding both showed twice the real rate
/// (issue #19). Skipping the tunnel leaves one copy.
fn sum_physical<'a>(entries: impl Iterator<Item = (&'a str, Counters)>) -> Counters {
    entries
        .filter(|(name, _)| !is_loopback_name(name) && !super::netinfo::is_tunnel_name(name))
        .fold(Counters::default(), |acc, (_, c)| acc.add(c))
}

/// `lo` / `lo0` on Unix, "Loopback Pseudo-Interface 1" on Windows. A bare
/// "lo" prefix would also catch "Local Area Connection", which is a real
/// Ethernet adapter on older Windows, so the Unix form wants digits only
/// after it.
fn is_loopback_name(name: &str) -> bool {
    name.strip_prefix("lo")
        .is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_digit()))
        || name.starts_with("Loopback")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(down: u64, up: u64) -> Counters {
        Counters {
            down,
            up,
            rx_pkt: down / 1000,
            tx_pkt: up / 1000,
            ..Default::default()
        }
    }

    /// A VPN's bytes cross the tunnel adapter and, encrypted, the physical
    /// one beneath it. The sum must carry them once.
    #[test]
    fn the_sum_counts_a_tunnels_traffic_once() {
        let entries = [
            ("Ethernet", bytes(1_000_000, 50_000)),
            ("NordLynx", bytes(1_000_000, 50_000)),
            ("WireGuard Tunnel", bytes(1_000_000, 50_000)),
            ("Loopback Pseudo-Interface 1", bytes(9_999, 9_999)),
        ];
        let c = sum_physical(entries.into_iter());
        assert_eq!(c.down, 1_000_000);
        assert_eq!(c.up, 50_000);
        assert_eq!(c.rx_pkt, 1_000);
    }

    /// Two physical adapters carry different traffic, so both are added;
    /// loopback never is.
    #[test]
    fn physical_adapters_are_added_and_loopback_skipped() {
        let entries = [
            ("en0", bytes(300, 30)),
            ("en5", bytes(200, 20)),
            ("lo0", bytes(500, 500)),
            ("utun4", bytes(300, 30)),
        ];
        let c = sum_physical(entries.into_iter());
        assert_eq!((c.down, c.up), (500, 50));
    }

    #[test]
    fn loopback_is_known_by_its_unix_and_windows_names_only() {
        for n in ["lo", "lo0", "Loopback Pseudo-Interface 1"] {
            assert!(is_loopback_name(n), "{n}");
        }
        for n in ["Local Area Connection", "lom0", "en0", "Ethernet"] {
            assert!(!is_loopback_name(n), "{n}");
        }
    }

    #[test]
    fn nothing_physical_sums_to_nothing() {
        let entries = [("lo0", bytes(5, 5)), ("tun0", bytes(5, 5))];
        assert_eq!(sum_physical(entries.into_iter()), Counters::default());
    }
}
