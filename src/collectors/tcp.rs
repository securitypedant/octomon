//! TCP connect probes: the ICMP stand-in. A SYN→established round trip to
//! port 443 measures network RTT the way tcping does — no ICMP required, so
//! networks that blackhole ping (Azure VMs, locked-down hotels) still get
//! real latency, jitter and loss columns. Anchors (and their auto-added v6
//! twins) only: discovered hops and gateways rarely serve 443, and probing
//! them would manufacture loss.
//!
//! One honesty caveat, documented rather than hidden: a lost SYN is
//! retransmitted by the kernel (~1 s), so single-packet loss shows up as a
//! *late* connect rather than a miss — TCP "loss" here means the handshake
//! failed outright within the timeout. Latency and jitter are solid.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::app::AppState;
use crate::config::Config;

/// The one port probed: HTTPS, which every default anchor serves (1.1.1.1,
/// 8.8.8.8 and 9.9.9.9 all answer DoH there; named targets are websites).
const PORT: u16 = 443;

pub async fn run(state: Arc<Mutex<AppState>>, cfg: Config) {
    let mut ticker = tokio::time::interval(Duration::from_millis(cfg.ping_interval_ms.max(200)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let timeout = Duration::from_millis(cfg.ping_timeout_ms.max(200));
    loop {
        ticker.tick().await;
        // Snapshot the anchors under the lock, probe without it.
        let targets: Vec<(u64, IpAddr)> = {
            let s = state.lock().unwrap();
            // Anchors and their v6 twins; never the gateway or the hops.
            s.targets
                .iter()
                .filter(|t| !t.discovered || t.is_v6_anchor())
                .map(|t| (t.id, t.addr))
                .collect()
        };
        if targets.is_empty() {
            continue;
        }
        let probes = targets.into_iter().map(|(id, addr)| async move {
            let started = std::time::Instant::now();
            let ok = tokio::time::timeout(timeout, tokio::net::TcpStream::connect((addr, PORT)))
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);
            // Dropping the stream closes it immediately; no bytes are sent.
            (id, ok.then(|| started.elapsed().as_secs_f64() * 1000.0))
        });
        let results = futures_util::future::join_all(probes).await;
        let mut s = state.lock().unwrap();
        for (id, rtt) in results {
            // Re-find by id: the target may have been deleted mid-probe.
            let Some(t) = s.targets.iter_mut().find(|t| t.id == id) else {
                continue;
            };
            match rtt {
                Some(ms) => t.tcp.record_reply(ms),
                None => t.tcp.record_loss(),
            }
        }
    }
}
