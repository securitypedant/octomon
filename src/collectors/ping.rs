//! ICMP quality collector. One async task per target, each with its own
//! [`surge_ping::Pinger`] sharing a single [`Client`]. Uses unprivileged datagram
//! ICMP sockets (`Config::default()` → `SOCK_DGRAM`), so no root is required on
//! macOS or Linux. Targets can be added at runtime via [`spawn_for`].

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use surge_ping::{Client, PingIdentifier, PingSequence};

use crate::app::AppState;
use crate::config::Config;

/// Spawn a ping loop for a target identified by its stable `id`. The task looks
/// the target up by id each tick, so it self-terminates if the target is
/// removed and is unaffected by other targets being added/deleted.
pub fn spawn_for(
    state: Arc<Mutex<AppState>>,
    client: Arc<Client>,
    cfg: Config,
    id: u64,
    addr: IpAddr,
) {
    tokio::spawn(async move {
        let mut pinger = client
            .pinger(addr, PingIdentifier((id as u16).wrapping_add(1)))
            .await;
        pinger.timeout(cfg.ping_timeout());
        let payload = [0u8; 56];
        let mut seq: u16 = 0;

        // Stagger targets across the interval so their probes don't all fire on
        // the same tick (which bunches sends and can distort timing).
        let offset = cfg.ping_interval_ms.saturating_mul(id % 10) / 10;
        tokio::time::sleep(std::time::Duration::from_millis(offset)).await;

        let mut ticker = tokio::time::interval(cfg.ping_interval());
        loop {
            ticker.tick().await;
            seq = seq.wrapping_add(1);
            let result = pinger.ping(PingSequence(seq), &payload).await;
            let mut s = state.lock().unwrap();
            // Look up by id; if the target was deleted, end this task.
            let Some(target) = s.targets.iter_mut().find(|t| t.id == id) else {
                break;
            };
            match result {
                Ok((_pkt, dur)) => target.record_reply(dur.as_secs_f64() * 1000.0),
                Err(_) => target.record_loss(),
            }
        }
    });
}

/// Spawn ping loops for all targets currently in the state.
pub fn spawn_all(state: Arc<Mutex<AppState>>, client: Arc<Client>, cfg: Config) {
    let snapshot: Vec<(u64, IpAddr)> = {
        let s = state.lock().unwrap();
        s.targets.iter().map(|t| (t.id, t.addr)).collect()
    };
    for (id, addr) in snapshot {
        spawn_for(state.clone(), client.clone(), cfg.clone(), id, addr);
    }
}
