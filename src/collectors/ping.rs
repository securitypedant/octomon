//! ICMP quality collector. One async task per target, each with its own
//! [`surge_ping::Pinger`] sharing a single [`Client`]. Uses unprivileged datagram
//! ICMP sockets (`Config::default()` → `SOCK_DGRAM`), so no root is required on
//! macOS or Linux. Targets can be added at runtime via [`spawn_for`].

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use surge_ping::{Client, PingIdentifier, PingSequence};

use crate::app::AppState;
use crate::config::Config;

/// Spawn a ping loop for a single target index. The identifier must be unique
/// per socket, so it is derived from the (stable) target index.
pub fn spawn_for(
    state: Arc<Mutex<AppState>>,
    client: Arc<Client>,
    cfg: Config,
    idx: usize,
    addr: IpAddr,
) {
    tokio::spawn(async move {
        let mut pinger = client.pinger(addr, PingIdentifier(idx as u16 + 1)).await;
        pinger.timeout(cfg.ping_timeout());
        let payload = [0u8; 56];
        let mut seq: u16 = 0;
        let mut ticker = tokio::time::interval(cfg.ping_interval());
        loop {
            ticker.tick().await;
            seq = seq.wrapping_add(1);
            let result = pinger.ping(PingSequence(seq), &payload).await;
            let mut s = state.lock().unwrap();
            // Guard against the target list having shrunk (not currently possible,
            // but keeps this robust against future removals).
            let Some(target) = s.targets.get_mut(idx) else {
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
    let snapshot: Vec<(usize, IpAddr)> = {
        let s = state.lock().unwrap();
        s.targets.iter().enumerate().map(|(i, t)| (i, t.addr)).collect()
    };
    for (idx, addr) in snapshot {
        spawn_for(state.clone(), client.clone(), cfg.clone(), idx, addr);
    }
}
