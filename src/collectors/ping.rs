//! ICMP quality collector. One async task per target, each with its own
//! [`surge_ping::Pinger`] and a unique identifier. Uses unprivileged datagram
//! ICMP sockets (`Config::default()` → `SOCK_DGRAM`), so no root is required on
//! macOS or Linux.

use std::sync::{Arc, Mutex};

use surge_ping::{Client, Config as PingConfig, PingIdentifier, PingSequence};

use crate::app::AppState;
use crate::config::Config;

pub async fn run(state: Arc<Mutex<AppState>>, cfg: Config) {
    let client = match Client::new(&PingConfig::default()) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::error!("failed to create ICMP client: {e}");
            return;
        }
    };

    let targets: Vec<(usize, std::net::IpAddr)> = {
        let s = state.lock().unwrap();
        s.targets.iter().enumerate().map(|(i, t)| (i, t.addr)).collect()
    };

    let mut handles = Vec::new();
    for (idx, addr) in targets {
        let client = client.clone();
        let state = state.clone();
        let interval = cfg.ping_interval();
        let timeout = cfg.ping_timeout();
        handles.push(tokio::spawn(async move {
            // Identifier must be unique per socket/target; offset to avoid 0.
            let mut pinger = client.pinger(addr, PingIdentifier(idx as u16 + 1)).await;
            pinger.timeout(timeout);
            let payload = [0u8; 56];
            let mut seq: u16 = 0;
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                seq = seq.wrapping_add(1);
                let result = pinger.ping(PingSequence(seq), &payload).await;
                let mut s = state.lock().unwrap();
                match result {
                    Ok((_pkt, dur)) => {
                        s.targets[idx].record_reply(dur.as_secs_f64() * 1000.0);
                    }
                    Err(_) => s.targets[idx].record_loss(),
                }
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }
}
