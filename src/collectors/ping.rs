//! ICMP quality collector. One async task per target, each with its own
//! [`surge_ping::Pinger`] sharing a per-family [`Client`]. Uses unprivileged
//! datagram ICMP sockets (`SOCK_DGRAM`), so no root is required on macOS or
//! Linux. Targets can be added at runtime via [`spawn_for`].

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use surge_ping::{Client, PingIdentifier, PingSequence};

use crate::app::AppState;
use crate::config::Config;

/// One ICMP client per address family. A v4 client cannot ping a v6 address
/// (a lesson from v6-only carrier hotspots, where every AAAA-resolved target
/// silently showed 100% loss), so both are opened up front and each target
/// picks by its family.
#[derive(Clone, Default)]
pub struct Clients {
    pub v4: Option<Arc<Client>>,
    pub v6: Option<Arc<Client>>,
}

impl Clients {
    /// Open both family clients. Returns the clients plus the v4 error when
    /// even IPv4 ICMP is unavailable — that is the "latency features are dead"
    /// condition; a missing v6 client just means v6 targets can't be probed.
    pub fn open() -> (Self, Option<String>) {
        let v4 = Client::new(&surge_ping::Config::default());
        let v4_err = v4.as_ref().err().map(|e| e.to_string());
        let v6 = Client::new(
            &surge_ping::Config::builder()
                .kind(surge_ping::ICMP::V6)
                .build(),
        );
        (
            Self {
                v4: v4.ok().map(Arc::new),
                v6: v6.ok().map(Arc::new),
            },
            v4_err,
        )
    }

    /// The client that can reach this address, if any.
    pub fn for_addr(&self, addr: IpAddr) -> Option<Arc<Client>> {
        match addr {
            IpAddr::V4(_) => self.v4.clone(),
            IpAddr::V6(_) => self.v6.clone(),
        }
    }

    pub fn available(&self) -> bool {
        self.v4.is_some() || self.v6.is_some()
    }
}

/// Spawn a ping loop for a target identified by its stable `id`. The task looks
/// the target up by id each tick, so it self-terminates if the target is
/// removed and is unaffected by other targets being added/deleted.
pub fn spawn_for(
    state: Arc<Mutex<AppState>>,
    clients: Clients,
    cfg: Config,
    id: u64,
    addr: IpAddr,
) {
    let Some(client) = clients.for_addr(addr) else {
        // No client for this family: say so once rather than accumulating
        // losses that read as a network fault.
        let mut s = state.lock().unwrap();
        let family = if addr.is_ipv6() { "IPv6" } else { "IPv4" };
        s.notice = Some(format!("no {family} ICMP socket — cannot probe {addr}"));
        return;
    };
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
            let rebind = {
                let mut s = state.lock().unwrap();
                // Look up by id; if the target was deleted, end this task.
                let Some(target) = s.targets.iter_mut().find(|t| t.id == id) else {
                    break;
                };
                match result {
                    Ok((_pkt, dur)) => target.record_reply(dur.as_secs_f64() * 1000.0),
                    Err(_) => target.record_loss(),
                }
                // Re-resolution can move a hostname target's address under us
                // (CDNs answer per network); the pinger is bound to an address,
                // so hand over to a fresh task aimed at the new one.
                (target.addr != addr).then_some(target.addr)
            };
            if let Some(new_addr) = rebind {
                spawn_for(state.clone(), clients.clone(), cfg.clone(), id, new_addr);
                break;
            }
        }
    });
}

/// Spawn ping loops for all targets currently in the state.
pub fn spawn_all(state: Arc<Mutex<AppState>>, clients: Clients, cfg: Config) {
    let snapshot: Vec<(u64, IpAddr)> = {
        let s = state.lock().unwrap();
        s.targets.iter().map(|t| (t.id, t.addr)).collect()
    };
    for (id, addr) in snapshot {
        spawn_for(state.clone(), clients.clone(), cfg.clone(), id, addr);
    }
}
