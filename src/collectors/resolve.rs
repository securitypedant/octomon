//! Hostname re-resolution for name-added targets.
//!
//! A CDN answers differently per network, so bbc.co.uk's address is a property
//! of *where you are*: it is re-resolved the moment the network changes (the
//! event that actually flips the answer) and on a slow cadence otherwise —
//! 60 s, matched to typical CDN TTLs; faster would mostly re-read the resolver
//! cache. Never per-ping, which would put a DNS query in front of every
//! latency sample.
//!
//! When the answer changes, the target keeps its identity but its stats reset
//! (latency to the old CDN node says nothing about the new one) and the move
//! lands on the timeline — making "did my network degrade, or did the CDN move
//! me?" answerable at a glance.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;

use crate::app::AppState;

const PERIODIC: Duration = Duration::from_secs(60);

pub async fn run(
    state: Arc<Mutex<AppState>>,
    clients: crate::collectors::ping::Clients,
    cfg: crate::config::Config,
    changed: Arc<Notify>,
) {
    let mut ticker = tokio::time::interval(PERIODIC);
    ticker.tick().await; // the interval fires immediately; targets don't exist yet
    loop {
        // Event-driven on network change — the moment the CDN answer actually
        // flips — with the slow periodic sweep covering DNS-based failover.
        tokio::select! {
            _ = ticker.tick() => {}
            _ = changed.notified() => {}
        }

        let named: Vec<(u64, String, IpAddr)> = {
            let s = state.lock().unwrap();
            s.targets
                .iter()
                .filter_map(|t| t.hostname.clone().map(|h| (t.id, h, t.addr)))
                .collect()
        };

        for (id, host, current) in named {
            let Ok(mut addrs) = tokio::net::lookup_host((host.as_str(), 0)).await else {
                continue; // resolution failing is the DNS story, told elsewhere
            };
            // Prefer an answer in the same family as the current address, so a
            // dual-stack answer doesn't flap the target between families.
            let same_family = addrs.find(|a| a.ip().is_ipv4() == current.is_ipv4());
            let new = match same_family {
                Some(sa) => sa.ip(),
                None => match tokio::net::lookup_host((host.as_str(), 0))
                    .await
                    .ok()
                    .and_then(|mut a| a.next())
                {
                    Some(sa) => sa.ip(),
                    None => continue,
                },
            };
            if new == current {
                continue;
            }

            let monitored = {
                let mut s = state.lock().unwrap();
                let Some(t) = s.targets.iter_mut().find(|t| t.id == id) else {
                    continue;
                };
                t.addr = new; // the ping task notices and rebinds
                t.reset();
                let message = format!("{host} → {new} (was {current}) — stats reset");
                s.push_event(
                    crate::verdict::Severity::Info,
                    crate::app::EventCategory::Network,
                    message,
                );
                // A path monitor on the old address would quietly keep probing
                // a host the target no longer points at — two different hosts
                // under one name on screen.
                s.hop_monitor
                    .as_ref()
                    .filter(|m| m.dest == current)
                    .map(|m| m.target.split(" (").next().unwrap_or(&m.target).to_string())
            };
            if let Some(label) = monitored {
                crate::collectors::hopmon::start(
                    state.clone(),
                    clients.clone(),
                    cfg.clone(),
                    new,
                    label,
                );
            }
        }
    }
}
