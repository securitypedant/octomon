//! Startup path discovery: traceroute a few hops toward the internet and add
//! the gateway + next hops as auto-discovered targets, so the user immediately
//! sees where local-network quality ends and the ISP path begins.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use surge_ping::Client;
use tokio::process::Command;

use crate::app::{AppState, TargetStat};
use crate::collectors::ping;
use crate::config::Config;
use crate::platform::traceroute as tr;

const MAX_HOPS: usize = 4; // gateway (1) + next three

pub async fn run(state: Arc<Mutex<AppState>>, client: Arc<Client>, cfg: Config) {
    // Configurable: the useful probe target depends on the network. Empty
    // disables discovery entirely, like `public_ip_url`.
    let probe = cfg.discovery_probe.trim().to_string();
    if probe.is_empty() {
        return;
    }
    let out = Command::new(tr::PROGRAM)
        .args(tr::args(MAX_HOPS, &probe))
        .stdin(std::process::Stdio::null())
        .output()
        .await;
    let Ok(out) = out else {
        return;
    };

    for line in String::from_utf8_lossy(&out.stdout).lines() {
        // Only hops that answered can be pinged; a `*` hop has no address.
        let Some(hop) = tr::parse_hop(line) else {
            continue;
        };
        let (ttl, Some(addr)) = (hop.ttl, hop.addr.and_then(|a| a.parse::<IpAddr>().ok())) else {
            continue;
        };
        // Name what the hop is on the way *to*: "hop 3" alone leaves you
        // wondering hop 3 of which path, since these come from one traceroute
        // toward the internet rather than from anywhere in the target list.
        let label = if ttl == 1 {
            "gateway".to_string()
        } else {
            format!("hop {ttl}→{probe}")
        };

        let (id, added) = {
            let mut s = state.lock().unwrap();
            // Skip if this address is already a target.
            if s.targets.iter().any(|t| t.addr == addr) {
                (0, false)
            } else {
                let mut t = TargetStat::new(label, addr);
                t.discovered = true;
                let id = t.id;
                s.targets.push(t);
                (id, true)
            }
        };
        if added {
            ping::spawn_for(state.clone(), client.clone(), cfg.clone(), id, addr);
        }
    }
}

/// Re-run discovery after the machine moved to a different network: the old
/// gateway and hops belong to a network that is no longer reachable, so they are
/// dropped before the path is walked again. Hand-added targets are left alone.
pub async fn refresh(state: Arc<Mutex<AppState>>, client: Arc<Client>, cfg: Config) {
    {
        let mut s = state.lock().unwrap();
        s.targets.retain(|t| !t.discovered);
        // The cursors index into `targets`, so they have to be pulled back in.
        let last = s.targets.len().saturating_sub(1);
        s.selected = s.selected.min(last);
        s.graph_target = s.graph_target.min(last);
    }
    run(state.clone(), client.clone(), cfg.clone()).await;
    public_ip(state, client, cfg).await;
}

/// Watch for the network changing under us and rebuild everything derived from
/// it: the discovered targets, and the path monitor if one is running.
pub async fn watch(
    state: Arc<Mutex<AppState>>,
    client: Arc<Client>,
    cfg: Config,
    changed: Arc<tokio::sync::Notify>,
) {
    let mut seen = state.lock().unwrap().net_change_seq;
    loop {
        // A slow fallback tick alongside the signal, so a change landing while
        // a rebuild is already in flight is still noticed.
        tokio::select! {
            _ = changed.notified() => {}
            _ = tokio::time::sleep(std::time::Duration::from_secs(15)) => {}
        }
        let (seq, monitoring) = {
            let s = state.lock().unwrap();
            (
                s.net_change_seq,
                s.hop_monitor.as_ref().map(|m| (m.dest, m.target.clone())),
            )
        };
        if seq == seen {
            continue;
        }
        seen = seq;

        refresh(state.clone(), client.clone(), cfg.clone()).await;

        // A path monitored on the old network says nothing about the new one.
        if let Some((dest, label)) = monitoring {
            let label = label.split(" (").next().unwrap_or(&label).to_string();
            crate::collectors::hopmon::start(
                state.clone(),
                client.clone(),
                cfg.clone(),
                dest,
                label,
            );
        }
    }
}

/// Discover the machine's public IP from `cfg.public_ip_url` (a plain-text IP
/// endpoint) and add it as a target. No-op if the URL is empty or the response
/// isn't a valid IP.
pub async fn public_ip(state: Arc<Mutex<AppState>>, client: Arc<Client>, cfg: Config) {
    if cfg.public_ip_url.trim().is_empty() {
        return;
    }
    let Ok(http) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    else {
        return;
    };
    // Cap the body (an IP is tiny); only accept a clean IP literal.
    let Ok(text) = crate::util::fetch_text_capped(&http, &cfg.public_ip_url, 4096).await else {
        return;
    };
    let Ok(addr) = text.trim().parse::<IpAddr>() else {
        return;
    };

    let (id, added) = {
        let mut s = state.lock().unwrap();
        if s.targets.iter().any(|t| t.addr == addr) {
            (0, false)
        } else {
            let mut t = TargetStat::new("public IP".to_string(), addr);
            t.discovered = true;
            let id = t.id;
            s.targets.push(t);
            (id, true)
        }
    };
    if added {
        ping::spawn_for(state, client, cfg, id, addr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_probe_defaults_to_cloudflare_and_can_be_disabled() {
        assert_eq!(Config::default().discovery_probe, "1.1.1.1");

        // An empty value disables discovery, matching `public_ip_url`.
        let cfg = Config {
            discovery_probe: "  ".to_string(),
            ..Default::default()
        };
        assert!(cfg.discovery_probe.trim().is_empty());
    }

    #[test]
    fn a_configured_probe_survives_a_round_trip_through_toml() {
        let cfg = Config {
            discovery_probe: "9.9.9.9".to_string(),
            ..Default::default()
        };
        let text = toml::to_string_pretty(&cfg).unwrap();
        assert!(text.contains("discovery_probe = \"9.9.9.9\""));
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back.discovery_probe, "9.9.9.9");
    }

    /// An older config without the key must still load, taking the default.
    #[test]
    fn missing_key_falls_back_to_the_default() {
        let cfg: Config = toml::from_str("ping_interval_ms = 500").unwrap();
        assert_eq!(cfg.discovery_probe, "1.1.1.1");
        assert_eq!(cfg.ping_interval_ms, 500);
    }
}
