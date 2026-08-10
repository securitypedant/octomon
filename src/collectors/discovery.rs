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

const PROBE: &str = "1.1.1.1";
const MAX_HOPS: usize = 4; // gateway (1) + next three

pub async fn run(state: Arc<Mutex<AppState>>, client: Arc<Client>, cfg: Config) {
    let out = Command::new("traceroute")
        .args([
            "-n",
            "-q",
            "1",
            "-w",
            "1",
            "-m",
            &MAX_HOPS.to_string(),
            PROBE,
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .await;
    let Ok(out) = out else {
        return;
    };

    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Some((ttl, addr)) = parse_hop(line) else {
            continue;
        };
        let label = if ttl == 1 {
            "gateway".to_string()
        } else {
            format!("hop {ttl}")
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

/// Parse a hop line, returning (ttl, addr) only for hops that responded.
fn parse_hop(line: &str) -> Option<(u8, IpAddr)> {
    let mut it = line.split_whitespace();
    let ttl: u8 = it.next()?.parse().ok()?;
    let addr: IpAddr = it.next()?.parse().ok()?;
    Some((ttl, addr))
}
