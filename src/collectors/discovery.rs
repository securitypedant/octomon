//! Startup path discovery: traceroute a few hops toward the internet and add
//! the gateway + next hops as auto-discovered targets, so the user immediately
//! sees where local-network quality ends and the ISP path begins.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use tokio::process::Command;

use crate::app::{AppState, TargetStat};
use crate::collectors::ping;
use crate::config::Config;
use crate::platform::traceroute as tr;

const MAX_HOPS: usize = 4; // gateway (1) + next three

pub async fn run(state: Arc<Mutex<AppState>>, clients: ping::Clients, cfg: Config) {
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
        //
        // TTL 1 is only "the gateway" when it plausibly IS this LAN's
        // gateway: the routing table's address, or at least something on the
        // private side. Hotel gateways that stay silent leave the first
        // *answering* hop upstream at TTL 1, and a VPN's walk starts at the
        // vendor's edge — labeling either "gateway" made the Quality panel
        // contradict the Network panel and fed a stranger's router into the
        // gateway baseline. (The routing-table gateway itself is probed by
        // the fallback below whenever the walk didn't cover it.)
        let plausibly_gateway = ttl == 1 && {
            let s = state.lock().unwrap();
            s.netinfo.gateway_ip == addr.to_string() || s.netinfo.is_lan_addr(addr)
        };
        let label = if plausibly_gateway {
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
            ping::spawn_for(state.clone(), clients.clone(), cfg.clone(), id, addr);
        }
    }

    // A gateway that answers nothing at all — not even the TTL-exceeded
    // replies the walk listens for (phone hotspots, hardened firewalls) —
    // never appears above, but the routing table still names it. Probe it
    // anyway: beside clean anchors, its 100% loss is exactly the evidence the
    // drops-ICMP judgement turns into "fine, just silent", and without a
    // probe the gateway rung would read "not discovered" forever. netinfo
    // populates on its own 5 s cadence, so wait briefly for it.
    for _ in 0..10 {
        let gw_ip = state.lock().unwrap().netinfo.gateway_ip.clone();
        if let Ok(addr) = gw_ip.parse::<IpAddr>() {
            let (id, added) = {
                let mut s = state.lock().unwrap();
                let have = s
                    .targets
                    .iter()
                    .any(|t| t.addr == addr || (t.discovered && t.label == "gateway"));
                if have {
                    (0, false)
                } else {
                    let mut t = TargetStat::new("gateway".to_string(), addr);
                    t.discovered = true;
                    let id = t.id;
                    s.targets.push(t);
                    (id, true)
                }
            };
            if added {
                ping::spawn_for(state.clone(), clients.clone(), cfg.clone(), id, addr);
            }
            return;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// Re-run discovery after the machine moved to a different network: the old
/// gateway and hops belong to a network that is no longer reachable, so they are
/// dropped before the path is walked again. Hand-added targets are left alone.
pub async fn refresh(state: Arc<Mutex<AppState>>, clients: ping::Clients, cfg: Config) {
    {
        let mut s = state.lock().unwrap();
        s.targets.retain(|t| !t.discovered);
        // The cursors index into `targets`, so they have to be pulled back in.
        let last = s.targets.len().saturating_sub(1);
        s.selected = s.selected.min(last);
        s.graph_target = s.graph_target.min(last);
    }
    run(state.clone(), clients.clone(), cfg.clone()).await;
    public_ip(state, clients, cfg).await;
}

/// Watch for the network changing under us and rebuild everything derived from
/// it: the discovered targets, and the path monitor if one is running.
pub async fn watch(
    state: Arc<Mutex<AppState>>,
    clients: ping::Clients,
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

        refresh(state.clone(), clients.clone(), cfg.clone()).await;

        // A path monitored on the old network says nothing about the new one.
        if let Some((dest, label)) = monitoring {
            let label = label.split(" (").next().unwrap_or(&label).to_string();
            crate::collectors::hopmon::start(
                state.clone(),
                clients.clone(),
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
pub async fn public_ip(state: Arc<Mutex<AppState>>, clients: ping::Clients, cfg: Config) {
    if cfg.public_ip_url.trim().is_empty() {
        return;
    }
    let Ok(http) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .no_proxy()
        .build()
    else {
        return;
    };
    // The configured endpoint first, then Cloudflare's own trace endpoint —
    // reachable when the configured one is filtered, and the natural answer
    // when the machine sits behind Cloudflare WARP. Cap the body (an IP is
    // tiny) and only accept a clean IP literal.
    let mut errors: Vec<String> = Vec::new();
    let mut found: Option<IpAddr> = None;
    for url in [
        cfg.public_ip_url.trim(),
        "https://one.one.one.one/cdn-cgi/trace",
    ] {
        match crate::util::fetch_text_capped(&http, url, 4096).await {
            Ok(text) => match parse_public_ip(&text) {
                Some(addr) => {
                    found = Some(addr);
                    break;
                }
                None => errors.push(format!("{url}: no address in the answer")),
            },
            Err(e) => errors.push(format!("{url}: {e}")),
        }
    }
    let Some(addr) = found else {
        state.lock().unwrap().public_ip_error = Some(errors.join("; "));
        return;
    };
    state.lock().unwrap().public_ip_error = None;

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
        ping::spawn_for(state, clients, cfg, id, addr);
    }
}

/// The address in a public-IP answer: either the bare literal most services
/// return, or the `ip=…` line of Cloudflare's `cdn-cgi/trace` format.
pub fn parse_public_ip(text: &str) -> Option<IpAddr> {
    let text = text.trim();
    if let Ok(addr) = text.parse::<IpAddr>() {
        return Some(addr);
    }
    text.lines()
        .find_map(|l| l.trim().strip_prefix("ip="))
        .and_then(|v| v.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_ip_answers_parse_in_both_shapes() {
        assert_eq!(
            parse_public_ip("203.0.113.9\n"),
            Some("203.0.113.9".parse().unwrap())
        );
        let trace = "fl=123f45\nh=one.one.one.one\nip=2001:db8::1\nts=1.2\nwarp=on\n";
        assert_eq!(parse_public_ip(trace), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(parse_public_ip("<html>nope</html>"), None);
    }

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
