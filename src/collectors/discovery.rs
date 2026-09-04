//! Startup path discovery: traceroute a few hops toward the internet and add
//! the gateway + next hops as auto-discovered targets, so the user immediately
//! sees where local-network quality ends and the ISP path begins.
//!
//! Discovery runs at startup and whenever the network's *identity* changes.
//! That is not the same moment as the network becoming usable, which is the
//! whole difficulty: joining hotel Wi-Fi bumps the identity immediately, and
//! for the next few minutes a captive portal answers the traceroute with
//! silence and the public-IP endpoint with its own sign-in page. Signing in
//! changes no identity, so the failed pass used to be the last word — the
//! gateway, hops 2-4 and the public IP were all simply absent until octomon
//! was restarted. So a short pass is retried on a backoff ([`RETRY_BACKOFF`]),
//! [`rescan`] forces one by hand from [G], and every way a pass can come back
//! empty writes a line to the error log.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use tokio::process::Command;

use crate::app::{AppState, TargetStat};
use crate::collectors::ping;
use crate::config::Config;
use crate::platform::traceroute as tr;

const MAX_HOPS: usize = 4; // gateway (1) + next three

/// A stalled traceroute must not hold the walk open forever. The unix flags
/// ask for one probe per hop at a one-second timeout and Windows' three at
/// 800 ms, so four hops is a couple of seconds when the path is dead — this is
/// the outer bound for a `traceroute` that hangs on something else entirely
/// (a wedged raw socket, a captive portal swallowing the process).
const WALK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

pub async fn run(state: Arc<Mutex<AppState>>, clients: ping::Clients, cfg: Config) -> Outcome {
    // Configurable: the useful probe target depends on the network. Empty
    // disables discovery entirely, like `public_ip_url`.
    let probe = cfg.discovery_probe.trim().to_string();
    if probe.is_empty() {
        return Outcome::Disabled;
    }
    let walk = Command::new(tr::PROGRAM)
        .args(tr::args(MAX_HOPS, &probe))
        .stdin(std::process::Stdio::null())
        .output();
    let out = match tokio::time::timeout(WALK_TIMEOUT, walk).await {
        Ok(Ok(out)) => out,
        // The two ways the walk yields nothing: no binary (or no permission
        // to run it), and a binary that never came back. Both used to return
        // in silence, which is why an empty Quality panel had no explanation
        // anywhere — not in the timeline, not on disk.
        Ok(Err(e)) => {
            crate::errlog::log(
                "discovery",
                format!("could not run {}: {e} — no hops discovered", tr::PROGRAM),
            );
            return gateway_only(state, clients, cfg).await;
        }
        Err(_) => {
            crate::errlog::log(
                "discovery",
                format!(
                    "{} did not finish within {}s toward {probe} — no hops discovered",
                    tr::PROGRAM,
                    WALK_TIMEOUT.as_secs()
                ),
            );
            return gateway_only(state, clients, cfg).await;
        }
    };
    if !out.status.success() {
        // Non-fatal: tracert exits non-zero on an unreachable destination
        // having still printed the hops that answered, so the output is
        // parsed either way — but the reason is worth keeping.
        let why = String::from_utf8_lossy(&out.stderr);
        crate::errlog::log(
            "discovery",
            format!(
                "{} exited {} toward {probe}{}",
                tr::PROGRAM,
                out.status.code().unwrap_or(-1),
                if why.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {}", why.trim())
                }
            ),
        );
    }

    let mut hops_found = 0usize;
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

        hops_found += 1;
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

    if hops_found == 0 {
        crate::errlog::log(
            "discovery",
            format!(
                "{} toward {probe} answered no hops — the path is filtered, or a captive portal is in the way",
                tr::PROGRAM
            ),
        );
    }

    let gw = gateway_only(state.clone(), clients.clone(), cfg.clone()).await;
    // gateway_only has waited for netinfo, so the link's addresses are known.
    add_v6_targets(&state, &clients, &cfg);
    // The v6 path: the same walk toward the probe's v6 twin, so the hop list
    // and the ISP-path reading exist for both families on a dual-stack link.
    if let Some(p6) = probe
        .parse::<IpAddr>()
        .ok()
        .and_then(crate::config::v6_twin)
        && clients.v6.is_some()
        && crate::collectors::http::has_global_v6(&state.lock().unwrap().netinfo.ipv6)
    {
        walk_v6(&state, &clients, &cfg, p6).await;
    }
    // The walk covering only the gateway is the hotel case: hop 1 answered,
    // nothing beyond it did. Worth a retry once the portal is cleared.
    match (hops_found, gw) {
        (0, Outcome::NothingFound) => Outcome::NothingFound,
        (0..=1, _) => Outcome::GatewayOnly,
        _ => Outcome::Complete,
    }
}

/// What one pass of discovery managed to find. `refresh` retries on anything
/// short of [`Outcome::Complete`], because "nothing answered" on a network
/// that is about to work (a captive portal not yet cleared, a lease not yet
/// settled) is indistinguishable at this moment from one that never will.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// Hops beyond the gateway were found: the path is walkable.
    Complete,
    /// Only the gateway (or not even a full first hop) came back.
    GatewayOnly,
    /// No hops, and no gateway address to fall back to.
    NothingFound,
    /// `discovery_probe` is empty — the user turned discovery off.
    Disabled,
}

/// Probe the routing table's gateway, whatever the walk did or didn't see.
///
/// A gateway that answers nothing at all — not even the TTL-exceeded replies
/// the walk listens for (phone hotspots, hardened firewalls) — never appears
/// in the walk, but the routing table still names it. Probe it anyway: beside
/// clean anchors, its 100% loss is exactly the evidence the drops-ICMP
/// judgement turns into "fine, just silent", and without a probe the gateway
/// rung would read "not discovered" forever. netinfo populates on its own 5 s
/// cadence, so wait briefly for it.
async fn gateway_only(state: Arc<Mutex<AppState>>, clients: ping::Clients, cfg: Config) -> Outcome {
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
            return Outcome::GatewayOnly;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    // Ten seconds of "-" from the routing table. On a network still handing
    // out a lease this is temporary, which is exactly why the caller retries.
    crate::errlog::log(
        "discovery",
        "no gateway address from the routing table after 10s — gateway not probed",
    );
    Outcome::NothingFound
}

/// The IPv6 side of the LAN, added while this link holds a global IPv6
/// address: the v6 default router, and the IPv6 twins of the built-in
/// anchors. Pinging them answers "is v6 configured here, does the router
/// carry it, does the route beyond" directly, which the v4 rows and the web
/// check cannot. Auto targets, so a network change drops them with the hops;
/// the analysis judges them as a family, never as part of the v4 consensus.
/// Nothing is added without a v6 ICMP socket to probe them with.
fn add_v6_targets(state: &Arc<Mutex<AppState>>, clients: &ping::Clients, cfg: &Config) {
    if clients.v6.is_none() {
        return;
    }
    let (gateway, twins, iface_index): (Option<IpAddr>, Vec<(String, IpAddr)>, u32) = {
        let s = state.lock().unwrap();
        if !crate::collectors::http::has_global_v6(&s.netinfo.ipv6) {
            return;
        }
        let have = |a: IpAddr| s.targets.iter().any(|t| t.addr == a);
        let gateway = s
            .netinfo
            .gateway_ipv6
            .split('%')
            .next()
            .and_then(|g| g.parse::<IpAddr>().ok())
            .filter(|g| g.is_ipv6() && !have(*g));
        let twins = s
            .targets
            .iter()
            .filter(|t| !t.discovered)
            .filter_map(|t| {
                crate::config::v6_twin(t.addr)
                    .map(|v6| (format!("{}{}", t.label, crate::app::V6_ANCHOR_SUFFIX), v6))
            })
            .filter(|(_, v6)| !have(*v6))
            .collect();
        (gateway, twins, s.netinfo.iface_index)
    };
    // The router first: link-local, so through a socket bound to the
    // interface — the plain v6 client has no scope to reach fe80:: with.
    if let Some(addr) = gateway {
        let link_local = matches!(addr, IpAddr::V6(a) if (a.segments()[0] & 0xffc0) == 0xfe80);
        let client = if link_local {
            ping::v6_client_on(iface_index)
        } else {
            clients.v6.clone()
        };
        if let Some(client) = client {
            let id = {
                let mut s = state.lock().unwrap();
                let mut t = TargetStat::new(crate::app::V6_GATEWAY_LABEL.to_string(), addr);
                t.discovered = true;
                let id = t.id;
                s.targets.push(t);
                id
            };
            ping::spawn_with_client(
                state.clone(),
                clients.clone(),
                client,
                cfg.clone(),
                id,
                addr,
            );
        }
    }
    for (label, addr) in twins {
        let id = {
            let mut s = state.lock().unwrap();
            let mut t = TargetStat::new(label, addr);
            t.discovered = true;
            let id = t.id;
            s.targets.push(t);
            id
        };
        ping::spawn_for(state.clone(), clients.clone(), cfg.clone(), id, addr);
    }
}

/// The v6 path: one walk toward `probe`, adding the hops that answered as
/// "hop N→<probe>" targets the way the v4 walk does. TTL 1 on the LAN is the
/// v6 router, named as such — never "gateway", which is the v4 row.
async fn walk_v6(
    state: &Arc<Mutex<AppState>>,
    clients: &ping::Clients,
    cfg: &Config,
    probe: IpAddr,
) {
    let dest = probe.to_string();
    let program = tr::program(&dest);
    let walk = Command::new(program)
        .args(tr::args(MAX_HOPS, &dest))
        .stdin(std::process::Stdio::null())
        .output();
    let out = match tokio::time::timeout(WALK_TIMEOUT, walk).await {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => {
            crate::errlog::log(
                "discovery",
                format!("could not run {program} toward {dest}: {e}"),
            );
            return;
        }
        Err(_) => {
            crate::errlog::log(
                "discovery",
                format!(
                    "{program} did not finish within {}s toward {dest}",
                    WALK_TIMEOUT.as_secs()
                ),
            );
            return;
        }
    };
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Some(hop) = tr::parse_hop(line) else {
            continue;
        };
        let (ttl, Some(addr)) = (hop.ttl, hop.addr.and_then(|a| a.parse::<IpAddr>().ok())) else {
            continue;
        };
        if addr == probe {
            break;
        }
        let (id, added) = {
            let mut s = state.lock().unwrap();
            let on_lan = ttl == 1 && s.is_lan_addr(addr);
            let label = if on_lan {
                crate::app::V6_GATEWAY_LABEL.to_string()
            } else {
                format!("hop {ttl}→{dest}")
            };
            let have = s
                .targets
                .iter()
                .any(|t| t.addr == addr || (on_lan && t.label == label));
            if have {
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
}

/// The public IPv6 address, from `public_ip6_url` over a client pinned to v6
/// so the answer is a v6 address or nothing — a dual-stack endpoint asked
/// unpinned would quietly answer over v4 when v6 does not get out. Added as
/// the "public IPv6" row; a failure is logged, not alarmed: the v6 rows
/// above already say whether v6 works.
async fn public_ip6(state: Arc<Mutex<AppState>>, clients: ping::Clients, cfg: Config) {
    let url = cfg.public_ip6_url.trim().to_string();
    if url.is_empty()
        || !crate::collectors::http::has_global_v6(&state.lock().unwrap().netinfo.ipv6)
    {
        return;
    }
    let Ok(http) = reqwest::Client::builder()
        .user_agent(crate::util::USER_AGENT)
        .local_address(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED))
        .no_proxy()
        .timeout(std::time::Duration::from_secs(6))
        .build()
    else {
        return;
    };
    let addr = match crate::util::fetch_text_capped(&http, &url, 4096).await {
        Ok(text) => parse_public_ip(&text).filter(|a| a.is_ipv6()),
        Err(e) => {
            crate::errlog::log("public-ip", format!("{url}: {e}"));
            None
        }
    };
    let Some(addr) = addr else {
        return;
    };
    let (id, added) = {
        let mut s = state.lock().unwrap();
        if s.targets.iter().any(|t| t.addr == addr) {
            (0, false)
        } else {
            let mut t = TargetStat::new("public IPv6".to_string(), addr);
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

/// How long to wait before each further attempt when a pass came back short.
/// Roughly seven minutes of cover in total, which comfortably spans signing
/// in to a hotel portal — after which the network identity has not changed, so
/// nothing else would ever trigger a re-walk.
const RETRY_BACKOFF: [u64; 5] = [15, 30, 60, 120, 240];

/// Re-run discovery after the machine moved to a different network: the old
/// gateway and hops belong to a network that is no longer reachable, so they are
/// dropped before the path is walked again. Hand-added targets are left alone.
///
/// A pass that finds nothing is retried on a backoff rather than accepted.
/// Joining a network and being able to use it are different moments: a captive
/// portal answers the walk with silence and the public-IP endpoint with its own
/// login page, DHCP may not have settled, and the gateway's ARP entry may not
/// exist yet. All of those clear within a few minutes and none of them changes
/// the network's identity, so without a retry the first failed pass was final
/// and the only fix was restarting octomon.
pub async fn refresh(state: Arc<Mutex<AppState>>, clients: ping::Clients, cfg: Config) {
    forget_discovered(&state);
    let seq = state.lock().unwrap().net_change_seq;
    // Each half is retried only until it lands: the public IP usually comes
    // back on the pass where the walk is still blocked, and re-fetching it
    // five more times would be five needless requests to someone else's
    // endpoint. Targets already added are skipped by address, so a repeated
    // walk adds the hops it newly sees and nothing else.
    let mut path_done = false;
    let mut ip_done = false;

    // The network moving again makes everything below about the wrong network.
    // Checked after every await, not just after the sleeps: a traceroute or a
    // public-IP fetch started before the change lands its result minutes later,
    // and adding those hops to the *new* network's target list is how a stale
    // gateway reappears after a VPN flap.
    let superseded = || state.lock().unwrap().net_change_seq != seq;

    for (attempt, wait) in std::iter::once(0).chain(RETRY_BACKOFF).enumerate() {
        if wait > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
        }
        if superseded() {
            return;
        }
        if !path_done {
            let outcome = run(state.clone(), clients.clone(), cfg.clone()).await;
            if superseded() {
                return;
            }
            path_done = matches!(outcome, Outcome::Complete | Outcome::Disabled);
        }
        if !ip_done {
            ip_done = public_ip(state.clone(), clients.clone(), cfg.clone()).await;
            if superseded() {
                return;
            }
        }
        if path_done && ip_done {
            if attempt > 0 {
                crate::errlog::log(
                    "discovery",
                    format!("path and public IP discovered on attempt {}", attempt + 1),
                );
            }
            return;
        }
    }
    let message = format!(
        "could not map the path after {} attempts — {} still unknown. Press [G] to rescan.",
        RETRY_BACKOFF.len() + 1,
        match (path_done, ip_done) {
            (false, false) => "hops beyond the gateway and the public IP are",
            (false, true) => "hops beyond the gateway are",
            _ => "the public IP is",
        }
    );
    crate::errlog::log("discovery", &message);
    state.lock().unwrap().push_event(
        crate::verdict::Severity::Info,
        crate::app::EventCategory::Network,
        message,
    );
}

/// Drop every auto-discovered target, pulling the dependent cursors back into
/// range — they index into `targets`.
fn forget_discovered(state: &Arc<Mutex<AppState>>) {
    let mut s = state.lock().unwrap();
    s.targets.retain(|t| !t.discovered);
    let last = s.targets.len().saturating_sub(1);
    s.selected = s.selected.min(last);
    s.graph_target = s.graph_target.min(last);
}

/// The [G] rescan: throw away what discovery found and map the path again from
/// scratch, without waiting for the network's identity to change.
///
/// The manual counterpart to the automatic retry — for the case where the
/// network came good in a way octomon has no way to observe (a portal signed
/// in to in a browser, an upstream link restored, a router rebooted) and the
/// automatic attempts had already run out.
pub async fn rescan(state: Arc<Mutex<AppState>>, clients: ping::Clients, cfg: Config) {
    {
        let mut s = state.lock().unwrap();
        s.public_ip_error = None;
        s.notice_event(
            crate::verdict::Severity::Info,
            crate::app::EventCategory::Network,
            "rescanning the path — gateway, hops and public IP".to_string(),
        );
    }
    refresh(state, clients, cfg).await;
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
    // The refresh currently in flight. A walk runs its backoff for about seven
    // minutes, so a network that flaps every few seconds — a VPN reconnecting
    // in a loop, a laptop roaming between weak APs — would otherwise leave
    // dozens of them alive at once, each spawning traceroute processes for a
    // network that has already been replaced. Only the newest one can be
    // right, so the previous is aborted rather than left to notice on its own.
    let mut in_flight: Option<tokio::task::JoinHandle<()>> = None;
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

        // A path monitored on the old network says nothing about the new one.
        // Restarted before the walk rather than after it: `refresh` now spends
        // minutes retrying a network that isn't answering yet, and the hop
        // monitor must not sit on the old network's hops for all of it.
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

        // Spawned rather than awaited: the retry backoff runs for minutes, and
        // a change landing during it has to be picked up by the next loop.
        // Aborting the previous walk first bounds this to one live task; it
        // stops at its next await, and `refresh` re-checks the sequence around
        // each of those anyway, so an abort only saves the waiting.
        if let Some(prev) = in_flight.replace(tokio::spawn(refresh(
            state.clone(),
            clients.clone(),
            cfg.clone(),
        ))) {
            prev.abort();
        }
    }
}

/// Discover the machine's public IP from `cfg.public_ip_url` (a plain-text IP
/// endpoint) and add it as a target. No-op if the URL is empty or the response
/// isn't a valid IP. Returns whether the address is now known — a caller
/// retrying a half-finished discovery needs to know which half failed.
pub async fn public_ip(state: Arc<Mutex<AppState>>, clients: ping::Clients, cfg: Config) -> bool {
    if cfg.public_ip_url.trim().is_empty() {
        return true; // switched off, not failed
    }
    let http = match reqwest::Client::builder()
        .user_agent(crate::util::USER_AGENT)
        .timeout(std::time::Duration::from_secs(10))
        .no_proxy()
        .build()
    {
        Ok(http) => http,
        Err(e) => {
            crate::errlog::log("public-ip", format!("could not build an HTTP client: {e}"));
            return false;
        }
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
        for e in &errors {
            crate::errlog::log("public-ip", e);
        }
        // The raw reqwest error chains (two of them, with full URLs) turned
        // the analysis row into a paragraph. The row gets one readable
        // sentence; the chains go to the events timeline — once per distinct
        // failure, not on every retry of the same one.
        let short = summarize_fetch_errors(&errors);
        let mut s = state.lock().unwrap();
        if s.public_ip_error.as_deref() != Some(short.as_str()) {
            s.push_event(
                crate::verdict::Severity::Info,
                crate::app::EventCategory::Network,
                format!("public IP discovery failed — {}", errors.join(" · ")),
            );
        }
        s.public_ip_error = Some(short);
        return false;
    };
    state.lock().unwrap().public_ip_error = None;
    // The v6 side rides along, on its own: it is never a reason to retry.
    tokio::spawn(public_ip6(state.clone(), clients.clone(), cfg.clone()));

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
    true
}

/// One readable sentence out of the per-URL fetch errors, for the analysis
/// row. When both endpoints failed the same way (the overwhelmingly common
/// case — DNS is down for everyone or no one), name the way once; otherwise
/// admit the mix. The full chains live in the events timeline.
pub fn summarize_fetch_errors(errors: &[String]) -> String {
    let kind = |e: &str| {
        let e = e.to_ascii_lowercase();
        if e.contains("dns error") || e.contains("lookup") || e.contains("resolve") {
            "DNS lookup failed"
        } else if e.contains("timed out") || e.contains("timeout") {
            "timed out"
        } else if e.contains("certificate") || e.contains("tls") {
            "TLS failed"
        } else if e.contains("connect") {
            "could not connect"
        } else if e.contains("no address in the answer") {
            "no address in the answer"
        } else {
            "request failed"
        }
    };
    let kinds: Vec<&str> = errors.iter().map(|e| kind(e)).collect();
    let uniform = kinds.windows(2).all(|w| w[0] == w[1]);
    let what = match (uniform, kinds.first()) {
        (true, Some(k)) => (*k).to_string(),
        (false, _) => kinds.join(" / "),
        (_, None) => "request failed".to_string(),
    };
    format!(
        "{what} ({} endpoints tried) — details in events [e]",
        errors.len().max(1)
    )
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

    /// The analysis row must stay one sentence however ugly the underlying
    /// error chains are; the chains themselves belong to the events log.
    #[test]
    fn fetch_errors_summarize_to_one_readable_line() {
        // The screenshot case: both endpoints, same DNS failure, full chains.
        let errors = vec![
            "https://api.ipify.org: could not connect: dns error: failed to lookup address information: nodename nor servname provided, or not known".to_string(),
            "https://one.one.one.one/cdn-cgi/trace: could not connect: dns error: failed to lookup address information: nodename nor servname provided, or not known".to_string(),
        ];
        assert_eq!(
            summarize_fetch_errors(&errors),
            "DNS lookup failed (2 endpoints tried) — details in events [e]"
        );

        // Different failures per endpoint: named, still short.
        let mixed = vec![
            "https://api.ipify.org: timed out".to_string(),
            "https://one.one.one.one/cdn-cgi/trace: no address in the answer".to_string(),
        ];
        let s = summarize_fetch_errors(&mixed);
        assert!(s.starts_with("timed out / no address in the answer"), "{s}");
        assert!(s.len() < 100, "still a row, not a paragraph: {s}");
    }

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

    /// The hotel case, as a decision table: only a walk that got *past* the
    /// gateway counts as done. A gateway-only answer is what a captive portal
    /// produces, and treating it as success is precisely the bug that left
    /// hops 2-4 and the public IP missing until octomon was restarted.
    #[test]
    fn only_a_walk_past_the_gateway_ends_the_retries() {
        let done = |o: Outcome| matches!(o, Outcome::Complete | Outcome::Disabled);
        assert!(done(Outcome::Complete));
        // Turned off in config: retrying cannot change the answer.
        assert!(done(Outcome::Disabled));
        assert!(!done(Outcome::GatewayOnly));
        assert!(!done(Outcome::NothingFound));
    }

    /// The backoff has to outlast a portal sign-in — the whole point is to
    /// still be trying when the network finally works.
    #[test]
    fn the_backoff_covers_several_minutes() {
        let total: u64 = RETRY_BACKOFF.iter().sum();
        assert!(total >= 300, "only {total}s of cover");
        // Strictly increasing: a flat retry would hammer a network that is
        // simply filtered, for as long as octomon runs.
        assert!(RETRY_BACKOFF.windows(2).all(|w| w[1] > w[0]));
        // And it ends. A network that genuinely filters traceroute must not
        // be walked forever.
        assert!(RETRY_BACKOFF.len() <= 8);
    }
}
