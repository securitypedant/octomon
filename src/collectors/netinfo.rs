//! Network identity from `netdev`: addresses, MAC, gateway, link type & speed,
//! DHCP and DNS. Re-probed periodically to pick up network changes.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use netdev::interface::types::InterfaceType;
use tokio::sync::Notify;

use crate::app::{AppState, BypassedTunnel, LinkMedium, NetInfo};

pub async fn run(state: Arc<Mutex<AppState>>, refresh: Arc<Notify>, changed: Arc<Notify>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    // Identifying the VPN behind a tunnel can fall back to scanning the process
    // table, so the answer is cached per tunnel rather than redone every tick
    // — for the tunnel carrying the traffic and for any sitting beside it.
    let mut vendor_cache = VendorCache::default();
    // The DHCP server behind the current lease barely ever changes, so it is
    // asked for once per attachment (a lease-file read or one-line shell-out)
    // and cached — keyed on interface + gateway, which is what a new
    // attachment changes.
    let mut dhcp_cache: Option<(String, String)> = None;
    // Whether the default route has vanished entirely (Wi-Fi switched off,
    // cable pulled) — a different situation from moving to another network.
    let mut link_lost = false;
    // Physical interfaces seen last tick, for plug/unplug events. `None` until
    // the first pass so startup doesn't announce every existing adapter.
    let mut known_ifaces: Option<std::collections::HashMap<String, LinkMedium>> = None;
    loop {
        // Re-probe on the timer or when the user presses 'r'.
        tokio::select! {
            _ = ticker.tick() => {}
            _ = refresh.notified() => {}
        }

        // Announce physical interfaces appearing or disappearing even when the
        // default route doesn't move. "Cable plugged in but the OS still
        // routes via Wi-Fi" is otherwise invisible — and it's the classic way
        // a USB dongle quietly fails to take over.
        let current: std::collections::HashMap<String, LinkMedium> =
            physical_interfaces().into_iter().collect();
        if let Some(prev) = known_ifaces.as_ref() {
            let default_name = state.lock().netinfo.iface.clone();
            let messages = iface_changes(prev, &current, &default_name);
            if !messages.is_empty() {
                let mut s = state.lock();
                for (name, up, m) in messages {
                    s.push_event(
                        crate::verdict::Severity::Info,
                        crate::app::EventCategory::Network,
                        m.clone(),
                    );
                    s.push_net_change(
                        if up {
                            crate::app::NetChangeKind::IfaceUp
                        } else {
                            crate::app::NetChangeKind::IfaceDown
                        },
                        name,
                        m,
                        vec![format!(
                            "default route: {}",
                            if default_name.is_empty() {
                                "none"
                            } else {
                                &default_name
                            }
                        )],
                    );
                }
            }
        }
        known_ifaces = Some(current);

        // The link is the interface internet traffic leaves from, found by
        // asking the kernel to route to a public address — not `netdev`'s own
        // default pick. Its probe goes to 10.254.254.254, an address a
        // corporate split tunnel pushing 10.0.0.0/8 claims, which made such a
        // tunnel (openfortivpn's ppp0) the "default interface": a Tunnel
        // medium, no gateway to discover, VPN events on every reconnect,
        // while every packet to the internet still left via Wi-Fi (issue
        // #27). `netdev`'s answer remains the fallback when nothing routes to
        // the internet at all, so "no default route" still means link lost.
        let (ifaces, egress_addr) =
            tokio::task::spawn_blocking(|| (netdev::get_interfaces(), egress_local_addr()))
                .await
                .unwrap_or_default();
        let chosen = egress_addr
            .and_then(|addr| iface_with_addr(&ifaces, addr))
            .cloned()
            .or_else(|| netdev::get_default_interface().ok());
        let Some(iface) = chosen else {
            let mut s = state.lock();
            s.link_lost = true;
            if !link_lost && !s.netinfo.iface.is_empty() {
                link_lost = true;
                let medium = s.netinfo.medium;
                let message = match medium {
                    LinkMedium::WiFi => "link lost — Wi-Fi is off or disconnected".to_string(),
                    m if m.is_wired() => "link lost — cable unplugged?".to_string(),
                    _ => "link lost — no default route".to_string(),
                };
                // Name the place that was lost, when it is one we know —
                // "which network did it drop off?" is the question a
                // multi-location machine's history has to answer.
                let message = match s.known_location_name() {
                    Some(name) => format!("{message} (was {name})"),
                    None => message,
                };
                s.notice_event(
                    crate::verdict::Severity::Down,
                    crate::app::EventCategory::Network,
                    message.clone(),
                );
                let detail = describe_attachment(&s.netinfo);
                let iface = s.netinfo.iface.clone();
                s.push_net_change(crate::app::NetChangeKind::LinkLost, iface, message, detail);
            }
            continue;
        };
        {
            let mut info = build(&iface);
            // On Linux `netdev` attaches the system resolvers only to the
            // interface it picked itself; when that was not this one, borrow
            // them — resolv.conf is system-wide anyway.
            if info.dns.is_empty()
                && let Some(picked) = ifaces.iter().find(|i| i.default)
            {
                info.dns = picked.dns_servers.iter().map(|d| d.to_string()).collect();
            }
            // Internet traffic leaves through a tunnel. When the kernel's
            // default route still points at a physical interface (WARP's
            // 0.0.0.0/1 + 128.0.0.0/1 shape), that interface is the link — its
            // gateway is the real, reachable LAN gateway — and the tunnel is a
            // split route laid over it. Otherwise the tunnel holds the default
            // route itself: a full tunnel, keyed on its underlay below.
            if info.tunnel.is_some()
                && let Ok(default) = netdev::get_default_interface()
                && classify(&default) != LinkMedium::Tunnel
                && counter_name(&default) != info.iface
            {
                let tunnel_iface = std::mem::take(&mut info.iface);
                info = build(&default);
                info.tunnel = Some(String::new()); // vendor resolved below
                info.tunnel_iface = tunnel_iface;
                info.tunnel_is_split = true;
            }
            // Tunnels that are up beside the link without carrying any of the
            // internet traffic — the split tunnel of issue #27, a mesh VPN.
            // Named below, shown, never part of the identity.
            let bypassed = bypassed_tunnels(&ifaces, &[&info.iface, &info.tunnel_iface]);
            // The tunnel holds the default route: find the physical network
            // underneath, so "Home via WARP" and "Hotel via WARP" stay
            // separate places instead of one mixed per-vendor bucket.
            if info.medium == LinkMedium::Tunnel
                && let Some((ip, mac, medium, iface)) =
                    tokio::task::spawn_blocking(underlay_identity)
                        .await
                        .ok()
                        .flatten()
            {
                info.underlay_gateway_ip = ip;
                info.underlay_gateway_mac = mac;
                info.underlay_medium = medium;
                info.underlay_iface = iface;
            }
            // Name every tunnel in play, once each.
            let mut devices: Vec<String> = bypassed.clone();
            if info.tunnel.is_some() {
                devices.push(info.tunnel_iface.clone());
            }
            // The system's resolvers, one list for every device: a client
            // that pushed its own DNS is active, whichever device is its.
            let resolvers: Vec<IpAddr> = info.dns.iter().filter_map(|d| d.parse().ok()).collect();
            let devices: Vec<(String, TunnelAddrs)> = devices
                .into_iter()
                .map(|dev| {
                    let addrs = tunnel_addrs(&ifaces, &dev, &resolvers);
                    (dev, addrs)
                })
                .collect();
            if info.tunnel.is_some()
                && let Some((_, addrs)) = devices.iter().find(|(d, _)| *d == info.tunnel_iface)
            {
                info.tunnel_addrs = addrs
                    .v4
                    .iter()
                    .map(|a| a.to_string())
                    .chain(addrs.v6.iter().map(|a| a.to_string()))
                    .collect();
            }
            vendor_cache
                .refresh(&devices, |addrs| async move {
                    tokio::task::spawn_blocking(move || tunnel_vendor(&addrs))
                        .await
                        .map_err(|_| Panicked)
                })
                .await;
            if info.tunnel.is_some() {
                info.tunnel = Some(vendor_cache.vendor_of(&info.tunnel_iface));
            }
            info.bypassed_tunnels = bypassed
                .into_iter()
                .map(|iface| BypassedTunnel {
                    vendor: vendor_cache.vendor_of(&iface),
                    iface,
                })
                .collect();
            // `Some(false)` is an explicit static config; `None` (the OS
            // didn't say) still gets asked — a lease found is proof of DHCP.
            if iface.dhcp_v4_enabled != Some(false) {
                let key = format!("{}|{}", info.iface, info.gateway_ip);
                info.dhcp_server = match &dhcp_cache {
                    Some((k, v)) if *k == key => v.clone(),
                    _ => {
                        let v = crate::platform::dhcp_server(&info.iface, info.iface_index)
                            .await
                            .unwrap_or_default();
                        dhcp_cache = Some((key, v.clone()));
                        v
                    }
                };
            }
            // Preserve Wi-Fi details, which are populated on a slower cadence by
            // the dedicated wifi collector, across these frequent base refreshes.
            let mut s = state.lock();
            let was = s.netinfo.identity();
            let now = info.identity();
            let before = describe_attachment(&s.netinfo);
            let prev_wifi = s.netinfo.wifi.take();
            let prev_dns = s.netinfo.dns.clone();
            let had_tunnel = s.netinfo.tunnel.is_some();
            let had_info = !s.netinfo.iface.is_empty();
            let prev_bypassed = s.netinfo.bypassed_tunnels.clone();
            let moved = had_info && was != now;
            s.netinfo = info;
            s.netinfo.wifi = if moved { None } else { prev_wifi };
            let restored = std::mem::take(&mut link_lost);
            s.link_lost = false;
            if restored {
                // The link is back (same network or not): stats accumulated
                // while it was down describe the outage, not the path — left
                // alone they'd keep the panel red for minutes.
                s.reset_quality_stats();
                // If the identity didn't move, this is the same location back
                // again — name it when known. When it *did* move, the stale
                // baseline would name the wrong place; the network-changed
                // entry below (and the recognised-location one, if any)
                // carries the story instead.
                let location = if moved {
                    String::new()
                } else {
                    s.known_location_name()
                        .map(|n| format!(" ({n})"))
                        .unwrap_or_default()
                };
                let message = format!(
                    "link restored → {}{location} — connection stats reset",
                    s.netinfo.iface
                );
                s.push_event(
                    crate::verdict::Severity::Info,
                    crate::app::EventCategory::Network,
                    message.clone(),
                );
                let detail = describe_attachment(&s.netinfo);
                let iface = s.netinfo.iface.clone();
                s.push_net_change(
                    crate::app::NetChangeKind::LinkRestored,
                    iface,
                    message,
                    detail,
                );
            }
            if moved {
                // Everything derived from the old network — discovered hops, the
                // path monitor, which interface throughput reads — is now stale,
                // and that includes every accumulated latency/loss figure.
                s.net_change_seq += 1;
                s.reset_quality_stats();
                // A tunnel coming up or down changes the identity too; name the
                // VPN rather than reporting a bare interface swap.
                let message = match (had_tunnel, s.netinfo.tunnel.is_some()) {
                    (false, true) => format!(
                        "VPN up — {} now carries the traffic",
                        s.netinfo.tunnel_label().unwrap_or_default()
                    ),
                    (true, false) => {
                        "VPN down — traffic no longer goes through the tunnel".to_string()
                    }
                    // The SSID isn't known yet (the Wi-Fi probe is slow); the
                    // gateway is the most identifying fact available now, and
                    // the wifi collector names the network moments later.
                    // The baseline still belongs to the network being left
                    // (the verdict task swaps it moments later), so it names
                    // the departed location while that is still knowable.
                    _ => format!(
                        "network changed → {}{}{}",
                        s.netinfo.iface,
                        if s.netinfo.gateway_ip != "-" && !s.netinfo.gateway_ip.is_empty() {
                            format!(" · gateway {}", s.netinfo.gateway_ip)
                        } else {
                            String::new()
                        },
                        s.known_location_name()
                            .map(|n| format!(" · was {n}"))
                            .unwrap_or_default()
                    ),
                };
                s.notice_event(
                    crate::verdict::Severity::Info,
                    crate::app::EventCategory::Network,
                    message.clone(),
                );
                let kind = match (had_tunnel, s.netinfo.tunnel.is_some()) {
                    (false, true) => crate::app::NetChangeKind::VpnUp,
                    (true, false) => crate::app::NetChangeKind::VpnDown,
                    _ => crate::app::NetChangeKind::NetworkChanged,
                };
                let mut detail = vec!["before:".to_string()];
                detail.extend(before.iter().map(|l| format!("  {l}")));
                detail.push("after:".to_string());
                detail.extend(
                    describe_attachment(&s.netinfo)
                        .iter()
                        .map(|l| format!("  {l}")),
                );
                let iface = s.netinfo.iface.clone();
                s.push_net_change(kind, iface, message, detail);
                changed.notify_waiters();
            } else if had_info && s.netinfo.dns != prev_dns {
                // Same network, new resolvers (DHCP renewal, profile change) —
                // invisible in any average, classic "it broke at 3pm" material.
                let message = format!(
                    "DNS servers changed → {} — same network, new resolvers (lease renewal or a pushed profile)",
                    s.netinfo.dns.join(", ")
                );
                s.push_event(
                    crate::verdict::Severity::Info,
                    crate::app::EventCategory::Network,
                    message.clone(),
                );
                let detail = vec![
                    format!("before: {}", prev_dns.join(", ")),
                    format!("after:  {}", s.netinfo.dns.join(", ")),
                ];
                let iface = s.netinfo.iface.clone();
                s.push_net_change(
                    crate::app::NetChangeKind::AddressChanged,
                    iface,
                    message,
                    detail,
                );
            }
            // A bypassed tunnel coming or going is worth a line on the
            // timeline — "the VPN reconnected at 3pm" — but it is an
            // interface event, not a VPN one: the path to the internet, the
            // location and the running statistics are all untouched.
            if had_info {
                let link = s.netinfo.iface.clone();
                let changes = bypassed_changes(&prev_bypassed, &s.netinfo.bypassed_tunnels, &link);
                for (name, up, message) in changes {
                    s.push_event(
                        crate::verdict::Severity::Info,
                        crate::app::EventCategory::Network,
                        message.clone(),
                    );
                    let detail = describe_attachment(&s.netinfo);
                    s.push_net_change(
                        if up {
                            crate::app::NetChangeKind::IfaceUp
                        } else {
                            crate::app::NetChangeKind::IfaceDown
                        },
                        name,
                        message,
                        detail,
                    );
                }
            }
        }
    }
}

fn build(iface: &netdev::Interface) -> NetInfo {
    let ipv4 = iface
        .ipv4
        .iter()
        .map(|n| format!("{}/{}", n.addr(), n.prefix_len()))
        .collect();
    let ipv6 = iface
        .ipv6
        .iter()
        .map(|n| format!("{}/{}", n.addr(), n.prefix_len()))
        .collect();
    let mac = iface
        .mac_addr
        .map(|m| m.to_string())
        .unwrap_or_else(|| "-".to_string());

    let (gateway_ip, gateway_mac, gateway_ipv6) = match &iface.gateway {
        Some(gw) => {
            let ip = gw
                .ipv4
                .first()
                .map(|i| i.to_string())
                .or_else(|| gw.ipv6.first().map(|i| i.to_string()))
                .unwrap_or_else(|| "-".to_string());
            let v6 = gw.ipv6.first().map(|i| i.to_string()).unwrap_or_default();
            (ip, gw.mac_addr.to_string(), v6)
        }
        None => ("-".to_string(), "-".to_string(), String::new()),
    };

    // Extra link facts beyond the medium: negotiated speed when the OS exposes
    // it (10/100/1000…), and whether the address came from DHCP.
    let link_speed_bps = iface.transmit_speed.filter(|b| *b > 0);
    let mut detail: Vec<String> = Vec::new();
    if let Some(bps) = link_speed_bps {
        detail.push(format!("{} Mb", bps / 1_000_000));
    }
    if iface.dhcp_v4_enabled == Some(true) {
        detail.push("DHCP".to_string());
    } else if iface.dhcp_v4_enabled == Some(false) {
        // A static config is worth a word of its own: "why is this machine
        // ignoring the DHCP plan" starts exactly here.
        detail.push("static".to_string());
    }

    let dns = iface.dns_servers.iter().map(|d| d.to_string()).collect();
    let dns_search = crate::platform::dns_search_domains(iface.index);

    let medium = classify(iface);
    NetInfo {
        iface: counter_name(iface),
        iface_index: iface.index,
        iface_label: iface.friendly_name.clone().unwrap_or_default(),
        ipv4,
        ipv6,
        mac,
        gateway_ip,
        gateway_mac,
        dns,
        dns_search,
        link_detail: detail.join(" · "),
        dhcp_server: String::new(), // filled by the caller (a lease probe)
        medium,
        link_speed_bps,
        mtu: iface.mtu,
        gateway_ipv6,
        // Vendor is filled in by the caller (it needs a process scan).
        tunnel: (medium == LinkMedium::Tunnel).then(String::new),
        tunnel_iface: if medium == LinkMedium::Tunnel {
            counter_name(iface)
        } else {
            String::new()
        },
        tunnel_addrs: Vec::new(), // filled by the caller with the vendor
        tunnel_is_split: false,
        // Filled by the caller when the tunnel holds the default route.
        underlay_gateway_ip: String::new(),
        underlay_gateway_mac: String::new(),
        underlay_medium: LinkMedium::Unknown,
        underlay_iface: String::new(),
        bypassed_tunnels: Vec::new(), // filled by the caller
        wifi: None,                   // filled in by the caller for Wi-Fi links
    }
}

/// The physical network under a full-tunnel VPN: the interface whose gateway
/// carries the tunnel's outer packets. Which one that is exactly is the OS's
/// business; the heuristic — the gatewayed physical interface, wired first —
/// matches how metrics fall out on every setup seen so far. `None` when no
/// physical interface has a gateway (some VMs put the tunnel alone).
/// The physical network under a tunnel that holds the default route: its
/// gateway (IP and MAC), medium, and the adapter's counter name.
///
/// The MAC comes from the neighbour cache, and under a full tunnel nothing
/// keeps that entry warm: octomon's own gateway pings go nowhere (the tunnel
/// has no gateway) and a WireGuard peer on the LAN never touches the router
/// at all. When the entry has aged out the location would key on the IP
/// instead and the same place would come back as a second location with the
/// same label, so an unknown MAC is resolved once, here, before it is used.
fn underlay_identity() -> Option<(String, String, LinkMedium, String)> {
    let found = underlay_from(&netdev::get_interfaces())?;
    if crate::baseline::mac_is_known(&found.1) {
        return Some(found);
    }
    nudge_neighbour(&found.0);
    underlay_from(&netdev::get_interfaces()).or(Some(found))
}

/// Make the kernel resolve a gateway's link-layer address: one UDP datagram
/// to the discard port, which needs no privilege and no reply. The gateway
/// is on-link, so even under a full tunnel the packet leaves on the physical
/// interface and the neighbour entry is filled in before the read that
/// follows. Best effort; a failure leaves the cache as it was.
fn nudge_neighbour(gateway: &str) {
    let Ok(ip) = gateway.parse::<IpAddr>() else {
        return;
    };
    let bind: std::net::SocketAddr = match ip {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    if let Ok(sock) = std::net::UdpSocket::bind(bind) {
        let _ = sock.send_to(&[0], (ip, 9));
        // Resolution is asynchronous; give the reply a moment to land.
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

fn underlay_from(ifaces: &[netdev::Interface]) -> Option<(String, String, LinkMedium, String)> {
    let mut candidates: Vec<_> = ifaces
        .iter()
        .filter(|i| !i.ipv4.is_empty() || !i.ipv6.is_empty())
        .filter(|i| {
            matches!(
                classify(i),
                LinkMedium::Ethernet | LinkMedium::WiFi | LinkMedium::Cellular
            )
        })
        .filter_map(|i| {
            let gw = i.gateway.as_ref()?;
            let ip = gw
                .ipv4
                .first()
                .map(|a| a.to_string())
                .or_else(|| gw.ipv6.first().map(|a| a.to_string()))?;
            Some((ip, gw.mac_addr.to_string(), classify(i), counter_name(i)))
        })
        .collect();
    candidates.sort_by_key(|(_, _, m, _)| match m {
        LinkMedium::Ethernet => 0,
        LinkMedium::WiFi => 1,
        _ => 2,
    });
    candidates.into_iter().next()
}

/// Physical interfaces worth announcing: up, addressed, and a medium a human
/// plugs or toggles (virtual/tunnel devices have their own events).
fn physical_interfaces() -> Vec<(String, LinkMedium)> {
    netdev::get_interfaces()
        .iter()
        .filter(|i| !i.ipv4.is_empty() || !i.ipv6.is_empty())
        .map(|i| (counter_name(i), classify(i)))
        .filter(|(_, m)| {
            matches!(
                m,
                LinkMedium::WiFi | LinkMedium::Ethernet | LinkMedium::Cellular
            )
        })
        .collect()
}

/// Messages for the diff between two interface snapshots. Pure, so the wording
/// rules are testable: an arriving interface that is NOT the default route
/// says so — that is the whole warning.
/// The facts about the current attachment, one per line — what the network
/// history keeps as "before" and "after".
fn describe_attachment(n: &NetInfo) -> Vec<String> {
    let mut out = Vec::new();
    if n.iface.is_empty() {
        out.push("no interface".to_string());
        return out;
    }
    out.push(format!("{} · {}", n.iface, n.medium.label()));
    if !n.ipv4.is_empty() {
        out.push(format!("ipv4 {}", n.ipv4.join(", ")));
    }
    if !n.ipv6.is_empty() {
        out.push(format!("ipv6 {}", n.ipv6.join(", ")));
    }
    out.push(format!("gateway {} ({})", n.gateway_ip, n.gateway_mac));
    if !n.dns.is_empty() {
        out.push(format!("dns {}", n.dns.join(", ")));
    }
    if let Some(v) = n.tunnel_label() {
        out.push(format!("tunnel {v} ({})", n.tunnel_iface));
    }
    for t in &n.bypassed_tunnels {
        out.push(format!(
            "split tunnel {} — internet traffic bypasses it",
            t.label()
        ));
    }
    if let Some(w) = &n.wifi {
        out.push(format!(
            "wifi {} · {} · ch {} · {}",
            w.ssid, w.phy, w.channel, w.rssi
        ));
    }
    out
}

/// (interface, came up?, message) for every physical interface that appeared
/// or vanished since the previous pass.
fn iface_changes(
    prev: &std::collections::HashMap<String, LinkMedium>,
    current: &std::collections::HashMap<String, LinkMedium>,
    default_name: &str,
) -> Vec<(String, bool, String)> {
    let mut out = Vec::new();
    for (name, medium) in current {
        if !prev.contains_key(name) {
            let note = if name != default_name && !default_name.is_empty() {
                format!(" — default route still {default_name}")
            } else {
                String::new()
            };
            out.push((
                name.clone(),
                true,
                format!("interface connected: {name} ({}){note}", medium.label()),
            ));
        }
    }
    for (name, medium) in prev {
        if !current.contains_key(name) {
            out.push((
                name.clone(),
                false,
                format!("interface disconnected: {name} ({})", medium.label()),
            ));
        }
    }
    out.sort();
    out
}

/// The interface name that `sysinfo`'s counters are keyed on.
///
/// On Windows `netdev` reports the adapter GUID — `{3F2504E0-4F89-...}` — while
/// `sysinfo` keys its per-interface counters on the alias ("Wi-Fi"). Using the
/// GUID means the throughput collector never finds the default interface and
/// silently falls back to summing every adapter, so the friendly name is what
/// has to be carried around. Elsewhere the two are the same string.
fn counter_name(iface: &netdev::Interface) -> String {
    #[cfg(windows)]
    {
        iface
            .friendly_name
            .clone()
            .unwrap_or_else(|| iface.name.clone())
    }
    #[cfg(not(windows))]
    {
        iface.name.clone()
    }
}

/// The local address the kernel would send a packet to the public internet
/// from — which is not always the address on its `default` route.
///
/// `netdev` picks its default interface by routing to 10.254.254.254, an
/// RFC1918 address that split-tunnel VPNs deliberately keep *off* the tunnel —
/// or, worse, inside a 10.0.0.0/8 a corporate tunnel pulls *onto* itself.
/// Cloudflare WARP compounds this by leaving `default` alone and installing
/// 0.0.0.0/1 + 128.0.0.0/1, which win on specificity. Only a public
/// destination tells the truth about where internet traffic goes.
///
/// Uses TEST-NET-1 (RFC 5737) and its v6 counterpart 2001:db8::/32 (RFC 3849):
/// globally routable as far as route selection is concerned, so any tunnel
/// claims them, but never a real host. Connecting a UDP socket only selects a
/// route — no packets are sent. v4 first; a v6-only host answers on the second.
fn egress_local_addr() -> Option<IpAddr> {
    use std::net::UdpSocket;
    let v4 = || {
        let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
        sock.connect((Ipv4Addr::new(192, 0, 2, 1), 1)).ok()?;
        sock.local_addr().ok().map(|a| a.ip())
    };
    let v6 = || {
        let sock = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).ok()?;
        sock.connect((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 1))
            .ok()?;
        sock.local_addr().ok().map(|a| a.ip())
    };
    v4().or_else(v6).filter(|a| !a.is_unspecified())
}

/// The interface holding `addr`.
fn iface_with_addr(ifaces: &[netdev::Interface], addr: IpAddr) -> Option<&netdev::Interface> {
    ifaces.iter().find(|i| match addr {
        IpAddr::V4(a) => i.ipv4.iter().any(|n| n.addr() == a),
        IpAddr::V6(a) => i.ipv6.iter().any(|n| n.addr() == a),
    })
}

/// Counter names of the tunnel devices that are up and addressed but are not
/// among `carrying` — the link itself and the tunnel the traffic leaves
/// through. Whatever these carry, it is not the internet: the kernel just
/// said so by routing a public address elsewhere.
///
/// "Addressed" means an IPv4 address or a ULA IPv6 one, which every VPN
/// client assigns its tunnel. macOS keeps utun0–utun3 up permanently with
/// nothing but a link-local address, and an `ipsec0` carrying the phone
/// carrier's global v6 for Wi-Fi Calling; a Mac would otherwise list five
/// "split tunnels" it has no VPN for.
fn bypassed_tunnels(ifaces: &[netdev::Interface], carrying: &[&str]) -> Vec<String> {
    let addressed = |i: &netdev::Interface| {
        !i.ipv4.is_empty() || i.ipv6.iter().any(|n| n.addr().is_unique_local())
    };
    let mut out: Vec<String> = ifaces
        .iter()
        .filter(|i| classify(i) == LinkMedium::Tunnel)
        .filter(|i| i.is_up() && addressed(i))
        .map(counter_name)
        .filter(|name| !carrying.contains(&name.as_str()))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// (device, came up?, message) for every bypassed tunnel that appeared or
/// vanished. Pure, so the wording is testable: the message has to say in the
/// same breath that the internet path did not move, or a reader scanning the
/// timeline will take "ppp0 up" for a VPN taking over.
fn bypassed_changes(
    prev: &[BypassedTunnel],
    now: &[BypassedTunnel],
    link: &str,
) -> Vec<(String, bool, String)> {
    let mut out = Vec::new();
    for t in now
        .iter()
        .filter(|t| !prev.iter().any(|p| p.iface == t.iface))
    {
        out.push((
            t.iface.clone(),
            true,
            format!(
                "split tunnel up: {} — only its own routes go through it; internet traffic still leaves via {link}",
                t.label()
            ),
        ));
    }
    for t in prev
        .iter()
        .filter(|t| !now.iter().any(|n| n.iface == t.iface))
    {
        out.push((
            t.iface.clone(),
            false,
            format!("split tunnel down: {} — internet path unchanged", t.label()),
        ));
    }
    out.sort();
    out
}

/// Classify the medium carrying the default route.
fn classify(iface: &netdev::Interface) -> LinkMedium {
    // Name first: macOS reports `utun` devices as plain Ethernet, so a VPN like
    // Cloudflare WARP is invisible to `if_type` alone. On Windows `name` is the
    // adapter GUID — the friendly name ("CloudflareWARP") is where the vendor's
    // naming actually shows up, so both are checked.
    if is_tunnel_name(&iface.name) || iface.friendly_name.as_deref().is_some_and(is_tunnel_name) {
        return LinkMedium::Tunnel;
    }
    // NetworkManager names a WireGuard device after its connection
    // ("home", "Trevor"), so no name rule can catch it, and netdev types it
    // Unknown. The kernel knows what the device is.
    if kernel_tunnel(&iface.name).is_some() {
        return LinkMedium::Tunnel;
    }
    let base = match iface.if_type {
        InterfaceType::Wireless80211 | InterfaceType::PeerToPeerWireless => LinkMedium::WiFi,
        InterfaceType::Ethernet
        | InterfaceType::Ethernet3Megabit
        | InterfaceType::FastEthernetT
        | InterfaceType::FastEthernetFx
        | InterfaceType::GigabitEthernet => LinkMedium::Ethernet,
        InterfaceType::Wwan
        | InterfaceType::Wwanpp
        | InterfaceType::Wwanpp2
        | InterfaceType::Wman => LinkMedium::Cellular,
        InterfaceType::Tunnel | InterfaceType::Ppp | InterfaceType::Slip => LinkMedium::Tunnel,
        InterfaceType::Loopback => LinkMedium::Loopback,
        InterfaceType::Bridge => LinkMedium::Bridge,
        _ => LinkMedium::Unknown,
    };
    // Windows reports WARP as an "Unknown adapter": no type, no MAC. An
    // unclassifiable, MAC-less device carrying a known VPN's address range is
    // that VPN's tunnel — a physical NIC always has a MAC, so this cannot
    // claim one (a CGNAT WAN address on a real NIC stays Unknown/Ethernet).
    if base == LinkMedium::Unknown && iface.mac_addr.is_none_or(|m| m.octets() == [0u8; 6]) {
        let v4: Vec<Ipv4Addr> = iface.ipv4.iter().map(|n| n.addr()).collect();
        let v6: Vec<Ipv6Addr> = iface.ipv6.iter().map(|n| n.addr()).collect();
        if vendor_match(&v4, &v6).is_some() {
            return LinkMedium::Tunnel;
        }
    }
    base
}

/// A tunnel device as the Linux kernel reports it in sysfs.
#[derive(Clone, Copy, Debug, PartialEq)]
enum KernelTunnel {
    /// `DEVTYPE=wireguard`: the in-kernel WireGuard that NetworkManager and
    /// wg-quick both create.
    WireGuard,
    /// A tun/tap device (OpenVPN, openconnect, tailscaled), or a
    /// point-to-point or IP-in-IP link (PPP, GRE, SIT, IPIP).
    Other,
}

/// What sysfs says about one device: `type` is its ARPHRD link type, `uevent`
/// carries `DEVTYPE`, and only tun/tap devices have a `tun_flags` file. Raw-IP
/// cellular modems share WireGuard's ARPHRD_NONE, so that type alone is not
/// taken as a tunnel; `DEVTYPE` or `tun_flags` has to say so.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn kernel_tunnel_from(arphrd: Option<u32>, uevent: &str, tun_flags: bool) -> Option<KernelTunnel> {
    if uevent.lines().any(|l| l.trim() == "DEVTYPE=wireguard") {
        return Some(KernelTunnel::WireGuard);
    }
    if tun_flags {
        return Some(KernelTunnel::Other);
    }
    // ARPHRD_PPP, _TUNNEL, _TUNNEL6, _SIT, _IPGRE, _IP6GRE.
    matches!(arphrd, Some(512 | 768 | 769 | 776 | 778 | 823)).then_some(KernelTunnel::Other)
}

#[cfg(target_os = "linux")]
fn kernel_tunnel(name: &str) -> Option<KernelTunnel> {
    if name.is_empty() || name.contains('/') || name.starts_with('.') {
        return None;
    }
    let dir = std::path::Path::new("/sys/class/net").join(name);
    let arphrd = std::fs::read_to_string(dir.join("type"))
        .ok()
        .and_then(|t| t.trim().parse().ok());
    let uevent = std::fs::read_to_string(dir.join("uevent")).unwrap_or_default();
    kernel_tunnel_from(arphrd, &uevent, dir.join("tun_flags").exists())
}

#[cfg(not(target_os = "linux"))]
fn kernel_tunnel(_name: &str) -> Option<KernelTunnel> {
    None
}

/// Interface-name prefixes used by tunnel/VPN virtual devices across platforms.
pub(crate) fn is_tunnel_name(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "utun",
        "tun",
        "tap",
        "ppp",
        "ipsec",
        "wg",
        "gpd",
        "nordlynx",
        "proton",
        "zt",
        "tailscale",
        // Windows adapter aliases, as the clients register them: the WARP
        // client's "CloudflareWARP" (one word), WireGuard's "WireGuard
        // Tunnel", OpenVPN's "OpenVPN Wintun" / "OpenVPN TAP-Windows6",
        // "Mullvad", "ZeroTier One".
        "cloudflarewarp",
        "wireguard",
        "openvpn",
        "mullvad",
        "zerotier",
    ];
    let n = name.to_ascii_lowercase();
    PREFIXES.iter().any(|p| n.starts_with(p))
}

/// A VPN's fingerprint. The address its tunnel device carries is the reliable
/// signal — it describes the tunnel that is actually *up*. Process names only
/// say a client is installed and running, which several can be at once. The
/// resolvers a client writes into the system's list when it connects are a
/// third witness: they say the client is *active*, from a place a bystander
/// process cannot reach.
struct Vpn {
    display: &'static str,
    v4: &'static [(Ipv4Addr, u32)],
    v6: &'static [(Ipv6Addr, u32)],
    /// Lowercase process-name fragments, used only as a last resort.
    procs: &'static [&'static str],
    /// Resolver addresses only this client ever configures: its own public
    /// resolvers, or a fixed private or loopback address its tunnel answers
    /// on. Not the addresses a server pushes (OpenVPN, WireGuard, corporate
    /// clients: whatever the site runs), and not a resolver networks use
    /// without the client (Cloudflare Gateway's 172.64.36.x).
    dns: &'static [IpAddr],
    /// The client only ever drives a tun/utun device, never an in-kernel
    /// WireGuard one, so on Linux it cannot own a `DEVTYPE=wireguard` device
    /// and is a bystander when one is being named.
    tun_only: bool,
}

const fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

const fn v6(segments: [u16; 8]) -> IpAddr {
    let [a, b, c, d, e, f, g, h] = segments;
    IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h))
}

/// Ordered most-specific first: WARP's 100.96.0.0/12 sits inside Tailscale's
/// 100.64.0.0/10, so it has to be tested before it.
const KNOWN_VPNS: &[Vpn] = &[
    Vpn {
        display: "Cloudflare WARP",
        // 100.96/12 is the device's CGNAT address, on the interface under
        // MASQUE or when a Zero Trust org assigns each device its own local
        // IP. Under WireGuard (consumer WARP, and orgs without that setting)
        // the interface is 172.16.0.2 on every device: a private address, so
        // it names WARP only with warp-svc running or its resolvers in use.
        v4: &[
            (Ipv4Addr::new(100, 96, 0, 0), 12),
            (Ipv4Addr::new(172, 16, 0, 2), 32),
        ],
        v6: &[(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0), 32)],
        procs: &["warp-svc", "cloudflarewarp"],
        dns: &[
            v4(127, 0, 2, 2),
            v4(127, 0, 2, 3),
            v6([0xfd01, 0xdb8, 0x1111, 0, 0, 0, 0, 2]),
            v6([0xfd01, 0xdb8, 0x1111, 0, 0, 0, 0, 3]),
        ],
        tun_only: true,
    },
    Vpn {
        display: "Tailscale",
        v4: &[(Ipv4Addr::new(100, 64, 0, 0), 10)],
        v6: &[(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0), 48)],
        procs: &["tailscaled", "tailscale"],
        dns: &[
            v4(100, 100, 100, 100),
            v6([0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x53]),
        ],
        tun_only: true,
    },
    Vpn {
        display: "Mullvad",
        v4: &[(Ipv4Addr::new(10, 64, 0, 0), 10)],
        v6: &[(Ipv6Addr::new(0xfc00, 0xbbbb, 0xbbbb, 0, 0, 0, 0, 0), 48)],
        procs: &["mullvad"],
        dns: &[v4(10, 64, 0, 1)],
        tun_only: false,
    },
    Vpn {
        display: "NordVPN",
        v4: &[(Ipv4Addr::new(10, 5, 0, 0), 16)],
        v6: &[],
        procs: &["nordvpn", "nordlynx"],
        dns: &[v4(103, 86, 96, 100), v4(103, 86, 99, 100)],
        tun_only: false,
    },
    Vpn {
        display: "Proton VPN",
        v4: &[(Ipv4Addr::new(10, 2, 0, 0), 16)],
        v6: &[],
        procs: &["protonvpn"],
        dns: &[v4(10, 2, 0, 1)],
        tun_only: false,
    },
    Vpn {
        display: "Cloudflare Tunnel",
        v4: &[],
        v6: &[],
        procs: &["cloudflared"],
        dns: &[],
        tun_only: true,
    },
    Vpn {
        display: "ExpressVPN",
        v4: &[],
        v6: &[],
        procs: &["expressvpn"],
        dns: &[],
        tun_only: true,
    },
    Vpn {
        display: "Surfshark",
        v4: &[],
        v6: &[],
        procs: &["surfshark"],
        dns: &[v4(162, 252, 172, 57), v4(149, 154, 159, 92)],
        tun_only: false,
    },
    Vpn {
        display: "Private Internet Access",
        v4: &[],
        v6: &[],
        procs: &["pia-daemon", "privateinternetaccess"],
        dns: &[v4(10, 0, 0, 241), v4(10, 0, 0, 242), v4(10, 0, 0, 243)],
        tun_only: false,
    },
    Vpn {
        display: "Windscribe",
        v4: &[],
        v6: &[],
        procs: &["windscribe"],
        dns: &[v4(10, 255, 255, 1)],
        tun_only: false,
    },
    Vpn {
        display: "Zscaler",
        v4: &[],
        v6: &[],
        procs: &["zsatunnel", "zstunnel", "zscaler"],
        dns: &[],
        tun_only: true,
    },
    Vpn {
        display: "FortiClient",
        v4: &[],
        v6: &[],
        procs: &["forticlient", "fortitray"],
        dns: &[],
        tun_only: true,
    },
    // The open-source client for the same FortiGate SSL VPNs, usually as a
    // split tunnel (issue #27).
    Vpn {
        display: "openfortivpn",
        v4: &[],
        v6: &[],
        procs: &["openfortivpn"],
        dns: &[],
        tun_only: true,
    },
    Vpn {
        display: "OpenVPN",
        v4: &[],
        v6: &[],
        procs: &["openvpn", "tunnelblick"],
        dns: &[],
        tun_only: true,
    },
    Vpn {
        display: "WireGuard",
        v4: &[],
        v6: &[],
        procs: &["wireguard", "wg-quick"],
        dns: &[],
        tun_only: false,
    },
    Vpn {
        display: "GlobalProtect",
        v4: &[],
        v6: &[],
        procs: &["globalprotect"],
        dns: &[],
        tun_only: true,
    },
    Vpn {
        display: "Cisco AnyConnect",
        v4: &[],
        v6: &[],
        procs: &["anyconnect"],
        dns: &[],
        tun_only: true,
    },
    Vpn {
        display: "ZeroTier",
        v4: &[],
        v6: &[],
        procs: &["zerotier"],
        dns: &[],
        tun_only: true,
    },
];

fn in_v4(addr: Ipv4Addr, net: Ipv4Addr, prefix: u32) -> bool {
    let shift = 32 - prefix;
    addr.to_bits() >> shift == net.to_bits() >> shift
}

fn in_v6(addr: Ipv6Addr, net: Ipv6Addr, prefix: u32) -> bool {
    let shift = 128 - prefix;
    addr.to_bits() >> shift == net.to_bits() >> shift
}

/// [`vendor_match`] without the trust level, for tests that only ask who.
#[cfg(test)]
fn vendor_from_addrs(v4: &[Ipv4Addr], v6: &[Ipv6Addr]) -> Option<&'static str> {
    vendor_match(v4, v6).map(|(vendor, _)| vendor)
}

/// A tunnel device and the addresses on it right now, plus the system's
/// resolvers, which are not the device's but change with the client that
/// configured them.
#[derive(Clone, Default, PartialEq)]
struct TunnelAddrs {
    v4: Vec<Ipv4Addr>,
    v6: Vec<Ipv6Addr>,
    /// The kernel says this is a WireGuard device (Linux only).
    kernel_wireguard: bool,
    /// The resolvers the system is using, system-wide: the same list for
    /// every device named in one pass.
    resolvers: Vec<IpAddr>,
}

fn tunnel_addrs(
    ifaces: &[netdev::Interface],
    iface_name: &str,
    resolvers: &[IpAddr],
) -> TunnelAddrs {
    ifaces
        .iter()
        .find(|i| counter_name(i) == iface_name)
        .map(|iface| TunnelAddrs {
            v4: iface.ipv4.iter().map(|n| n.addr()).collect(),
            v6: iface.ipv6.iter().map(|n| n.addr()).collect(),
            kernel_wireguard: kernel_tunnel(&iface.name) == Some(KernelTunnel::WireGuard),
            resolvers: resolvers.to_vec(),
        })
        .unwrap_or_default()
}

/// The vendors whose own resolvers are in the system's list right now. A
/// client that pushes its DNS writes it there when it connects and takes it
/// back when it disconnects, so unlike a resident process this says the
/// client is *active*. It is system-wide, though: it names a vendor, not a
/// device, and the caller narrows it by what each device's addresses allow.
fn vendors_by_resolver(resolvers: &[IpAddr]) -> std::collections::BTreeSet<&'static str> {
    KNOWN_VPNS
        .iter()
        .filter(|vpn| vpn.dns.iter().any(|d| resolvers.contains(d)))
        .map(|vpn| vpn.display)
        .collect()
}

/// The vendor of each tunnel device in play, cached on the device *and* its
/// addresses: macOS hands a freed utunN to whichever VPN connects next, and a
/// name-only key kept the old vendor. Cached on the addresses also means a
/// client started after its tunnel came up doesn't rename it until the
/// addresses change.
#[derive(Default)]
struct VendorCache(HashMap<String, (TunnelAddrs, Option<&'static str>)>);

/// A vendor lookup that panicked: its answer is not cached as "unnamed", so
/// the next pass asks again.
struct Panicked;

impl VendorCache {
    /// Name every device in `devices`, asking `lookup` only about one never
    /// seen, or last seen with other addresses. Devices no longer in play are
    /// forgotten, so a utunN that comes back belongs to whoever has it now.
    async fn refresh<F, Fut>(&mut self, devices: &[(String, TunnelAddrs)], lookup: F)
    where
        F: Fn(TunnelAddrs) -> Fut,
        Fut: std::future::Future<Output = Result<Option<&'static str>, Panicked>>,
    {
        for (dev, addrs) in devices {
            if self.0.get(dev).is_none_or(|(had, _)| had != addrs) {
                match lookup(addrs.clone()).await {
                    Ok(v) => {
                        self.0.insert(dev.clone(), (addrs.clone(), v));
                    }
                    Err(Panicked) => {
                        self.0.remove(dev);
                    }
                }
            }
        }
        self.0
            .retain(|dev, _| devices.iter().any(|(d, _)| d == dev));
    }

    /// The cached vendor, or an empty name for a tunnel nothing could name.
    fn vendor_of(&self, dev: &str) -> String {
        self.0
            .get(dev)
            .and_then(|(_, v)| *v)
            .unwrap_or_default()
            .to_string()
    }
}

/// Identify the VPN carrying a tunnel. `None` when nothing can be pinned
/// down — the tunnel is still reported, just unnamed, which beats naming the
/// wrong one. Cached on the addresses, so a client started after its tunnel
/// came up doesn't rename it until the addresses change.
fn tunnel_vendor(t: &TunnelAddrs) -> Option<&'static str> {
    // The live tunnel's own addresses are the first signal.
    let by_addr = vendor_match(&t.v4, &t.v6);

    // The process table is the other: every VPN client whose process is
    // resident, which several can be at once.
    let mut running = std::collections::BTreeSet::new();
    if let Ok(mut sys) = sysinfo::System::new() {
        sys.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::All,
            true,
            sysinfo::ProcessRefreshKind::nothing(),
        );
        for proc in sys.processes().values() {
            let name = proc.name().to_string_lossy().to_ascii_lowercase();
            for vpn in KNOWN_VPNS {
                if vpn.procs.iter().any(|frag| name.contains(frag)) {
                    running.insert(vpn.display);
                }
            }
        }
    }
    plausible_owners(&mut running, &t.v4, &t.v6);

    // The resolvers the active client configured are the third, narrowed
    // the same way: Tailscale's MagicDNS in the list says nothing about a
    // wg-quick tunnel at 10.9.8.10 beside it.
    let mut by_dns = vendors_by_resolver(&t.resolvers);
    plausible_owners(&mut by_dns, &t.v4, &t.v6);
    name_tunnel(by_addr, &running, &by_dns, t.kernel_wireguard)
}

/// Drop from `running` every client that cannot own a tunnel with these
/// addresses: one whose addresses always come from its own blocks (Tailscale,
/// WARP, Mullvad, NordVPN, Proton) when none of the tunnel's addresses is in
/// them. A WireGuard tunnel at 10.9.8.10 beside a resident Tailscale is then
/// named WireGuard, the one client left, instead of being left unnamed as
/// ambiguous — and the name no longer comes and goes with what else happens
/// to be running. A tunnel with no addresses yet is left to the process
/// table as a whole.
fn plausible_owners(
    running: &mut std::collections::BTreeSet<&'static str>,
    v4: &[Ipv4Addr],
    v6: &[Ipv6Addr],
) {
    if v4.is_empty() && v6.is_empty() {
        return;
    }
    running.retain(|name| {
        KNOWN_VPNS
            .iter()
            .find(|vpn| vpn.display == *name)
            .is_none_or(|vpn| {
                (vpn.v4.is_empty() && vpn.v6.is_empty())
                    || v4
                        .iter()
                        .any(|a| vpn.v4.iter().any(|(n, p)| in_v4(*a, *n, *p)))
                    || v6
                        .iter()
                        .any(|a| vpn.v6.iter().any(|(n, p)| in_v6(*a, *n, *p)))
            })
    });
}

/// The vendor whose address block a tunnel's address falls in, with how far
/// that match can be trusted. Classified by the address that matched, not by
/// the tunnel's addresses as a whole, and a v6 block (always a vendor's own)
/// is looked for first: a Tailscale tunnel carrying fd7a:115c:a1e0:: and a
/// 100.x address is named by the v6 outright, where its 100.x alone could
/// fall in WARP's /12 or yield to a running Zscaler.
fn vendor_match(v4: &[Ipv4Addr], v6: &[Ipv6Addr]) -> Option<(&'static str, AddrMatch)> {
    let by_v6 = KNOWN_VPNS.iter().find(|vpn| {
        v6.iter()
            .any(|a| vpn.v6.iter().any(|(n, p)| in_v6(*a, *n, *p)))
    });
    if let Some(vpn) = by_v6 {
        return Some((vpn.display, AddrMatch::Own));
    }
    KNOWN_VPNS.iter().find_map(|vpn| {
        v4.iter()
            .find(|a| vpn.v4.iter().any(|(n, p)| in_v4(**a, *n, *p)))
            .map(|a| (vpn.display, addr_match(*a)))
    })
}

type Vendors = std::collections::BTreeSet<&'static str>;

/// Name a tunnel from its address match, the running clients and the active
/// resolvers. A kernel WireGuard device (NetworkManager's, wg-quick's,
/// NetBird's) has no process of its own, so a client resident for some other
/// reason must not lend it its name, and a shared-space address on its own
/// does not either: it takes a vendor's name from that vendor's own block
/// (Mullvad's v6), from a shared or private match with that vendor's client
/// running or its resolvers configured (wg0-mullvad on 10.64.x), or from the
/// one client that drives such devices (PIA's wgpia0) when it is the only
/// one running, or the one the resolvers single out; otherwise it is plain
/// WireGuard.
fn name_tunnel(
    by_addr: Option<(&'static str, AddrMatch)>,
    running: &Vendors,
    by_dns: &Vendors,
    kernel_wireguard: bool,
) -> Option<&'static str> {
    if kernel_wireguard {
        return Some(match by_addr {
            Some((vendor, AddrMatch::Own)) => vendor,
            Some((vendor, _)) if running.contains(vendor) || by_dns.contains(vendor) => vendor,
            _ => {
                // PIA, Surfshark and Windscribe drive kernel WireGuard devices
                // on Linux with addresses in no table: the one such client
                // running names the device. A client that only ever uses tun
                // (Tailscale beside NetworkManager's "Trevor") is a bystander.
                let drivers: Vendors = running.iter().copied().filter(|v| !tun_only(v)).collect();
                let dns_drivers: Vendors =
                    by_dns.iter().copied().filter(|v| !tun_only(v)).collect();
                sole(&drivers, &dns_drivers).unwrap_or("WireGuard")
            }
        });
    }
    pick_vendor(by_addr, running, by_dns)
}

/// The one candidate, when there is one: the only running client; among
/// several, the only one whose resolvers are configured; with none running
/// (the process table hidden, a client octomon cannot see), the only one the
/// resolvers name. Two of anything is ambiguity, and ambiguity names nothing.
fn sole(running: &Vendors, by_dns: &Vendors) -> Option<&'static str> {
    let one = |set: &Vendors| (set.len() == 1).then(|| *set.iter().next().unwrap());
    match running.len() {
        0 => one(by_dns),
        1 => one(running),
        _ => one(&running.intersection(by_dns).copied().collect()),
    }
}

/// Whether a known client, by display name, never drives a kernel WireGuard
/// device. A name not in the table is treated as tun-only, so it cannot name
/// one.
fn tun_only(display: &str) -> bool {
    KNOWN_VPNS
        .iter()
        .find(|v| v.display == display)
        .is_none_or(|v| v.tun_only)
}

/// How far an address match on a tunnel can be trusted on its own.
#[derive(Clone, Copy, Debug, PartialEq)]
enum AddrMatch {
    /// A v6 block, or a v4 address outside the shared spaces below: the
    /// vendor's own, so the address names it outright.
    Own,
    /// 100.64.0.0/10, carrier-grade NAT space that several clients carve
    /// tunnel addresses from: Tailscale owns the whole /10 in [`KNOWN_VPNS`],
    /// WARP a /12 inside it, and Zscaler Client Connector a configurable /16
    /// anywhere in it. The match stands unless one other client is running.
    Shared,
    /// A private 10.x block a vendor happens to use (Mullvad's 10.64/10,
    /// NordVPN's 10.5/16) is the address space every corporate VPN hands out,
    /// so it only counts with that vendor's client running.
    Private,
}

fn addr_match(a: Ipv4Addr) -> AddrMatch {
    if a.is_private() {
        AddrMatch::Private
    } else if in_v4(a, Ipv4Addr::new(100, 64, 0, 0), 10) {
        AddrMatch::Shared
    } else {
        AddrMatch::Own
    }
}

/// Weigh the three signals: the tunnel's address, the VPN clients whose
/// processes are resident, and the one whose resolvers are configured. A
/// vendor's own block names it outright (see [`AddrMatch`]); a shared or
/// private match stands when its client runs or its resolvers are in use. A
/// shared match otherwise stands unless exactly one other client is running,
/// which then wins (an openfortivpn tunnel on 10.99.0.2 is not Mullvad;
/// Zscaler's 100.64.0.1 is not Tailscale). With no address to go on, the
/// process table decides only when it is unambiguous — two clients resident
/// say nothing about which one is up, unless the resolvers say which (see
/// [`sole`]).
///
/// One tie is broken by hand: a 100.64/10 address with both Tailscale and
/// Zscaler resident. A real Tailscale tunnel nearly always carries its own
/// v6 too, which names it outright, so a v4-only shared match beside a
/// running Zscaler is more likely the corporate client's tunnel than the
/// mesh's — unless MagicDNS is the system resolver, which only Tailscale
/// sets.
fn pick_vendor(
    by_addr: Option<(&'static str, AddrMatch)>,
    running: &Vendors,
    by_dns: &Vendors,
) -> Option<&'static str> {
    let sole = sole(running, by_dns);
    match by_addr {
        Some((vendor, AddrMatch::Own)) => Some(vendor),
        Some(("Tailscale", AddrMatch::Shared))
            if running.contains("Zscaler") && !by_dns.contains("Tailscale") =>
        {
            Some("Zscaler")
        }
        Some((vendor, _)) if running.contains(vendor) || by_dns.contains(vendor) => Some(vendor),
        Some((vendor, AddrMatch::Shared)) => sole.or(Some(vendor)),
        Some((_, AddrMatch::Private)) | None => sole,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BypassedTunnel, IpAddr, Ipv4Addr, Ipv6Addr, Vendors, bypassed_changes, bypassed_tunnels,
        iface_changes, iface_with_addr, is_tunnel_name, pick_vendor, vendor_from_addrs,
    };

    /// No vendor's resolvers configured: how every test written before the
    /// resolver signal reads.
    const NO: Vendors = Vendors::new();

    /// Kubuntu 26.04: NetworkManager's WireGuard connections "home" and
    /// "Trevor" are devices named after the connection, ARPHRD_NONE with
    /// DEVTYPE=wireguard. They have to read as tunnels, or the full tunnel is
    /// a link with "an address but no gateway".
    #[test]
    fn the_kernel_names_tunnels_that_their_names_do_not() {
        use super::{KernelTunnel, kernel_tunnel_from};
        let wg = "INTERFACE=Trevor\nIFINDEX=7\nDEVTYPE=wireguard\n";
        assert_eq!(
            kernel_tunnel_from(Some(65534), wg, false),
            Some(KernelTunnel::WireGuard)
        );
        assert_eq!(
            kernel_tunnel_from(Some(65534), "INTERFACE=tun0\n", true),
            Some(KernelTunnel::Other)
        );
        assert_eq!(
            kernel_tunnel_from(Some(512), "INTERFACE=ppp0\n", false),
            Some(KernelTunnel::Other)
        );
        // Wi-Fi, Ethernet, and a raw-IP modem that shares ARPHRD_NONE.
        assert_eq!(kernel_tunnel_from(Some(1), "DEVTYPE=wlan\n", false), None);
        assert_eq!(kernel_tunnel_from(Some(1), "INTERFACE=eth0\n", false), None);
        assert_eq!(
            kernel_tunnel_from(Some(65534), "DEVTYPE=wwan\n", false),
            None
        );
        assert_eq!(kernel_tunnel_from(None, "", false), None);
        // Every point-to-point and IP-in-IP type, by its ARPHRD number:
        // PPP, IPIP (TUNNEL), IP6IP6 (TUNNEL6), SIT, GRE, IP6GRE.
        for arphrd in [512, 768, 769, 776, 778, 823] {
            assert_eq!(
                kernel_tunnel_from(Some(arphrd), "", false),
                Some(KernelTunnel::Other),
                "ARPHRD {arphrd}"
            );
        }
        // Loopback and IEEE 802.11 radiotap are not tunnels.
        for arphrd in [772, 803] {
            assert_eq!(
                kernel_tunnel_from(Some(arphrd), "", false),
                None,
                "ARPHRD {arphrd}"
            );
        }
    }

    /// A device name is only ever joined under /sys/class/net, never used to
    /// climb out of it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_device_name_cannot_leave_sysfs() {
        use super::kernel_tunnel;
        for name in ["", "../../../etc", ".", "..", "a/b"] {
            assert_eq!(kernel_tunnel(name), None, "{name:?}");
        }
    }

    /// Zscaler ZPA puts 100.64.0.1 on its utun, inside Tailscale's range.
    #[test]
    fn a_shared_cgnat_address_defers_to_the_running_client() {
        use super::{AddrMatch, addr_match, vendor_match};
        use std::collections::BTreeSet;
        let v4 = [Ipv4Addr::new(100, 64, 0, 1)];
        assert_eq!(addr_match(v4[0]), AddrMatch::Shared);
        let addr = vendor_match(&v4, &[]);
        assert_eq!(addr, Some(("Tailscale", AddrMatch::Shared)));
        let run = |names: &[&'static str]| names.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(pick_vendor(addr, &run(&["Zscaler"]), &NO), Some("Zscaler"));
        assert_eq!(
            pick_vendor(addr, &run(&["Tailscale"]), &NO),
            Some("Tailscale")
        );
        // Both resident: the corporate client is the likelier owner of a
        // v4-only CGNAT address (Tailscale's own tunnel carries its v6).
        assert_eq!(
            pick_vendor(addr, &run(&["Tailscale", "Zscaler"]), &NO),
            Some("Zscaler")
        );
        assert_eq!(pick_vendor(addr, &run(&[]), &NO), Some("Tailscale"));
        assert_eq!(pick_vendor(None, &run(&["Zscaler"]), &NO), Some("Zscaler"));
        assert_eq!(pick_vendor(None, &run(&["Mullvad", "Zscaler"]), &NO), None);
    }

    /// A Tailscale tunnel carries its fd7a:115c:a1e0:: address and a 100.x
    /// one, which can fall in WARP's /12. The v6 names it outright, so a
    /// sole running Zscaler doesn't take it over.
    #[test]
    fn a_vendors_own_v6_outweighs_its_shared_v4() {
        use super::{AddrMatch, vendor_match};
        use std::collections::BTreeSet;
        let v4 = [Ipv4Addr::new(100, 101, 2, 3)];
        let v6: [Ipv6Addr; 1] = ["fd7a:115c:a1e0::1".parse().unwrap()];
        let addr = vendor_match(&v4, &v6);
        assert_eq!(addr, Some(("Tailscale", AddrMatch::Own)));
        assert_eq!(
            pick_vendor(addr, &BTreeSet::from(["Zscaler"]), &NO),
            Some("Tailscale")
        );
        // The same 100.x alone is WARP's, and shared.
        assert_eq!(
            vendor_match(&v4, &[]),
            Some(("Cloudflare WARP", AddrMatch::Shared))
        );
        // Classified by the address that matched: Mullvad's 10.64.x stays
        // Private even beside an unrelated public address.
        assert_eq!(
            vendor_match(
                &[Ipv4Addr::new(203, 0, 113, 7), Ipv4Addr::new(10, 64, 0, 7)],
                &[]
            ),
            Some(("Mullvad", AddrMatch::Private))
        );
    }

    /// A client whose addresses always come from its own blocks cannot own a
    /// tunnel outside them: a WireGuard tunnel at 10.9.8.10 beside a resident
    /// Tailscale is WireGuard, the one client left, rather than ambiguous.
    /// Clients with no block of their own, and the matched vendor, stay.
    #[test]
    fn clients_that_cannot_own_the_address_do_not_make_it_ambiguous() {
        use super::plausible_owners;
        use std::collections::BTreeSet;
        let wg = [Ipv4Addr::new(10, 9, 8, 10)];
        let mut running = BTreeSet::from(["Tailscale", "WireGuard", "Cloudflare WARP"]);
        plausible_owners(&mut running, &wg, &[]);
        assert_eq!(running, BTreeSet::from(["WireGuard"]));
        assert_eq!(pick_vendor(None, &running, &NO), Some("WireGuard"));

        // Mullvad's block: Mullvad stays, Tailscale goes, OpenVPN (no block)
        // stays, so the private match still needs Mullvad's client and two
        // candidates are still ambiguous without it.
        let mullvad = [Ipv4Addr::new(10, 64, 0, 7)];
        let mut running = BTreeSet::from(["Tailscale", "Mullvad", "OpenVPN"]);
        plausible_owners(&mut running, &mullvad, &[]);
        assert_eq!(running, BTreeSet::from(["Mullvad", "OpenVPN"]));

        // A v6 in Tailscale's block keeps Tailscale.
        let v6: [Ipv6Addr; 1] = ["fd7a:115c:a1e0::1".parse().unwrap()];
        let mut running = BTreeSet::from(["Tailscale", "WireGuard"]);
        plausible_owners(&mut running, &[], &v6);
        assert_eq!(running, BTreeSet::from(["Tailscale", "WireGuard"]));

        // No addresses yet: nothing can be ruled out.
        let mut running = BTreeSet::from(["Tailscale", "WireGuard"]);
        plausible_owners(&mut running, &[], &[]);
        assert_eq!(running.len(), 2);
    }

    /// The resolvers a client configures are the third witness, from the
    /// rig: NordVPN writes 103.86.96.100 and 103.86.99.100, WARP 127.0.2.2
    /// and 127.0.2.3, Tailscale's MagicDNS is 100.100.100.100. They confirm
    /// a private match the way a running process does, break a tie between
    /// two resident clients, and stand in when no process is visible; being
    /// system-wide they are narrowed by the device's addresses like the
    /// process table, so MagicDNS never names a wg-quick tunnel beside it.
    #[test]
    fn the_active_clients_resolvers_are_a_third_witness() {
        use super::{AddrMatch, name_tunnel, plausible_owners, vendors_by_resolver};
        use std::collections::BTreeSet;
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let nord = vendors_by_resolver(&[ip("103.86.96.100"), ip("103.86.99.100")]);
        assert_eq!(nord, BTreeSet::from(["NordVPN"]));
        assert_eq!(
            vendors_by_resolver(&[ip("127.0.2.2"), ip("127.0.2.3")]),
            BTreeSet::from(["Cloudflare WARP"])
        );
        let magic = vendors_by_resolver(&[ip("100.100.100.100")]);
        assert_eq!(magic, BTreeSet::from(["Tailscale"]));
        // A LAN resolver, a public one, Cloudflare Gateway's: nobody's.
        assert!(
            vendors_by_resolver(&[ip("192.168.1.1"), ip("1.1.1.1"), ip("172.64.36.1")]).is_empty()
        );
        let none = BTreeSet::new();

        // nordlynx at 10.5.0.2 with the process table unreadable: the
        // resolvers confirm the private match.
        let nord_addr = Some(("NordVPN", AddrMatch::Private));
        assert_eq!(
            name_tunnel(nord_addr, &none, &none, true),
            Some("WireGuard")
        );
        assert_eq!(name_tunnel(nord_addr, &none, &nord, true), Some("NordVPN"));
        assert_eq!(pick_vendor(nord_addr, &none, &nord), Some("NordVPN"));

        // Two block-less clients resident, a utun at 10.14.0.2: ambiguous
        // until the resolvers say which one connected.
        let both = BTreeSet::from(["Surfshark", "Private Internet Access"]);
        assert_eq!(pick_vendor(None, &both, &none), None);
        let surf = vendors_by_resolver(&[ip("162.252.172.57")]);
        assert_eq!(pick_vendor(None, &both, &surf), Some("Surfshark"));
        assert_eq!(name_tunnel(None, &both, &surf, true), Some("Surfshark"));
        // Nothing visible running at all: the resolvers alone name it.
        assert_eq!(pick_vendor(None, &none, &surf), Some("Surfshark"));
        // Two vendors' resolvers at once say nothing.
        let two: BTreeSet<_> = surf.union(&nord).copied().collect();
        assert_eq!(pick_vendor(None, &none, &two), None);

        // MagicDNS beside a wg-quick tunnel at 10.13.13.2: the device's
        // address rules Tailscale out before the resolvers are weighed.
        let mut by_dns = magic.clone();
        plausible_owners(&mut by_dns, &[Ipv4Addr::new(10, 13, 13, 2)], &[]);
        assert!(by_dns.is_empty());
        assert_eq!(name_tunnel(None, &none, &by_dns, true), Some("WireGuard"));
        // And it breaks the Tailscale/Zscaler tie the other way.
        let ts_addr = Some(("Tailscale", AddrMatch::Shared));
        let ts_zs = BTreeSet::from(["Tailscale", "Zscaler"]);
        assert_eq!(pick_vendor(ts_addr, &ts_zs, &none), Some("Zscaler"));
        assert_eq!(pick_vendor(ts_addr, &ts_zs, &magic), Some("Tailscale"));
    }

    /// WARP over WireGuard puts 172.16.0.2 on every device's interface
    /// (consumer mode, and a Zero Trust org that does not assign per-device
    /// local IPs); the 100.96/12 CGNAT address is on the interface only under
    /// MASQUE or with that setting on. With its 2606:4700 v6 the device is
    /// WARP's outright; without it, the private 172.16.0.2 still keeps WARP a
    /// plausible owner and names it once warp-svc or its resolvers confirm,
    /// while a corporate tunnel that happens to use 172.16.0.2 does not become
    /// WARP on the address alone.
    #[test]
    fn warp_over_wireguard_is_named_from_its_fixed_private_address() {
        use super::{AddrMatch, plausible_owners, vendor_match, vendors_by_resolver};
        use std::collections::BTreeSet;
        let wg_v4 = [Ipv4Addr::new(172, 16, 0, 2)];
        let v6 = ["2606:4700:110:8c7d:7369:7526:a59b:5636"
            .parse::<Ipv6Addr>()
            .unwrap()];
        assert_eq!(
            vendor_match(&wg_v4, &v6),
            Some(("Cloudflare WARP", AddrMatch::Own))
        );
        assert_eq!(
            vendor_match(&[Ipv4Addr::new(100, 96, 0, 7)], &[]),
            Some(("Cloudflare WARP", AddrMatch::Shared))
        );

        // IPv6 gone from the device: the address is only a hint.
        let hint = vendor_match(&wg_v4, &[]);
        assert_eq!(hint, Some(("Cloudflare WARP", AddrMatch::Private)));
        let none = BTreeSet::new();
        assert_eq!(pick_vendor(hint, &none, &none), None);
        let mut running = BTreeSet::from(["Cloudflare WARP", "Tailscale"]);
        plausible_owners(&mut running, &wg_v4, &[]);
        assert_eq!(running, BTreeSet::from(["Cloudflare WARP"]));
        assert_eq!(pick_vendor(hint, &running, &none), Some("Cloudflare WARP"));
        let by_dns = vendors_by_resolver(&["127.0.2.2".parse::<IpAddr>().unwrap()]);
        assert_eq!(pick_vendor(hint, &none, &by_dns), Some("Cloudflare WARP"));
    }

    /// NetworkManager's "Trevor" with Tailscale running for something else:
    /// the kernel WireGuard device is WireGuard, not Tailscale. A client
    /// whose address the device carries, and which is running, still names
    /// it (Mullvad's wg0-mullvad).
    #[test]
    fn a_bystander_client_does_not_name_a_kernel_wireguard_device() {
        use super::{AddrMatch, name_tunnel};
        use std::collections::BTreeSet;
        let tailscale = BTreeSet::from(["Tailscale"]);
        let mullvad = BTreeSet::from(["Mullvad"]);
        let none = BTreeSet::new();
        let mullvad_addr = Some(("Mullvad", AddrMatch::Private));

        assert_eq!(name_tunnel(None, &tailscale, &NO, true), Some("WireGuard"));
        assert_eq!(name_tunnel(None, &none, &NO, true), Some("WireGuard"));
        // PIA, Surfshark and Windscribe drive kernel WireGuard devices on
        // Linux with addresses in no table: the one such client running
        // names the device, and a tun-only client beside it stays a
        // bystander. Two such clients, or a tun-only one alone, do not.
        let surfshark = BTreeSet::from(["Surfshark"]);
        assert_eq!(name_tunnel(None, &surfshark, &NO, true), Some("Surfshark"));
        assert_eq!(
            name_tunnel(None, &BTreeSet::from(["Surfshark", "Tailscale"]), &NO, true),
            Some("Surfshark")
        );
        assert_eq!(
            name_tunnel(None, &BTreeSet::from(["Surfshark", "Mullvad"]), &NO, true),
            Some("WireGuard")
        );
        assert_eq!(
            name_tunnel(None, &BTreeSet::from(["OpenVPN"]), &NO, true),
            Some("WireGuard")
        );
        assert_eq!(
            name_tunnel(
                None,
                &BTreeSet::from(["Private Internet Access"]),
                &NO,
                true
            ),
            Some("Private Internet Access")
        );
        assert_eq!(
            name_tunnel(mullvad_addr, &mullvad, &NO, true),
            Some("Mullvad")
        );
        assert_eq!(
            name_tunnel(mullvad_addr, &none, &NO, true),
            Some("WireGuard")
        );
        assert_eq!(
            name_tunnel(mullvad_addr, &tailscale, &NO, true),
            Some("WireGuard")
        );
        // A shared-space (CGNAT) address alone doesn't make a kernel
        // WireGuard device Tailscale or WARP: NetBird's wt0, or any
        // wg-quick config on 100.64/10. Tailscale's own Linux device is tun.
        let tailscale_addr = Some(("Tailscale", AddrMatch::Shared));
        assert_eq!(
            name_tunnel(tailscale_addr, &none, &NO, true),
            Some("WireGuard")
        );
        assert_eq!(
            name_tunnel(tailscale_addr, &tailscale, &NO, true),
            Some("Tailscale")
        );
        // A vendor's own block names it outright.
        let mullvad_v6 = Some(("Mullvad", AddrMatch::Own));
        assert_eq!(name_tunnel(mullvad_v6, &none, &NO, true), Some("Mullvad"));
        // Not a kernel WireGuard device: unchanged.
        assert_eq!(
            name_tunnel(tailscale_addr, &none, &NO, false),
            Some("Tailscale")
        );
        assert_eq!(name_tunnel(None, &tailscale, &NO, false), Some("Tailscale"));
        assert_eq!(name_tunnel(None, &none, &NO, false), None);
    }

    /// The vendor cache asks once per device, again when the device's
    /// addresses change (a freed utunN handed to the next VPN), not when a
    /// lookup panicked, and forgets devices that are gone.
    #[tokio::test]
    async fn the_vendor_cache_asks_again_only_when_the_addresses_change() {
        use super::{Panicked, TunnelAddrs, VendorCache};
        use std::cell::RefCell;
        let asked = RefCell::new(Vec::new());
        let answers = RefCell::new(Vec::<Result<Option<&'static str>, Panicked>>::new());
        let lookup = |a: TunnelAddrs| {
            asked.borrow_mut().push(a.v4.clone());
            let next = answers.borrow_mut().remove(0);
            async move { next }
        };
        let addrs = |v4: &str| TunnelAddrs {
            v4: vec![v4.parse().unwrap()],
            ..Default::default()
        };
        let mut cache = VendorCache::default();

        // First sight: asked, cached.
        answers.borrow_mut().push(Ok(Some("Cloudflare WARP")));
        let warp = vec![("utun4".to_string(), addrs("100.96.0.2"))];
        cache.refresh(&warp, lookup).await;
        assert_eq!(cache.vendor_of("utun4"), "Cloudflare WARP");
        assert_eq!(asked.borrow().len(), 1);

        // Same device, same addresses: not asked again.
        cache.refresh(&warp, lookup).await;
        assert_eq!(asked.borrow().len(), 1);

        // Same device name, new addresses: a different VPN has it now.
        answers.borrow_mut().push(Ok(Some("Tailscale")));
        let reused = vec![("utun4".to_string(), addrs("100.101.2.3"))];
        cache.refresh(&reused, lookup).await;
        assert_eq!(cache.vendor_of("utun4"), "Tailscale");
        assert_eq!(asked.borrow().len(), 2);

        // A lookup that panicked is not remembered as "unnamed": the next
        // pass asks again, and meanwhile the tunnel is simply unnamed.
        answers.borrow_mut().push(Err(Panicked));
        let other = vec![("utun5".to_string(), addrs("10.9.8.10"))];
        cache.refresh(&other, lookup).await;
        assert_eq!(cache.vendor_of("utun5"), "");
        answers.borrow_mut().push(Ok(Some("WireGuard")));
        cache.refresh(&other, lookup).await;
        assert_eq!(cache.vendor_of("utun5"), "WireGuard");
        assert_eq!(asked.borrow().len(), 4);

        // utun4 left the device list above, so it was forgotten.
        assert_eq!(cache.vendor_of("utun4"), "");
    }

    /// An up interface named `name` carrying `v4`, typed by its name alone.
    fn up(name: &str, v4: &str) -> netdev::Interface {
        let mut i = netdev::Interface::dummy();
        i.name = name.to_string();
        // IFF_UP is bit 0 on every platform; netdev types the constant
        // differently per OS, so the bit is set directly and checked.
        i.flags = 0x1;
        assert!(i.is_up());
        i.ipv4 = vec![v4.parse().unwrap()];
        i
    }

    /// Issue #27, as the reporter's routing table had it: `default` on Wi-Fi,
    /// ppp0 holding 10.0.0.0/8 and some seventy more corporate prefixes. The
    /// kernel routes a public address via Wi-Fi, and the tunnel is a
    /// bystander — up, addressed, carrying none of the internet traffic.
    #[test]
    fn a_split_tunnel_beside_the_link_is_bypassed_not_default() {
        let ifaces = vec![
            up("lo", "127.0.0.1/8"),
            up("wlp3s0", "192.168.1.23/24"),
            up("ppp0", "10.212.134.200/32"),
        ];
        // What the egress probe yields on that machine: the Wi-Fi address.
        let link = iface_with_addr(&ifaces, "192.168.1.23".parse().unwrap()).unwrap();
        assert_eq!(link.name, "wlp3s0");
        assert_eq!(bypassed_tunnels(&ifaces, &[&link.name, ""]), vec!["ppp0"]);
        // The tunnel that carries the traffic is never listed as bypassed.
        assert!(bypassed_tunnels(&ifaces, &["wlp3s0", "ppp0"]).is_empty());
        // An address nobody holds names no interface.
        assert!(iface_with_addr(&ifaces, IpAddr::V4(Ipv4Addr::new(10, 254, 254, 254))).is_none());
    }

    #[test]
    fn a_tunnel_without_addresses_or_down_is_not_a_bypassed_tunnel() {
        let mut down = up("tun0", "10.8.0.2/24");
        down.flags = 0;
        let mut bare = up("wg0", "10.9.0.2/24");
        bare.ipv4.clear();
        let ifaces = vec![up("eth0", "10.0.0.5/24"), down, bare];
        assert!(bypassed_tunnels(&ifaces, &["eth0", ""]).is_empty());
    }

    /// A Mac as shipped: utun0–utun3 up with link-local v6 only, ipsec0 with
    /// the carrier's global v6 for Wi-Fi Calling. None is a VPN. A Tailscale
    /// tunnel with its ULA v6 alone still counts.
    #[test]
    fn apples_own_tunnels_are_not_listed() {
        let v6_only = |name: &str, addr: &str| {
            let mut i = up(name, "0.0.0.0/32");
            i.ipv4.clear();
            i.ipv6 = vec![addr.parse().unwrap()];
            i
        };
        let ifaces = vec![
            up("en0", "192.168.1.89/23"),
            v6_only("utun0", "fe80::49c4:35f8:4089:5fbc/64"),
            v6_only("utun3", "fe80::ce81:b1c:bd2c:69e/64"),
            v6_only("ipsec0", "2607:fb90:fa7f:21ba:fcda:5875:5ebf:7c8/64"),
            v6_only("utun5", "fd7a:115c:a1e0::1234/128"),
            up("utun4", "100.96.0.7/32"),
        ];
        assert_eq!(
            bypassed_tunnels(&ifaces, &["en0", ""]),
            vec!["utun4", "utun5"]
        );
    }

    /// The wording has to carry "internet path unchanged" itself: on the
    /// timeline a bare "ppp0 up" reads as a VPN taking over.
    #[test]
    fn bypassed_tunnel_events_say_the_path_did_not_move() {
        let ppp = BypassedTunnel {
            iface: "ppp0".into(),
            vendor: "openfortivpn".into(),
        };
        let changes = bypassed_changes(&[], std::slice::from_ref(&ppp), "wlp3s0");
        assert_eq!(changes.len(), 1);
        let (name, came_up, message) = &changes[0];
        assert_eq!(name, "ppp0");
        assert!(*came_up);
        assert!(message.starts_with("split tunnel up: openfortivpn (ppp0)"));
        assert!(message.contains("still leaves via wlp3s0"));

        let changes = bypassed_changes(std::slice::from_ref(&ppp), &[], "wlp3s0");
        assert_eq!(changes.len(), 1);
        assert!(!changes[0].1);
        assert!(changes[0].2.contains("internet path unchanged"));

        // Same set, no chatter; an unnamed vendor shows the device alone.
        assert!(
            bypassed_changes(
                std::slice::from_ref(&ppp),
                std::slice::from_ref(&ppp),
                "wlp3s0"
            )
            .is_empty()
        );
        let unnamed = BypassedTunnel {
            iface: "tun0".into(),
            vendor: String::new(),
        };
        let changes = bypassed_changes(&[], std::slice::from_ref(&unnamed), "eth0");
        assert!(changes[0].2.starts_with("split tunnel up: tun0 —"));
    }

    /// The Ubuntu USB-dongle lesson: a wired interface coming up while Wi-Fi
    /// keeps the default route must be announced — with the "default route
    /// still Wi-Fi" warning, because that is the whole problem.
    #[test]
    fn hotplugged_interface_warns_when_the_route_does_not_follow() {
        use crate::app::LinkMedium;
        use std::collections::HashMap;
        let wifi_only: HashMap<String, LinkMedium> =
            [("wlp2s0".to_string(), LinkMedium::WiFi)].into();
        let both: HashMap<String, LinkMedium> = [
            ("wlp2s0".to_string(), LinkMedium::WiFi),
            ("enx00e04c".to_string(), LinkMedium::Ethernet),
        ]
        .into();

        // Plugged in, route still on Wi-Fi: say so.
        let msgs = iface_changes(&wifi_only, &both, "wlp2s0");
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].2.contains("interface connected: enx00e04c"));
        assert!(msgs[0].2.contains("default route still wlp2s0"));
        assert!(msgs[0].1, "came up");

        // Plugged in and it IS the default: no warning clause.
        let msgs = iface_changes(&wifi_only, &both, "enx00e04c");
        assert!(!msgs[0].2.contains("default route still"));

        // Unplugged: announced too.
        let msgs = iface_changes(&both, &wifi_only, "wlp2s0");
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].2.contains("interface disconnected: enx00e04c"));
        assert!(!msgs[0].1, "went down");

        // No change, no chatter.
        assert!(iface_changes(&both, &both, "wlp2s0").is_empty());
    }

    /// Real values observed on a Mac running WARP with NordVPN also installed
    /// and its helpers resident: the interface must decide, not the process list.
    #[test]
    fn warp_is_identified_from_its_tunnel_addresses() {
        let v4 = [Ipv4Addr::new(100, 96, 0, 7)];
        let v6 = ["2606:4700:cf1:1000::2".parse::<Ipv6Addr>().unwrap()];
        assert_eq!(vendor_from_addrs(&v4, &v6), Some("Cloudflare WARP"));
        // Either address alone is enough.
        assert_eq!(vendor_from_addrs(&v4, &[]), Some("Cloudflare WARP"));
        assert_eq!(vendor_from_addrs(&[], &v6), Some("Cloudflare WARP"));
    }

    /// WARP's 100.96.0.0/12 lives inside Tailscale's 100.64.0.0/10, so ordering
    /// decides. A Tailscale address outside WARP's block must still say Tailscale.
    #[test]
    fn overlapping_cgnat_ranges_resolve_to_the_narrower_match() {
        assert_eq!(
            vendor_from_addrs(&[Ipv4Addr::new(100, 101, 2, 3)], &[]),
            Some("Cloudflare WARP")
        );
        assert_eq!(
            vendor_from_addrs(&[Ipv4Addr::new(100, 70, 1, 2)], &[]),
            Some("Tailscale")
        );
    }

    /// Found in the field: a tun device on 10.99.0.2 was labelled Mullvad,
    /// whose 10.64/10 block it fell into — and any corporate VPN handing out
    /// 10.x addresses can do the same. Private-range matches need the client.
    #[test]
    fn a_private_address_match_needs_the_vendors_client_running() {
        use super::AddrMatch;
        use std::collections::BTreeSet;
        let none = BTreeSet::new();
        let mullvad: BTreeSet<&'static str> = ["Mullvad"].into();
        let others: BTreeSet<&'static str> = ["Tailscale", "openfortivpn"].into();
        // WARP's CGNAT block is shared: the address stands while no single
        // other client is running.
        assert_eq!(
            pick_vendor(Some(("Cloudflare WARP", AddrMatch::Shared)), &none, &NO),
            Some("Cloudflare WARP")
        );
        // A 10.x match stands only with the client resident...
        assert_eq!(
            pick_vendor(Some(("Mullvad", AddrMatch::Private)), &mullvad, &NO),
            Some("Mullvad")
        );
        // ...otherwise the process table decides, unambiguous or not at all.
        assert_eq!(
            pick_vendor(Some(("Mullvad", AddrMatch::Private)), &none, &NO),
            None
        );
        assert_eq!(
            pick_vendor(Some(("Mullvad", AddrMatch::Private)), &others, &NO),
            None
        );
        let forti: BTreeSet<&'static str> = ["openfortivpn"].into();
        assert_eq!(
            pick_vendor(Some(("Mullvad", AddrMatch::Private)), &forti, &NO),
            Some("openfortivpn")
        );
        assert_eq!(pick_vendor(None, &forti, &NO), Some("openfortivpn"));
        assert_eq!(pick_vendor(None, &others, &NO), None);
    }

    #[test]
    fn other_vpn_ranges_and_unknown_addresses() {
        assert_eq!(
            vendor_from_addrs(&[Ipv4Addr::new(10, 5, 0, 2)], &[]),
            Some("NordVPN")
        );
        assert_eq!(
            vendor_from_addrs(&[Ipv4Addr::new(10, 64, 1, 1)], &[]),
            Some("Mullvad")
        );
        // An unrecognised tunnel address names no vendor rather than guessing.
        assert_eq!(
            vendor_from_addrs(&[Ipv4Addr::new(172, 20, 3, 4)], &[]),
            None
        );
    }

    #[test]
    fn tunnel_names_are_recognised() {
        for n in [
            "utun4",
            "tun0",
            "wg0",
            "ppp0",
            "ZT0",
            "ipsec1",
            // Windows adapters' friendly names, exactly as the clients
            // register them.
            "CloudflareWARP",
            "NordLynx",
            "WireGuard Tunnel",
            "OpenVPN Wintun",
            "Mullvad",
            "ZeroTier One",
        ] {
            assert!(is_tunnel_name(n), "{n} should be a tunnel");
        }
        for n in ["en0", "eth0", "wlan0", "bridge0", "lo0"] {
            assert!(!is_tunnel_name(n), "{n} should not be a tunnel");
        }
    }
}
