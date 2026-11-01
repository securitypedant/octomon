//! Network identity from `netdev`: addresses, MAC, gateway, link type & speed,
//! DHCP and DNS. Re-probed periodically to pick up network changes.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use netdev::interface::types::InterfaceType;
use tokio::sync::Notify;

use crate::app::{AppState, BypassedTunnel, LinkMedium, NetInfo};

pub async fn run(state: Arc<Mutex<AppState>>, refresh: Arc<Notify>, changed: Arc<Notify>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    // Identifying the VPN behind a tunnel can fall back to scanning the process
    // table, so the answer is cached per tunnel device rather than redone every
    // tick — for the tunnel carrying the traffic and for any sitting beside it.
    let mut vendor_cache: HashMap<String, String> = HashMap::new();
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
            let default_name = state.lock().unwrap().netinfo.iface.clone();
            let messages = iface_changes(prev, &current, &default_name);
            if !messages.is_empty() {
                let mut s = state.lock().unwrap();
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
            let mut s = state.lock().unwrap();
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
            for dev in &devices {
                if !vendor_cache.contains_key(dev) {
                    let name = dev.clone();
                    let v = tokio::task::spawn_blocking(move || tunnel_vendor(name))
                        .await
                        .unwrap_or_default();
                    vendor_cache.insert(dev.clone(), v);
                }
            }
            vendor_cache.retain(|dev, _| devices.contains(dev));
            if info.tunnel.is_some() {
                info.tunnel = vendor_cache.get(&info.tunnel_iface).cloned();
            }
            info.bypassed_tunnels = bypassed
                .into_iter()
                .map(|iface| BypassedTunnel {
                    vendor: vendor_cache.get(&iface).cloned().unwrap_or_default(),
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
            let mut s = state.lock().unwrap();
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
fn underlay_identity() -> Option<(String, String, LinkMedium, String)> {
    let ifaces = netdev::get_interfaces();
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
fn bypassed_tunnels(ifaces: &[netdev::Interface], carrying: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = ifaces
        .iter()
        .filter(|i| classify(i) == LinkMedium::Tunnel)
        .filter(|i| i.is_up() && (!i.ipv4.is_empty() || !i.ipv6.is_empty()))
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
        if vendor_from_addrs(&v4, &v6).is_some() {
            return LinkMedium::Tunnel;
        }
    }
    base
}

/// Interface-name prefixes used by tunnel/VPN virtual devices across platforms.
fn is_tunnel_name(name: &str) -> bool {
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
        // Windows adapter aliases: the WARP client names its adapter
        // "CloudflareWARP" (one word).
        "cloudflarewarp",
    ];
    let n = name.to_ascii_lowercase();
    PREFIXES.iter().any(|p| n.starts_with(p))
}

/// A VPN's fingerprint. The address its tunnel device carries is the reliable
/// signal — it describes the tunnel that is actually *up*. Process names only
/// say a client is installed and running, which several can be at once.
struct Vpn {
    display: &'static str,
    v4: &'static [(Ipv4Addr, u32)],
    v6: &'static [(Ipv6Addr, u32)],
    /// Lowercase process-name fragments, used only as a last resort.
    procs: &'static [&'static str],
}

/// Ordered most-specific first: WARP's 100.96.0.0/12 sits inside Tailscale's
/// 100.64.0.0/10, so it has to be tested before it.
const KNOWN_VPNS: &[Vpn] = &[
    Vpn {
        display: "Cloudflare WARP",
        v4: &[(Ipv4Addr::new(100, 96, 0, 0), 12)],
        v6: &[(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0), 32)],
        procs: &["warp-svc", "cloudflarewarp"],
    },
    Vpn {
        display: "Tailscale",
        v4: &[(Ipv4Addr::new(100, 64, 0, 0), 10)],
        v6: &[(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0), 48)],
        procs: &["tailscaled", "tailscale"],
    },
    Vpn {
        display: "Mullvad",
        v4: &[(Ipv4Addr::new(10, 64, 0, 0), 10)],
        v6: &[(Ipv6Addr::new(0xfc00, 0xbbbb, 0xbbbb, 0, 0, 0, 0, 0), 48)],
        procs: &["mullvad"],
    },
    Vpn {
        display: "NordVPN",
        v4: &[(Ipv4Addr::new(10, 5, 0, 0), 16)],
        v6: &[],
        procs: &["nordvpn", "nordlynx"],
    },
    Vpn {
        display: "Proton VPN",
        v4: &[(Ipv4Addr::new(10, 2, 0, 0), 16)],
        v6: &[],
        procs: &["protonvpn"],
    },
    Vpn {
        display: "Cloudflare Tunnel",
        v4: &[],
        v6: &[],
        procs: &["cloudflared"],
    },
    Vpn {
        display: "ExpressVPN",
        v4: &[],
        v6: &[],
        procs: &["expressvpn"],
    },
    Vpn {
        display: "Surfshark",
        v4: &[],
        v6: &[],
        procs: &["surfshark"],
    },
    Vpn {
        display: "Private Internet Access",
        v4: &[],
        v6: &[],
        procs: &["pia-daemon", "privateinternetaccess"],
    },
    Vpn {
        display: "Windscribe",
        v4: &[],
        v6: &[],
        procs: &["windscribe"],
    },
    Vpn {
        display: "Zscaler",
        v4: &[],
        v6: &[],
        procs: &["zsatunnel", "zstunnel", "zscaler"],
    },
    Vpn {
        display: "FortiClient",
        v4: &[],
        v6: &[],
        procs: &["forticlient", "fortitray"],
    },
    // The open-source client for the same FortiGate SSL VPNs, usually as a
    // split tunnel (issue #27).
    Vpn {
        display: "openfortivpn",
        v4: &[],
        v6: &[],
        procs: &["openfortivpn"],
    },
    Vpn {
        display: "OpenVPN",
        v4: &[],
        v6: &[],
        procs: &["openvpn", "tunnelblick"],
    },
    Vpn {
        display: "WireGuard",
        v4: &[],
        v6: &[],
        procs: &["wireguard", "wg-quick"],
    },
    Vpn {
        display: "GlobalProtect",
        v4: &[],
        v6: &[],
        procs: &["globalprotect"],
    },
    Vpn {
        display: "Cisco AnyConnect",
        v4: &[],
        v6: &[],
        procs: &["anyconnect"],
    },
    Vpn {
        display: "ZeroTier",
        v4: &[],
        v6: &[],
        procs: &["zerotier"],
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

/// Identify the VPN from the addresses assigned to its tunnel device.
fn vendor_from_addrs(v4: &[Ipv4Addr], v6: &[Ipv6Addr]) -> Option<&'static str> {
    KNOWN_VPNS
        .iter()
        .find(|vpn| {
            v4.iter()
                .any(|a| vpn.v4.iter().any(|(n, p)| in_v4(*a, *n, *p)))
                || v6
                    .iter()
                    .any(|a| vpn.v6.iter().any(|(n, p)| in_v6(*a, *n, *p)))
        })
        .map(|vpn| vpn.display)
}

/// Identify the VPN carrying `iface_name`. Returns an empty string when nothing
/// can be pinned down — the tunnel is still reported, just unnamed, which beats
/// naming the wrong one.
fn tunnel_vendor(iface_name: String) -> String {
    // The live tunnel's own addresses are the first signal.
    let by_addr = netdev::get_interfaces()
        .into_iter()
        .find(|i| counter_name(i) == iface_name)
        .and_then(|iface| {
            let v4: Vec<Ipv4Addr> = iface.ipv4.iter().map(|n| n.addr()).collect();
            let v6: Vec<Ipv6Addr> = iface.ipv6.iter().map(|n| n.addr()).collect();
            let vendor = vendor_from_addrs(&v4, &v6)?;
            // Only an RFC1918 address could belong to anyone's VPN.
            Some((vendor, v4.iter().any(Ipv4Addr::is_private)))
        });

    // The process table is the other: every VPN client whose process is
    // resident, which several can be at once.
    let mut sys = sysinfo::System::new();
    sys.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::All,
        true,
        sysinfo::ProcessRefreshKind::nothing(),
    );
    let mut running = std::collections::BTreeSet::new();
    for proc in sys.processes().values() {
        let name = proc.name().to_string_lossy().to_ascii_lowercase();
        for vpn in KNOWN_VPNS {
            if vpn.procs.iter().any(|frag| name.contains(frag)) {
                running.insert(vpn.display);
            }
        }
    }
    pick_vendor(by_addr, &running)
        .unwrap_or_default()
        .to_string()
}

/// Weigh the two signals. A tunnel address in a vendor's own CGNAT or v6
/// block (WARP's 100.96/12, Tailscale's fd7a:115c:a1e0::/48) names it
/// outright. One in a private 10.x block the vendor happens to use (Mullvad's
/// 10.64/10, NordVPN's 10.5/16) is the same address space every corporate
/// VPN hands out, so it only counts with that vendor's client running: an
/// openfortivpn tunnel on 10.99.0.2 is not Mullvad. With no address to go on,
/// the process table decides only when it is unambiguous — two clients
/// resident say nothing about which one is up.
fn pick_vendor(
    by_addr: Option<(&'static str, bool)>,
    running: &std::collections::BTreeSet<&'static str>,
) -> Option<&'static str> {
    match by_addr {
        Some((vendor, false)) => Some(vendor),
        Some((vendor, true)) if running.contains(vendor) => Some(vendor),
        _ => (running.len() == 1).then(|| *running.iter().next().unwrap()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BypassedTunnel, IpAddr, Ipv4Addr, Ipv6Addr, bypassed_changes, bypassed_tunnels,
        iface_changes, iface_with_addr, is_tunnel_name, pick_vendor, vendor_from_addrs,
    };

    /// An up interface named `name` carrying `v4`, typed by its name alone.
    fn up(name: &str, v4: &str) -> netdev::Interface {
        let mut i = netdev::Interface::dummy();
        i.name = name.to_string();
        i.flags = netdev::interface::flags::IFF_UP as u32;
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
        use std::collections::BTreeSet;
        let none = BTreeSet::new();
        let mullvad: BTreeSet<&'static str> = ["Mullvad"].into();
        let others: BTreeSet<&'static str> = ["Tailscale", "openfortivpn"].into();
        // CGNAT / v6 blocks are the vendor's own: the address alone decides.
        assert_eq!(
            pick_vendor(Some(("Cloudflare WARP", false)), &none),
            Some("Cloudflare WARP")
        );
        // A 10.x match stands only with the client resident...
        assert_eq!(
            pick_vendor(Some(("Mullvad", true)), &mullvad),
            Some("Mullvad")
        );
        // ...otherwise the process table decides, unambiguous or not at all.
        assert_eq!(pick_vendor(Some(("Mullvad", true)), &none), None);
        assert_eq!(pick_vendor(Some(("Mullvad", true)), &others), None);
        let forti: BTreeSet<&'static str> = ["openfortivpn"].into();
        assert_eq!(
            pick_vendor(Some(("Mullvad", true)), &forti),
            Some("openfortivpn")
        );
        assert_eq!(pick_vendor(None, &forti), Some("openfortivpn"));
        assert_eq!(pick_vendor(None, &others), None);
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
            // The Windows WARP adapter's friendly name, exactly as the client
            // registers it.
            "CloudflareWARP",
        ] {
            assert!(is_tunnel_name(n), "{n} should be a tunnel");
        }
        for n in ["en0", "eth0", "wlan0", "bridge0", "lo0"] {
            assert!(!is_tunnel_name(n), "{n} should not be a tunnel");
        }
    }
}
