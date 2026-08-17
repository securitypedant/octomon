//! Network identity from `netdev`: addresses, MAC, gateway, link type & speed,
//! DHCP and DNS. Re-probed periodically to pick up network changes.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use netdev::interface::types::InterfaceType;
use tokio::sync::Notify;

use crate::app::{AppState, LinkMedium, NetInfo};

pub async fn run(state: Arc<Mutex<AppState>>, refresh: Arc<Notify>, changed: Arc<Notify>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    // Identifying the VPN behind a tunnel can fall back to scanning the process
    // table, so the answer is cached per tunnel device rather than redone every
    // tick.
    let mut vendor_cache: Option<(String, String)> = None;
    // Whether the default route has vanished entirely (Wi-Fi switched off,
    // cable pulled) — a different situation from moving to another network.
    let mut link_lost = false;
    loop {
        // Re-probe on the timer or when the user presses 'r'.
        tokio::select! {
            _ = ticker.tick() => {}
            _ = refresh.notified() => {}
        }
        if netdev::get_default_interface().is_err() {
            let mut s = state.lock().unwrap();
            if !link_lost && !s.netinfo.iface.is_empty() {
                link_lost = true;
                let medium = s.netinfo.medium;
                s.notice_event(
                    crate::verdict::Severity::Down,
                    crate::app::EventCategory::Network,
                    match medium {
                        LinkMedium::WiFi => "link lost — Wi-Fi is off or disconnected".to_string(),
                        m if m.is_wired() => "link lost — cable unplugged?".to_string(),
                        _ => "link lost — no default route".to_string(),
                    },
                );
            }
            continue;
        }
        if let Ok(iface) = netdev::get_default_interface() {
            let mut info = build(&iface);
            // The kernel's default route can point at the physical NIC while a
            // split-tunnel VPN quietly carries every packet bound for the
            // internet, so `build` alone misses it. Probe the real egress.
            if info.tunnel.is_none()
                && let Ok(Some(name)) = tokio::task::spawn_blocking(egress_iface_name).await
                && name != info.iface
                && is_tunnel_name(&name)
            {
                info.tunnel = Some(String::new()); // vendor resolved below
                info.tunnel_iface = name;
                info.tunnel_is_split = true;
            }
            if info.tunnel.is_some() {
                let vendor = match &vendor_cache {
                    Some((name, v)) if *name == info.tunnel_iface => v.clone(),
                    _ => {
                        let dev = info.tunnel_iface.clone();
                        let v = tokio::task::spawn_blocking(move || tunnel_vendor(dev))
                            .await
                            .unwrap_or_default();
                        vendor_cache = Some((info.tunnel_iface.clone(), v.clone()));
                        v
                    }
                };
                info.tunnel = Some(vendor);
            } else {
                vendor_cache = None;
            }
            // Preserve Wi-Fi details, which are populated on a slower cadence by
            // the dedicated wifi collector, across these frequent base refreshes.
            let mut s = state.lock().unwrap();
            let was = s.netinfo.identity();
            let now = info.identity();
            let prev_wifi = s.netinfo.wifi.take();
            let prev_dns = s.netinfo.dns.clone();
            let had_tunnel = s.netinfo.tunnel.is_some();
            let had_info = !s.netinfo.iface.is_empty();
            let moved = had_info && was != now;
            s.netinfo = info;
            s.netinfo.wifi = if moved { None } else { prev_wifi };
            let restored = std::mem::take(&mut link_lost);
            if restored {
                // The link is back (same network or not): stats accumulated
                // while it was down describe the outage, not the path — left
                // alone they'd keep the panel red for minutes.
                s.reset_quality_stats();
                let message = format!(
                    "link restored → {} — connection stats reset",
                    s.netinfo.iface
                );
                s.push_event(
                    crate::verdict::Severity::Info,
                    crate::app::EventCategory::Network,
                    message,
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
                    (false, true) => {
                        format!("VPN up — {}", s.netinfo.tunnel_label().unwrap_or_default())
                    }
                    (true, false) => "VPN down".to_string(),
                    // The SSID isn't known yet (the Wi-Fi probe is slow); the
                    // gateway is the most identifying fact available now, and
                    // the wifi collector names the network moments later.
                    _ => format!(
                        "network changed → {}{}",
                        s.netinfo.iface,
                        if s.netinfo.gateway_ip != "-" && !s.netinfo.gateway_ip.is_empty() {
                            format!(" · gateway {}", s.netinfo.gateway_ip)
                        } else {
                            String::new()
                        }
                    ),
                };
                s.notice_event(
                    crate::verdict::Severity::Info,
                    crate::app::EventCategory::Network,
                    message,
                );
                changed.notify_waiters();
            } else if had_info && s.netinfo.dns != prev_dns {
                // Same network, new resolvers (DHCP renewal, profile change) —
                // invisible in any average, classic "it broke at 3pm" material.
                let message = format!("DNS servers changed → {}", s.netinfo.dns.join(", "));
                s.push_event(
                    crate::verdict::Severity::Info,
                    crate::app::EventCategory::Network,
                    message,
                );
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

    let (gateway_ip, gateway_mac) = match &iface.gateway {
        Some(gw) => {
            let ip = gw
                .ipv4
                .first()
                .map(|i| i.to_string())
                .or_else(|| gw.ipv6.first().map(|i| i.to_string()))
                .unwrap_or_else(|| "-".to_string());
            (ip, gw.mac_addr.to_string())
        }
        None => ("-".to_string(), "-".to_string()),
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
    }

    let dns = iface.dns_servers.iter().map(|d| d.to_string()).collect();

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
        link_detail: detail.join(" · "),
        medium,
        link_speed_bps,
        // Vendor is filled in by the caller (it needs a process scan).
        tunnel: (medium == LinkMedium::Tunnel).then(String::new),
        tunnel_iface: if medium == LinkMedium::Tunnel {
            counter_name(iface)
        } else {
            String::new()
        },
        tunnel_is_split: false,
        wifi: None, // filled in by the caller for Wi-Fi links
    }
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

/// Name of the interface that traffic to the public internet actually leaves
/// from, which is not always the kernel's default route.
///
/// `netdev` picks the default interface by asking the kernel to route to
/// 10.254.254.254 — an RFC1918 address that split-tunnel VPNs deliberately keep
/// *off* the tunnel. Cloudflare WARP compounds this by leaving `default` alone
/// and installing 0.0.0.0/1 + 128.0.0.0/1, which win on specificity. Both make
/// the tunnel invisible unless a public destination is used for the probe.
///
/// Uses TEST-NET-1 (RFC 5737): globally routable as far as route selection is
/// concerned, so any tunnel claims it, but never a real host. Connecting a UDP
/// socket only selects a route — no packets are sent.
fn egress_iface_name() -> Option<String> {
    use std::net::{IpAddr, Ipv4Addr, UdpSocket};

    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    sock.connect((Ipv4Addr::new(192, 0, 2, 1), 1)).ok()?;
    let IpAddr::V4(local) = sock.local_addr().ok()?.ip() else {
        return None;
    };
    netdev::get_interfaces()
        .iter()
        // Must match how `build` names interfaces, or the split-tunnel
        // comparison against `info.iface` can never be equal on Windows.
        .find(|i| i.ipv4.iter().any(|n| n.addr() == local))
        .map(counter_name)
}

/// Classify the medium carrying the default route.
fn classify(iface: &netdev::Interface) -> LinkMedium {
    // Name first: macOS reports `utun` devices as plain Ethernet, so a VPN like
    // Cloudflare WARP is invisible to `if_type` alone.
    if is_tunnel_name(&iface.name) {
        return LinkMedium::Tunnel;
    }
    match iface.if_type {
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
    }
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
    // The live tunnel's own addresses settle it.
    if let Some(iface) = netdev::get_interfaces()
        .into_iter()
        .find(|i| i.name == iface_name)
    {
        let v4: Vec<Ipv4Addr> = iface.ipv4.iter().map(|n| n.addr()).collect();
        let v6: Vec<Ipv6Addr> = iface.ipv6.iter().map(|n| n.addr()).collect();
        if let Some(display) = vendor_from_addrs(&v4, &v6) {
            return display.to_string();
        }
    }

    // Fall back to the process table, but only when it is unambiguous: having
    // two clients installed and running says nothing about which one is up.
    let mut sys = sysinfo::System::new();
    sys.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::All,
        true,
        sysinfo::ProcessRefreshKind::nothing(),
    );
    let mut hits = std::collections::BTreeSet::new();
    for proc in sys.processes().values() {
        let name = proc.name().to_string_lossy().to_ascii_lowercase();
        for vpn in KNOWN_VPNS {
            if vpn.procs.iter().any(|frag| name.contains(frag)) {
                hits.insert(vpn.display);
            }
        }
    }
    match hits.len() {
        1 => hits.iter().next().unwrap().to_string(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::{Ipv4Addr, Ipv6Addr, is_tunnel_name, vendor_from_addrs};

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
        for n in ["utun4", "tun0", "wg0", "ppp0", "ZT0", "ipsec1"] {
            assert!(is_tunnel_name(n), "{n} should be a tunnel");
        }
        for n in ["en0", "eth0", "wlan0", "bridge0", "lo0"] {
            assert!(!is_tunnel_name(n), "{n} should not be a tunnel");
        }
    }
}
