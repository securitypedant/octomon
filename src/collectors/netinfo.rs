//! Network identity from `netdev`: addresses, MAC, gateway, link type & speed,
//! DHCP and DNS. Re-probed periodically to pick up network changes.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use netdev::interface::types::InterfaceType;
use tokio::sync::Notify;

use crate::app::{AppState, LinkMedium, NetInfo};

pub async fn run(state: Arc<Mutex<AppState>>, refresh: Arc<Notify>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    // Identifying the VPN behind a tunnel means scanning the process table, so
    // the answer is cached per interface name rather than redone every tick.
    let mut vendor_cache: Option<(String, String)> = None;
    loop {
        // Re-probe on the timer or when the user presses 'r'.
        tokio::select! {
            _ = ticker.tick() => {}
            _ = refresh.notified() => {}
        }
        if let Ok(iface) = netdev::get_default_interface() {
            let mut info = build(&iface);
            if info.tunnel.is_some() {
                let vendor = match &vendor_cache {
                    Some((name, v)) if *name == info.iface => v.clone(),
                    _ => {
                        let v = tokio::task::spawn_blocking(tunnel_vendor)
                            .await
                            .unwrap_or_default();
                        vendor_cache = Some((info.iface.clone(), v.clone()));
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
            let prev_wifi = s.netinfo.wifi.take();
            s.netinfo = info;
            s.netinfo.wifi = prev_wifi;
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
        iface: iface.name.clone(),
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
        wifi: None, // filled in by the caller for Wi-Fi links
    }
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

/// Best-effort identification of the VPN behind a tunnelled default route, by
/// looking for a known client in the process table. Returns an empty string when
/// nothing recognisable is running — the tunnel is still reported, just unnamed.
fn tunnel_vendor() -> String {
    /// (process-name fragment, display name), matched case-insensitively.
    const KNOWN: &[(&str, &str)] = &[
        ("warp-svc", "Cloudflare WARP"),
        ("cloudflarewarp", "Cloudflare WARP"),
        ("cloudflared", "Cloudflare Tunnel"),
        ("tailscaled", "Tailscale"),
        ("openvpn", "OpenVPN"),
        ("wireguard", "WireGuard"),
        ("wg-quick", "WireGuard"),
        ("nordvpn", "NordVPN"),
        ("mullvad", "Mullvad"),
        ("protonvpn", "Proton VPN"),
        ("expressvpn", "ExpressVPN"),
        ("tunnelblick", "Tunnelblick"),
        ("globalprotect", "GlobalProtect"),
        ("anyconnect", "Cisco AnyConnect"),
        ("zerotier", "ZeroTier"),
        ("tailscale", "Tailscale"),
    ];

    let mut sys = sysinfo::System::new();
    sys.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::All,
        true,
        sysinfo::ProcessRefreshKind::nothing(),
    );
    for proc in sys.processes().values() {
        let name = proc.name().to_string_lossy().to_ascii_lowercase();
        if let Some((_, display)) = KNOWN.iter().find(|(frag, _)| name.contains(frag)) {
            return (*display).to_string();
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::is_tunnel_name;

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
