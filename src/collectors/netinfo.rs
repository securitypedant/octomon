//! Network identity from `netdev`: addresses, MAC, gateway, link type & speed,
//! DHCP and DNS. Re-probed periodically to pick up network changes.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;

use crate::app::{AppState, NetInfo};

pub async fn run(state: Arc<Mutex<AppState>>, refresh: Arc<Notify>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    loop {
        // Re-probe on the timer or when the user presses 'r'.
        tokio::select! {
            _ = ticker.tick() => {}
            _ = refresh.notified() => {}
        }
        if let Ok(iface) = netdev::get_default_interface() {
            let info = build(&iface);
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

    // Link description: friendly name (Windows/macOS) or classified type, plus
    // negotiated speed when the OS exposes it (10/100/1000…).
    let mut link_kind = iface
        .friendly_name
        .clone()
        .unwrap_or_else(|| iface.if_type.name());
    if let Some(bps) = iface.transmit_speed.filter(|b| *b > 0) {
        link_kind = format!("{link_kind} · {} Mb", bps / 1_000_000);
    }
    if iface.dhcp_v4_enabled == Some(true) {
        link_kind.push_str(" · DHCP");
    }

    NetInfo {
        iface: iface.name.clone(),
        ipv4,
        ipv6,
        mac,
        gateway_ip,
        gateway_mac,
        link_kind,
        wifi: None, // filled in by the caller for Wi-Fi links
    }
}
