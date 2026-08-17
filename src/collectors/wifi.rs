//! Wi-Fi radio details collector. Kept separate from `netinfo` because the only
//! unprivileged source of RSSI / PHY / tx-rate on modern macOS
//! (`system_profiler SPAirPortDataType`) is slow (~10-15s, it scans), so it runs
//! on a long cadence and must not gate the fast base-info refresh.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;

use crate::app::AppState;

pub async fn run(state: Arc<Mutex<AppState>>, refresh: Arc<Notify>) {
    // Let the netinfo collector classify the link first so we can skip the
    // expensive probe on non-Wi-Fi links.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Tracked here rather than in state: a network change clears the state's
    // wifi details, and it's exactly across such changes that "which SSID did
    // we land on" is worth an event.
    let mut last_ssid: Option<String> = None;

    let mut ticker = tokio::time::interval(Duration::from_secs(60));
    loop {
        // Re-probe on the timer or when the user presses 'r'.
        tokio::select! {
            _ = ticker.tick() => {}
            _ = refresh.notified() => {}
        }

        let is_wifi = state.lock().unwrap().netinfo.medium == crate::app::LinkMedium::WiFi;
        if !is_wifi {
            continue;
        }

        if let Some(w) = crate::platform::wifi_details().await {
            let mut s = state.lock().unwrap();
            let known = !w.ssid.is_empty() && !w.ssid.contains("redacted");
            if known {
                if let Some(prev) = last_ssid.as_deref()
                    && prev != w.ssid
                {
                    s.push_event(
                        crate::verdict::Severity::Info,
                        crate::app::EventCategory::Wifi,
                        format!("Wi-Fi network → {}", w.ssid),
                    );
                }
                last_ssid = Some(w.ssid.clone());
            }
            s.netinfo.wifi = Some(w);
        }
    }
}
