//! Live Wi-Fi signal collector. Samples RSSI / noise / tx-rate frequently via
//! the platform probe (CoreWLAN on macOS — fast and unprivileged) so the
//! Network panel can graph how signal and link rate change over time.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::app::AppState;
use crate::platform;

pub async fn run(state: Arc<Mutex<AppState>>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(2));
    loop {
        ticker.tick().await;
        match platform::wifi_signal() {
            Some(sig) => {
                let mut s = state.lock().unwrap();
                let sd = &mut s.signal;
                sd.present = true;
                sd.rssi_dbm = sig.rssi_dbm;
                sd.noise_dbm = sig.noise_dbm;
                sd.tx_rate_mbps = sig.tx_rate_mbps;
                sd.rssi_hist.push(sig.rssi_dbm as f64);
                sd.tx_hist.push(sig.tx_rate_mbps);
            }
            None => state.lock().unwrap().signal.present = false,
        }
    }
}
