//! Platform-specific probes that have no good cross-platform crate. Each public
//! function returns `None` where the platform is unsupported, so callers degrade
//! gracefully.

use crate::app::WifiInfo;

/// Wi-Fi details for the active connection, when available.
#[cfg(target_os = "macos")]
pub async fn wifi_details() -> Option<WifiInfo> {
    macos::wifi_details().await
}

#[cfg(target_os = "linux")]
pub async fn wifi_details() -> Option<WifiInfo> {
    linux::wifi_details().await
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub async fn wifi_details() -> Option<WifiInfo> {
    None
}

#[cfg(target_os = "macos")]
mod macos {
    use crate::app::WifiInfo;

    /// Parse the "Current Network Information" block from
    /// `system_profiler SPAirPortDataType`. Unprivileged; a few hundred ms.
    pub async fn wifi_details() -> Option<WifiInfo> {
        let out = tokio::process::Command::new("system_profiler")
            .arg("SPAirPortDataType")
            .output()
            .await
            .ok()?;
        if !out.status.success() {
            return None;
        }
        parse(&String::from_utf8_lossy(&out.stdout))
    }

    fn parse(text: &str) -> Option<WifiInfo> {
        let mut lines = text.lines();
        // Advance to the current-network marker.
        lines.by_ref().find(|l| l.trim() == "Current Network Information:")?;

        // The next non-empty line is the SSID (a "<name>:" header).
        let ssid_line = lines.by_ref().find(|l| !l.trim().is_empty())?;
        let ssid = ssid_line.trim().trim_end_matches(':').to_string();
        let ssid_indent = indent(ssid_line);

        let mut info = WifiInfo { ssid, ..Default::default() };
        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            // A line indented no deeper than the SSID ends this network's block.
            if indent(line) <= ssid_indent {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                let v = v.trim().to_string();
                match k.trim() {
                    "PHY Mode" => info.phy = v,
                    "Channel" => info.channel = v,
                    "Signal / Noise" => info.rssi = v,
                    "Transmit Rate" => {
                        info.tx_rate = if v.chars().all(|c| c.is_ascii_digit()) {
                            format!("{v} Mbps")
                        } else {
                            v
                        };
                    }
                    _ => {}
                }
            }
        }
        Some(info)
    }

    fn indent(line: &str) -> usize {
        line.len() - line.trim_start().len()
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use crate::app::WifiInfo;

    /// Best-effort via `iw dev` (present on most modern distros). Returns `None`
    /// when `iw` is missing or no interface is associated.
    pub async fn wifi_details() -> Option<WifiInfo> {
        let out = tokio::process::Command::new("iw")
            .args(["dev"])
            .output()
            .await
            .ok()?;
        if !out.status.success() {
            return None;
        }
        // A fuller parser (SSID/signal/bitrate via `iw dev <if> link`) can be
        // layered on later; for now report association presence.
        let text = String::from_utf8_lossy(&out.stdout);
        let ssid = text
            .lines()
            .find_map(|l| l.trim().strip_prefix("ssid "))
            .map(|s| s.to_string())?;
        Some(WifiInfo { ssid, ..Default::default() })
    }
}
