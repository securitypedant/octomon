//! Platform-specific probes that have no good cross-platform crate. Each public
//! function returns `None` where the platform is unsupported, so callers degrade
//! gracefully.

use crate::app::WifiInfo;

/// A single process's cumulative network counters at a point in time.
pub struct ProcSample {
    pub pid: u32,
    pub name: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Cumulative TCP retransmissions.
    pub retx: u64,
}

/// Sample cumulative per-process network counters. `None` on platforms without
/// an unprivileged source, so per-process attribution degrades gracefully.
#[cfg(target_os = "macos")]
pub async fn proc_net_sample() -> Option<Vec<ProcSample>> {
    macos::proc_net_sample().await
}

#[cfg(not(target_os = "macos"))]
pub async fn proc_net_sample() -> Option<Vec<ProcSample>> {
    None
}

/// Live Wi-Fi signal metrics (fast, unprivileged; RSSI/noise/tx-rate don't
/// require location permission — only SSID/BSSID do).
pub struct WifiSignal {
    pub rssi_dbm: i32,
    pub noise_dbm: i32,
    pub tx_rate_mbps: f64,
}

/// Sample the current Wi-Fi signal. `None` when not on Wi-Fi or unsupported.
#[cfg(target_os = "macos")]
pub fn wifi_signal() -> Option<WifiSignal> {
    macos::wifi_signal()
}

#[cfg(not(target_os = "macos"))]
pub fn wifi_signal() -> Option<WifiSignal> {
    None
}

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
    use super::{ProcSample, WifiSignal};
    use crate::app::WifiInfo;

    /// Read RSSI / noise / tx-rate via CoreWLAN. Returns `None` when there is no
    /// associated Wi-Fi interface. `rssiValue()` is 0 when not associated.
    pub fn wifi_signal() -> Option<WifiSignal> {
        use objc2_core_wlan::CWWiFiClient;
        // SAFETY: standard CoreWLAN read-only accessors on the shared client's
        // default interface; all return values are owned/primitive.
        unsafe {
            let client = CWWiFiClient::sharedWiFiClient();
            let iface = client.interface()?;
            let rssi = iface.rssiValue() as i32;
            let tx = iface.transmitRate();
            if rssi == 0 && tx == 0.0 {
                return None; // not associated
            }
            Some(WifiSignal {
                rssi_dbm: rssi,
                noise_dbm: iface.noiseMeasurement() as i32,
                tx_rate_mbps: tx,
            })
        }
    }

    /// One-shot per-process cumulative counters via `nettop`. Note: passing `-s`
    /// makes nettop reject the arg set and print usage, so it is omitted; `-L 1`
    /// takes a single sample (~5s incl. startup). Unprivileged for the user's
    /// own processes.
    pub async fn proc_net_sample() -> Option<Vec<ProcSample>> {
        let out = tokio::process::Command::new("nettop")
            .args(["-P", "-L", "1", "-x", "-J", "bytes_in,bytes_out,re-tx"])
            .stdin(std::process::Stdio::null())
            .output()
            .await
            .ok()?;
        // Key off parseable content rather than exit status (nettop's status is
        // unreliable when stdout is not a TTY).
        let samples = parse_nettop(&String::from_utf8_lossy(&out.stdout));
        if samples.is_empty() {
            None
        } else {
            Some(samples)
        }
    }

    /// Parse nettop CSV. Requesting extra columns makes nettop prepend a `time`
    /// column and reorder fields, so map columns by header name rather than
    /// position. The process column has an empty header and holds `name.pid`
    /// (the pid follows the final dot; names contain dots).
    fn parse_nettop(text: &str) -> Vec<ProcSample> {
        let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
        let Some(header) = lines.next() else {
            return Vec::new();
        };
        let cols: Vec<&str> = header.split(',').collect();
        let idx = |name: &str| cols.iter().position(|c| *c == name);
        let (Some(i_in), Some(i_out)) = (idx("bytes_in"), idx("bytes_out")) else {
            return Vec::new();
        };
        let i_retx = idx("re-tx");
        // The process column is the empty-named one (skip a leading "time").
        let i_proc = cols.iter().position(|c| c.is_empty()).unwrap_or(0);

        fn get<'a>(row: &[&'a str], i: usize) -> &'a str {
            row.get(i).map(|s| s.trim()).unwrap_or("")
        }
        let mut samples = Vec::new();
        for line in lines {
            let row: Vec<&str> = line.split(',').collect();
            let Some((name, pid_str)) = get(&row, i_proc).rsplit_once('.') else {
                continue;
            };
            let Ok(pid) = pid_str.parse::<u32>() else {
                continue;
            };
            samples.push(ProcSample {
                pid,
                name: name.to_string(),
                bytes_in: get(&row, i_in).parse().unwrap_or(0),
                bytes_out: get(&row, i_out).parse().unwrap_or(0),
                retx: i_retx
                    .map(|i| get(&row, i).parse().unwrap_or(0))
                    .unwrap_or(0),
            });
        }
        samples
    }

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
        // One invocation feeds both: this probe takes ~10-15s, so the neighbour
        // scan rides along with the current-network details rather than paying
        // that cost twice.
        let text = String::from_utf8_lossy(&out.stdout);
        let mut info = parse(&text)?;
        info.neighbours = parse_neighbours(&text);
        Some(info)
    }

    /// Channels of every other network the radio can see, from the
    /// "Other Local Wi-Fi Networks" block of the same report. SSIDs are ignored
    /// — macOS redacts them without Location permission, and congestion only
    /// depends on spectrum occupancy.
    fn parse_neighbours(text: &str) -> Vec<crate::app::Neighbour> {
        let mut lines = text.lines();
        let Some(header) = lines
            .by_ref()
            .find(|l| l.trim() == "Other Local Wi-Fi Networks:")
        else {
            return Vec::new();
        };
        let header_indent = indent(header);

        let mut out = Vec::new();
        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            // A line no deeper than the header ends this block.
            if indent(line) <= header_indent {
                break;
            }
            if let Some((k, v)) = line.split_once(':')
                && k.trim() == "Channel"
                && let Some(n) = crate::app::parse_channel(v.trim())
            {
                out.push(n);
            }
        }
        out
    }

    fn parse(text: &str) -> Option<WifiInfo> {
        let mut lines = text.lines();
        // Advance to the current-network marker.
        lines
            .by_ref()
            .find(|l| l.trim() == "Current Network Information:")?;

        // The next non-empty line is the SSID (a "<name>:" header).
        let ssid_line = lines.by_ref().find(|l| !l.trim().is_empty())?;
        let ssid = ssid_line.trim().trim_end_matches(':').to_string();
        let ssid_indent = indent(ssid_line);

        let mut info = WifiInfo {
            ssid,
            ..Default::default()
        };
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
        Some(WifiInfo {
            ssid,
            ..Default::default()
        })
    }
}
