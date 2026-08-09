//! Platform-specific probes that have no good cross-platform crate. Each public
//! function returns `None` where the platform is unsupported, so callers degrade
//! gracefully.

use crate::app::WifiInfo;

/// A single process's cumulative network byte counters at a point in time.
pub struct ProcSample {
    pub pid: u32,
    pub name: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
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
    use super::ProcSample;
    use crate::app::WifiInfo;

    /// One-shot per-process cumulative byte counters via `nettop`. Note: passing
    /// `-s` makes nettop reject the arg set and print usage, so it is omitted;
    /// `-L 1` takes a single sample (~5s incl. startup). Unprivileged for the
    /// user's own processes.
    pub async fn proc_net_sample() -> Option<Vec<ProcSample>> {
        let out = tokio::process::Command::new("nettop")
            .args(["-P", "-L", "1", "-x", "-J", "bytes_in,bytes_out"])
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

    /// Lines look like `Google Chrome H.1542,251614786,356212,`. The process
    /// column is `name.pid`; the pid follows the final dot (names contain dots).
    fn parse_nettop(text: &str) -> Vec<ProcSample> {
        let mut samples = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            let cols: Vec<&str> = line.split(',').collect();
            if cols.len() < 3 || cols[0].is_empty() {
                continue; // blank or the ",bytes_in,bytes_out," header
            }
            let Some((name, pid_str)) = cols[0].rsplit_once('.') else {
                continue;
            };
            let Ok(pid) = pid_str.parse::<u32>() else {
                continue;
            };
            samples.push(ProcSample {
                pid,
                name: name.to_string(),
                bytes_in: cols[1].trim().parse().unwrap_or(0),
                bytes_out: cols[2].trim().parse().unwrap_or(0),
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
