//! Platform-specific probes that have no good cross-platform crate. Each public
//! function returns `None` where the platform is unsupported, so callers degrade
//! gracefully.

use crate::app::WifiInfo;

pub mod tools;

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

#[cfg(target_os = "linux")]
pub async fn proc_net_sample() -> Option<Vec<ProcSample>> {
    linux::proc_net_sample().await
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
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

#[cfg(target_os = "linux")]
pub fn wifi_signal() -> Option<WifiSignal> {
    linux::wifi_signal()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn wifi_signal() -> Option<WifiSignal> {
    None
}

/// Thermal / power state. Throttling collapses throughput while CPU reads idle,
/// which is otherwise one of the more baffling failure modes to diagnose.
pub struct ThermalState {
    /// Short human summary, e.g. "nominal" or "CPU limited to 70%".
    pub summary: String,
    pub throttled: bool,
    /// "AC Power" / "Battery Power", where the platform reports it.
    pub power_source: String,
}

/// `None` on platforms with no unprivileged source. Linux exposes per-zone
/// temperatures under /sys, but no equivalent "am I being throttled" verdict,
/// so it is deliberately not guessed at.
#[cfg(target_os = "macos")]
pub async fn thermal_state() -> Option<ThermalState> {
    macos::thermal_state().await
}

#[cfg(not(target_os = "macos"))]
pub async fn thermal_state() -> Option<ThermalState> {
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

    /// Thermal and power state via `pmset`, which is unprivileged.
    pub async fn thermal_state() -> Option<super::ThermalState> {
        let therm = tokio::process::Command::new("pmset")
            .args(["-g", "therm"])
            .output()
            .await
            .ok()?;
        let (summary, throttled) = parse_therm(&String::from_utf8_lossy(&therm.stdout));

        // Power source is separate but cheap, and explains a throttle: a laptop
        // on battery may be limited deliberately rather than by heat.
        let power_source = tokio::process::Command::new("pmset")
            .args(["-g", "ps"])
            .output()
            .await
            .ok()
            .map(|o| parse_power_source(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default();

        Some(super::ThermalState {
            summary,
            throttled,
            power_source,
        })
    }

    /// `pmset -g therm` prints "No ... has been recorded" lines when all is
    /// well, and `CPU_Speed_Limit = N` when the CPU is being held back.
    fn parse_therm(text: &str) -> (String, bool) {
        let mut limit: Option<u32> = None;
        for line in text.lines() {
            if let Some((k, v)) = line.split_once('=')
                && k.trim().ends_with("CPU_Speed_Limit")
                && let Ok(n) = v.trim().parse::<u32>()
            {
                limit = Some(n);
            }
        }
        match limit {
            // 100 means "reported, and not limited".
            Some(n) if n < 100 => (format!("CPU limited to {n}%"), true),
            Some(_) => ("nominal".to_string(), false),
            None if text.contains("No thermal warning level") => ("nominal".to_string(), false),
            None => (String::new(), false),
        }
    }

    /// First line of `pmset -g ps` is "Now drawing from 'AC Power'".
    fn parse_power_source(text: &str) -> String {
        text.lines()
            .find_map(|l| l.split_once('\'').map(|(_, r)| r))
            .and_then(|r| r.split_once('\'').map(|(name, _)| name.to_string()))
            .unwrap_or_default()
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
    use super::{ProcSample, WifiSignal};
    use crate::app::{Neighbour, WifiInfo};
    use std::collections::HashMap;

    /// Live signal from `/proc/net/wireless`, which the kernel exposes to any
    /// user — no `iw`, no netlink, no privilege. Column 3 is the signal level in
    /// dBm and column 4 the noise floor.
    pub fn wifi_signal() -> Option<WifiSignal> {
        let text = std::fs::read_to_string("/proc/net/wireless").ok()?;
        parse_proc_wireless(&text)
    }

    fn parse_proc_wireless(text: &str) -> Option<WifiSignal> {
        // Two header lines, then one row per interface.
        for line in text.lines().skip(2) {
            let Some((_iface, rest)) = line.split_once(':') else {
                continue;
            };
            let f: Vec<&str> = rest.split_whitespace().collect();
            if f.len() < 4 {
                continue;
            }
            // Values carry a trailing '.' ("-40.") and are floats in the spec.
            let num = |s: &str| s.trim_end_matches('.').parse::<f64>().ok();
            let (Some(level), Some(noise)) = (num(f[2]), num(f[3])) else {
                continue;
            };
            if level == 0.0 {
                continue; // not associated
            }
            return Some(WifiSignal {
                rssi_dbm: level as i32,
                noise_dbm: noise as i32,
                // /proc/net/wireless has no bitrate; filled in by wifi_details.
                tx_rate_mbps: 0.0,
            });
        }
        None
    }

    /// Wi-Fi details, preferring `nmcli` over `iw`.
    ///
    /// `iw` is the obvious choice but is absent from a default Ubuntu install
    /// (only *suggested* by netplan-generator, which apt never pulls in) and
    /// from Fedora's Core group. NetworkManager ships in Fedora's Core and on
    /// every mainstream desktop, so `nmcli` reaches more machines — and it reads
    /// the scan cache unprivileged, where `iw scan` needs CAP_NET_ADMIN.
    pub async fn wifi_details() -> Option<WifiInfo> {
        let mut info = match nmcli_active().await {
            Some(info) => info,
            None => {
                let iface = wireless_iface()?;
                let out = tokio::process::Command::new("iw")
                    .args(["dev", &iface, "link"])
                    .output()
                    .await
                    .ok()?;
                if !out.status.success() {
                    return None;
                }
                parse_iw_link(&String::from_utf8_lossy(&out.stdout))?
            }
        };
        info.neighbours = scan_neighbours().await;
        Some(info)
    }

    /// The connected network, from NetworkManager's view.
    async fn nmcli_active() -> Option<WifiInfo> {
        let out = tokio::process::Command::new("nmcli")
            .args([
                "-t",
                "-f",
                "ACTIVE,SSID,CHAN,FREQ,SIGNAL,RATE",
                "device",
                "wifi",
                "list",
            ])
            .output()
            .await
            .ok()?;
        if !out.status.success() {
            return None;
        }
        parse_nmcli_active(&String::from_utf8_lossy(&out.stdout))
    }

    /// `nmcli -t` rows are colon-separated:
    /// "yes:my-network:36:5180 MHz:74:270 Mbit/s". Only the active row matters.
    fn parse_nmcli_active(text: &str) -> Option<WifiInfo> {
        for line in text.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 4 || f[0].trim() != "yes" {
                continue;
            }
            let channel: u16 = f[2].trim().parse().ok()?;
            let mhz: u32 = f[3].split_whitespace().next()?.parse().ok()?;
            let (_, band) = channel_from_freq(mhz)?;
            let mut info = WifiInfo {
                ssid: f[1].trim().to_string(),
                // nmcli exposes no channel width; 20MHz under-counts overlap
                // rather than inventing it.
                channel: format!("{channel} ({band}GHz, 20MHz)"),
                ..Default::default()
            };
            if let Some(rate) = f.get(5) {
                info.tx_rate = rate.trim().to_string();
            }
            return Some(info);
        }
        None
    }

    /// First interface listed in `/proc/net/wireless`.
    fn wireless_iface() -> Option<String> {
        let text = std::fs::read_to_string("/proc/net/wireless").ok()?;
        text.lines()
            .skip(2)
            .find_map(|l| l.split_once(':').map(|(n, _)| n.trim().to_string()))
    }

    /// Parse `iw dev <if> link`. Returns `None` when the radio is unassociated,
    /// where `iw` prints "Not connected.".
    fn parse_iw_link(text: &str) -> Option<WifiInfo> {
        if text.contains("Not connected") {
            return None;
        }
        let mut info = WifiInfo::default();
        let mut freq_mhz: Option<u32> = None;
        for line in text.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("SSID: ") {
                info.ssid = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("freq: ") {
                freq_mhz = v.split_whitespace().next()?.parse().ok();
            } else if let Some(v) = line.strip_prefix("signal: ") {
                info.rssi = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("tx bitrate: ") {
                info.tx_rate = v.trim().to_string();
                // "540.0 MBit/s VHT-MCS 7 80MHz ..." also carries the width.
                if let Some(w) = v.split_whitespace().find(|t| t.ends_with("MHz")) {
                    info.phy = w.to_string();
                }
            }
        }
        // iw reports frequency, not channel; the rest of octomon speaks the
        // "<channel> (<band>GHz, <width>MHz)" shape macOS uses.
        if let Some(mhz) = freq_mhz {
            let width = info
                .phy
                .strip_suffix("MHz")
                .and_then(|w| w.parse::<u16>().ok())
                .unwrap_or(20);
            if let Some((channel, band)) = channel_from_freq(mhz) {
                info.channel = format!("{channel} ({band}GHz, {width}MHz)");
            }
        }
        info.phy = String::new(); // width was borrowed above; PHY mode is not in `iw link`
        Some(info)
    }

    /// Map a centre frequency back to (channel, band in GHz).
    fn channel_from_freq(mhz: u32) -> Option<(u16, u16)> {
        match mhz {
            2412..=2484 => Some((((mhz - 2407) / 5) as u16, 2)),
            5000..=5895 => Some((((mhz - 5000) / 5) as u16, 5)),
            5955..=7115 => Some((((mhz - 5950) / 5) as u16, 6)),
            _ => None,
        }
    }

    /// Neighbouring networks from NetworkManager's cached scan results.
    async fn scan_neighbours() -> Vec<Neighbour> {
        let Ok(out) = tokio::process::Command::new("nmcli")
            .args(["-t", "-f", "CHAN,FREQ", "device", "wifi", "list"])
            .output()
            .await
        else {
            return Vec::new();
        };
        if !out.status.success() {
            return Vec::new();
        }
        parse_nmcli(&String::from_utf8_lossy(&out.stdout))
    }

    /// `nmcli -t` is colon-separated: "36:5180 MHz".
    fn parse_nmcli(text: &str) -> Vec<Neighbour> {
        text.lines()
            .filter_map(|line| {
                let mut f = line.split(':');
                let channel: u16 = f.next()?.trim().parse().ok()?;
                let mhz: u32 = f.next()?.split_whitespace().next()?.parse().ok()?;
                let (_, band_ghz) = channel_from_freq(mhz)?;
                // nmcli does not report channel width; 20MHz is the conservative
                // assumption — it under-counts overlap rather than inventing it.
                Some(Neighbour {
                    channel,
                    band_ghz,
                    width_mhz: 20,
                })
            })
            .collect()
    }

    /// Per-process network usage from `ss -tinp`: socket byte counters attributed
    /// to the owning process. Linux has no unprivileged per-process byte counter
    /// (`/proc/<pid>/net/dev` is namespace-wide, and nethogs/eBPF need root), so
    /// this sums TCP sockets instead. It therefore covers TCP only, and only the
    /// current user's processes.
    pub async fn proc_net_sample() -> Option<Vec<ProcSample>> {
        let out = tokio::process::Command::new("ss")
            .args(["-tinpH"])
            .stdin(std::process::Stdio::null())
            .output()
            .await
            .ok()?;
        let samples = parse_ss(&String::from_utf8_lossy(&out.stdout));
        if samples.is_empty() {
            None
        } else {
            Some(samples)
        }
    }

    /// Parse `ss -tinpH`. Each socket spans two lines: the address line carries
    /// `users:(("name",pid=123,fd=4))`, and the following line the tcp_info
    /// fields including `bytes_sent:`, `bytes_received:` and `retrans:a/b`.
    fn parse_ss(text: &str) -> Vec<ProcSample> {
        let mut by_pid: HashMap<u32, ProcSample> = HashMap::new();
        let mut current: Option<(u32, String)> = None;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            // An indented continuation line holds this socket's counters.
            let is_continuation = line.starts_with([' ', '\t']) && current.is_some();
            if is_continuation {
                let (pid, name) = current.clone().unwrap();
                let entry = by_pid.entry(pid).or_insert_with(|| ProcSample {
                    pid,
                    name,
                    bytes_in: 0,
                    bytes_out: 0,
                    retx: 0,
                });
                for tok in trimmed.split_whitespace() {
                    if let Some(v) = tok.strip_prefix("bytes_sent:") {
                        entry.bytes_out += v.parse().unwrap_or(0);
                    } else if let Some(v) = tok.strip_prefix("bytes_received:") {
                        entry.bytes_in += v.parse().unwrap_or(0);
                    } else if let Some(v) = tok.strip_prefix("retrans:") {
                        // "retrans:0/12" — cumulative total is after the slash.
                        let total = v.split('/').nth(1).unwrap_or("0");
                        entry.retx += total.parse().unwrap_or(0);
                    }
                }
                continue;
            }
            current = parse_ss_users(trimmed);
        }
        by_pid.into_values().collect()
    }

    /// Pull ("name", pid) out of `users:(("firefox",pid=1234,fd=56))`.
    fn parse_ss_users(line: &str) -> Option<(u32, String)> {
        let rest = line.split("users:((").nth(1)?;
        let name = rest.split('"').nth(1)?.to_string();
        let pid = rest.split("pid=").nth(1)?;
        let pid: u32 = pid
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .ok()?;
        Some((pid, name))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn proc_wireless_gives_signal_and_noise() {
            let text = "Inter-| sta-|   Quality        |   Discarded packets\n\
                        face | tus | link level noise |  nwid  crypt   frag\n\
                        wlp3s0: 0000   70.  -40.  -95.       0      0      0\n";
            let s = parse_proc_wireless(text).expect("associated");
            assert_eq!(s.rssi_dbm, -40);
            assert_eq!(s.noise_dbm, -95);
        }

        #[test]
        fn unassociated_radio_reports_nothing() {
            let text = "h1\nh2\nwlp3s0: 0000    0.    0.    0.       0      0      0\n";
            assert!(parse_proc_wireless(text).is_none());
        }

        #[test]
        fn iw_link_becomes_a_macos_shaped_channel() {
            let text = "Connected to 11:22:33:44:55:66 (on wlp3s0)\n\
                        \tSSID: my-network\n\
                        \tfreq: 5180\n\
                        \tsignal: -42 dBm\n\
                        \ttx bitrate: 540.0 MBit/s VHT-MCS 7 80MHz short GI\n";
            let info = parse_iw_link(text).expect("connected");
            assert_eq!(info.ssid, "my-network");
            assert_eq!(info.rssi, "-42 dBm");
            // 5180MHz is channel 36, and the width comes off the bitrate line.
            assert_eq!(info.channel, "36 (5GHz, 80MHz)");
            assert_eq!(info.channel_spec().unwrap().channel, 36);
        }

        #[test]
        fn unconnected_iw_link_is_none() {
            assert!(parse_iw_link("Not connected.\n").is_none());
        }

        #[test]
        fn frequencies_map_to_the_right_band() {
            assert_eq!(channel_from_freq(2412), Some((1, 2)));
            assert_eq!(channel_from_freq(2437), Some((6, 2)));
            assert_eq!(channel_from_freq(5180), Some((36, 5)));
            assert_eq!(channel_from_freq(5805), Some((161, 5)));
            assert_eq!(channel_from_freq(6135), Some((37, 6)));
            assert_eq!(channel_from_freq(1234), None);
        }

        #[test]
        fn nmcli_active_row_gives_ssid_and_channel() {
            let text = "no:neighbour-net:1:2412 MHz:47:130 Mbit/s\n\
                        yes:my-network:36:5180 MHz:74:270 Mbit/s\n\
                        no:other:161:5805 MHz:30:54 Mbit/s\n";
            let info = parse_nmcli_active(text).expect("an active row");
            assert_eq!(info.ssid, "my-network");
            assert_eq!(info.channel, "36 (5GHz, 20MHz)");
            assert_eq!(info.tx_rate, "270 Mbit/s");
            assert_eq!(info.channel_spec().unwrap().band_ghz, 5);
        }

        #[test]
        fn nmcli_with_no_active_network_falls_through() {
            assert!(parse_nmcli_active("no:a:1:2412 MHz:47:130 Mbit/s\n").is_none());
            assert!(parse_nmcli_active("").is_none());
        }

        #[test]
        fn nmcli_scan_becomes_neighbours() {
            let out = "1:2412 MHz\n36:5180 MHz\n161:5805 MHz\nbogus\n";
            let n = parse_nmcli(out);
            assert_eq!(n.len(), 3);
            assert_eq!((n[0].channel, n[0].band_ghz), (1, 2));
            assert_eq!((n[2].channel, n[2].band_ghz), (161, 5));
        }

        #[test]
        fn ss_output_is_attributed_per_process() {
            // Two sockets for one process, one for another.
            let text = "\
ESTAB 0 0 10.0.0.2:443 1.1.1.1:443 users:((\"firefox\",pid=100,fd=64))
\t cubic wscale:7,7 rtt:12.5/1.0 bytes_sent:1000 bytes_received:5000 retrans:0/3
ESTAB 0 0 10.0.0.2:80 2.2.2.2:80 users:((\"firefox\",pid=100,fd=65))
\t cubic rtt:9/1 bytes_sent:500 bytes_received:2500 retrans:0/1
ESTAB 0 0 10.0.0.2:22 3.3.3.3:22 users:((\"ssh\",pid=200,fd=3))
\t cubic rtt:30/2 bytes_sent:99 bytes_received:77
";
            let mut s = parse_ss(text);
            s.sort_by_key(|p| p.pid);
            assert_eq!(s.len(), 2);

            // Both of firefox's sockets fold into one process entry.
            assert_eq!(s[0].pid, 100);
            assert_eq!(s[0].name, "firefox");
            assert_eq!(s[0].bytes_out, 1500);
            assert_eq!(s[0].bytes_in, 7500);
            assert_eq!(s[0].retx, 4);

            assert_eq!(s[1].pid, 200);
            assert_eq!(s[1].name, "ssh");
            assert_eq!(s[1].retx, 0);
        }

        /// Verbatim `ss -tinpH` output from iproute2, so the parser is pinned to
        /// the real format rather than an idealised one. Note `retrans:` is
        /// absent here — ss omits it entirely when nothing has been retransmitted.
        #[test]
        fn real_ss_output_parses() {
            let text = concat!(
                "ESTAB 98322  0      172.17.0.3:42636 172.66.0.218:443 ",
                "users:((\"curl\",pid=254,fd=4))\n",
                "\t cubic wscale:7,7 rto:221 rtt:20.175/16.06 ato:40 mss:65483 ",
                "pmtu:65535 rcvmss:11584 advmss:65483 cwnd:10 bytes_sent:1786 ",
                "bytes_acked:1787 bytes_received:112531 segs_out:15 segs_in:24 ",
                "data_segs_out:3 data_segs_in:20 send 259659975bps lastsnd:3856 ",
                "lastrcv:3745 lastack:650 pacing_rate 519313512bps delivered:4 ",
                "app_limited rcv_rtt:69.727 rcv_space:65495 minrtt:0.069\n"
            );
            let s = parse_ss(text);
            assert_eq!(s.len(), 1);
            assert_eq!(s[0].name, "curl");
            assert_eq!(s[0].pid, 254);
            assert_eq!(s[0].bytes_out, 1786);
            // bytes_acked sits right next to bytes_sent and must not be read.
            assert_eq!(s[0].bytes_in, 112531);
            assert_eq!(s[0].retx, 0);
        }

        #[test]
        fn sockets_without_a_process_are_skipped() {
            // Without -p, or for another user's socket, there is no users:(()).
            let text = "ESTAB 0 0 10.0.0.2:443 1.1.1.1:443\n\t cubic bytes_sent:10\n";
            assert!(parse_ss(text).is_empty());
        }
    }
}
