//! Configuration: default + user-provided ICMP targets and timing knobs.
//!
//! Loaded from `~/.config/octomon/config.toml` (via `directories`) when present,
//! otherwise falls back to sensible defaults. Missing file is not an error.

use std::net::IpAddr;
use std::time::Duration;

use serde::Deserialize;

/// A single ICMP target.
#[derive(Clone, Debug, Deserialize)]
pub struct Target {
    /// Human-readable label shown in the UI.
    pub label: String,
    /// IP address to ping.
    pub addr: IpAddr,
}

/// User-facing configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Targets to probe with ICMP.
    pub targets: Vec<Target>,
    /// Ping interval in milliseconds.
    pub ping_interval_ms: u64,
    /// Per-probe timeout in milliseconds.
    pub ping_timeout_ms: u64,
    /// Sampling interval for throughput / vitals in milliseconds.
    pub sample_interval_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        // Defaults: the two anycast DNS resolvers from the README, plus a couple
        // of well-known unicast hosts for a broader picture.
        let t = |label: &str, ip: &str| Target {
            label: label.to_string(),
            addr: ip.parse().expect("valid default IP"),
        };
        Self {
            targets: vec![
                t("Cloudflare", "1.1.1.1"),
                t("Google", "8.8.8.8"),
                t("Quad9", "9.9.9.9"),
            ],
            ping_interval_ms: 1000,
            ping_timeout_ms: 1000,
            sample_interval_ms: 1000,
        }
    }
}

/// Parse a CLI target string: `"LABEL=IP"` or bare `"IP"` (label = the IP).
pub fn parse_target(s: &str) -> Result<Target, String> {
    let (label, ip) = match s.split_once('=') {
        Some((l, ip)) => (l.trim().to_string(), ip.trim()),
        None => (s.trim().to_string(), s.trim()),
    };
    let addr = ip.parse().map_err(|_| format!("invalid IP in target '{s}'"))?;
    Ok(Target { label, addr })
}

impl Config {
    pub fn ping_interval(&self) -> Duration {
        Duration::from_millis(self.ping_interval_ms)
    }
    pub fn ping_timeout(&self) -> Duration {
        Duration::from_millis(self.ping_timeout_ms)
    }
    pub fn sample_interval(&self) -> Duration {
        Duration::from_millis(self.sample_interval_ms)
    }

    /// Load config from the standard path, falling back to defaults. Returns the
    /// defaults (and logs) on any read/parse problem so the app always starts.
    pub fn load() -> Self {
        let Some(dirs) = directories::ProjectDirs::from("", "", "octomon") else {
            return Config::default();
        };
        let path = dirs.config_dir().join("config.toml");
        match std::fs::read_to_string(&path) {
            Ok(text) => match toml::from_str::<Config>(&text) {
                Ok(cfg) => cfg,
                Err(e) => {
                    tracing::warn!("failed to parse {}: {e}; using defaults", path.display());
                    Config::default()
                }
            },
            Err(_) => Config::default(), // no file → defaults, silently
        }
    }
}
