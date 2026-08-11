//! Configuration.
//!
//! Loaded from `$XDG_CONFIG_HOME/octomon/config.toml` (default
//! `~/.config/octomon/config.toml`) on both macOS and Linux. On first run a
//! default file is written there so it can be edited.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// A single ICMP target.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Target {
    /// Human-readable label shown in the UI.
    pub label: String,
    /// IP address to ping.
    pub addr: IpAddr,
}

/// User-facing configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    /// Selected speed-test provider ("cloudflare", "mlab", "librespeed").
    pub speedtest_provider: String,
    /// Base URL for Cloudflare's speed-test endpoints.
    pub cloudflare_url: String,
    /// M-Lab locate service URL (returns a nearby NDT7 server).
    pub mlab_locate_url: String,
    /// Optional LibreSpeed backend base URL to force a specific server, e.g.
    /// "https://example.com/backend". When unset, a public server is picked
    /// automatically from `librespeed_server_list`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub librespeed_server: Option<String>,
    /// LibreSpeed public server-list URL (used when `librespeed_server` is unset).
    pub librespeed_server_list: String,
    /// Public-IP discovery endpoint (plain-text IP response). Added as a target
    /// on startup. Set to "" to disable.
    pub public_ip_url: String,
    /// How often each configured DNS resolver is probed, in milliseconds.
    pub dns_interval_ms: u64,
    /// Per-query DNS timeout, in milliseconds.
    pub dns_timeout_ms: u64,
    /// Name looked up when probing resolvers. A widely cached name measures what
    /// applications actually experience; something obscure measures recursion.
    pub dns_probe_name: String,
}

impl Default for Config {
    fn default() -> Self {
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
            speedtest_provider: "cloudflare".to_string(),
            cloudflare_url: "https://speed.cloudflare.com".to_string(),
            mlab_locate_url: "https://locate.measurementlab.net/v2/nearest/ndt/ndt7".to_string(),
            librespeed_server: None,
            librespeed_server_list: "https://librespeed.org/backend-servers/servers.json"
                .to_string(),
            public_ip_url: "https://api.ipify.org".to_string(),
            dns_interval_ms: 5000,
            dns_timeout_ms: 2000,
            dns_probe_name: "example.com".to_string(),
        }
    }
}

/// Parse a CLI target string: `"LABEL=IP"` or bare `"IP"` (label = the IP).
pub fn parse_target(s: &str) -> Result<Target, String> {
    let (label, ip) = match s.split_once('=') {
        Some((l, ip)) => (l.trim().to_string(), ip.trim()),
        None => (s.trim().to_string(), s.trim()),
    };
    let addr = ip
        .parse()
        .map_err(|_| format!("invalid IP in target '{s}'"))?;
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
    pub fn dns_interval(&self) -> Duration {
        Duration::from_millis(self.dns_interval_ms.max(500))
    }
    pub fn dns_timeout(&self) -> Duration {
        Duration::from_millis(self.dns_timeout_ms.max(100))
    }

    /// The config file path: `$XDG_CONFIG_HOME/octomon/config.toml`, or
    /// `~/.config/octomon/config.toml` (used on macOS as well as Linux).
    pub fn path() -> Option<PathBuf> {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| directories::BaseDirs::new().map(|b| b.home_dir().join(".config")))?;
        Some(base.join("octomon").join("config.toml"))
    }

    /// Load config, writing a default file on first run. Any read/parse problem
    /// falls back to defaults so the app always starts.
    pub fn load() -> Self {
        let Some(path) = Self::path() else {
            return Config::default();
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => match toml::from_str::<Config>(&text) {
                Ok(cfg) => cfg,
                Err(e) => {
                    tracing::warn!("failed to parse {}: {e}; using defaults", path.display());
                    Config::default()
                }
            },
            Err(_) => {
                // No file yet — write the defaults so the user has a starting point.
                let cfg = Config::default();
                if let Err(e) = cfg.write_to(&path) {
                    tracing::warn!("could not write default config to {}: {e}", path.display());
                }
                cfg
            }
        }
    }

    /// Update just the selected provider in the on-disk config (best-effort),
    /// preserving other settings.
    pub fn persist_provider(name: &str) {
        let Some(path) = Self::path() else { return };
        let mut cfg = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| toml::from_str::<Config>(&t).ok())
            .unwrap_or_default();
        cfg.speedtest_provider = name.to_string();
        let _ = cfg.write_to(&path);
    }

    fn write_to(&self, path: &PathBuf) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let body = toml::to_string_pretty(self).map_err(std::io::Error::other)?;
        let header = "# octomon configuration — edit and restart octomon.\n\
                      # Deleting this file regenerates it with defaults.\n\n";
        std::fs::write(path, format!("{header}{body}"))
    }
}
