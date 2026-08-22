//! Configuration.
//!
//! Loaded from `$XDG_CONFIG_HOME/octomon/config.toml` (default
//! `~/.config/octomon/config.toml`) on both macOS and Linux, and from
//! `%APPDATA%\octomon\config.toml` on Windows. On first run a default file is
//! written there so it can be edited.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use ratatui::symbols::Marker;
use serde::{Deserialize, Serialize};

/// A single ICMP target.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Target {
    /// Human-readable label shown in the UI.
    pub label: String,
    /// IP address to ping.
    pub addr: IpAddr,
    /// The DNS name this target was added as, when it was one. A name gets
    /// re-resolved when the network changes and probed over HTTPS with real
    /// SNI — properties a bare IP cannot have, and worth keeping across
    /// restarts for targets saved from the [a] prompt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
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
    /// Address (or hostname) traced at startup to find the gateway and the next
    /// few hops toward the internet, which are added as targets. Pick something
    /// reliably reachable and beyond your ISP. Set to "" to disable discovery.
    pub discovery_probe: String,
    /// How often each configured DNS resolver is probed, in milliseconds.
    pub dns_interval_ms: u64,
    /// Per-query DNS timeout, in milliseconds.
    pub dns_timeout_ms: u64,
    /// Name looked up when probing resolvers. A widely cached name measures what
    /// applications actually experience; something obscure measures recursion.
    /// Once a minute a random name *under* it is also queried; an address back
    /// for a name that cannot exist means the resolver redirects misses.
    pub dns_probe_name: String,
    /// A public resolver probed alongside the system ones for contrast: yours
    /// failing while it works means "change DNS"; it failing while yours work
    /// means this network forces its own DNS. Set to "" to disable.
    pub dns_reference_resolver: String,
    /// HTTP connectivity-check endpoint: "auto" uses this OS's own (Apple /
    /// Microsoft / Ubuntu — the machine already polls it, so octomon adds no
    /// new party learning it is online); or name one of "apple", "microsoft",
    /// "ubuntu", "cloudflare", "google". A failing answer is verified against a
    /// second, independent provider before any finding is raised.
    pub http_probe_provider: String,
    /// How often the HTTP reachability probe runs, in milliseconds.
    pub http_probe_interval_ms: u64,
    /// Time server asked (once at startup, then every 15 min) whether the
    /// system clock is right — a wrong clock breaks every HTTPS site while
    /// ping and DNS look perfect. Set to "" to disable.
    pub ntp_server: String,
    /// Host whose QUIC port answers the path-MTU probe's version-negotiation
    /// packets — must speak QUIC on 443 (Cloudflare and Google resolvers do).
    /// Set to "" to disable the probe.
    pub pmtu_probe_host: String,
    /// The [c] egress scan: which ports/protocols to try, each against a host
    /// that reliably answers. Edit to add your own (a VPN endpoint, a work
    /// server); `proto` is "tcp", or "dns" / "ntp" / "quic" for a UDP exchange.
    pub egress_checks: Vec<crate::collectors::egress::EgressCheck>,
    /// Whether the first-run explainer has been shown (set automatically).
    pub explainer_seen: bool,
    /// Glyphs used to plot chart lines: "auto", "braille", "halfblock" or
    /// "dot".
    ///
    /// Braille packs 2x4 dots into one cell and is what the charts are drawn
    /// around, but those glyphs are missing from the raster fonts a legacy
    /// Windows console still defaults to, where every plotted point comes out
    /// as an empty box. "halfblock" gives up half the vertical resolution for
    /// glyphs that render essentially anywhere. "auto" picks braille except on
    /// a legacy Windows console.
    pub graph_marker: String,
    /// Glyphs the bar graphs (bandwidth, CPU, per-hop sparklines) are built
    /// from: "auto", "fine" or "coarse".
    ///
    /// The fine set resolves eight levels per cell with the eighth-block
    /// glyphs (▁▂▃…), but the fonts a legacy Windows console offers (Consolas
    /// included) carry only the half and full blocks, so every bar tip comes
    /// out as an empty box. "coarse" sticks to those two glyphs; "auto" picks
    /// fine unless this is a legacy Windows console whose current font
    /// really lacks the glyphs (the font itself is asked, so a conhost set
    /// to Cascadia Mono keeps the fine set).
    pub bar_glyphs: String,
}

/// Two-level bar glyphs for consoles whose fonts lack the eighth-blocks.
/// Unlike ratatui's own three-level set this keeps `one_eighth` visible: the
/// bandwidth traces promise that any non-zero sample shows at least one
/// sub-cell, and a blank there would break that.
const COARSE_BARS: ratatui::symbols::bar::Set<'static> = ratatui::symbols::bar::Set {
    full: ratatui::symbols::bar::FULL,
    seven_eighths: ratatui::symbols::bar::FULL,
    three_quarters: ratatui::symbols::bar::HALF,
    five_eighths: ratatui::symbols::bar::HALF,
    half: ratatui::symbols::bar::HALF,
    three_eighths: ratatui::symbols::bar::HALF,
    one_quarter: ratatui::symbols::bar::HALF,
    one_eighth: ratatui::symbols::bar::HALF,
    empty: " ",
};

/// True on the legacy Windows console (conhost) — the host an elevated
/// PowerShell or cmd typically opens in. Windows Terminal sets WT_SESSION,
/// and other modern emulators and unix-ish environments set TERM or
/// TERM_PROGRAM (ConEmu sets ConEmuANSI); conhost sets none of them.
fn legacy_windows_console() -> bool {
    cfg!(windows)
        && std::env::var_os("WT_SESSION").is_none()
        && std::env::var_os("TERM_PROGRAM").is_none()
        && std::env::var_os("TERM").is_none()
        && std::env::var_os("ConEmuANSI").is_none()
}

/// The glyphs the fine bar set needs beyond the universal half/full blocks.
const BAR_PROBE: [char; 6] = ['▁', '▂', '▃', '▅', '▆', '▇'];
/// A sample of the braille range the line charts plot with.
const MARKER_PROBE: [char; 2] = ['⠁', '⣿'];

/// Whether an "auto" glyph setting must fall back to the plainer set: only
/// ever on a legacy Windows console, and even there the console's actual
/// font gets the last word when it can be asked — someone who pointed
/// conhost at Cascadia Mono has the glyphs and deserves the fine set. When
/// the font cannot be asked (output redirected, a raster font), missing is
/// assumed: the coarse sets render anywhere, tofu does not.
fn auto_needs_fallback(probe: &[char]) -> bool {
    if !legacy_windows_console() {
        return false;
    }
    #[cfg(windows)]
    {
        crate::platform::console_font_has_glyphs(probe) != Some(true)
    }
    #[cfg(not(windows))]
    {
        let _ = probe;
        true // unreachable: legacy_windows_console() is false off Windows
    }
}

impl Default for Config {
    fn default() -> Self {
        let t = |label: &str, ip: &str| Target {
            label: label.to_string(),
            addr: ip.parse().expect("valid default IP"),
            host: None,
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
            discovery_probe: "1.1.1.1".to_string(),
            dns_interval_ms: 5000,
            dns_timeout_ms: 2000,
            dns_probe_name: "example.com".to_string(),
            dns_reference_resolver: "1.1.1.1".to_string(),
            http_probe_provider: "auto".to_string(),
            http_probe_interval_ms: 12_000,
            ntp_server: "time.cloudflare.com".to_string(),
            pmtu_probe_host: "1.1.1.1".to_string(),
            egress_checks: crate::collectors::egress::default_checks(),
            explainer_seen: false,
            graph_marker: "auto".to_string(),
            bar_glyphs: "auto".to_string(),
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
    Ok(Target {
        label,
        addr,
        host: None,
    })
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
    pub fn http_probe_interval(&self) -> Duration {
        Duration::from_millis(self.http_probe_interval_ms.max(2000))
    }

    /// Chart marker, falling back to auto for an unrecognised value rather
    /// than refusing to start over a cosmetic setting.
    pub fn marker(&self) -> Marker {
        match self.graph_marker.trim().to_ascii_lowercase().as_str() {
            "halfblock" | "half_block" | "half-block" => Marker::HalfBlock,
            "dot" => Marker::Dot,
            "block" => Marker::Block,
            "bar" => Marker::Bar,
            "braille" => Marker::Braille,
            _ if auto_needs_fallback(&MARKER_PROBE) => Marker::HalfBlock,
            _ => Marker::Braille,
        }
    }

    /// Sparkline bar glyphs, resolved the same way as [`Config::marker`]:
    /// an explicit "fine"/"coarse" is honoured, anything else auto-detects.
    pub fn bar_set(&self) -> ratatui::symbols::bar::Set<'static> {
        match self.bar_glyphs.trim().to_ascii_lowercase().as_str() {
            "fine" => ratatui::symbols::bar::NINE_LEVELS,
            "coarse" => COARSE_BARS,
            _ if auto_needs_fallback(&BAR_PROBE) => COARSE_BARS,
            _ => ratatui::symbols::bar::NINE_LEVELS,
        }
    }

    /// The config file path.
    pub fn path() -> Option<PathBuf> {
        Some(Self::dir()?.join("config.toml"))
    }

    /// Where an exported event timeline goes: beside the config, named for the
    /// moment of export, so repeated exports never overwrite one another.
    pub fn events_export_path() -> Option<PathBuf> {
        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
        Some(Self::dir()?.join(format!("events-{stamp}.csv")))
    }

    /// octomon's config directory.
    ///
    /// Unix keeps the XDG layout octomon has always used — on macOS as well as
    /// Linux. `~/Library/Application Support` would be more Apple-native, and
    /// would silently orphan every config already on disk, so it is
    /// deliberately not done. Windows has no such history and gets `%APPDATA%`.
    fn dir() -> Option<PathBuf> {
        #[cfg(unix)]
        {
            let base = std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .or_else(|| directories::BaseDirs::new().map(|b| b.home_dir().join(".config")))?;
            Some(base.join("octomon"))
        }
        #[cfg(not(unix))]
        {
            // BaseDirs::config_dir() is %APPDATA% (Roaming). ProjectDirs would
            // add a redundant qualifier/organisation path plus a `config`
            // segment, where this mirrors the unix shape one-for-one.
            directories::BaseDirs::new().map(|b| b.config_dir().join("octomon"))
        }
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
        Self::update_on_disk(|cfg| cfg.speedtest_provider = name.to_string());
    }

    /// Record that the first-run explainer has been shown (best-effort).
    pub fn persist_explainer_seen() {
        Self::update_on_disk(|cfg| cfg.explainer_seen = true);
    }

    /// Remember a target added from the [a] prompt, so it is probed on every
    /// start. Discovered targets (gateway, hops) never reach the file.
    pub fn persist_target_added(label: &str, addr: IpAddr, host: Option<&str>) {
        Self::update_on_disk(|cfg| {
            if cfg.targets.iter().any(|t| t.addr == addr) {
                return;
            }
            cfg.targets.push(Target {
                label: label.to_string(),
                addr,
                host: host.map(str::to_string),
            });
        });
    }

    /// Forget a deleted target — including a default one: deleting Google and
    /// finding it back at the next start would read as the delete not working.
    pub fn persist_target_removed(addr: IpAddr) {
        Self::update_on_disk(|cfg| cfg.targets.retain(|t| t.addr != addr));
    }

    /// Read-modify-write one field of the on-disk config, preserving the rest.
    fn update_on_disk(mutate: impl FnOnce(&mut Config)) {
        let Some(path) = Self::path() else { return };
        let mut cfg = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| toml::from_str::<Config>(&t).ok())
            .unwrap_or_default();
        mutate(&mut cfg);
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

#[cfg(test)]
mod path_tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn the_unix_layout_has_not_moved() {
        // Existing installs must keep finding their config; see `dir`.
        let p = Config::path().expect("a home directory");
        assert!(p.ends_with("octomon/config.toml"), "got {}", p.display());
    }

    #[test]
    fn the_config_file_sits_in_the_config_directory() {
        let dir = Config::dir().expect("a home directory");
        assert!(Config::path().unwrap().starts_with(&dir));
    }

    #[test]
    fn the_graph_marker_falls_back_rather_than_failing() {
        let with = |v: &str| Config {
            graph_marker: v.to_string(),
            ..Config::default()
        };
        // What "auto" resolves to depends on where the tests run (a legacy
        // Windows console gets halfblock), so assert against the same probe.
        let auto = if auto_needs_fallback(&MARKER_PROBE) {
            Marker::HalfBlock
        } else {
            Marker::Braille
        };
        assert_eq!(Config::default().marker(), auto);
        // An explicit choice is never second-guessed by the detection.
        assert_eq!(with("braille").marker(), Marker::Braille);
        assert_eq!(with("halfblock").marker(), Marker::HalfBlock);
        assert_eq!(with("HalfBlock").marker(), Marker::HalfBlock);
        assert_eq!(with("half-block").marker(), Marker::HalfBlock);
        assert_eq!(with(" dot ").marker(), Marker::Dot);
        // A typo in a cosmetic setting must not stop octomon starting.
        assert_eq!(with("brailel").marker(), auto);
        assert_eq!(with("").marker(), auto);
    }

    /// Saved name-targets keep their hostname across a config round-trip,
    /// and config files from before the `host` key still parse.
    #[test]
    fn saved_targets_round_trip_with_their_hostname() {
        let mut cfg = Config::default();
        cfg.targets.push(Target {
            label: "bbc.co.uk".into(),
            addr: "151.101.0.81".parse().unwrap(),
            host: Some("bbc.co.uk".into()),
        });
        let text = toml::to_string_pretty(&cfg).unwrap();
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(
            back.targets.last().unwrap().host.as_deref(),
            Some("bbc.co.uk")
        );
        // Defaults carry no host and must not serialise one.
        assert!(back.targets[0].host.is_none());

        let legacy = "[[targets]]\nlabel = \"Cloudflare\"\naddr = \"1.1.1.1\"\n";
        let back: Config = toml::from_str(legacy).unwrap();
        assert!(back.targets[0].host.is_none());
    }

    #[test]
    fn the_bar_glyphs_stay_within_what_a_console_font_has() {
        let with = |v: &str| Config {
            bar_glyphs: v.to_string(),
            ..Config::default()
        };
        assert_eq!(with("fine").bar_set(), ratatui::symbols::bar::NINE_LEVELS);
        let coarse = with(" Coarse ").bar_set();
        // Only the glyphs every console font carries — the eighth-blocks are
        // exactly what a legacy Windows console cannot draw.
        for g in [
            coarse.full,
            coarse.seven_eighths,
            coarse.three_quarters,
            coarse.five_eighths,
            coarse.half,
            coarse.three_eighths,
            coarse.one_quarter,
            coarse.one_eighth,
            coarse.empty,
        ] {
            assert!(matches!(g, "█" | "▄" | " "), "unsafe glyph {g:?}");
        }
        // The bandwidth traces promise any non-zero sample stays visible.
        assert_ne!(coarse.one_eighth, " ");
        // "auto" and typos resolve by detection, and must agree.
        let auto = if auto_needs_fallback(&BAR_PROBE) {
            COARSE_BARS
        } else {
            ratatui::symbols::bar::NINE_LEVELS
        };
        assert_eq!(Config::default().bar_set(), auto);
        assert_eq!(with("nonsense").bar_set(), auto);
    }
}
