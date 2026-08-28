//! Persistent speed-test history, appended as JSON Lines to the OS data dir
//! (`$XDG_DATA_HOME/octomon/speedtests.jsonl`, default `~/.local/share/...`;
//! `%LOCALAPPDATA%\octomon\speedtests.jsonl` on Windows).

use std::io::Write;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// One recorded speed-test result.
#[derive(Clone, Serialize, Deserialize)]
pub struct SpeedRecord {
    /// Unix timestamp (seconds).
    pub at: i64,
    pub provider: String,
    pub down_mbps: f64,
    pub up_mbps: f64,
    #[serde(default)]
    pub idle_ms: Option<f64>,
    #[serde(default)]
    pub loaded_ms: Option<f64>,
    /// The known network the test ran on — the location's user-given name,
    /// else its auto label (SSID / gateway address). A snapshot at test time:
    /// renaming the location later does not rewrite history. Absent in
    /// records from before the field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// How the machine was attached ("Wi-Fi (wireless)", "Ethernet (wired)"):
    /// the same LAN over a cable and over the radio are two different speed
    /// stories.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub medium: Option<String>,
    /// Which far end actually served the test: the Cloudflare edge colo, the
    /// LibreSpeed backend's listed name, the M-Lab machine. Two "LibreSpeed"
    /// rows an hour apart can be two different servers on two different
    /// continents — without this the history can't tell test-server variance
    /// from network variance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
}

impl SpeedRecord {
    /// Local time formatted for display, e.g. "08-09 15:42".
    pub fn when(&self) -> String {
        use chrono::{Local, TimeZone};
        Local
            .timestamp_opt(self.at, 0)
            .single()
            .map(|dt| dt.format("%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "—".to_string())
    }
}

/// Directory for octomon's own data files.
///
/// Unix keeps the XDG layout existing installs already use; moving it would
/// orphan people's speed-test history. Windows uses `%LOCALAPPDATA%` rather than
/// `%APPDATA%`: a growing JSONL and per-session CSVs are machine-local state,
/// not something worth dragging across a roaming profile.
pub fn data_dir() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| directories::BaseDirs::new().map(|b| b.home_dir().join(".local/share")))?;
        Some(base.join("octomon"))
    }
    #[cfg(not(unix))]
    {
        directories::BaseDirs::new().map(|b| b.data_local_dir().join("octomon"))
    }
}

/// Everything octomon writes about a network — SSIDs, MACs, gateway and public
/// addresses, the processes talking and who they talk to — is private to the
/// person running it, so every file it creates is owner-only and the
/// directories holding them are owner-only too. On unix that is an explicit
/// mode rather than whatever the umask happens to be, because the common
/// default (022) leaves a shared machine's other accounts able to read all of
/// it. Windows inherits the profile directory's ACL, which is already
/// restricted to the user, so there is nothing to set.
#[cfg(unix)]
pub const FILE_MODE: u32 = 0o600;
#[cfg(unix)]
pub const DIR_MODE: u32 = 0o700;

/// `create_dir_all`, then make the leaf owner-only.
pub fn create_dir_private(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // Best-effort: a directory we do not own (someone else's $XDG_DATA_HOME)
        // is not ours to re-permission, and failing here would cost the write.
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(DIR_MODE));
    }
    Ok(())
}

/// `OpenOptions` that creates owner-only files. The mode applies only when the
/// file is created, which is why [`tighten_permissions`] exists for the ones
/// written before this was the rule.
pub fn private_options() -> std::fs::OpenOptions {
    // Windows compiles the mode block out and never mutates this, so the
    // binding is only `mut` on unix — and `-D warnings` fails the build there
    // without saying so.
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut opts = std::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(FILE_MODE);
    }
    opts
}

/// `std::fs::write`, owner-only.
pub fn write_private(path: &std::path::Path, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut f = private_options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    f.write_all(contents.as_ref())
}

/// Re-permission everything octomon has already written. `OpenOptions::mode`
/// only applies at creation, so an install that predates owner-only files would
/// keep its world-readable history forever without a pass like this. Runs once
/// at startup, best-effort, and never recurses — the data and config
/// directories are flat.
#[cfg(unix)]
pub fn tighten_permissions() {
    use std::os::unix::fs::PermissionsExt as _;
    for dir in [data_dir(), crate::config::Config::dir()]
        .into_iter()
        .flatten()
    {
        if !dir.is_dir() {
            continue;
        }
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(DIR_MODE));
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(FILE_MODE));
            }
        }
    }
}

#[cfg(not(unix))]
pub fn tighten_permissions() {}

/// Where a support bundle ([D]) lands: somewhere the person at the keyboard
/// can actually find to attach to a message — the Desktop when the platform
/// has one, else the home directory. Stamped so repeats never overwrite.
pub fn bundle_path() -> Option<PathBuf> {
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let dirs = directories::UserDirs::new()?;
    let dir = dirs
        .desktop_dir()
        .map(|d| d.to_path_buf())
        .unwrap_or_else(|| dirs.home_dir().to_path_buf());
    Some(dir.join(format!("octomon-bundle-{stamp}.zip")))
}

/// Path for a new session log, named for the moment recording started.
pub fn session_log_path() -> Option<PathBuf> {
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    Some(data_dir()?.join(format!("octomon-{stamp}.csv")))
}

fn path() -> Option<PathBuf> {
    Some(data_dir()?.join("speedtests.jsonl"))
}

/// Where the network-change history persists between sessions.
fn net_history_path() -> Option<PathBuf> {
    Some(data_dir()?.join("net_history.jsonl"))
}

/// Append network changes (best-effort) — the verdict tick calls this with
/// whatever the collectors pushed since its last pass.
pub fn append_net_changes(changes: &[crate::app::NetChange]) {
    if changes.is_empty() {
        return;
    }
    let Some(path) = net_history_path() else {
        crate::errlog::log(
            "store",
            "no data directory — network history is not persisting",
        );
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = create_dir_private(dir);
    }
    let mut f = match private_options().create(true).append(true).open(&path) {
        Ok(f) => f,
        Err(e) => {
            crate::errlog::log(
                "store",
                format!(
                    "could not open {}: {e} — {} network changes not persisted",
                    path.display(),
                    changes.len()
                ),
            );
            return;
        }
    };
    for c in changes {
        if let Ok(line) = serde_json::to_string(c) {
            let _ = writeln!(f, "{line}");
        }
    }
}

/// The stored network history, oldest → newest, capped to what the pane
/// keeps. A file grown to several caps' worth is rewritten down to the tail
/// while we're here, so an always-on machine doesn't accrete an unbounded
/// log of DHCP renewals. Unparseable lines (older formats) are skipped.
pub fn load_net_history() -> std::collections::VecDeque<crate::app::NetChange> {
    let Some(path) = net_history_path() else {
        return Default::default();
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Default::default();
    };
    let all: Vec<crate::app::NetChange> = text
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let cap = crate::app::NET_HISTORY_CAP;
    let skip = all.len().saturating_sub(cap);
    let tail: std::collections::VecDeque<_> = all.into_iter().skip(skip).collect();
    if skip > cap * 3 {
        let mut out = String::new();
        for c in &tail {
            if let Ok(line) = serde_json::to_string(c) {
                out.push_str(&line);
                out.push('\n');
            }
        }
        let _ = write_private(&path, out);
    }
    tail
}

/// Delete the whole data directory — baselines, incident history, speed-test
/// history and session CSVs. The total-reset path; best-effort.
pub fn erase() {
    if let Some(dir) = data_dir() {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Append a record (best-effort; ignored on error, but logged — a speed test
/// that ran and then vanished from the history is exactly the sort of thing
/// nobody can reconstruct afterwards).
pub fn append(rec: &SpeedRecord) {
    let Some(path) = path() else {
        crate::errlog::log("store", "no data directory — speed test not saved");
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = create_dir_private(dir);
    }
    match (
        private_options().create(true).append(true).open(&path),
        serde_json::to_string(rec),
    ) {
        (Ok(mut f), Ok(line)) => {
            if let Err(e) = writeln!(f, "{line}") {
                crate::errlog::log("store", format!("speed test not saved: {e}"));
            }
        }
        (Err(e), _) => crate::errlog::log(
            "store",
            format!(
                "could not open {}: {e} — speed test not saved",
                path.display()
            ),
        ),
        (_, Err(e)) => crate::errlog::log("store", format!("speed test not serializable: {e}")),
    }
}

/// Remove one record from the history file (blocking file rewrite — call off
/// the lock). Matched on timestamp + provider + the speeds, first match only:
/// `at` alone can collide when two providers are raced in the same second.
pub fn forget(rec: &SpeedRecord) {
    let Some(path) = path() else { return };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return;
    };
    let mut removed = false;
    let kept: Vec<&str> = text
        .lines()
        .filter(|l| {
            if removed {
                return true;
            }
            let same = serde_json::from_str::<SpeedRecord>(l).is_ok_and(|r| {
                r.at == rec.at
                    && r.provider == rec.provider
                    && r.down_mbps == rec.down_mbps
                    && r.up_mbps == rec.up_mbps
            });
            removed |= same;
            !same
        })
        .collect();
    if removed {
        let mut out = kept.join("\n");
        if !out.is_empty() {
            out.push('\n');
        }
        let _ = write_private(&path, out);
    }
}

/// Load the most recent `n` records (oldest → newest), plus how many are stored
/// in total — the UI shows both, so "showing 500 of 812" stays honest when the
/// history outgrows what is kept in memory.
pub fn load_recent(n: usize) -> (Vec<SpeedRecord>, usize) {
    let Some(path) = path() else {
        return (Vec::new(), 0);
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return (Vec::new(), 0);
    };
    let mut recs: Vec<SpeedRecord> = text
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let total = recs.len();
    if recs.len() > n {
        recs.drain(0..recs.len() - n);
    }
    (recs, total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn the_unix_layout_has_not_moved() {
        // Existing installs must keep finding their history. A "more native"
        // ~/Library/Application Support on macOS would silently orphan it.
        let dir = data_dir().expect("a home directory");
        assert!(dir.ends_with("octomon"), "got {}", dir.display());
        assert!(path().unwrap().ends_with("octomon/speedtests.jsonl"));
    }

    #[test]
    fn history_lines_from_before_the_network_field_still_parse() {
        // speedtests.jsonl accumulates across versions; one unreadable line
        // shape would silently drop a person's whole older history.
        let legacy =
            r#"{"at":1700000000,"provider":"Cloudflare","down_mbps":953.2,"up_mbps":941.9}"#;
        let r: SpeedRecord = serde_json::from_str(legacy).expect("legacy line parses");
        assert_eq!(r.network, None);
        assert_eq!(r.medium, None);

        // And a full record round-trips with its network.
        let rec = SpeedRecord {
            at: 1_700_000_000,
            provider: "Cloudflare".into(),
            down_mbps: 104.3,
            up_mbps: 142.8,
            idle_ms: Some(15.0),
            loaded_ms: Some(232.0),
            network: Some("United WiFi".into()),
            medium: Some("Wi-Fi (wireless)".into()),
            server: Some("MIA (edge)".into()),
        };
        let back: SpeedRecord =
            serde_json::from_str(&serde_json::to_string(&rec).unwrap()).unwrap();
        assert_eq!(back.network.as_deref(), Some("United WiFi"));
        assert_eq!(back.medium.as_deref(), Some("Wi-Fi (wireless)"));
    }

    #[test]
    fn every_data_file_sits_under_the_one_directory() {
        // The history, the session logs and the directory itself were three
        // separate path derivations before; they must not drift apart again.
        let dir = data_dir().expect("a home directory");
        assert!(path().unwrap().starts_with(&dir));
        assert!(session_log_path().unwrap().starts_with(&dir));
    }
}
