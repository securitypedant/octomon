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

/// Append a record (best-effort; ignored on error).
pub fn append(rec: &SpeedRecord) {
    let Some(path) = path() else { return };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let (Ok(mut f), Ok(line)) = (
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path),
        serde_json::to_string(rec),
    ) {
        let _ = writeln!(f, "{line}");
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
    fn every_data_file_sits_under_the_one_directory() {
        // The history, the session logs and the directory itself were three
        // separate path derivations before; they must not drift apart again.
        let dir = data_dir().expect("a home directory");
        assert!(path().unwrap().starts_with(&dir));
        assert!(session_log_path().unwrap().starts_with(&dir));
    }
}
