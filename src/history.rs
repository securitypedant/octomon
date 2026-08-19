//! Per-network incident history, kept across sessions.
//!
//! Baselines remember what *normal* looks like on a network; this remembers
//! what went *wrong* there and when. A one-off run can show that the line is
//! bad right now; only history can show that it is bad every evening from
//! eight to eleven — the most common ISP complaint, and the one a single
//! snapshot can never prove. It also gives the doctor report an availability
//! figure ("3 outages, 4m 12s down this week") that people paste into tickets.
//!
//! What is stored is small: one line per *finished* episode of a Degraded or
//! Down finding — the cause, the summary, when it started and how long it
//! lasted — keyed by the network fingerprint the baselines use. Nothing is
//! written for an episode still in progress; the live view has that. The file
//! is `history.jsonl` beside `baselines.json`, pruned to 90 days on read.

use std::io::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::verdict::{Cause, Severity};

/// How long to keep episodes.
const RETAIN_DAYS: i64 = 90;
/// The summary window the doctor and overlays talk about.
pub const WINDOW_DAYS: i64 = 7;

/// One finished episode.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Episode {
    /// The network's baseline key.
    pub network: String,
    /// Unix seconds when the finding raised.
    pub at: i64,
    pub duration_secs: u64,
    /// `Cause::label()`.
    pub cause: String,
    /// `Severity::label()`.
    pub severity: String,
    pub summary: String,
}

impl Episode {
    pub fn is_down(&self) -> bool {
        self.severity == Severity::Down.label()
    }
    /// Episodes that are the *connection* failing, as opposed to a caveat
    /// (machine load) or a single destination.
    pub fn is_connectivity(&self) -> bool {
        matches!(
            self.cause.as_str(),
            "no-link"
                | "captive-portal"
                | "gateway"
                | "link"
                | "dns"
                | "isp"
                | "internet"
                | "http-blocked"
        )
    }
    pub fn cause_word(&self) -> &str {
        match self.cause.as_str() {
            "no-link" => "link down",
            "captive-portal" => "captive portal",
            "gateway" => "gateway",
            "link" => "Wi-Fi/link",
            "dns" => "DNS",
            "dns-hijack" => "DNS hijack",
            "isp" => "ISP path",
            "internet" => "internet",
            "ipv6" => "IPv6",
            "path-mtu" => "path MTU",
            "http-blocked" => "web blocked",
            "web-target" => "web target",
            "destination" => "destination",
            "bufferbloat" => "bufferbloat",
            "clock" => "clock",
            "machine" => "machine",
            other => other,
        }
    }
}

fn path() -> Option<PathBuf> {
    crate::store::data_dir().map(|d| d.join("history.jsonl"))
}

/// Append one finished episode (best-effort; ignored on error).
pub fn append(ep: &Episode) {
    let Some(p) = path() else { return };
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let (Ok(mut f), Ok(line)) = (
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p),
        serde_json::to_string(ep),
    ) {
        let _ = writeln!(f, "{line}");
    }
}

/// Every retained episode, oldest first. Lines that fail to parse are
/// skipped; episodes older than the retention window are dropped and, when
/// any were, the file is rewritten without them.
pub fn load() -> Vec<Episode> {
    let Some(p) = path() else {
        return Vec::new();
    };
    let Ok(text) = std::fs::read_to_string(&p) else {
        return Vec::new();
    };
    let cutoff = chrono::Utc::now().timestamp() - RETAIN_DAYS * 86_400;
    let all: Vec<Episode> = text
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let kept: Vec<Episode> = all.iter().filter(|e| e.at >= cutoff).cloned().collect();
    if kept.len() != all.len() {
        let body: String = kept
            .iter()
            .filter_map(|e| serde_json::to_string(e).ok())
            .map(|l| l + "\n")
            .collect();
        let _ = std::fs::write(&p, body);
    }
    kept
}

/// Something worth saying about one network's recent history.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Summary {
    pub days: i64,
    /// Connectivity episodes (link, gateway, DNS, ISP, internet, web blocked).
    pub episodes: usize,
    /// Of those, how many were Down.
    pub outages: usize,
    pub down_secs: u64,
    pub degraded_secs: u64,
    /// The three-hour window (start hour, local) holding the most episode
    /// starts, when episodes cluster there — "evenings 20–23h".
    pub cluster: Option<(u32, usize)>,
    /// Cause → count, most frequent first.
    pub by_cause: Vec<(String, usize)>,
}

impl Summary {
    /// One line for the overlay / doctor: "7d: 3 outages · 4m 12s down · 9
    /// degraded episodes · clusters 20–23h".
    pub fn line(&self) -> String {
        if self.episodes == 0 {
            return format!("{}d: no connectivity incidents recorded", self.days);
        }
        let mut parts: Vec<String> = Vec::new();
        if self.outages > 0 {
            parts.push(format!(
                "{} outage{} · {} down",
                self.outages,
                if self.outages == 1 { "" } else { "s" },
                crate::verdict::fmt_duration(std::time::Duration::from_secs(self.down_secs))
            ));
        }
        let degraded = self.episodes - self.outages;
        if degraded > 0 {
            parts.push(format!(
                "{} degraded episode{} ({})",
                degraded,
                if degraded == 1 { "" } else { "s" },
                crate::verdict::fmt_duration(std::time::Duration::from_secs(self.degraded_secs))
            ));
        }
        if let Some((hour, n)) = self.cluster {
            parts.push(format!(
                "{n} of {} start {:02}–{:02}h",
                self.episodes,
                hour,
                (hour + 3) % 24
            ));
        }
        if let Some((cause, n)) = self.by_cause.first() {
            parts.push(format!("mostly {cause} ({n})"));
        }
        format!("{}d: {}", self.days, parts.join(" · "))
    }
}

/// Summarise `episodes` for `network` over the last `days`.
pub fn summarise(episodes: &[Episode], network: &str, days: i64) -> Summary {
    use chrono::{Local, TimeZone, Timelike};
    let since = chrono::Utc::now().timestamp() - days * 86_400;
    let mine: Vec<&Episode> = episodes
        .iter()
        .filter(|e| e.network == network && e.at >= since && e.is_connectivity())
        .collect();
    let mut s = Summary {
        days,
        episodes: mine.len(),
        ..Default::default()
    };
    let mut hours = [0usize; 24];
    let mut causes: std::collections::HashMap<&str, usize> = Default::default();
    for e in &mine {
        if e.is_down() {
            s.outages += 1;
            s.down_secs += e.duration_secs;
        } else {
            s.degraded_secs += e.duration_secs;
        }
        if let Some(dt) = Local.timestamp_opt(e.at, 0).single() {
            hours[dt.hour() as usize] += 1;
        }
        *causes.entry(e.cause_word()).or_default() += 1;
    }
    // Clustering: the best three-hour window, if it holds at least three
    // episodes and 40% of them — otherwise the timing is unremarkable.
    if s.episodes >= 3 {
        let (best_start, best_n) = (0..24u32)
            .map(|h| {
                let n: usize = (0..3).map(|k| hours[((h + k) % 24) as usize]).sum();
                (h, n)
            })
            .max_by_key(|(_, n)| *n)
            .unwrap_or((0, 0));
        if best_n >= 3 && best_n * 10 >= s.episodes * 4 {
            s.cluster = Some((best_start, best_n));
        }
    }
    let mut by_cause: Vec<(String, usize)> = causes
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    by_cause.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    s.by_cause = by_cause;
    s
}

/// A finished finding as an episode, or `None` when it isn't worth keeping
/// (Info-class, or no network to key it to).
pub fn episode_from(
    network: Option<&str>,
    cause: Cause,
    severity: Severity,
    summary: &str,
    started_at: i64,
    duration: std::time::Duration,
) -> Option<Episode> {
    if severity < Severity::Degraded {
        return None;
    }
    Some(Episode {
        network: network?.to_string(),
        at: started_at,
        duration_secs: duration.as_secs(),
        cause: cause.label().to_string(),
        severity: severity.label().to_string(),
        summary: summary.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(network: &str, at: i64, secs: u64, cause: &str, sev: Severity) -> Episode {
        Episode {
            network: network.into(),
            at,
            duration_secs: secs,
            cause: cause.into(),
            severity: sev.label().into(),
            summary: String::new(),
        }
    }

    #[test]
    fn a_summary_counts_outages_and_downtime_for_one_network_only() {
        let now = chrono::Utc::now().timestamp();
        let eps = vec![
            ep("home", now - 3600, 120, "gateway", Severity::Down),
            ep("home", now - 7200, 60, "internet", Severity::Down),
            ep("home", now - 9000, 300, "dns", Severity::Degraded),
            ep("home", now - 9500, 30, "machine", Severity::Degraded), // caveat: not counted
            ep("office", now - 100, 999, "internet", Severity::Down),
            ep("home", now - 30 * 86_400, 999, "internet", Severity::Down), // outside 7d
        ];
        let s = summarise(&eps, "home", 7);
        assert_eq!(s.episodes, 3);
        assert_eq!(s.outages, 2);
        assert_eq!(s.down_secs, 180);
        assert_eq!(s.degraded_secs, 300);
        assert!(s.line().contains("2 outages · 3m 00s down"), "{}", s.line());
        assert_eq!(summarise(&eps, "cafe", 7).episodes, 0);
        assert!(
            summarise(&eps, "cafe", 7)
                .line()
                .contains("no connectivity incidents")
        );
    }

    #[test]
    fn evening_episodes_are_called_a_cluster() {
        use chrono::{Local, TimeZone};
        // Six episodes, four of them at 21:00-ish local on different days.
        let mut eps = Vec::new();
        for day in 1..=4 {
            let at = Local
                .with_ymd_and_hms(2026, 8, 10 + day, 21, 15, 0)
                .single()
                .unwrap()
                .timestamp();
            eps.push(ep("home", at, 60, "internet", Severity::Degraded));
        }
        for (day, hour) in [(1, 9), (2, 14)] {
            let at = Local
                .with_ymd_and_hms(2026, 8, 10 + day, hour, 0, 0)
                .single()
                .unwrap()
                .timestamp();
            eps.push(ep("home", at, 60, "internet", Severity::Degraded));
        }
        // Summarise "as of" a window that contains those days.
        let s = summarise(&eps, "home", 3650);
        let (start, n) = s.cluster.expect("a cluster");
        assert_eq!(n, 4);
        assert!((19..=21).contains(&start), "window starting {start}");
        assert!(s.line().contains("4 of 6 start"), "{}", s.line());
    }

    #[test]
    fn only_degraded_or_worse_becomes_an_episode() {
        let d = std::time::Duration::from_secs(10);
        assert!(episode_from(Some("k"), Cause::Machine, Severity::Info, "x", 0, d).is_none());
        assert!(episode_from(None, Cause::GatewayLan, Severity::Down, "x", 0, d).is_none());
        let e = episode_from(Some("k"), Cause::GatewayLan, Severity::Down, "x", 5, d).unwrap();
        assert_eq!(e.cause, "gateway");
        assert!(e.is_down() && e.is_connectivity());
    }
}
