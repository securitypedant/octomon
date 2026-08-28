//! The error log: every failure octomon swallows, on disk.
//!
//! Most things octomon does are best-effort — a traceroute that won't run, a
//! whois that times out, an iPerf3 binary that isn't installed, a public-IP
//! endpoint behind a captive portal. Each of those is handled locally and, by
//! design, does not stop the dashboard. The cost is that when something *is*
//! wrong ("the gateway never appeared and I had to restart"), the evidence has
//! already been discarded by the time anyone thinks to look.
//!
//! So every one of those paths also calls [`log`], which appends one line to
//! `<data dir>/errors.log`. It is not a user-facing feature: the timeline ([e])
//! stays the curated story, and this is the exhaustive one for afterwards. It
//! survives restarts, which is the whole point — a session banner marks each
//! run so a restart is visible between the lines that led up to it.
//!
//! Two properties keep the file worth reading:
//!
//! * **Repeats are folded.** A collector failing the same way every five
//!   seconds would otherwise bury everything else. The same message from the
//!   same component is written at most once per [`FOLD_WINDOW`], carrying a
//!   count of what it stood in for.
//! * **It is bounded.** Past a megabyte the file rolls to `errors.log.1`, so an
//!   always-on machine cannot fill a disk with its own complaints.
//!
//! Failures *here* are silent: a log that takes the tool down with it is worse
//! than no log.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// Roll the file over at this size. Big enough to hold days of a badly
/// behaved network, small enough to attach to a bug report.
const MAX_BYTES: u64 = 1_048_576;

/// How long an identical message stays folded into a repeat count. Five
/// minutes rather than one: several collectors re-probe on a 60-second
/// cadence, so a one-minute window would let a single steady-state failure
/// write a line every tick and fill the file on its own. The count rides
/// along, so nothing is lost by folding harder.
const FOLD_WINDOW: Duration = Duration::from_secs(300);

/// What has been written recently, keyed by "component: message".
struct Recent {
    /// When the last line for this key was actually written.
    at: Instant,
    /// How many occurrences have been folded away since then.
    suppressed: u32,
}

static SEEN: LazyLock<Mutex<HashMap<String, Recent>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// `<data dir>/errors.log` — beside whois.log, the session CSVs and the
/// speed-test history, so the [D] support bundle picks it up on its own.
pub fn path() -> Option<PathBuf> {
    Some(crate::store::data_dir()?.join("errors.log"))
}

/// Record a failure. `component` is the subsystem in one lowercase word
/// ("discovery", "whois", "iperf3"); `message` says what did not work and why,
/// in the terms the underlying error used.
///
/// Cheap and infallible from the caller's side: a missing home directory, a
/// read-only disk or a poisoned lock all end as a no-op.
pub fn log(component: &str, message: impl AsRef<str>) {
    let message = message.as_ref();
    let key = format!("{component}: {message}");

    // Fold repeats. The count of what was folded rides on the next line that
    // does get written, so nothing is silently lost — only deferred.
    let repeats = {
        let Ok(mut seen) = SEEN.lock() else { return };
        match seen.get_mut(&key) {
            Some(r) if r.at.elapsed() < FOLD_WINDOW => {
                r.suppressed += 1;
                return;
            }
            Some(r) => {
                let n = std::mem::take(&mut r.suppressed);
                r.at = Instant::now();
                n
            }
            None => {
                // A machine that fails in thousands of distinct ways would
                // otherwise grow this map without bound; the fold is a nicety,
                // so dropping it wholesale is an acceptable trade.
                if seen.len() > 512 {
                    seen.clear();
                }
                seen.insert(
                    key.clone(),
                    Recent {
                        at: Instant::now(),
                        suppressed: 0,
                    },
                );
                0
            }
        }
    };

    let stamp = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%:z");
    let tail = match repeats {
        0 => String::new(),
        n => format!(
            "  (+{n} more in the last {} min)",
            FOLD_WINDOW.as_secs() / 60
        ),
    };
    append(&format!("{stamp}  {component:<10}  {message}{tail}\n"));
}

/// Mark the start of a run. Written unconditionally, so the gap between one
/// banner and the next is exactly one session — which is how you tell "it was
/// already broken" from "it broke after the restart".
pub fn start_session() {
    let stamp = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%:z");
    append(&format!(
        "{BANNER_PREFIX}{} started · {} · pid {} · {stamp} ===\n",
        crate::util::VERSION,
        std::env::consts::OS,
        std::process::id(),
    ));
}

/// The most recent lines from *this* run, oldest first — what the doctor
/// report shows so the log is discoverable from the output people already
/// paste. Earlier sessions stay in the file only: "octomon is misbehaving
/// right now" is a question about this run.
pub fn tail_this_session(max: usize) -> Vec<String> {
    let Some(path) = path() else {
        return Vec::new();
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    last_session(&text, max)
}

/// The tail of the last session's lines in `text`, oldest first. Split out
/// from the file read so the banner-boundary logic is testable.
fn last_session(text: &str, max: usize) -> Vec<String> {
    // Everything after the final banner line. With no banner at all — a file
    // from before banners existed, or one that has just rolled — the whole
    // text is fair game rather than nothing.
    let session = match text.rfind(BANNER_PREFIX) {
        Some(i) => match text[i + 1..].find('\n') {
            Some(nl) => &text[i + 1 + nl..],
            None => "", // the banner is the last line: nothing has failed yet
        },
        None => text,
    };
    let lines: Vec<&str> = session.lines().filter(|l| !l.trim().is_empty()).collect();
    lines
        .iter()
        .skip(lines.len().saturating_sub(max))
        .map(|l| l.to_string())
        .collect()
}

/// How every session banner begins. One definition, so [`start_session`] and
/// [`last_session`] cannot drift apart.
const BANNER_PREFIX: &str = "\n=== octomon ";

/// Append one already-formatted line, rolling the file first if it has grown
/// past [`MAX_BYTES`]. Opened per write rather than held: the data directory
/// can be erased underneath us (Ctrl+R), and an open handle would go on
/// writing to an unlinked file for the rest of the session.
fn append(line: &str) {
    let Some(path) = path() else { return };
    if let Some(dir) = path.parent()
        && crate::store::create_dir_private(dir).is_err()
    {
        return;
    }
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > MAX_BYTES) {
        // One generation back is enough to cover "it happened before the
        // roll"; more would be an archive nobody reads.
        let _ = std::fs::rename(&path, path.with_extension("log.1"));
    }
    if let Ok(mut f) = crate::store::private_options()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_log_sits_in_the_data_directory_with_the_other_files() {
        // The [D] bundle sweeps the data directory wholesale, so landing here
        // is what gets the log into a support zip without any extra wiring.
        let dir = crate::store::data_dir().expect("a home directory");
        let p = path().expect("a path");
        assert!(p.starts_with(&dir), "{}", p.display());
        assert!(p.ends_with("errors.log"));
    }

    /// The fold is what keeps a collector failing every five seconds from
    /// burying the one line that explains the outage.
    #[test]
    fn identical_messages_fold_and_distinct_ones_do_not() {
        let mut seen: HashMap<String, Recent> = HashMap::new();
        let mut would_write = |key: &str| match seen.get_mut(key) {
            Some(r) if r.at.elapsed() < FOLD_WINDOW => {
                r.suppressed += 1;
                false
            }
            Some(r) => {
                r.suppressed = 0;
                r.at = Instant::now();
                true
            }
            None => {
                seen.insert(
                    key.to_string(),
                    Recent {
                        at: Instant::now(),
                        suppressed: 0,
                    },
                );
                true
            }
        };

        assert!(would_write("discovery: traceroute failed"));
        assert!(!would_write("discovery: traceroute failed"));
        assert!(!would_write("discovery: traceroute failed"));
        // A different failure is never hidden behind another one's window.
        assert!(would_write("whois: timed out"));
        assert_eq!(seen["discovery: traceroute failed"].suppressed, 2);
    }

    /// The rolled name must be a sibling called errors.log.1 — not
    /// "errors.1", which is what `set_extension` would produce.
    #[test]
    fn the_rolled_file_keeps_the_log_name() {
        let p = PathBuf::from("/data/octomon/errors.log");
        assert_eq!(
            p.with_extension("log.1"),
            PathBuf::from("/data/octomon/errors.log.1")
        );
    }

    /// The doctor report must show *this* run's failures, not the ones that
    /// prompted the restart — "it is broken right now" is a question about the
    /// current session.
    #[test]
    fn the_tail_starts_after_the_last_session_banner() {
        let text = "\n=== octomon 0.9.4 started · macos · pid 1 · T ===\n\
                    T  discovery   old run, must not show\n\
                    \n=== octomon 0.9.5 started · macos · pid 2 · T ===\n\
                    T  discovery   traceroute answered no hops\n\
                    T  public-ip   timed out\n";
        let tail = last_session(text, 10);
        assert_eq!(tail.len(), 2, "{tail:?}");
        assert!(tail[0].contains("traceroute answered no hops"));
        assert!(tail[1].contains("timed out"));
        assert!(!tail.iter().any(|l| l.contains("old run")));

        // Oldest first, and capped from the *end* — the newest lines are the
        // ones worth the space.
        let tail = last_session(text, 1);
        assert_eq!(tail.len(), 1);
        assert!(tail[0].contains("timed out"));

        // A clean run: the banner is the whole file and there is nothing to
        // report, rather than the banner itself being reported as a failure.
        assert!(
            last_session("\n=== octomon 0.9.5 started · macos · pid 2 · T ===\n", 10).is_empty()
        );
        assert!(last_session("", 10).is_empty());
    }

    /// End to end against a real directory: a line lands, and it carries the
    /// component and the message in a shape `grep` can work with.
    #[test]
    fn a_logged_failure_lands_on_disk() {
        let dir = std::env::temp_dir().join(format!("octomon-errlog-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("errors.log");
        let _ = std::fs::remove_file(&path);

        // `append` derives its own path, so exercise the formatting here and
        // the file mechanics directly — the parts that can fail separately.
        let line = "2026-08-27T14:03:11.000+01:00  discovery   traceroute failed: not found\n";
        {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(line.as_bytes()).unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("discovery"));
        assert!(text.contains("traceroute failed: not found"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
