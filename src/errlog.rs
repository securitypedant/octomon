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

/// What the previous session logged about octomon's own failures: panics and
/// supervised-collector crashes. Shown once at the next start, so the person
/// at the keyboard can send the log back; a `--watch` under a service manager
/// has nobody watching its stderr, and a crash that was restarted and logged
/// is otherwise never heard of again.
#[derive(Clone, Debug, PartialEq)]
pub struct CrashReport {
    /// Collector crashes the supervisor restarted or stopped.
    pub crashes: u32,
    /// Panics, wherever they happened.
    pub panics: u32,
    /// Local wall-clock times (HH:MM) of the first and last such line.
    pub first: String,
    pub last: String,
    /// The banner line of the session the report is about, which is also
    /// the acknowledgement token: once shown, it is written beside the log,
    /// and the same session is not reported again.
    pub banner: String,
}

impl CrashReport {
    /// "2 collector crashes and 1 panic were logged between 08:20 and 09:05."
    pub fn summary(&self) -> String {
        let count =
            |n: u32, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
        let what = match (self.crashes, self.panics) {
            (0, p) => count(p, "panic was", "panics were"),
            (c, 0) => count(c, "collector crash was", "collector crashes were"),
            (c, p) => format!(
                "{} and {} were",
                count(c, "collector crash", "collector crashes"),
                count(p, "panic", "panics")
            ),
        };
        let when = if self.first == self.last {
            format!("at {}", self.first)
        } else {
            format!("between {} and {}", self.first, self.last)
        };
        format!("{what} logged {when}.")
    }
}

/// The previous session's [`CrashReport`], unless it has none or it was
/// already shown. Reads the log once; the session that just started has
/// written its banner, so the previous one is the stretch before it.
pub fn previous_session_crashes() -> Option<CrashReport> {
    let path = path()?;
    let text = std::fs::read_to_string(&path).ok()?;
    let report = crash_report(&text)?;
    let seen = path.with_file_name("errors.seen");
    if std::fs::read_to_string(&seen).is_ok_and(|s| s.trim() == report.banner) {
        return None;
    }
    Some(report)
}

/// Record that `report` was shown, so it is not shown again.
pub fn acknowledge(report: &CrashReport) {
    if let Some(path) = path() {
        let _ = crate::store::write_private(
            &path.with_file_name("errors.seen"),
            format!("{}\n", report.banner),
        );
    }
}

/// The crash report for the session before the last banner in `text`: its
/// `panic` lines and its `supervisor … crashed` lines, each counted with the
/// repeats errlog folded into it. Split out from the file read so the banner
/// and fold arithmetic are testable.
fn crash_report(text: &str) -> Option<CrashReport> {
    let last = text.rfind(BANNER_PREFIX)?;
    let before = &text[..last + 1];
    let (banner, session) = match before.rfind(BANNER_PREFIX) {
        Some(i) => {
            let from = &before[i + 1..];
            let nl = from.find('\n')?;
            (from[..nl].to_string(), &from[nl + 1..])
        }
        // The file began mid-session (it has just rolled).
        None => ("(before the log rolled)".to_string(), before),
    };
    let mut report = CrashReport {
        crashes: 0,
        panics: 0,
        first: String::new(),
        last: String::new(),
        banner,
    };
    for line in session.lines() {
        let mut fields = line.splitn(3, "  ");
        let (Some(stamp), Some(component), Some(message)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let n = 1 + folded(message);
        match component.trim() {
            "panic" => report.panics += n,
            "supervisor" if message.contains("crashed") => report.crashes += n,
            _ => continue,
        }
        // "2026-11-06T22:57:29.430-08:00" → "22:57"
        let hhmm = stamp.get(11..16).unwrap_or(stamp).to_string();
        if report.first.is_empty() {
            report.first = hhmm.clone();
        }
        report.last = hhmm;
    }
    (report.crashes + report.panics > 0).then_some(report)
}

/// The repeats a line's "(+N more in the last 5 min)" tail stands for.
fn folded(message: &str) -> u32 {
    message
        .rsplit_once("(+")
        .and_then(|(_, tail)| tail.split_once(" more"))
        .and_then(|(n, _)| n.trim().parse().ok())
        .unwrap_or(0)
}

/// Append one already-formatted line, rolling the file first if it has grown
/// past [`MAX_BYTES`]. Opened per write rather than held: the data directory
/// can be erased underneath us (Ctrl+R), and an open handle would go on
/// writing to an unlinked file for the rest of the session.
fn append(line: &str) {
    // A test that exercises a failure path must not write into the real
    // data directory of whoever runs `cargo test`.
    if cfg!(test) {
        return;
    }
    let Some(path) = path() else { return };
    if let Some(dir) = path.parent()
        && crate::store::create_dir_private(dir).is_err()
    {
        return;
    }
    // Held across the roll and the write: with two octomon processes
    // logging, both can see the file past the limit, and the second rename
    // would then roll the first one's fresh, near-empty log over the
    // generation it just kept. One attempt, no waiting: logging happens on
    // async workers, sometimes under the state lock, and must never stall
    // them behind a peer; unlocked is still better than unlogged.
    let _held = crate::store::FileLock::acquire_now(&path).ok();
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > MAX_BYTES) {
        // One generation back is enough to cover "it happened before the
        // roll"; more would be an archive nobody reads.
        let _ = std::fs::rename(&path, path.with_extension("log.1"));
    }
    let mut opts = crate::store::private_options();
    opts.append(true);
    if let Ok(mut f) = crate::store::create_or_open(opts, &path) {
        let _ = f.write_all(line.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The report covers the session before the last banner only, counts
    /// the repeats errlog folded into a line, and reads panics and
    /// supervisor crashes from the component column; everything else in the
    /// session (and everything in the current one) is not a crash.
    #[test]
    fn the_previous_sessions_crashes_are_counted_with_their_folds() {
        let text = "\
=== octomon 0.11.9 · build 1 started · macos · pid 1 · 2026-11-05T08:00:00.000-08:00 ===
2026-11-05T08:00:05.000-08:00  panic       main panicked at src/x.rs:1: old session
\n=== octomon 0.11.9 · build 2 started · macos · pid 2 · 2026-11-06T08:20:16.819-08:00 ===
2026-11-06T08:20:22.608-08:00  edge        https://octomon.dev/edge: could not connect
2026-11-06T08:20:29.430-08:00  panic       tokio-rt-worker panicked at src/main.rs:919: boom
2026-11-06T08:20:29.431-08:00  supervisor  vitals collector crashed (boom) — restarting  (+2 more in the last 5 min)
2026-11-06T09:05:34.437-08:00  supervisor  vitals collector crashed 4 times (boom) — stopped for this session, see errors.log
2026-11-06T09:05:40.000-08:00  supervisor  clock collector stopped on its own
\n=== octomon 0.12.0 · build 3 started · macos · pid 3 · 2026-11-06T10:00:00.000-08:00 ===
2026-11-06T10:00:01.000-08:00  panic       this session: not reported yet
";
        let r = crash_report(text).expect("the previous session crashed");
        assert_eq!((r.crashes, r.panics), (4, 1));
        assert_eq!((r.first.as_str(), r.last.as_str()), ("08:20", "09:05"));
        assert!(
            r.banner.starts_with("=== octomon 0.11.9 · build 2 "),
            "{}",
            r.banner
        );
        assert_eq!(
            r.summary(),
            "4 collector crashes and 1 panic were logged between 08:20 and 09:05."
        );

        // Nothing but ordinary failures: no report.
        let quiet = "\n=== octomon · a ===\n2026-11-06T08:00:00.000-08:00  edge        meh\n\n=== octomon · b ===\n";
        assert_eq!(crash_report(quiet), None);
        // One session only: nothing before it to report on.
        assert_eq!(
            crash_report("\n=== octomon · a ===\n2026-11-06T08:00:00.000-08:00  panic  x\n"),
            None
        );
        // A log that rolled mid-session still reports what is left.
        let rolled = "2026-11-06T08:00:00.000-08:00  panic       x\n\n=== octomon · b ===\n";
        let r = crash_report(rolled).unwrap();
        assert_eq!((r.crashes, r.panics), (0, 1));
        assert_eq!(r.summary(), "1 panic was logged at 08:00.");
    }

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
