//! External command-line tools octomon shells out to.
//!
//! Several probes have no unprivileged in-process equivalent, so they run a
//! system tool. Which of those ship by default varies sharply by distribution —
//! `traceroute` is absent from a stock Ubuntu or Fedora install, and `iw` is
//! absent even from Ubuntu Desktop — so a missing binary is a normal condition,
//! not a bug. Probing at startup lets the UI say *which* tool is missing and
//! which package provides it, instead of a feature silently never appearing.

/// A tool octomon uses, and what is lost without it.
pub struct Tool {
    pub name: &'static str,
    /// What stops working when it is absent.
    pub provides: &'static str,
    /// Install hint, e.g. "apt install traceroute".
    pub package: &'static str,
    /// True when nothing important degrades without it.
    pub optional: bool,
}

/// Tools relevant to the current platform, most important first.
pub fn required() -> Vec<Tool> {
    let mut v = vec![Tool {
        // Named `tracert` on Windows. Taken from the one definition so the
        // lookup and the spawn can never disagree.
        name: crate::platform::traceroute::PROGRAM,
        provides: "path discovery, [t] traceroute, [m] path monitor",
        package: if cfg!(target_os = "macos") {
            "preinstalled on macOS"
        } else if cfg!(windows) {
            "preinstalled on Windows"
        } else {
            "apt install traceroute · dnf install traceroute"
        },
        optional: false,
    }];

    if cfg!(target_os = "linux") {
        v.push(Tool {
            name: "ss",
            provides: "per-process bandwidth",
            package: "apt install iproute2 · dnf install iproute",
            optional: true,
        });
        v.push(Tool {
            name: "nmcli",
            provides: "Wi-Fi details and airspace congestion",
            package: "apt install network-manager · dnf install NetworkManager",
            optional: true,
        });
        v.push(Tool {
            name: "iw",
            provides: "Wi-Fi details (fallback when nmcli is absent)",
            package: "apt install iw · dnf install iw",
            optional: true,
        });
    }
    if cfg!(target_os = "macos") {
        v.push(Tool {
            name: "nettop",
            provides: "per-process bandwidth",
            package: "preinstalled on macOS",
            optional: true,
        });
        v.push(Tool {
            name: "system_profiler",
            provides: "Wi-Fi details and airspace congestion",
            package: "preinstalled on macOS",
            optional: true,
        });
    }
    v
}

/// Whether `name` resolves on `PATH`. Uses the same lookup the shell would.
///
/// On Windows that means honouring `PATHEXT`: the file on disk is `TRACERT.EXE`,
/// so joining the bare name finds nothing and every tool would be reported
/// missing — which shows the startup notice before the user sees a dashboard.
pub fn exists(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        // Existence is enough: an unexecutable hit would fail at spawn anyway,
        // and reporting it as present is more useful than claiming it's absent.
        if dir.join(name).is_file() {
            return true;
        }
        #[cfg(windows)]
        {
            // PATHEXT is ';'-separated and its entries carry the leading dot.
            std::env::var("PATHEXT")
                .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string())
                .split(';')
                .filter(|e| !e.is_empty())
                .any(|ext| dir.join(format!("{name}{ext}")).is_file())
        }
        #[cfg(not(windows))]
        false
    })
}

/// True when the process has whatever privilege its platform gates probes on:
/// an effective uid of 0 on unix, and on Windows membership of a group that can
/// open an ETW session. Not called `is_root` because Windows has no such thing.
#[cfg(unix)]
pub fn is_privileged() -> bool {
    // SAFETY: geteuid() takes no arguments, cannot fail, and only reads the
    // calling process's own credentials.
    unsafe { libc::geteuid() == 0 }
}

/// Windows gates per-process bandwidth on starting an ETW session, which
/// Administrators can do — and so can members of Performance Log Users, which
/// is the better answer for a monitoring tool since it is granted once rather
/// than re-elevated every run. Either is enough, so both are checked.
#[cfg(windows)]
pub fn is_privileged() -> bool {
    use windows_sys::Win32::Foundation::{FALSE, HANDLE};
    use windows_sys::Win32::Security::{
        AllocateAndInitializeSid, CheckTokenMembership, FreeSid, PSID, SECURITY_NT_AUTHORITY,
    };

    // Both are aliases in the BUILTIN domain, so they differ only in the RID.
    const SECURITY_BUILTIN_DOMAIN_RID: u32 = 0x20;
    const DOMAIN_ALIAS_RID_ADMINS: u32 = 0x220;
    const DOMAIN_ALIAS_RID_LOGGING_USERS: u32 = 0x22c;

    fn in_builtin_group(rid: u32) -> bool {
        let authority = SECURITY_NT_AUTHORITY;
        let mut sid: PSID = std::ptr::null_mut();
        // SAFETY: builds a two-subauthority BUILTIN SID into `sid`, which is
        // freed below on every path. The trailing zeros are the unused
        // subauthority slots the signature requires.
        let ok = unsafe {
            AllocateAndInitializeSid(
                &authority,
                2,
                SECURITY_BUILTIN_DOMAIN_RID,
                rid,
                0,
                0,
                0,
                0,
                0,
                0,
                &mut sid,
            )
        };
        if ok == FALSE || sid.is_null() {
            return false;
        }
        let mut member = FALSE;
        // SAFETY: a null token means "the calling thread's effective token".
        // `member` is only trusted when the call reports success.
        let checked =
            unsafe { CheckTokenMembership(std::ptr::null_mut::<HANDLE>() as _, sid, &mut member) };
        // SAFETY: `sid` came from AllocateAndInitializeSid and is not used after.
        unsafe { FreeSid(sid) };
        checked != FALSE && member != FALSE
    }

    in_builtin_group(DOMAIN_ALIAS_RID_ADMINS) || in_builtin_group(DOMAIN_ALIAS_RID_LOGGING_USERS)
}

/// What is degraded by running unprivileged, if anything.
///
/// octomon is built to work without root, but two things are genuinely
/// narrower: on Linux, ICMP needs the kernel's ping-socket range opened (which
/// several distributions ship closed), and per-process bandwidth can only ever
/// see the calling user's own processes.
pub fn privilege_notice() -> Option<String> {
    if is_privileged() {
        return None;
    }
    if cfg!(windows) {
        Some(
            "Running unprivileged. Per-process bandwidth needs an ETW session: run octomon \
             from an elevated terminal, or add yourself to the local \"Performance Log Users\" \
             group once and it works unelevated thereafter."
                .to_string(),
        )
    } else if cfg!(target_os = "linux") {
        Some(
            "Running unprivileged. Per-process bandwidth covers only your own processes; \
             system daemons and other users are invisible. If latency is also empty, the \
             kernel's ping-socket range is closed — see above."
                .to_string(),
        )
    } else {
        Some(
            "Running unprivileged. Per-process bandwidth covers only your own processes."
                .to_string(),
        )
    }
}

/// Tools that are missing, in the order [`required`] lists them.
pub fn missing() -> Vec<Tool> {
    required().into_iter().filter(|t| !exists(t.name)).collect()
}

/// One-line summary for the UI notice, or `None` when everything is present.
/// A missing non-optional tool is called out as such — losing `traceroute`
/// costs three features, while losing `iw` costs a fallback nobody will notice.
pub fn missing_notice() -> Option<String> {
    let missing = missing();
    if missing.is_empty() {
        return None;
    }
    let names: Vec<&str> = missing.iter().map(|t| t.name).collect();
    let severity = if missing.iter().any(|t| !t.optional) {
        "features disabled"
    } else {
        "some detail unavailable"
    };
    Some(format!(
        "missing: {} — {severity}, see [?] help",
        names.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_lookup_finds_real_binaries() {
        // Both ship with the OS. `cmd` resolves only via PATHEXT — System32 is
        // always on PATH but the file is `cmd.exe` — so this doubles as the
        // regression test for that lookup.
        assert!(exists(if cfg!(windows) { "cmd" } else { "sh" }));
        assert!(!exists("octomon-definitely-not-a-real-binary"));
    }

    #[test]
    fn the_traceroute_program_is_the_only_non_optional_tool() {
        let required = required();
        let hard: Vec<&str> = required
            .iter()
            .filter(|t| !t.optional)
            .map(|t| t.name)
            .collect();
        // Compared against the one definition rather than a literal, which
        // would only happen to be right on two of the three platforms.
        assert_eq!(hard, vec![crate::platform::traceroute::PROGRAM]);
        // Every tool names something concrete that breaks without it.
        assert!(required.iter().all(|t| !t.provides.is_empty()));
        assert!(required.iter().all(|t| !t.package.is_empty()));
    }
}

/// Startup warnings about the terminal itself, when there is reason to
/// think the screen will not come out right. Nothing is changed on the
/// terminal's behalf: the right fix is in the user's environment, and a
/// program that switched the terminal's encoding under the shell would leave
/// every other program disagreeing with it.
///
/// - A locale that is not UTF-8 (xterm started from an X session with no
///   `LANG`, a server with `LANG=C`): the terminal decodes every border and
///   glyph as three Latin-1 letters and the layout falls apart. Seen in the
///   field on XQuartz, where Terminal.app sets the locale for itself and
///   xterm does not.
/// - xterm itself, which has a bitmap default font with box drawing but no
///   braille or eighth-block characters: the graphs come out as boxes. A
///   hint, not a switch — [#] is one key away, and the user can see whether
///   the boxes are there.
pub fn terminal_notices() -> Vec<String> {
    let var = |n: &str| std::env::var(n).ok().filter(|v| !v.is_empty());
    terminal_notices_for(
        var("LC_ALL").as_deref(),
        var("LC_CTYPE").as_deref(),
        var("LANG").as_deref(),
        var("XTERM_VERSION").is_some(),
    )
}

fn terminal_notices_for(
    lc_all: Option<&str>,
    lc_ctype: Option<&str>,
    lang: Option<&str>,
    is_xterm: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    // Windows consoles do not take their encoding from these variables.
    if cfg!(windows) {
        return out;
    }
    // Precedence as libc resolves it: LC_ALL beats LC_CTYPE beats LANG.
    let locale = lc_all.or(lc_ctype).or(lang);
    let utf8 = locale.is_some_and(|l| {
        let l = l.to_ascii_lowercase();
        l.contains("utf-8") || l.contains("utf8")
    });
    if !utf8 {
        let what = match locale {
            Some(l) => format!("locale is {l:?}"),
            None => "LANG is not set".to_string(),
        };
        let fix = if is_xterm {
            "export LANG=en_US.UTF-8, or start xterm with -u8 (XTerm*utf8: 1)"
        } else {
            "export LANG=en_US.UTF-8 (or C.UTF-8) in the terminal's environment"
        };
        out.push(format!(
            "terminal is not in UTF-8 mode ({what}) — if the borders look garbled, that is why: {fix}"
        ));
    } else if is_xterm {
        out.push(
            "xterm: its default font has no braille or block glyphs — if the graphs show boxes, \
             press # for plainer glyphs, or start xterm with -fa Menlo"
                .to_string(),
        );
    }
    out
}

#[cfg(test)]
mod terminal_tests {
    use super::terminal_notices_for;

    #[test]
    fn a_utf8_locale_in_an_ordinary_terminal_says_nothing() {
        for ok in ["en_US.UTF-8", "C.UTF-8", "de_DE.utf8", "en_GB.UTF-8@euro"] {
            assert!(
                terminal_notices_for(None, None, Some(ok), false).is_empty(),
                "{ok}"
            );
        }
        // LC_ALL wins over a bare LANG, both ways round.
        assert!(terminal_notices_for(Some("en_US.UTF-8"), None, Some("C"), false).is_empty());
        assert_eq!(
            terminal_notices_for(Some("C"), None, Some("en_US.UTF-8"), false).len(),
            usize::from(!cfg!(windows))
        );
    }

    #[test]
    fn a_missing_or_latin1_locale_is_called_out_with_the_fix() {
        if cfg!(windows) {
            return;
        }
        let none = terminal_notices_for(None, None, None, true);
        assert_eq!(none.len(), 1);
        assert!(none[0].contains("LANG is not set"), "{}", none[0]);
        assert!(
            none[0].contains("-u8"),
            "xterm gets the xterm fix: {}",
            none[0]
        );
        let c = terminal_notices_for(None, None, Some("C"), false);
        assert!(c[0].contains("locale is \"C\""), "{}", c[0]);
        assert!(c[0].contains("C.UTF-8"), "{}", c[0]);
    }

    #[test]
    fn xterm_with_a_good_locale_gets_the_glyph_hint_only() {
        if cfg!(windows) {
            return;
        }
        let v = terminal_notices_for(None, None, Some("en_US.UTF-8"), true);
        assert_eq!(v.len(), 1);
        assert!(v[0].contains("press #"), "{}", v[0]);
    }
}
