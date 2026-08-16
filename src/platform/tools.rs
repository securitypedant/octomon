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
