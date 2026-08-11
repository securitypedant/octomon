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
        name: "traceroute",
        provides: "path discovery, [t] traceroute, [m] path monitor",
        package: if cfg!(target_os = "macos") {
            "preinstalled on macOS"
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
pub fn exists(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let candidate = dir.join(name);
        // Existence is enough: an unexecutable hit would fail at spawn anyway,
        // and reporting it as present is more useful than claiming it's absent.
        candidate.is_file()
    })
}

/// True when running with an effective uid of 0.
pub fn is_root() -> bool {
    // SAFETY: geteuid() takes no arguments, cannot fail, and only reads the
    // calling process's own credentials.
    #[cfg(unix)]
    unsafe {
        libc::geteuid() == 0
    }
    #[cfg(not(unix))]
    false
}

/// What is degraded by running unprivileged, if anything.
///
/// octomon is built to work without root, but two things are genuinely
/// narrower: on Linux, ICMP needs the kernel's ping-socket range opened (which
/// several distributions ship closed), and per-process bandwidth can only ever
/// see the calling user's own processes.
pub fn privilege_notice() -> Option<String> {
    if is_root() {
        return None;
    }
    if cfg!(target_os = "linux") {
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
        // `sh` exists on every platform octomon targets.
        assert!(exists("sh"));
        assert!(!exists("octomon-definitely-not-a-real-binary"));
    }

    #[test]
    fn traceroute_is_the_only_non_optional_tool() {
        let required = required();
        let hard: Vec<&str> = required
            .iter()
            .filter(|t| !t.optional)
            .map(|t| t.name)
            .collect();
        assert_eq!(hard, vec!["traceroute"]);
        // Every tool names something concrete that breaks without it.
        assert!(required.iter().all(|t| !t.provides.is_empty()));
        assert!(required.iter().all(|t| !t.package.is_empty()));
    }
}
