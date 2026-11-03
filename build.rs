//! Stamps a build number into the binary so a screenshot or bug report says
//! exactly which build it came from, not just which release it was near.
//!
//! The number is the commit count on the checked-out history, followed by the
//! short hash — e.g. `build 143 (b91da39)`. A dirty tree adds `+` and the
//! build's wall-clock time, e.g. `build 143 (b91da39+ 08-24 21:26:33)`:
//! uncommitted rebuilds all share the same count and hash, and the timestamp
//! is the only thing that tells two of them apart while iterating locally.
//! Clean builds carry no timestamp, so a release build stays reproducible.
//! Outside a git checkout (a crates.io build) the stamp is empty and the
//! version stands alone.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn main() {
    let build = match (
        git(&["rev-list", "--count", "HEAD"]),
        git(&["rev-parse", "--short", "HEAD"]),
    ) {
        (Some(count), Some(hash)) => {
            // `status --porcelain` prints nothing for a clean tree.
            let dirty = git(&["status", "--porcelain", "--untracked-files=no"]).is_some();
            if dirty {
                let at = chrono::Local::now().format("%m-%d %H:%M:%S");
                format!("{count} ({hash}+ {at})")
            } else {
                format!("{count} ({hash})")
            }
        }
        _ => String::new(),
    };
    println!("cargo:rustc-env=OCTOMON_BUILD={build}");
    // The version as every "which octomon is this?" surface prints it.
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let full = if build.is_empty() {
        version
    } else {
        format!("{version} · build {build}")
    };
    println!("cargo:rustc-env=OCTOMON_VERSION_FULL={full}");
    // Re-run when the checkout moves *or any source changes*. Watching only
    // HEAD/index meant an edit-and-rebuild kept the cached stamp — the exact
    // builds a person iterating locally needs to tell apart.
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");
    if let Some(dir) = git(&["rev-parse", "--git-dir"]) {
        println!("cargo:rerun-if-changed={dir}/HEAD");
        println!("cargo:rerun-if-changed={dir}/index");
    }

    // wlanapi.dll does not exist on Windows Server unless the optional
    // Wireless LAN Service feature is installed, and a load-time import
    // stops octomon starting there at all — STATUS_DLL_NOT_FOUND before
    // main, with nothing printed. Delay-load it so the import resolves on
    // first call instead; the guard in `platform::windows` never makes that
    // call when the DLL is absent.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        println!("cargo:rustc-link-arg=/DELAYLOAD:wlanapi.dll");
        println!("cargo:rustc-link-arg=delayimp.lib");
    }

    #[cfg(windows)]
    windows_resources();
}

/// Embeds a VERSIONINFO block, an application manifest and the icon in the
/// Windows exe.
///
/// Without them the binary has no resource section at all: no product name,
/// no company, no version, no manifest. Real software almost always carries
/// these and malware often does not, so their absence is one of the signals
/// Defender's cloud classifier weighs when it decides an unsigned exe is
/// `Trojan:Win32/Bearfoos.A!ml`, which it has done to two releases. This
/// does not replace a signature; it removes a cheap reason to look like one
/// of the bad ones, and gives Explorer, Task Manager and the firewall prompt
/// a proper name to show.
///
/// Only compiled when the build runs on Windows: the resources go through
/// the SDK's `rc.exe`, which winresource finds for the host architecture, so
/// native x64 and ARM64 builds both work. A cross-compile from another OS
/// has no rc.exe and ships without resources, as every release before this
/// did.
#[cfg(windows)]
fn windows_resources() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let mut res = winresource::WindowsResource::new();
    res.set_icon("resources/windows/octomon.ico")
        .set_manifest_file("resources/windows/octomon.manifest")
        .set_language(0x0409) // en-US
        .set("ProductName", "octomon")
        .set("FileDescription", "octomon network monitor")
        .set("CompanyName", "Simon Thorpe")
        .set(
            "LegalCopyright",
            "Copyright (c) Simon Thorpe. MIT or Apache-2.0 licence.",
        )
        .set("OriginalFilename", "octomon.exe")
        .set("InternalName", "octomon")
        .set("Comments", "https://octomon.dev")
        .set("ProductVersion", &version)
        .set("FileVersion", &version);
    println!("cargo:rerun-if-changed=resources/windows/octomon.ico");
    println!("cargo:rerun-if-changed=resources/windows/octomon.manifest");
    if let Err(e) = res.compile() {
        // A missing rc.exe must not stop someone's `cargo install`: the
        // resources are reputation and polish, not function. CI and the
        // release build, where every exe is expected to carry them, fail
        // loudly instead of quietly shipping a bare binary.
        if std::env::var_os("CI").is_some() {
            panic!("embedding Windows resources failed: {e}");
        }
        println!(
            "cargo:warning=Windows resources not embedded ({e}); the exe builds without version info or icon"
        );
    }
}
