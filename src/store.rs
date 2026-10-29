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

/// Whether `path` is a real (non-symlink) file or directory owned by the
/// effective user. Everything that re-permissions or writes through a path
/// checks this first, because `chmod` and `open` follow symlinks: run as root
/// over a home directory that stays the invoking user's (`sudo` on macOS
/// keeps `$HOME`), a planted `~/.local/share/octomon/x -> /etc/sudoers` would
/// otherwise have octomon make the target owner-only — or truncate it.
#[cfg(unix)]
pub fn owned_by_me(path: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    // SAFETY: geteuid() takes no arguments, cannot fail, and only reads the
    // calling process's own credentials.
    let me = unsafe { libc::geteuid() };
    std::fs::symlink_metadata(path)
        .map(|m| !m.file_type().is_symlink() && m.uid() == me)
        .unwrap_or(false)
}

/// The account a `sudo` run is acting for, as `(uid, gid)`: set only when the
/// effective uid is 0 and sudo's `SUDO_UID` / `SUDO_GID` name somebody other
/// than root. That is the run whose `$HOME` can still be the invoking user's
/// (macOS keeps it; `sudo -E` keeps it on Linux), so the files it creates
/// there would otherwise be root-owned and owner-only — and the next
/// unprivileged run could neither read nor append its own baselines, history
/// or logs, failing as quietly as every other best-effort write here.
/// Computed once: none of the inputs change for the life of the process.
#[cfg(unix)]
fn invoker() -> Option<(u32, u32)> {
    static INVOKER: std::sync::OnceLock<Option<(u32, u32)>> = std::sync::OnceLock::new();
    *INVOKER.get_or_init(|| {
        // SAFETY: geteuid() takes no arguments, cannot fail, and only reads the
        // calling process's own credentials.
        let euid = unsafe { libc::geteuid() };
        invoker_from(
            euid,
            std::env::var("SUDO_UID").ok().as_deref(),
            std::env::var("SUDO_GID").ok().as_deref(),
        )
    })
}

/// [`invoker`]'s decision, apart from the process it reads. A `SUDO_UID` of 0
/// (root sudo-ing to root) has nobody to hand anything back to, and a value
/// that does not parse is not guessed at: the files simply stay root's, which
/// is what happened before this existed.
#[cfg(unix)]
fn invoker_from(euid: u32, uid: Option<&str>, gid: Option<&str>) -> Option<(u32, u32)> {
    if euid != 0 {
        return None;
    }
    let uid: u32 = uid?.trim().parse().ok()?;
    let gid: u32 = gid?.trim().parse().ok()?;
    (uid != 0).then_some((uid, gid))
}

/// The invoking user's home directory, from the password database rather than
/// `$HOME` — the environment is exactly what is in question under `sudo` —
/// and with symlinks resolved, so it compares against the resolved path of an
/// open file. Computed once.
#[cfg(unix)]
fn invoker_home(uid: u32) -> Option<&'static std::path::Path> {
    static HOME: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    HOME.get_or_init(|| {
        use std::os::unix::ffi::OsStrExt as _;
        // SAFETY: an all-zero `passwd` is a valid value for getpwuid_r to fill
        // in (every field is an integer or a pointer).
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0 as libc::c_char; 16 * 1024];
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is to a live local of the size passed, and the
        // strings it fills in point into `buf`, which outlives their use below.
        let rc =
            unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut found) };
        if rc != 0 || found.is_null() || pwd.pw_dir.is_null() {
            return None;
        }
        // SAFETY: getpwuid_r succeeded, so pw_dir is a NUL-terminated string
        // inside `buf`.
        let dir = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
        std::fs::canonicalize(std::ffi::OsStr::from_bytes(dir.to_bytes())).ok()
    })
    .as_deref()
}

/// Where an open file or directory actually is, asked of the descriptor rather
/// than worked out from the path it was opened by. The path's directories sit
/// in the invoking user's home, where anything running as that user can swap
/// one for a symlink between a check and a use; the descriptor's own answer
/// cannot be redirected that way. Platforms without a way to ask return
/// `None`, and nothing is handed back there.
#[cfg(target_os = "macos")]
fn real_path(fd: std::os::fd::RawFd) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt as _;
    let mut buf = [0u8; libc::PATH_MAX as usize];
    // SAFETY: F_GETPATH writes at most MAXPATHLEN (== PATH_MAX) bytes,
    // NUL-terminated, into the buffer, which is that size.
    if unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr()) } == -1 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0)?;
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..end])))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn real_path(fd: std::os::fd::RawFd) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()
}

#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "linux", target_os = "android"))
))]
fn real_path(_fd: std::os::fd::RawFd) -> Option<PathBuf> {
    None
}

/// What a resolved path is to octomon, for deciding whether a `sudo` run may
/// give it to the invoking user.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq)]
enum Scope {
    /// One of octomon's own directories, or something inside one.
    Own,
    /// A directory between the home directory and one of octomon's own that
    /// this very call had to create (`~/.local/share` on a Mac that never had
    /// one). Left root-owned, it would break every other program that keeps
    /// its data there, not just octomon.
    CreatedParent,
}

/// Whether `real` — a resolved path, from [`real_path`] — may be chowned to the
/// invoking user. Never the home directory itself and never anything outside
/// it: that is the line that keeps a planted link from turning "give the user
/// back their file" into "give the user a file of root's". And within the
/// home, only octomon's own directories (`roots`, also resolved) and what is
/// in them, or a parent of one that octomon just created. A home of `/` would
/// make every path qualify, so it disqualifies everything instead.
#[cfg(unix)]
fn may_hand_back(
    real: &std::path::Path,
    home: &std::path::Path,
    roots: &[PathBuf],
    scope: Scope,
) -> bool {
    use std::path::Component;
    let plain = |p: &std::path::Path| {
        p.is_absolute()
            && p.components()
                .all(|c| !matches!(c, Component::ParentDir | Component::CurDir))
    };
    if !plain(real) || !plain(home) || home.parent().is_none() {
        return false;
    }
    if real == home || !real.starts_with(home) {
        return false;
    }
    roots
        .iter()
        .filter(|r| plain(r) && r.starts_with(home) && r.as_path() != home)
        .any(|r| match scope {
            Scope::Own => real.starts_with(r),
            Scope::CreatedParent => r.starts_with(real),
        })
}

/// octomon's own directories, resolved: the data directory and the default
/// config directory. A `--config` file elsewhere is not among them — its
/// directory is whatever the user named, and is not octomon's to give away.
#[cfg(unix)]
fn own_roots() -> Vec<PathBuf> {
    [data_dir(), crate::config::Config::dir()]
        .into_iter()
        .flatten()
        .filter_map(|d| std::fs::canonicalize(d).ok())
        .collect()
}

/// Give a file or directory octomon holds open back to the user who ran
/// `sudo octomon` (see [`invoker`]). A no-op unprivileged, and for anything
/// not owned by root: a file that already belongs to the user stays theirs,
/// and one that belongs to some third account is not ours to give away.
///
/// Everything is decided from the descriptor — `fstat` for what it is and who
/// owns it, [`real_path`] for where it is — and the change is an `fchown` of
/// that same descriptor, so no symlink planted along the path can point it at
/// anything else. A regular file with more than one link is left alone: a
/// hard link to a root file (macOS does not stop a user making one) would
/// otherwise hand the user that file.
#[cfg(unix)]
fn hand_back_fd(fd: std::os::fd::BorrowedFd<'_>, scope: Scope) {
    use std::os::fd::AsRawFd as _;
    let Some((uid, gid)) = invoker() else { return };
    let raw = fd.as_raw_fd();
    // SAFETY: an all-zero `stat` is a valid value for fstat to overwrite.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `raw` is a descriptor borrowed for this call, and `st` is a
    // live local of the right type.
    if unsafe { libc::fstat(raw, &mut st) } != 0 || st.st_uid != 0 {
        return;
    }
    let kind = st.st_mode & libc::S_IFMT;
    let regular = kind == libc::S_IFREG && st.st_nlink == 1;
    if !regular && kind != libc::S_IFDIR {
        return;
    }
    let Some(home) = invoker_home(uid) else {
        return;
    };
    let Some(real) = real_path(raw) else { return };
    if !may_hand_back(&real, home, &own_roots(), scope) {
        return;
    }
    // Best-effort, like every write it follows: a failure leaves the file
    // root-owned, which is no worse than before.
    // SAFETY: `raw` is a live descriptor for the duration of this call.
    let _ = unsafe { libc::fchown(raw, uid, gid) };
}

/// [`hand_back_fd`] for a file just opened in one of octomon's own
/// directories. Call it on every file octomon creates there — it costs one
/// `fstat` once the file is already the user's, and nothing at all
/// unprivileged. Shaped to slot into `open(..).inspect(store::hand_back)`.
#[cfg(unix)]
pub fn hand_back<F: std::os::fd::AsFd>(file: &F) {
    if invoker().is_some() {
        hand_back_fd(file.as_fd(), Scope::Own);
    }
}

#[cfg(not(unix))]
pub fn hand_back<F>(_file: &F) {}

/// Open `path` without following a symlink and without blocking (a planted
/// FIFO would otherwise hang the open), for [`hand_back_fd`]. Read-only is
/// enough: `fchown` needs ownership privileges, not write access.
#[cfg(unix)]
fn open_nofollow(path: &std::path::Path, dir: bool) -> Option<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut flags = libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    if dir {
        flags |= libc::O_DIRECTORY;
    }
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .ok()
}

/// `create_dir_all`, then make the leaf owner-only — when it is ours. A
/// directory somebody else owns (their `$XDG_DATA_HOME`, or the user's own
/// tree seen from a `sudo` run) is not ours to re-permission.
///
/// Under `sudo`, the directories this call created are then given to the
/// invoking user (see [`hand_back`]) — the leaf after it has been made
/// owner-only, since once it is theirs [`owned_by_me`] no longer lets root
/// touch its mode.
pub fn create_dir_private(dir: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    let created: Vec<PathBuf> = if invoker().is_some() {
        dir.ancestors()
            .take_while(|a| std::fs::symlink_metadata(a).is_err())
            .map(std::path::Path::to_path_buf)
            .collect()
    } else {
        Vec::new()
    };
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsFd as _;
        use std::os::unix::fs::PermissionsExt as _;
        // Best-effort: failing here would cost the write.
        if owned_by_me(dir) {
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(DIR_MODE));
        }
        if invoker().is_some() {
            // The leaf is octomon's own whether or not this call made it, so
            // one a past `sudo` run left root-owned is repaired here too. Its
            // parents are handed back only if this call created them.
            if let Some(f) = open_nofollow(dir, true) {
                hand_back_fd(f.as_fd(), Scope::Own);
            }
            for parent in created.iter().filter(|p| p.as_path() != dir) {
                if let Some(f) = open_nofollow(parent, true) {
                    hand_back_fd(f.as_fd(), Scope::CreatedParent);
                }
            }
        }
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
        // Elevated, never write through a symlink: the file's directory is
        // the invoking user's when `sudo` keeps `$HOME`, and a link planted
        // there would have root truncate or append to whatever it points at.
        // Unprivileged, a symlinked config.toml in a dotfiles repo is a
        // legitimate arrangement and keeps working.
        if crate::platform::tools::is_privileged() {
            opts.custom_flags(libc::O_NOFOLLOW);
        }
    }
    opts
}

/// `std::fs::write`, owner-only and atomic: the contents go to a sibling
/// temporary file that is renamed over the target, so a crash mid-write leaves
/// the previous file intact rather than a truncated one — which, for
/// config.toml and baselines.json, would read as every setting or every
/// learned network gone at the next start.
///
/// The rename means the target takes the temporary file's owner, so under
/// `sudo` a file the user owned would come back root's at every save. The
/// temporary file is handed back (see [`hand_back`]) before the rename for
/// that reason. It is also always a fresh one: a leftover from a crash is
/// removed and the new one created exclusively, so a hard link planted under
/// that name can neither be truncated through nor end up in place.
pub fn write_private(path: &std::path::Path, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    use std::io::Write as _;
    // A symlinked target (a config.toml kept in a dotfiles repo) is written
    // where it points, so the rename does not replace the link with a file.
    // Elevated, that is exactly the write `private_options` refuses, and for
    // the same reason.
    let resolved;
    let path = match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            if crate::platform::tools::is_privileged() {
                return Err(std::io::Error::other(
                    "refusing to write through a symlink while elevated",
                ));
            }
            resolved = std::fs::canonicalize(path)?;
            resolved.as_path()
        }
        _ => path,
    };
    let tmp = path.with_file_name(format!(
        ".{}.tmp",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "octomon".to_string())
    ));
    let fresh = || private_options().write(true).create_new(true).open(&tmp);
    let mut f = match fresh() {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(&tmp)?;
            fresh()?
        }
        opened => opened?,
    };
    hand_back(&f);
    let written = f
        .write_all(contents.as_ref())
        .and_then(|()| f.sync_all())
        .and_then(|()| std::fs::rename(&tmp, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

/// How long to wait for another octomon process to let go of a data file
/// before going ahead without it. Holders only ever append a line or rewrite a
/// few hundred kilobytes, so anything past this is a stuck or stopped process
/// (a dashboard suspended with Ctrl+Z mid-write), and the verdict loop must not
/// hang behind it.
const LOCK_PATIENCE: std::time::Duration = std::time::Duration::from_secs(2);

/// An exclusive, cross-process hold on one data file, released on drop.
///
/// Two octomon processes routinely share the data directory — the dashboard
/// and a `--watch` service, say — and both append to the same history files.
/// An append is safe on its own (`O_APPEND` lands each line whole at the end),
/// but a rewrite is read → tmp file → rename: a line another process appends
/// between the read and the rename goes to the inode the rename then unlinks,
/// and is gone. So every append and every rewrite of a shared file takes this
/// first, and a rewrite re-reads the file once it holds it.
///
/// The lock is a sibling `.<name>.lock` rather than the file itself, because
/// the rewrite replaces the file's inode: a lock on the old one would not stop
/// a writer that opened the new one. Advisory — it only orders octomon against
/// octomon, which is all that writes here.
pub struct FileLock {
    _file: std::fs::File,
}

impl FileLock {
    /// Take the lock for `path`, waiting up to [`LOCK_PATIENCE`]. `None` when
    /// it could not be had in time or the lock file could not be opened;
    /// callers decide whether to go ahead unlocked (an append — a racy line
    /// beats a lost one) or give up (a rewrite — never safe unlocked).
    pub fn acquire(path: &std::path::Path) -> Option<FileLock> {
        let lock = path.with_file_name(format!(".{}.lock", path.file_name()?.to_string_lossy()));
        let deadline = std::time::Instant::now() + LOCK_PATIENCE;
        loop {
            match Self::try_acquire(&lock) {
                Ok(Some(held)) => return Some(held),
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                _ => return None,
            }
        }
    }

    /// One non-blocking attempt: `Ok(None)` when another process holds it.
    /// Non-blocking plus a deadline rather than a blocking `flock`, so a peer
    /// that never lets go costs two seconds and not the rest of the session.
    #[cfg(unix)]
    fn try_acquire(lock: &std::path::Path) -> std::io::Result<Option<FileLock>> {
        use std::os::fd::AsRawFd as _;
        let file = private_options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock)
            .inspect(hand_back)?;
        loop {
            // SAFETY: the descriptor is open for the duration of the call (it
            // is borrowed from `file`), and flock only reads its arguments.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                // Released by the kernel when `file` closes — on drop, or when
                // the process dies, so a crash never leaves it held.
                return Ok(Some(FileLock { _file: file }));
            }
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EWOULDBLOCK) => return Ok(None),
                _ => return Err(e),
            }
        }
    }

    /// Windows has no `flock`, but a handle opened with no sharing is the same
    /// thing: while it is open,
    /// every other open of the file fails with a sharing violation, and the
    /// OS closes it if the process dies.
    #[cfg(windows)]
    fn try_acquire(lock: &std::path::Path) -> std::io::Result<Option<FileLock>> {
        use std::os::windows::fs::OpenOptionsExt as _;
        /// `ERROR_SHARING_VIOLATION`: somebody else has it open.
        const SHARING_VIOLATION: i32 = 32;
        match private_options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0)
            .open(lock)
        {
            Ok(file) => Ok(Some(FileLock { _file: file })),
            Err(e) if e.raw_os_error() == Some(SHARING_VIOLATION) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Anything else gets no lock and the old, racy behaviour.
    #[cfg(not(any(unix, windows)))]
    fn try_acquire(_: &std::path::Path) -> std::io::Result<Option<FileLock>> {
        Err(std::io::Error::other("no file locking on this platform"))
    }
}

/// Append `text` to `path` (creating it owner-only), holding its [`FileLock`]
/// so the line cannot land in the middle of another process's rewrite. When
/// the lock cannot be had the append goes ahead anyway: losing the line to a
/// race that may not even be happening is worse than risking it.
pub fn append_locked(path: &std::path::Path, text: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        let _ = create_dir_private(dir);
    }
    let _held = FileLock::acquire(path);
    private_options()
        .create(true)
        .append(true)
        .open(path)
        .inspect(hand_back)?
        .write_all(text.as_bytes())
}

/// Rewrite `path` from its current contents, under its [`FileLock`]. The file
/// is read *after* the lock is taken, so whatever another process appended
/// since the caller last looked is in what `edit` sees and survives. `edit`
/// returns the new contents, or `None` to leave the file alone. `Ok(false)`
/// when nothing needed writing (no file, or no change). A lock that stays
/// busy is an error rather than a quiet skip: never writing unlocked is what
/// makes this safe, but a [x] delete that silently didn't happen should say
/// why in the error log.
pub fn rewrite_locked(
    path: &std::path::Path,
    edit: impl FnOnce(&str) -> Option<String>,
) -> std::io::Result<bool> {
    let Some(_held) = FileLock::acquire(path) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "another octomon process is holding the file",
        ));
    };
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    match edit(&text) {
        Some(body) => write_private(path, body).map(|()| true),
        None => Ok(false),
    }
}

/// How often a long run re-checks a growing file against its bound. Startup
/// prunes too, but a `--watch` service can run for weeks without one; hourly
/// keeps the files near their bound at the cost of one small read an hour,
/// and the rewrite itself still only happens when something is due to go.
pub const PRUNE_EVERY: std::time::Duration = std::time::Duration::from_secs(3600);

/// When a file was last checked against its bound, so the append path can
/// prune "every so often" without rewriting on every append.
pub struct PruneClock(std::sync::Mutex<Option<std::time::Instant>>);

impl PruneClock {
    pub const fn new() -> Self {
        Self(std::sync::Mutex::new(None))
    }

    /// Record a check made now (the startup load counts as one).
    pub fn mark(&self) {
        if let Ok(mut last) = self.0.lock() {
            *last = Some(std::time::Instant::now());
        }
    }

    /// Whether a check is due — and if so, claim it, so concurrent appenders
    /// in this process don't both run it. Never checked counts as due.
    pub fn due(&self, every: std::time::Duration) -> bool {
        let Ok(mut last) = self.0.lock() else {
            return false;
        };
        if last.is_some_and(|t| t.elapsed() < every) {
            return false;
        }
        *last = Some(std::time::Instant::now());
        true
    }
}

/// Re-permission everything octomon has already written. `OpenOptions::mode`
/// only applies at creation, so an install that predates owner-only files would
/// keep its world-readable history forever without a pass like this. Runs once
/// at startup, best-effort, and never recurses — the data and config
/// directories are flat.
///
/// Under `sudo` it also gives back to the invoking user whatever an earlier
/// `sudo` run left root-owned there (see [`hand_back`]) — without that, an
/// install hit before files were handed back would stay unwritable to its
/// own user.
#[cfg(unix)]
pub fn tighten_permissions() {
    use std::os::unix::fs::PermissionsExt as _;
    for dir in [data_dir(), crate::config::Config::dir()]
        .into_iter()
        .flatten()
    {
        if invoker().is_some() {
            hand_back_tree(&dir);
        }
        // Only a directory this user owns, and never through a symlink: an
        // elevated run over the invoking user's home must not chmod whatever
        // a planted link points at (see `owned_by_me`).
        if !dir.is_dir() || !owned_by_me(&dir) {
            continue;
        }
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(DIR_MODE));
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // `file_type()` from the directory entry does not follow links,
            // so a symlinked file is skipped rather than its target touched.
            let regular = entry.file_type().is_ok_and(|t| t.is_file());
            if regular && owned_by_me(&path) {
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(FILE_MODE));
            }
        }
    }
}

/// The `sudo` half of [`tighten_permissions`]: one of octomon's directories
/// and the regular files directly in it, each opened without following links
/// and handed back through its descriptor. Flat, like the directories.
#[cfg(unix)]
fn hand_back_tree(dir: &std::path::Path) {
    use std::os::fd::AsFd as _;
    let Some(d) = open_nofollow(dir, true) else {
        return;
    };
    hand_back_fd(d.as_fd(), Scope::Own);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        if let Some(f) = open_nofollow(&entry.path(), false) {
            hand_back_fd(f.as_fd(), Scope::Own);
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

/// When net_history.jsonl was last checked against its cap.
static NET_HISTORY_PRUNED: PruneClock = PruneClock::new();

/// Append network changes (best-effort) — the verdict tick calls this with
/// whatever the collectors pushed since its last pass. Every
/// [`PRUNE_EVERY`] it also trims the file the way the startup load does, so a
/// `--watch` that runs for weeks stays as bounded as one restarted daily.
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
    let body: String = changes
        .iter()
        .filter_map(|c| serde_json::to_string(c).ok())
        .map(|l| l + "\n")
        .collect();
    if let Err(e) = append_locked(&path, &body) {
        crate::errlog::log(
            "store",
            format!(
                "could not append to {}: {e} — {} network changes not persisted",
                path.display(),
                changes.len()
            ),
        );
        return;
    }
    if NET_HISTORY_PRUNED.due(PRUNE_EVERY) {
        prune_net_history(&path);
    }
}

/// Trim net_history.jsonl to its tail, under the lock and from a fresh read,
/// when [`net_history_tail`] says it has outgrown its slack.
fn prune_net_history(path: &std::path::Path) {
    if let Err(e) = rewrite_locked(path, |text| net_history_tail(text).1) {
        crate::errlog::log("store", format!("could not trim {}: {e}", path.display()));
    }
}

/// The last [`crate::app::NET_HISTORY_CAP`] changes in `text`, plus — when the
/// file holds several caps' worth — the body to rewrite it down to them. The
/// slack is what keeps this from rewriting on every append once the file sits
/// at the cap: a trimmed file has to grow by three caps before it is due again.
fn net_history_tail(
    text: &str,
) -> (
    std::collections::VecDeque<crate::app::NetChange>,
    Option<String>,
) {
    let all: Vec<crate::app::NetChange> = text
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let cap = crate::app::NET_HISTORY_CAP;
    let skip = all.len().saturating_sub(cap);
    let tail: std::collections::VecDeque<_> = all.into_iter().skip(skip).collect();
    let rewrite = (skip > cap * 3).then(|| {
        tail.iter()
            .filter_map(|c| serde_json::to_string(c).ok())
            .map(|l| l + "\n")
            .collect()
    });
    (tail, rewrite)
}

/// The stored network history, oldest → newest, capped to what the pane
/// keeps. A file grown to several caps' worth is rewritten down to the tail
/// while we're here, so an always-on machine doesn't accrete an unbounded
/// log of DHCP renewals; [`append_net_changes`] repeats that during a long
/// run. Unparseable lines (older formats) are skipped.
pub fn load_net_history() -> std::collections::VecDeque<crate::app::NetChange> {
    let Some(path) = net_history_path() else {
        return Default::default();
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Default::default();
    };
    NET_HISTORY_PRUNED.mark();
    let (tail, rewrite) = net_history_tail(&text);
    // The rewrite re-reads under the lock rather than writing `rewrite`
    // as-is: a `--watch` beside us may have appended since the read above.
    if rewrite.is_some() {
        prune_net_history(&path);
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
    match serde_json::to_string(rec) {
        Ok(line) => {
            if let Err(e) = append_locked(&path, &(line + "\n")) {
                crate::errlog::log(
                    "store",
                    format!(
                        "could not append to {}: {e} — speed test not saved",
                        path.display()
                    ),
                );
            }
        }
        Err(e) => crate::errlog::log("store", format!("speed test not serializable: {e}")),
    }
}

/// Remove one record from the history file (blocking file rewrite — call off
/// the lock). Matched on timestamp + provider + the speeds, first match only:
/// `at` alone can collide when two providers are raced in the same second.
/// Rewritten under the file lock from a fresh read, so a speed test another
/// octomon process records meanwhile is not swept away with this one.
pub fn forget(rec: &SpeedRecord) {
    let Some(path) = path() else { return };
    let rewrote = rewrite_locked(&path, |text| {
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
        removed.then(|| {
            let mut out = kept.join("\n");
            if !out.is_empty() {
                out.push('\n');
            }
            out
        })
    });
    if let Err(e) = rewrote {
        crate::errlog::log(
            "store",
            format!(
                "could not rewrite {}: {e} — speed test not removed",
                path.display()
            ),
        );
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

    /// A scratch directory under the system temp dir, unique to this test and
    /// this process — never the real data directory.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("octomon-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn change(at: i64) -> String {
        let c = crate::app::NetChange {
            at,
            kind: crate::app::NetChangeKind::LinkLost,
            iface: "en0".into(),
            summary: format!("change {at}"),
            detail: Vec::new(),
        };
        serde_json::to_string(&c).unwrap() + "\n"
    }

    /// The trim has slack, so a file sitting at the cap is not rewritten on
    /// every append — only once it has grown three caps past it.
    #[test]
    fn net_history_is_trimmed_only_once_it_outgrows_the_slack() {
        let cap = crate::app::NET_HISTORY_CAP;
        let lines = |n: usize| (0..n as i64).map(change).collect::<String>();

        let (tail, rewrite) = net_history_tail(&lines(cap / 2));
        assert_eq!(tail.len(), cap / 2);
        assert!(rewrite.is_none());

        // Over the cap but within the slack: the pane still gets only the
        // tail, and the file is left alone.
        let (tail, rewrite) = net_history_tail(&lines(cap * 4));
        assert_eq!(tail.len(), cap);
        assert_eq!(tail.front().unwrap().at, (cap * 3) as i64);
        assert!(rewrite.is_none());

        let (tail, rewrite) = net_history_tail(&lines(cap * 4 + 1));
        let body = rewrite.expect("past the slack");
        assert_eq!(body.lines().count(), cap);
        assert_eq!(tail.back().unwrap().at, (cap * 4) as i64);
        // What would be written is exactly what the pane shows, newest last.
        let (again, rewrite) = net_history_tail(&body);
        assert_eq!(again.len(), cap);
        assert_eq!(again.back().unwrap().at, (cap * 4) as i64);
        assert!(rewrite.is_none());
    }

    /// The periodic prune claims its slot, so it runs once per interval no
    /// matter how often the append path asks — and the startup load counts.
    #[test]
    fn the_prune_clock_is_due_once_per_interval() {
        let every = std::time::Duration::from_secs(3600);
        let clock = PruneClock::new();
        assert!(clock.due(every), "never checked is due");
        assert!(!clock.due(every), "claimed by the first ask");
        assert!(clock.due(std::time::Duration::ZERO));

        let clock = PruneClock::new();
        clock.mark();
        assert!(!clock.due(every), "a startup load counts as a check");
    }

    /// The race this lock exists for: a line another process appends after
    /// the rewriter first read the file must survive the rewrite, because
    /// the rewrite re-reads once it holds the lock.
    #[test]
    fn a_locked_rewrite_keeps_a_line_appended_after_the_first_read() {
        let dir = scratch("rewrite");
        let path = dir.join("net_history.jsonl");
        append_locked(&path, &(change(1) + &change(2))).unwrap();

        let stale = std::fs::read_to_string(&path).unwrap();
        append_locked(&path, &change(3)).unwrap();

        // Drop the first line, as a prune would.
        let drop_first =
            |text: &str| Some(text.lines().skip(1).map(|l| format!("{l}\n")).collect());
        assert_eq!(stale.lines().count(), 2);
        assert!(rewrite_locked(&path, drop_first).unwrap());
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, change(2) + &change(3));

        // Nothing to change means nothing written, and no file is not an error.
        assert!(!rewrite_locked(&path, |_| None).unwrap());
        assert!(!rewrite_locked(&dir.join("absent.jsonl"), |_| Some(String::new())).unwrap());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, FILE_MODE, "rewritten file stays owner-only");
            let lock = dir.join(".net_history.jsonl.lock");
            let mode = std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, FILE_MODE, "the lock file is owner-only too");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// While another holder has the file, a rewrite gives up with an error
    /// instead of writing unlocked — and once it lets go, it goes through.
    #[test]
    fn a_rewrite_never_runs_while_someone_else_holds_the_lock() {
        let dir = scratch("held");
        let path = dir.join("history.jsonl");
        append_locked(&path, "a\nb\n").unwrap();

        let held = FileLock::acquire(&path).expect("free to start with");
        let err = rewrite_locked(&path, |_| Some(String::new())).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "a\nb\n");

        drop(held);
        assert!(rewrite_locked(&path, |_| Some("b\n".into())).unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "b\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Only a real `sudo` run hands anything back: root with a non-root
    /// `SUDO_UID`. An unprivileged process with sudo's variables inherited
    /// (a shell spawned from a sudo session) has nothing to give away, and a
    /// mangled variable is not guessed at.
    #[cfg(unix)]
    #[test]
    fn only_root_acting_for_someone_else_has_an_invoker() {
        assert_eq!(invoker_from(0, Some("501"), Some("20")), Some((501, 20)));
        assert_eq!(invoker_from(501, Some("501"), Some("20")), None);
        assert_eq!(invoker_from(0, Some("0"), Some("0")), None);
        assert_eq!(invoker_from(0, None, Some("20")), None);
        assert_eq!(invoker_from(0, Some("501"), None), None);
        assert_eq!(invoker_from(0, Some("-1"), Some("20")), None);
        assert_eq!(invoker_from(0, Some("alice"), Some("20")), None);
    }

    /// The line between "give the user back their file" and "give the user a
    /// file of root's" — every case a planted link could steer a resolved path
    /// into.
    #[cfg(unix)]
    #[test]
    fn only_octomons_own_files_under_the_home_are_handed_back() {
        use std::path::Path;
        let home = Path::new("/Users/alice");
        let roots = [
            PathBuf::from("/Users/alice/.local/share/octomon"),
            PathBuf::from("/Users/alice/.config/octomon"),
        ];
        let own = |p: &str| may_hand_back(Path::new(p), home, &roots, Scope::Own);
        let parent = |p: &str| may_hand_back(Path::new(p), home, &roots, Scope::CreatedParent);

        // octomon's directories and what is in them.
        assert!(own("/Users/alice/.local/share/octomon"));
        assert!(own("/Users/alice/.local/share/octomon/baselines.json"));
        assert!(own("/Users/alice/.config/octomon/.config.toml.tmp"));

        // A link steered the open somewhere else entirely.
        assert!(!own("/etc/sudoers"));
        assert!(!own("/Users/bob/.local/share/octomon/history.jsonl"));
        // A sibling whose name merely starts the same way.
        assert!(!own("/Users/alice/.local/share/octomon-old/history.jsonl"));
        assert!(!own("/Users/alicex/.local/share/octomon/history.jsonl"));
        // In the home, but not octomon's.
        assert!(!own("/Users/alice/.ssh/authorized_keys"));
        assert!(!own("/Users/alice"));
        // Lexical tricks never count as inside.
        assert!(!own(
            "/Users/alice/.local/share/octomon/../../../../etc/passwd"
        ));
        assert!(!own("relative/octomon/x"));

        // Parents: only directories on the way to one of octomon's own, and
        // never the home itself.
        assert!(parent("/Users/alice/.local"));
        assert!(parent("/Users/alice/.local/share"));
        assert!(parent("/Users/alice/.config"));
        assert!(!parent("/Users/alice"));
        assert!(!parent("/Users"));
        assert!(!parent("/Users/alice/Library"));
        // `Own` does not stretch to the parents, nor `CreatedParent` to files.
        assert!(!own("/Users/alice/.local/share"));
        assert!(!parent("/Users/alice/.local/share/octomon/errors.log"));
    }

    /// A home or a root that would make the containment checks vacuous
    /// disqualifies rather than qualifies.
    #[cfg(unix)]
    #[test]
    fn a_degenerate_home_or_root_hands_back_nothing() {
        use std::path::Path;
        let anywhere = [PathBuf::from("/etc")];
        assert!(!may_hand_back(
            Path::new("/etc/sudoers"),
            Path::new("/"),
            &anywhere,
            Scope::Own
        ));
        // An `$XDG_DATA_HOME` pointing outside the home is not octomon's to
        // hand out, even though it is octomon's directory.
        let home = Path::new("/Users/alice");
        assert!(!may_hand_back(
            Path::new("/etc/sudoers"),
            home,
            &anywhere,
            Scope::Own
        ));
        // The home named as a root does not make the whole home fair game.
        let whole = [PathBuf::from("/Users/alice")];
        assert!(!may_hand_back(
            Path::new("/Users/alice/.ssh/id_ed25519"),
            home,
            &whole,
            Scope::Own
        ));
    }

    /// Everything [`hand_back_fd`] decides rests on the descriptor reporting
    /// where it really is: through a symlinked directory, the resolved path,
    /// not the one it was opened by.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_descriptor_reports_its_resolved_path() {
        use std::os::fd::AsRawFd as _;
        let dir = std::env::temp_dir().join(format!("octomon-realpath-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("real")).unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).unwrap();
        std::fs::write(dir.join("real/f"), "x").unwrap();

        let f = std::fs::File::open(dir.join("link/f")).unwrap();
        let want = std::fs::canonicalize(dir.join("real/f")).unwrap();
        assert_eq!(real_path(f.as_raw_fd()), Some(want));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The temporary file `write_private` renames into place is created fresh
    /// even when a stale one is lying there — a hard link under that name must
    /// be replaced, not truncated through. Runs in a scratch directory, never
    /// the real data directory.
    #[test]
    fn a_stale_temporary_file_is_replaced_not_written_through() {
        let dir = std::env::temp_dir().join(format!("octomon-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, "keep me").unwrap();
        let target = dir.join("baselines.json");
        std::fs::hard_link(&victim, dir.join(".baselines.json.tmp")).unwrap();

        write_private(&target, "{}").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "{}");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep me");
        let _ = std::fs::remove_dir_all(&dir);
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
