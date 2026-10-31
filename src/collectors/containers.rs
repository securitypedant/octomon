//! Container traffic for the talkers table.
//!
//! A container on a bridge network has its own network namespace, and `ss`
//! lists only the sockets of the namespace it runs in — so a host whose
//! services run in Docker or Podman shows a busy interface graph over a quiet
//! processes table. This fills the gap with one row per container, built from
//! the container's own interface counters, which say how many bytes crossed
//! its eth0 but not to whom: container rows join the processes table and
//! never the remote-addresses table.
//!
//! Two sources, each used where it works:
//!
//! - **`/proc` (Linux).** Every process's `/proc/<pid>/cgroup` names the
//!   container it belongs to, and `/proc/<pid>/net/dev` is the counter table
//!   of that process's network namespace. Both are world-readable, so this
//!   works unprivileged for containers owned by other users — the one place
//!   on Linux where octomon sees other users' traffic without `sudo`. The
//!   inode of `net/dev` identifies the namespace: two containers sharing one
//!   (`--network container:X`, a Kubernetes pod) are counted once, and a
//!   host-network container, whose counters are the host's, is skipped.
//!   Without a runtime API the row carries the short container id.
//! - **The Engine API** (Docker, Podman and their lookalikes: Colima,
//!   OrbStack, Rancher Desktop, Docker Desktop on macOS and Windows). Reached
//!   over the local Unix socket or named pipe, read-only, two endpoints:
//!   the container list, for names and images, and one-shot stats, for the
//!   counters where `/proc` cannot provide them (macOS and Windows run the
//!   containers inside a VM). Never TCP: `DOCKER_HOST=tcp://…` is ignored.
//!
//! Counters are cumulative; the caller diffs them per tick exactly as it does
//! socket counters.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// One container's cumulative interface counters, as of this tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerSample {
    /// The runtime's id, 64 hex digits for every runtime that matters.
    pub id: String,
    /// Display name: the runtime's name when an API answered, else the
    /// first twelve digits of the id, which is how `docker ps` shows it.
    pub name: String,
    /// "docker", "podman", "containerd", "cri-o" — or "container" when the
    /// cgroup path says only that it is one.
    pub runtime: String,
    /// Image name, when known.
    pub image: String,
    /// The container's init process on Linux; 0 where the containers live
    /// in a VM.
    pub pid: u32,
    /// Bytes received / sent on the container's own interfaces (not `lo`).
    pub rx: u64,
    pub tx: u64,
}

impl ContainerSample {
    /// The name as the processes table shows it: `echoradio (docker)`. The
    /// runtime rides in the name so a '/' filter on "docker" keeps every
    /// container and a sort by name groups them.
    pub fn display_name(&self) -> String {
        format!("{} ({})", self.name, self.runtime)
    }
}

/// How often to look for a runtime API that was not there at startup —
/// Docker Desktop is often started after the terminal.
const API_RETRY: Duration = Duration::from_secs(60);
/// One request's budget. The socket is local; anything slower is a daemon
/// that is wedged, and the tick must not wait on it.
const API_TIMEOUT: Duration = Duration::from_secs(3);
/// Response body cap. A container list is kilobytes; a stats document a few
/// more. The daemon is trusted, but a cap costs nothing.
const API_BODY_MAX: usize = 4 << 20;

/// The per-tick sampler. Holds whichever API endpoint answered and retries
/// discovery when none has.
pub struct Source {
    enabled: bool,
    /// From the config, when set: the only endpoint tried.
    configured: Option<String>,
    api: Option<Api>,
    api_tried_at: Option<Instant>,
    /// Logged once per session: which endpoint is in use, or that none is.
    announced: bool,
    /// Set when an API was found on this tick, so the caller can treat the
    /// containers it lists as already running rather than as just started.
    fresh: bool,
}

/// What the Machine panel and `--doctor` say about containers on this
/// machine: how many are running and where octomon reads them from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Presence {
    pub running: usize,
    /// "docker", "podman", or "/proc" when no runtime API answered.
    pub via: String,
}

impl Source {
    pub fn new(cfg: &crate::config::Config) -> Self {
        Self {
            enabled: cfg.containers,
            configured: Some(cfg.container_socket.trim().to_string()).filter(|s| !s.is_empty()),
            api: None,
            api_tried_at: None,
            announced: false,
            fresh: false,
        }
    }

    /// True once after an API is found: the containers in that sample were
    /// already running, not started at that moment.
    pub fn api_just_connected(&mut self) -> bool {
        std::mem::take(&mut self.fresh)
    }

    /// The presence line, given how many containers this tick's sample held.
    /// `None` when there is nothing to say: the feature is off, or no API
    /// answered and (off Linux) nothing else can see containers — a line
    /// saying "none" on every laptop without Docker would be noise.
    pub fn presence(&self, running: usize) -> Option<Presence> {
        if !self.enabled {
            return None;
        }
        if let Some(api) = &self.api {
            return Some(Presence {
                running,
                via: api.runtime.clone(),
            });
        }
        (cfg!(target_os = "linux") && running > 0).then(|| Presence {
            running,
            via: "/proc".to_string(),
        })
    }

    /// Whether this source can produce rows at all: on Linux `/proc` always
    /// can, elsewhere only an API can — and discovery has not run yet.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// This tick's containers. Empty when there are none, or none can be
    /// seen; never an error — a runtime that stops answering just drops out.
    pub async fn sample(&mut self) -> Vec<ContainerSample> {
        if !self.enabled {
            return Vec::new();
        }
        self.discover().await;

        // /proc first: free, and the counters are read in-kernel rather than
        // through a daemon.
        let mut rows: Vec<ContainerSample> = proc_rows().await;

        let Some(api) = &self.api else {
            return rows;
        };
        let listed = match api.list().await {
            Ok(l) => l,
            Err(e) => {
                crate::errlog::log(
                    "talkers",
                    format!("container API at {} stopped answering: {e}", api.endpoint),
                );
                self.api = None;
                self.api_tried_at = Some(Instant::now());
                return rows;
            }
        };
        let runtime = api.runtime.clone();

        // Names for the rows /proc found, counters for the ones it could not.
        let by_id: HashMap<String, usize> = rows
            .iter()
            .enumerate()
            .map(|(i, r)| (r.id.clone(), i))
            .collect();
        let mut need_stats: Vec<ApiContainer> = Vec::new();
        for c in listed {
            if let Some(&i) = by_id.get(&c.id) {
                let r = &mut rows[i];
                r.name = c.name.clone();
                r.image = c.image.clone();
                r.runtime = runtime.clone();
                continue;
            }
            // A sharer's bytes are on the owner's row; a host-network
            // container's are the host's own.
            if c.network_mode == "host" || c.network_mode.starts_with("container:") {
                continue;
            }
            need_stats.push(c);
        }

        if !need_stats.is_empty() {
            let fetches = need_stats.iter().map(|c| api.stats(&c.id));
            let results = futures_util::future::join_all(fetches).await;
            for (c, r) in need_stats.into_iter().zip(results) {
                match r {
                    Ok((rx, tx)) => rows.push(ContainerSample {
                        id: c.id,
                        name: c.name,
                        runtime: runtime.clone(),
                        image: c.image,
                        pid: 0,
                        rx,
                        tx,
                    }),
                    Err(e) => crate::errlog::log(
                        "talkers",
                        format!("container stats for {} failed: {e}", c.name),
                    ),
                }
            }
        }
        rows
    }

    /// Find an API if none is held, at most once a minute.
    async fn discover(&mut self) {
        if self.api.is_some() {
            return;
        }
        if let Some(t) = self.api_tried_at
            && t.elapsed() < API_RETRY
        {
            return;
        }
        self.api_tried_at = Some(Instant::now());
        let candidates = match &self.configured {
            Some(c) => vec![Endpoint::parse(c)].into_iter().flatten().collect(),
            None => candidates(),
        };
        for ep in candidates {
            if let Some(api) = Api::probe(ep).await {
                crate::errlog::log(
                    "talkers",
                    format!(
                        "container traffic: {} API at {} — containers join the processes table",
                        api.runtime, api.endpoint
                    ),
                );
                self.api = Some(api);
                self.announced = true;
                self.fresh = true;
                return;
            }
        }
        if !self.announced {
            self.announced = true;
            let how = if cfg!(target_os = "linux") {
                "containers are read from /proc and carry their short id"
            } else {
                "container traffic is not attributed"
            };
            crate::errlog::log("talkers", format!("no container runtime API found — {how}"));
        }
    }
}

// ---------------------------------------------------------------------------
// /proc (Linux)

#[cfg(target_os = "linux")]
async fn proc_rows() -> Vec<ContainerSample> {
    tokio::task::spawn_blocking(linux::scan)
        .await
        .unwrap_or_default()
}

#[cfg(not(target_os = "linux"))]
async fn proc_rows() -> Vec<ContainerSample> {
    Vec::new()
}

/// Which runtime a cgroup path names, and the container's id. The id is the
/// 64-hex segment; the runtime is read off the segment's prefix or the
/// directory above it. Returns `None` for an ordinary process.
///
/// Shapes seen in the wild (cgroup v2 single line and v1 per-controller
/// lines both pass through here, one line at a time):
/// - `0::/system.slice/docker-<id>.scope` — Docker, systemd driver
/// - `0::/docker/<id>` — Docker, cgroupfs driver
/// - `0::/../<id>` — Docker Desktop's VM, seen from inside it
/// - `0::/user.slice/…/user@1000.service/user.slice/libpod-<id>.scope` — rootless Podman
/// - `0::/machine.slice/libpod-<id>.scope` — rootful Podman
/// - `0::/kubepods.slice/…/cri-containerd-<id>.scope` — containerd under Kubernetes
/// - `0::/kubepods/besteffort/pod…/crio-<id>.scope` — CRI-O
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn container_from_cgroup(text: &str) -> Option<(String, &'static str)> {
    fn hex64(s: &str) -> bool {
        s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
    }
    for line in text.lines() {
        // "hierarchy:controllers:path" — the path is everything after the
        // second colon; a v2 line is "0::/path".
        let path = line.splitn(3, ':').nth(2).unwrap_or("");
        let segs: Vec<&str> = path.split('/').collect();
        for (i, seg) in segs.iter().enumerate() {
            let seg = seg.strip_suffix(".scope").unwrap_or(seg);
            for (prefix, runtime) in [
                ("docker-", "docker"),
                ("libpod-", "podman"),
                ("cri-containerd-", "containerd"),
                ("crio-", "cri-o"),
            ] {
                if let Some(id) = seg.strip_prefix(prefix)
                    && hex64(id)
                {
                    return Some((id.to_string(), runtime));
                }
            }
            if hex64(seg) {
                let parent = if i > 0 { segs[i - 1] } else { "" };
                let runtime = match parent {
                    "docker" => "docker",
                    "libpod" | "podman" => "podman",
                    p if p.starts_with("libpod_parent") => "podman",
                    _ => "container",
                };
                return Some((seg.to_string(), runtime));
            }
        }
    }
    None
}

/// Sum of `/proc/<pid>/net/dev` over every interface but `lo`: (rx, tx).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_net_dev(text: &str) -> (u64, u64) {
    let (mut rx, mut tx) = (0u64, 0u64);
    for line in text.lines() {
        let Some((iface, rest)) = line.split_once(':') else {
            continue;
        };
        if iface.trim() == "lo" {
            continue;
        }
        let f: Vec<&str> = rest.split_whitespace().collect();
        if f.len() < 16 {
            continue;
        }
        rx = rx.saturating_add(f[0].parse().unwrap_or(0));
        tx = tx.saturating_add(f[8].parse().unwrap_or(0));
    }
    (rx, tx)
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{ContainerSample, container_from_cgroup, parse_net_dev};
    use std::collections::HashMap;
    use std::os::unix::fs::MetadataExt as _;

    /// One `/proc` walk: every container with its lowest pid (the init, or
    /// the oldest survivor), then one `net/dev` read per container.
    pub fn scan() -> Vec<ContainerSample> {
        // The namespace octomon itself runs in; a container found there is
        // on the host network and its counters are already the graph's.
        let own_ns = std::fs::metadata("/proc/self/net/dev")
            .map(|m| m.ino())
            .unwrap_or(0);
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return Vec::new();
        };
        // id → (runtime, lowest pid)
        let mut found: HashMap<String, (&'static str, u32)> = HashMap::new();
        for entry in dir.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Ok(cg) = std::fs::read_to_string(entry.path().join("cgroup")) else {
                continue;
            };
            let Some((id, runtime)) = container_from_cgroup(&cg) else {
                continue;
            };
            found
                .entry(id)
                .and_modify(|e| e.1 = e.1.min(pid))
                .or_insert((runtime, pid));
        }

        // namespace inode → index into rows, so a shared namespace is one row
        // (the earlier container's: the owner starts before its sharers).
        let mut by_ns: HashMap<u64, usize> = HashMap::new();
        let mut rows: Vec<ContainerSample> = Vec::new();
        let mut ids: Vec<(String, &'static str, u32)> =
            found.into_iter().map(|(id, (r, p))| (id, r, p)).collect();
        ids.sort_by_key(|(_, _, pid)| *pid);
        for (id, runtime, pid) in ids {
            let dev = format!("/proc/{pid}/net/dev");
            let Ok(meta) = std::fs::metadata(&dev) else {
                continue;
            };
            let ns = meta.ino();
            if ns == own_ns || by_ns.contains_key(&ns) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&dev) else {
                continue;
            };
            let (rx, tx) = parse_net_dev(&text);
            by_ns.insert(ns, rows.len());
            rows.push(ContainerSample {
                name: id.chars().take(12).collect(),
                id,
                runtime: runtime.to_string(),
                image: String::new(),
                pid,
                rx,
                tx,
            });
        }
        rows
    }
}

// ---------------------------------------------------------------------------
// Engine API

/// Where a runtime API listens. Local transports only.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Endpoint {
    Unix(std::path::PathBuf),
    #[cfg_attr(not(windows), allow(dead_code))]
    Pipe(String),
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Endpoint::Unix(p) => write!(f, "{}", p.display()),
            Endpoint::Pipe(p) => write!(f, "{p}"),
        }
    }
}

impl Endpoint {
    /// `unix:///path`, `npipe:////./pipe/name`, or a bare path. `tcp://` and
    /// anything else is `None`: octomon does not open network listeners of
    /// other tools, and the daemon's TCP port is unauthenticated by default.
    fn parse(s: &str) -> Option<Endpoint> {
        let s = s.trim();
        if let Some(p) = s.strip_prefix("unix://") {
            return Some(Endpoint::Unix(p.into()));
        }
        if let Some(p) = s.strip_prefix("npipe://") {
            return Some(Endpoint::Pipe(p.replace('/', "\\")));
        }
        if s.starts_with(r"\\.\pipe\") {
            return Some(Endpoint::Pipe(s.to_string()));
        }
        if s.contains("://") {
            return None;
        }
        Some(Endpoint::Unix(s.into()))
    }
}

/// Every place a local runtime API is known to listen, most common first.
/// Environment overrides lead: `DOCKER_HOST` (Docker and friends) and
/// `CONTAINER_HOST` (Podman).
fn candidates() -> Vec<Endpoint> {
    let mut v: Vec<Endpoint> = Vec::new();
    for var in ["DOCKER_HOST", "CONTAINER_HOST"] {
        if let Ok(val) = std::env::var(var)
            && let Some(ep) = Endpoint::parse(&val)
        {
            v.push(ep);
        }
    }
    if cfg!(windows) {
        v.push(Endpoint::Pipe(r"\\.\pipe\docker_engine".into()));
        v.push(Endpoint::Pipe(r"\\.\pipe\podman-machine-default".into()));
        return v;
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").ok();
    let mut paths: Vec<String> = vec!["/var/run/docker.sock".into()];
    if let Some(rd) = &runtime_dir {
        paths.push(format!("{rd}/docker.sock"));
        paths.push(format!("{rd}/podman/podman.sock"));
    }
    paths.push("/run/podman/podman.sock".into());
    if !home.is_empty() {
        for p in [
            ".docker/run/docker.sock",
            ".docker/desktop/docker.sock",
            ".colima/default/docker.sock",
            ".colima/docker.sock",
            ".orbstack/run/docker.sock",
            ".rd/docker.sock",
            ".lima/default/sock/docker.sock",
            ".local/share/containers/podman/machine/podman.sock",
            ".local/share/containers/podman/machine/podman-machine-default/podman.sock",
        ] {
            paths.push(format!("{home}/{p}"));
        }
    }
    for p in paths {
        let ep = Endpoint::Unix(p.into());
        if !v.contains(&ep) {
            v.push(ep);
        }
    }
    v
}

/// A container as the list endpoint describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ApiContainer {
    id: String,
    name: String,
    image: String,
    /// "bridge", "host", "container:<id>", or a user network's name.
    network_mode: String,
}

/// Parse `GET /containers/json`. Anything not running is dropped (the
/// default listing already omits it, but Podman's compat layer has been
/// seen to differ).
fn parse_list(body: &[u8]) -> Result<Vec<ApiContainer>, String> {
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    let arr = v.as_array().ok_or("container list is not an array")?;
    Ok(arr
        .iter()
        .filter(|c| c["State"].as_str().unwrap_or("running") == "running")
        .filter_map(|c| {
            let id = c["Id"].as_str()?.to_string();
            let name = c["Names"]
                .as_array()
                .and_then(|n| n.first())
                .and_then(|n| n.as_str())
                .map(|n| n.trim_start_matches('/').to_string())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| id.chars().take(12).collect());
            Some(ApiContainer {
                id,
                name: crate::util::strip_control(&name),
                image: crate::util::strip_control(c["Image"].as_str().unwrap_or("")),
                network_mode: c["HostConfig"]["NetworkMode"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
            })
        })
        .collect())
}

/// Parse one stats document: the sum over the container's interfaces.
/// A missing `networks` block (host networking) is zero traffic.
fn parse_stats(body: &[u8]) -> Result<(u64, u64), String> {
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    let (mut rx, mut tx) = (0u64, 0u64);
    if let Some(nets) = v["networks"].as_object() {
        for n in nets.values() {
            rx = rx.saturating_add(n["rx_bytes"].as_u64().unwrap_or(0));
            tx = tx.saturating_add(n["tx_bytes"].as_u64().unwrap_or(0));
        }
    }
    Ok((rx, tx))
}

/// Which runtime answered `GET /version`: Podman announces itself in the
/// platform name; everything else speaks Docker's API as Docker.
fn runtime_from_version(body: &[u8]) -> String {
    let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    let platform = v["Platform"]["Name"]
        .as_str()
        .unwrap_or("")
        .to_ascii_lowercase();
    let components = v["Components"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|c| c["Name"].as_str())
                .collect::<Vec<_>>()
                .join(" ")
                .to_ascii_lowercase()
        })
        .unwrap_or_default();
    if platform.contains("podman") || components.contains("podman") {
        "podman".to_string()
    } else {
        "docker".to_string()
    }
}

struct Api {
    endpoint: Endpoint,
    runtime: String,
}

impl Api {
    /// `/_ping` then `/version`; `None` unless both answer.
    async fn probe(endpoint: Endpoint) -> Option<Api> {
        let api = Api {
            endpoint,
            runtime: "docker".to_string(),
        };
        let pong = api.get("/_ping").await.ok()?;
        if pong.trim_ascii() != b"OK" {
            return None;
        }
        let version = api.get("/version").await.ok()?;
        Some(Api {
            runtime: runtime_from_version(&version),
            ..api
        })
    }

    async fn list(&self) -> Result<Vec<ApiContainer>, String> {
        parse_list(&self.get("/containers/json").await?)
    }

    /// Cumulative (rx, tx). `one-shot` keeps the daemon from sleeping a
    /// second to compute a CPU percentage nobody asked for.
    async fn stats(&self, id: &str) -> Result<(u64, u64), String> {
        parse_stats(
            &self
                .get(&format!(
                    "/containers/{id}/stats?stream=false&one-shot=true"
                ))
                .await?,
        )
    }

    /// One HTTP/1.1 GET over the local transport, body returned whole.
    async fn get(&self, path: &str) -> Result<Vec<u8>, String> {
        tokio::time::timeout(API_TIMEOUT, self.get_inner(path))
            .await
            .map_err(|_| "timed out".to_string())?
    }

    async fn get_inner(&self, path: &str) -> Result<Vec<u8>, String> {
        use http_body_util::{BodyExt as _, Empty, Limited};
        use hyper::body::Bytes;

        let req = hyper::Request::builder()
            .uri(path)
            .header(hyper::header::HOST, "localhost")
            .body(Empty::<Bytes>::new())
            .map_err(|e| e.to_string())?;

        let resp = match &self.endpoint {
            #[cfg(unix)]
            Endpoint::Unix(p) => {
                let io = tokio::net::UnixStream::connect(p)
                    .await
                    .map_err(|e| e.to_string())?;
                send(io, req).await?
            }
            #[cfg(not(unix))]
            Endpoint::Unix(_) => return Err("unix sockets are not a Windows transport".into()),
            #[cfg(windows)]
            Endpoint::Pipe(name) => {
                let io = tokio::net::windows::named_pipe::ClientOptions::new()
                    .open(name)
                    .map_err(|e| e.to_string())?;
                send(io, req).await?
            }
            #[cfg(not(windows))]
            Endpoint::Pipe(_) => return Err("named pipes are a Windows transport".into()),
        };
        let status = resp.status();
        let body = Limited::new(resp.into_body(), API_BODY_MAX)
            .collect()
            .await
            .map_err(|e| e.to_string())?
            .to_bytes();
        if !status.is_success() {
            return Err(format!("HTTP {status}"));
        }
        Ok(body.to_vec())
    }
}

/// Drive one request over an already-open stream.
async fn send<I>(
    io: I,
    req: hyper::Request<http_body_util::Empty<hyper::body::Bytes>>,
) -> Result<hyper::Response<hyper::body::Incoming>, String>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(io))
            .await
            .map_err(|e| e.to_string())?;
    // The connection task ends when the response body has been read.
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender.send_request(req).await.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_paths_name_the_runtime_and_id() {
        let id = "8013eee81deccbb900269df8a41a2e0f656b732ad219b1d67e67a73823754b33";
        let cases = [
            (format!("0::/system.slice/docker-{id}.scope"), "docker"),
            (format!("0::/docker/{id}"), "docker"),
            // Docker Desktop's VM, seen from a container with the host's pids.
            (format!("0::/../{id}"), "container"),
            (
                format!(
                    "0::/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-{id}.scope"
                ),
                "podman",
            ),
            (format!("0::/machine.slice/libpod-{id}.scope"), "podman"),
            (
                format!(
                    "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1.slice/cri-containerd-{id}.scope"
                ),
                "containerd",
            ),
            (
                format!("0::/kubepods/besteffort/podX/crio-{id}.scope"),
                "cri-o",
            ),
            // cgroup v1: one line per controller, the path after two colons.
            (
                format!(
                    "12:pids:/docker/{id}\n11:memory:/docker/{id}\n1:name=systemd:/docker/{id}"
                ),
                "docker",
            ),
        ];
        for (text, runtime) in cases {
            assert_eq!(
                container_from_cgroup(&text),
                Some((id.to_string(), runtime)),
                "{text}"
            );
        }
        for plain in [
            "0::/",
            "0::/user.slice/user-1000.slice/session-2.scope",
            "0::/system.slice/nginx.service",
            // A 63-digit id is not an id.
            &format!("0::/docker/{}", &id[..63]),
            "0::/../..",
        ] {
            assert_eq!(container_from_cgroup(plain), None, "{plain}");
        }
    }

    #[test]
    fn net_dev_sums_every_interface_but_loopback() {
        let text = "Inter-|   Receive                                                |  Transmit\n \
            face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    \
            lo: 40088231   65849    0    0    0     0          0         0 40088231   65849    0    0    0     0       0          0\n \
            tunl0:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n  \
            eth0: 11012149    2351    0    0    0     0          0         0   364553    2282    0    0    0     0       0          0\n  \
            eth1:     1000      10    0    0    0     0          0         0      500       5    0    0    0     0       0          0\n";
        assert_eq!(parse_net_dev(text), (11_013_149, 365_053));
        assert_eq!(parse_net_dev(""), (0, 0));
    }

    #[test]
    fn container_list_keeps_running_ones_with_names_and_modes() {
        let body = br#"[
          {"Id":"8013eee81deccbb900269df8a41a2e0f656b732ad219b1d67e67a73823754b33","Names":["/echoradio"],"Image":"echoradio:dev","State":"running","HostConfig":{"NetworkMode":"echoradio_default"}},
          {"Id":"0313970000000000000000000000000000000000000000000000000000000000","Names":["/octo_sharer"],"Image":"alpine","State":"running","HostConfig":{"NetworkMode":"container:8013eee81deccbb900269df8a41a2e0f656b732ad219b1d67e67a73823754b33"}},
          {"Id":"08a8c2d800000000000000000000000000000000000000000000000000000000","Names":[],"Image":"alpine","State":"running","HostConfig":{"NetworkMode":"host"}},
          {"Id":"dead000000000000000000000000000000000000000000000000000000000000","Names":["/gone"],"Image":"alpine","State":"exited","HostConfig":{"NetworkMode":"bridge"}}
        ]"#;
        let list = parse_list(body).unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].name, "echoradio");
        assert_eq!(list[0].image, "echoradio:dev");
        assert_eq!(list[0].network_mode, "echoradio_default");
        assert!(list[1].network_mode.starts_with("container:"));
        assert_eq!(list[2].name, "08a8c2d80000", "no name: the short id");
        assert!(parse_list(b"{}").is_err());
    }

    #[test]
    fn stats_sum_interfaces_and_tolerate_host_networking() {
        let body = br#"{"read":"2026-10-27T02:54:53Z","networks":{"eth0":{"rx_bytes":10080297,"tx_bytes":346902},"eth1":{"rx_bytes":3,"tx_bytes":4}},"cpu_stats":{}}"#;
        assert_eq!(parse_stats(body).unwrap(), (10_080_300, 346_906));
        assert_eq!(parse_stats(br#"{"read":"x"}"#).unwrap(), (0, 0));
        assert!(parse_stats(b"nope").is_err());
    }

    #[test]
    fn version_tells_podman_from_docker() {
        assert_eq!(
            runtime_from_version(br#"{"Platform":{"Name":"Docker Desktop 4.96.3 (244472)"},"Components":[{"Name":"Engine"}]}"#),
            "docker"
        );
        assert_eq!(
            runtime_from_version(
                br#"{"Platform":{"Name":"Podman Engine"},"Components":[{"Name":"Podman Engine"}]}"#
            ),
            "podman"
        );
        assert_eq!(runtime_from_version(b"garbage"), "docker");
    }

    #[test]
    fn endpoints_are_local_transports_only() {
        assert_eq!(
            Endpoint::parse("unix:///var/run/docker.sock"),
            Some(Endpoint::Unix("/var/run/docker.sock".into()))
        );
        assert_eq!(
            Endpoint::parse("/run/podman/podman.sock"),
            Some(Endpoint::Unix("/run/podman/podman.sock".into()))
        );
        assert_eq!(
            Endpoint::parse("npipe:////./pipe/docker_engine"),
            Some(Endpoint::Pipe(r"\\.\pipe\docker_engine".into()))
        );
        assert_eq!(Endpoint::parse("tcp://127.0.0.1:2375"), None);
        assert_eq!(Endpoint::parse("ssh://host"), None);
    }

    #[test]
    fn display_name_carries_the_runtime() {
        let c = ContainerSample {
            id: "abc".into(),
            name: "echoradio".into(),
            runtime: "docker".into(),
            image: String::new(),
            pid: 0,
            rx: 0,
            tx: 0,
        };
        assert_eq!(c.display_name(), "echoradio (docker)");
    }
}
