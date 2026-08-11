//! On-demand speed test with a user-selectable provider.
//!
//! HTTP providers (Cloudflare, LibreSpeed) share one parallel-stream engine:
//! several connections run for a fixed duration, an initial warm-up is discarded
//! so TCP slow-start doesn't bias the result, and throughput is the steady-state
//! bytes/second. M-Lab NDT7 speaks WebSockets and lives in [`crate::collectors::ndt7`].
//! Only the selected provider runs (no fallback); on failure the reason is shown.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{StreamExt, stream};
use tokio::sync::Notify;

use crate::app::{AppState, SpeedStatus};
use crate::collectors::ndt7;

const STREAMS: usize = 4;
const WARMUP: Duration = Duration::from_secs(2);
const MEASURE: Duration = Duration::from_secs(6);
const UP_CHUNK: usize = 64 * 1024;
pub(crate) const TICK: Duration = Duration::from_millis(200);

/// A speed-test provider, carrying its (config-driven) endpoint URLs.
#[derive(Clone)]
pub enum Provider {
    /// Cloudflare base URL.
    Cloudflare(String),
    /// LibreSpeed: an explicit backend base URL, or a server-list URL to auto-pick.
    LibreSpeed {
        server: Option<String>,
        list_url: String,
    },
    /// M-Lab locate service URL.
    Mlab(String),
}

impl Provider {
    /// Resolve a provider name against config.
    pub fn from_name(name: &str, cfg: &crate::config::Config) -> Option<Provider> {
        match name.to_lowercase().as_str() {
            "cloudflare" | "cf" => Some(Provider::Cloudflare(cfg.cloudflare_url.clone())),
            "mlab" | "m-lab" | "ndt7" => Some(Provider::Mlab(cfg.mlab_locate_url.clone())),
            "librespeed" => Some(Provider::LibreSpeed {
                server: cfg.librespeed_server.clone(),
                list_url: cfg.librespeed_server_list.clone(),
            }),
            _ => None,
        }
    }
}

/// Result of a completed test.
pub struct Report {
    pub provider: String,
    pub down_mbps: f64,
    pub up_mbps: f64,
    pub idle_ms: Option<f64>,
    pub loaded_ms: Option<f64>,
}

/// Endpoint shape for an HTTP provider.
struct HttpSpec {
    name: &'static str,
    down_url: String,
    down_param: &'static str,
    down_size: u64,
    up_url: String,
    probe_url: String,
}

fn cloudflare_spec(base: &str) -> HttpSpec {
    let base = base.trim_end_matches('/');
    HttpSpec {
        name: "Cloudflare",
        down_url: format!("{base}/__down"),
        down_param: "bytes",
        down_size: 99_000_000, // just under the 100 MB cap
        up_url: format!("{base}/__up"),
        probe_url: format!("{base}/__down?bytes=1"),
    }
}

fn librespeed_spec(base: &str) -> HttpSpec {
    let base = base.trim_end_matches('/');
    HttpSpec {
        name: "LibreSpeed",
        down_url: format!("{base}/garbage.php"),
        down_param: "ckSize", // in MB
        down_size: 90,
        up_url: format!("{base}/empty.php"),
        probe_url: format!("{base}/empty.php"),
    }
}

pub async fn run(state: Arc<Mutex<AppState>>, trigger: Arc<Notify>, cfg: crate::config::Config) {
    let client = match reqwest::Client::builder()
        .pool_max_idle_per_host(STREAMS)
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("speedtest client: {e}");
            return;
        }
    };

    loop {
        trigger.notified().await;

        // Run only the user-selected provider (no fallback).
        let selected = {
            let s = state.lock().unwrap();
            s.speedtest_provider_names
                .get(s.speedtest_provider_idx)
                .cloned()
        };
        let result = match selected.as_deref() {
            Some(name) => match Provider::from_name(name, &cfg) {
                Some(provider) => run_provider(&client, &state, &provider).await,
                None => Err(format!("unknown provider '{name}'")),
            },
            None => Err("no provider selected".to_string()),
        };

        let mut s = state.lock().unwrap();
        s.speedtest.progress = 0.0;
        s.speedtest.live_mbps = 0.0;
        s.speedtest.last_run = Some(Instant::now());
        match result {
            Ok(r) => {
                let record = crate::store::SpeedRecord {
                    at: chrono::Utc::now().timestamp(),
                    provider: r.provider.clone(),
                    down_mbps: r.down_mbps,
                    up_mbps: r.up_mbps,
                    idle_ms: r.idle_ms,
                    loaded_ms: r.loaded_ms,
                };
                crate::store::append(&record);
                s.speed_history.push(record);
                s.speed_total += 1;

                s.speedtest.status = SpeedStatus::Done;
                s.speedtest.provider = r.provider;
                s.speedtest.down_mbps = Some(r.down_mbps);
                s.speedtest.up_mbps = Some(r.up_mbps);
                s.speedtest.idle_latency_ms = r.idle_ms;
                s.speedtest.loaded_latency_ms = r.loaded_ms;
                s.speedtest.phase = "done".to_string();
            }
            Err(e) => {
                s.speedtest.status = SpeedStatus::Failed(e.clone());
                s.speedtest.phase = format!("failed: {e}");
            }
        }
    }
}

async fn run_provider(
    client: &reqwest::Client,
    state: &Arc<Mutex<AppState>>,
    provider: &Provider,
) -> Result<Report, String> {
    match provider {
        Provider::Cloudflare(base) => run_http(client, state, cloudflare_spec(base)).await,
        Provider::LibreSpeed { server, list_url } => {
            let spec = match server {
                Some(base) => librespeed_spec(base),
                None => librespeed_pick(client, state, list_url).await?,
            };
            run_http(client, state, spec).await
        }
        Provider::Mlab(locate) => ndt7::run(client, state, locate).await,
    }
}

/// Pick a public LibreSpeed server: fetch the list, ping several, use the
/// lowest-latency responder.
async fn librespeed_pick(
    client: &reqwest::Client,
    state: &Arc<Mutex<AppState>>,
    list_url: &str,
) -> Result<HttpSpec, String> {
    set_phase(state, "LibreSpeed · finding server");
    let text = crate::util::fetch_text_capped(client, list_url, 512 * 1024)
        .await
        .map_err(|e| format!("server list: {e}"))?;
    let list: Vec<serde_json::Value> =
        serde_json::from_str(&text).map_err(|e| format!("server list json: {e}"))?;

    // (server, dlURL, ulURL, pingURL) for the first several entries.
    let cands: Vec<(String, String, String, String)> = list
        .iter()
        .filter_map(|e| {
            let server = e["server"].as_str()?;
            let server = server
                .strip_prefix("//")
                .map(|r| format!("https://{r}"))
                .unwrap_or_else(|| server.to_string());
            Some((
                server,
                e["dlURL"].as_str()?.to_string(),
                e["ulURL"].as_str()?.to_string(),
                e["pingURL"].as_str()?.to_string(),
            ))
        })
        .take(12)
        .collect();
    if cands.is_empty() {
        return Err("no LibreSpeed servers in list".to_string());
    }

    // Ping each (bounded), pick the fastest responder.
    let latencies = futures_util::future::join_all(cands.iter().map(|(server, _, _, ping)| {
        let url = join_url(server, ping);
        async move {
            tokio::time::timeout(Duration::from_secs(2), probe_latency(client, &url))
                .await
                .ok()
                .flatten()
        }
    }))
    .await;

    let best = latencies
        .iter()
        .enumerate()
        .filter_map(|(i, l)| l.map(|ms| (i, ms)))
        .min_by(|a, b| a.1.total_cmp(&b.1));
    let (i, _) = best.ok_or("no LibreSpeed server responded")?;
    let (server, dl, ul, ping) = &cands[i];
    Ok(HttpSpec {
        name: "LibreSpeed",
        down_url: join_url(server, dl),
        down_param: "ckSize",
        down_size: 90,
        up_url: join_url(server, ul),
        probe_url: join_url(server, ping),
    })
}

fn join_url(base: &str, path: &str) -> String {
    if path.starts_with("http") {
        return path.to_string();
    }
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

#[derive(Clone, Copy)]
enum Dir {
    Down,
    Up,
}

impl Dir {
    fn label(self) -> &'static str {
        match self {
            Dir::Down => "download",
            Dir::Up => "upload",
        }
    }
}

async fn run_http(
    client: &reqwest::Client,
    state: &Arc<Mutex<AppState>>,
    spec: HttpSpec,
) -> Result<Report, String> {
    let spec = Arc::new(spec);

    set_phase(state, &format!("{} · latency", spec.name));
    let idle_ms = idle_latency(client, &spec.probe_url).await;

    let (down_mbps, mut rtts) = measure(client, state, &spec, Dir::Down).await?;
    let (up_mbps, up_rtts) = measure(client, state, &spec, Dir::Up).await?;
    rtts.extend(up_rtts);

    Ok(Report {
        provider: spec.name.to_string(),
        down_mbps,
        up_mbps,
        idle_ms,
        loaded_ms: median(&mut rtts),
    })
}

/// Run `STREAMS` transfers for WARMUP+MEASURE, returning steady-state Mbps and
/// the latency samples gathered while loaded.
async fn measure(
    client: &reqwest::Client,
    state: &Arc<Mutex<AppState>>,
    spec: &Arc<HttpSpec>,
    dir: Dir,
) -> Result<(f64, Vec<f64>), String> {
    set_phase(state, &format!("{} · {}", spec.name, dir.label()));
    let total = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::new();
    for _ in 0..STREAMS {
        let (c, sp, t, s) = (client.clone(), spec.clone(), total.clone(), stop.clone());
        handles.push(tokio::spawn(async move {
            match dir {
                Dir::Down => down_stream(c, sp, t, s).await,
                Dir::Up => up_stream(c, sp, t, s).await,
            }
        }));
    }

    let (mbps, rtts) = controller(client, state, &total, &spec.probe_url).await;
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.abort();
    }

    if total.load(Ordering::Relaxed) == 0 {
        return Err(format!(
            "{} got no data (endpoint may be rate-limiting — retry shortly)",
            dir.label()
        ));
    }
    Ok((mbps, rtts))
}

async fn controller(
    client: &reqwest::Client,
    state: &Arc<Mutex<AppState>>,
    total: &AtomicU64,
    probe_url: &str,
) -> (f64, Vec<f64>) {
    let rtts: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
    let start = Instant::now();
    let full = WARMUP + MEASURE;
    let mut ticker = tokio::time::interval(TICK);
    let mut last_bytes = 0u64;
    let mut last_t = start;
    let mut measure_start: Option<(Instant, u64)> = None;
    let mut since_probe = Duration::ZERO;

    loop {
        ticker.tick().await;
        let elapsed = start.elapsed();
        let bytes = total.load(Ordering::Relaxed);

        let dt = last_t.elapsed().as_secs_f64().max(0.001);
        let live = (bytes.saturating_sub(last_bytes)) as f64 * 8.0 / 1_000_000.0 / dt;
        last_bytes = bytes;
        last_t = Instant::now();
        update(
            state,
            (elapsed.as_secs_f64() / full.as_secs_f64()).min(1.0),
            live,
        );

        if measure_start.is_none() && elapsed >= WARMUP {
            measure_start = Some((Instant::now(), bytes));
        }

        if elapsed >= WARMUP {
            since_probe += TICK;
            if since_probe >= Duration::from_millis(600) {
                since_probe = Duration::ZERO;
                let (c, r, url) = (client.clone(), rtts.clone(), probe_url.to_string());
                tokio::spawn(async move {
                    if let Some(ms) = probe_latency(&c, &url).await {
                        r.lock().unwrap().push(ms);
                    }
                });
            }
        }

        if elapsed >= full {
            let (mt, mb) = measure_start.unwrap_or((start, 0));
            let secs = mt.elapsed().as_secs_f64().max(0.001);
            let mbps = (bytes.saturating_sub(mb)) as f64 * 8.0 / 1_000_000.0 / secs;
            let out = rtts.lock().unwrap().clone();
            return (mbps, out);
        }
    }
}

async fn down_stream(
    client: reqwest::Client,
    spec: Arc<HttpSpec>,
    total: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) {
    let mut backoff = Duration::from_millis(200);
    while !stop.load(Ordering::Relaxed) {
        let resp = client
            .get(&spec.down_url)
            .query(&[(spec.down_param, spec.down_size.to_string())])
            .send()
            .await
            .and_then(|r| r.error_for_status());
        let resp = match resp {
            Ok(r) => {
                backoff = Duration::from_millis(200);
                r
            }
            Err(_) => {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(3));
                continue;
            }
        };
        let mut body = resp.bytes_stream();
        while let Some(item) = body.next().await {
            match item {
                Ok(chunk) => total.fetch_add(chunk.len() as u64, Ordering::Relaxed),
                Err(_) => break,
            };
            if stop.load(Ordering::Relaxed) {
                return;
            }
        }
    }
}

async fn up_stream(
    client: reqwest::Client,
    spec: Arc<HttpSpec>,
    total: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) {
    let mut backoff = Duration::from_millis(200);
    while !stop.load(Ordering::Relaxed) {
        let (t, s) = (total.clone(), stop.clone());
        let body = reqwest::Body::wrap_stream(stream::unfold(0u64, move |sent| {
            let (t, s) = (t.clone(), s.clone());
            async move {
                if s.load(Ordering::Relaxed) {
                    return None;
                }
                t.fetch_add(UP_CHUNK as u64, Ordering::Relaxed);
                Some((
                    Ok::<_, std::io::Error>(vec![0u8; UP_CHUNK]),
                    sent + UP_CHUNK as u64,
                ))
            }
        }));
        match client
            .post(&spec.up_url)
            .body(body)
            .send()
            .await
            .and_then(|r| r.error_for_status())
        {
            Ok(_) => backoff = Duration::from_millis(200),
            Err(_) => {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(3));
            }
        }
    }
}

async fn idle_latency(client: &reqwest::Client, probe_url: &str) -> Option<f64> {
    let mut best: Option<f64> = None;
    for _ in 0..5 {
        if let Some(ms) = probe_latency(client, probe_url).await {
            best = Some(best.map_or(ms, |b| b.min(ms)));
        }
    }
    best
}

async fn probe_latency(client: &reqwest::Client, probe_url: &str) -> Option<f64> {
    let start = Instant::now();
    let resp = client.get(probe_url).send().await.ok()?;
    // These endpoints return tiny/empty bodies; cap in case a server misbehaves.
    crate::util::drain_capped(resp, 64 * 1024).await;
    Some(start.elapsed().as_secs_f64() * 1000.0)
}

pub(crate) fn mbps(bytes: u64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64().max(0.001);
    (bytes as f64 * 8.0) / 1_000_000.0 / secs
}

fn median(v: &mut [f64]) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(f64::total_cmp);
    Some(v[v.len() / 2])
}

pub(crate) fn set_phase(state: &Arc<Mutex<AppState>>, phase: &str) {
    let mut s = state.lock().unwrap();
    s.speedtest.phase = phase.to_string();
    s.speedtest.progress = 0.0;
    s.speedtest.live_mbps = 0.0;
}

pub(crate) fn update(state: &Arc<Mutex<AppState>>, progress: f64, live_mbps: f64) {
    let mut s = state.lock().unwrap();
    s.speedtest.progress = progress.clamp(0.0, 1.0);
    s.speedtest.live_mbps = live_mbps;
}
