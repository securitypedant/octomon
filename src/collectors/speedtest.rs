//! On-demand down/up speed test against Cloudflare's public endpoints
//! (`speed.cloudflare.com`, no API key). Triggered by the user (`s` key) via a
//! [`Notify`].
//!
//! Method (mirroring how a real speed test works, unlike a single fixed-size
//! transfer): several parallel connections run for a fixed duration, an initial
//! warm-up is discarded so TCP slow-start doesn't bias the result, and
//! throughput is the steady-state bytes/second across the remaining window.
//! Small latency probes during the loaded phases yield a bufferbloat figure.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{stream, StreamExt};
use tokio::sync::Notify;

use crate::app::{AppState, SpeedStatus};

const DOWN_URL: &str = "https://speed.cloudflare.com/__down";
const UP_URL: &str = "https://speed.cloudflare.com/__up";

const STREAMS: usize = 6; // parallel connections per direction
const WARMUP: Duration = Duration::from_secs(2); // discarded (slow-start ramp)
const MEASURE: Duration = Duration::from_secs(6); // steady-state window
// Per-request size; streams reconnect if exhausted, so this bounds reconnect
// overhead (bigger = fewer reconnects on fast links), not total throughput.
// Cloudflare's __down rejects bytes >= 100_000_000 with 403, so sit just under.
const REQ_BYTES: u64 = 99_000_000;
const UP_CHUNK: usize = 64 * 1024;
const TICK: Duration = Duration::from_millis(200);

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

struct Report {
    down_mbps: f64,
    up_mbps: f64,
    idle_ms: Option<f64>,
    loaded_ms: Option<f64>,
}

pub async fn run(state: Arc<Mutex<AppState>>, trigger: Arc<Notify>) {
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
        let result = run_once(&client, &state).await;

        let mut s = state.lock().unwrap();
        s.speedtest.progress = 0.0;
        s.speedtest.live_mbps = 0.0;
        s.speedtest.last_run = Some(Instant::now());
        match result {
            Ok(r) => {
                s.speedtest.status = SpeedStatus::Done;
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

async fn run_once(client: &reqwest::Client, state: &Arc<Mutex<AppState>>) -> Result<Report, String> {
    // Unloaded baseline latency.
    set_phase(state, "latency");
    let idle_ms = idle_latency(client).await;

    let (down_mbps, mut rtts) = measure(client, state, Dir::Down).await?;
    let (up_mbps, up_rtts) = measure(client, state, Dir::Up).await?;
    rtts.extend(up_rtts);

    let loaded_ms = median(&mut rtts);
    Ok(Report {
        down_mbps,
        up_mbps,
        idle_ms,
        loaded_ms,
    })
}

/// Run `STREAMS` transfers for WARMUP+MEASURE, returning steady-state Mbps and
/// the latency samples gathered while loaded.
async fn measure(
    client: &reqwest::Client,
    state: &Arc<Mutex<AppState>>,
    dir: Dir,
) -> Result<(f64, Vec<f64>), String> {
    set_phase(state, dir.label());
    let total = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::new();
    for _ in 0..STREAMS {
        let (c, t, s) = (client.clone(), total.clone(), stop.clone());
        handles.push(tokio::spawn(async move {
            match dir {
                Dir::Down => down_stream(c, t, s).await,
                Dir::Up => up_stream(c, t, s).await,
            }
        }));
    }

    let (mbps, rtts) = controller(client, state, &total).await;
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.abort();
    }

    if total.load(Ordering::Relaxed) == 0 {
        return Err(format!("{} transfer produced no data", dir.label()));
    }
    Ok((mbps, rtts))
}

/// Drives timing: live updates, warm-up boundary, steady-state rate, and
/// periodic loaded-latency probes.
async fn controller(
    client: &reqwest::Client,
    state: &Arc<Mutex<AppState>>,
    total: &AtomicU64,
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

        // Live instantaneous throughput for the gauge.
        let dt = last_t.elapsed().as_secs_f64().max(0.001);
        let live = (bytes.saturating_sub(last_bytes)) as f64 * 8.0 / 1_000_000.0 / dt;
        last_bytes = bytes;
        last_t = Instant::now();
        update(state, (elapsed.as_secs_f64() / full.as_secs_f64()).min(1.0), live);

        if measure_start.is_none() && elapsed >= WARMUP {
            measure_start = Some((Instant::now(), bytes));
        }

        // Probe loaded latency ~every 600ms once past warm-up.
        if elapsed >= WARMUP {
            since_probe += TICK;
            if since_probe >= Duration::from_millis(600) {
                since_probe = Duration::ZERO;
                let (c, r) = (client.clone(), rtts.clone());
                tokio::spawn(async move {
                    if let Some(ms) = probe_latency(&c).await {
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

/// Repeatedly download large responses, counting bytes, until stopped.
async fn down_stream(client: reqwest::Client, total: Arc<AtomicU64>, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        let resp = client
            .get(DOWN_URL)
            .query(&[("bytes", REQ_BYTES.to_string())])
            .send()
            .await;
        let resp = match resp.and_then(|r| r.error_for_status()) {
            Ok(r) => r,
            Err(_) => {
                // e.g. an oversized `bytes` value → 403; back off briefly.
                tokio::time::sleep(Duration::from_millis(50)).await;
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

/// Repeatedly upload a streamed body, counting bytes handed to the socket.
async fn up_stream(client: reqwest::Client, total: Arc<AtomicU64>, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        let (t, s) = (total.clone(), stop.clone());
        let body = reqwest::Body::wrap_stream(stream::unfold(0u64, move |sent| {
            let (t, s) = (t.clone(), s.clone());
            async move {
                if s.load(Ordering::Relaxed) || sent >= REQ_BYTES {
                    return None;
                }
                t.fetch_add(UP_CHUNK as u64, Ordering::Relaxed);
                Some((Ok::<_, std::io::Error>(vec![0u8; UP_CHUNK]), sent + UP_CHUNK as u64))
            }
        }));
        let _ = client.post(UP_URL).body(body).send().await;
    }
}

/// Baseline (unloaded) latency: the minimum of a few small round-trips.
async fn idle_latency(client: &reqwest::Client) -> Option<f64> {
    let mut best: Option<f64> = None;
    for _ in 0..5 {
        if let Some(ms) = probe_latency(client).await {
            best = Some(best.map_or(ms, |b| b.min(ms)));
        }
    }
    best
}

/// One tiny request timed end to end, in milliseconds.
async fn probe_latency(client: &reqwest::Client) -> Option<f64> {
    let start = Instant::now();
    let resp = client
        .get(DOWN_URL)
        .query(&[("bytes", "1")])
        .send()
        .await
        .ok()?;
    resp.bytes().await.ok()?;
    Some(start.elapsed().as_secs_f64() * 1000.0)
}

fn median(v: &mut [f64]) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(f64::total_cmp);
    Some(v[v.len() / 2])
}

fn set_phase(state: &Arc<Mutex<AppState>>, phase: &str) {
    let mut s = state.lock().unwrap();
    s.speedtest.phase = phase.to_string();
    s.speedtest.progress = 0.0;
    s.speedtest.live_mbps = 0.0;
}

fn update(state: &Arc<Mutex<AppState>>, progress: f64, live_mbps: f64) {
    let mut s = state.lock().unwrap();
    s.speedtest.progress = progress.clamp(0.0, 1.0);
    s.speedtest.live_mbps = live_mbps;
}
