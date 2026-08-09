//! On-demand down/up speed test against Cloudflare's public endpoints
//! (`speed.cloudflare.com`, no API key). Triggered by the user (`s` key) via a
//! [`Notify`]; deliberately not automatic, since an active test consumes real
//! bandwidth and would skew the passive throughput panel while it runs. Reports
//! live phase / progress / instantaneous rate into the shared state as it runs.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{stream, StreamExt};
use tokio::sync::Notify;

use crate::app::{AppState, SpeedStatus};

const DOWN_URL: &str = "https://speed.cloudflare.com/__down";
const UP_URL: &str = "https://speed.cloudflare.com/__up";
const DOWN_BYTES: u64 = 25 * 1024 * 1024; // 25 MiB
const UP_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB
const UP_CHUNK: usize = 64 * 1024;
const UI_UPDATE: Duration = Duration::from_millis(120);

pub async fn run(state: Arc<Mutex<AppState>>, trigger: Arc<Notify>) {
    let client = match reqwest::Client::builder()
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
            Ok((down, up)) => {
                s.speedtest.status = SpeedStatus::Done;
                s.speedtest.down_mbps = Some(down);
                s.speedtest.up_mbps = Some(up);
                s.speedtest.phase = "done".to_string();
            }
            Err(e) => {
                s.speedtest.status = SpeedStatus::Failed(e.clone());
                s.speedtest.phase = format!("failed: {e}");
            }
        }
    }
}

async fn run_once(
    client: &reqwest::Client,
    state: &Arc<Mutex<AppState>>,
) -> Result<(f64, f64), String> {
    let down = measure_download(client, state).await.map_err(|e| e.to_string())?;
    let up = measure_upload(client, state).await.map_err(|e| e.to_string())?;
    Ok((down, up))
}

/// Streams `DOWN_BYTES` from Cloudflare, updating live progress, returns Mbps.
async fn measure_download(
    client: &reqwest::Client,
    state: &Arc<Mutex<AppState>>,
) -> reqwest::Result<f64> {
    set_phase(state, "download");
    let resp = client
        .get(DOWN_URL)
        .query(&[("bytes", DOWN_BYTES.to_string())])
        .send()
        .await?
        .error_for_status()?;

    let start = Instant::now();
    let mut stream = resp.bytes_stream();
    let mut total: u64 = 0;
    let mut last = Instant::now();
    while let Some(chunk) = stream.next().await {
        total += chunk?.len() as u64;
        if last.elapsed() >= UI_UPDATE {
            update(state, total as f64 / DOWN_BYTES as f64, mbps(total, start.elapsed()));
            last = Instant::now();
        }
    }
    Ok(mbps(total, start.elapsed()))
}

/// Uploads `UP_BYTES` to Cloudflare as a chunked stream, updating live progress.
async fn measure_upload(
    client: &reqwest::Client,
    state: &Arc<Mutex<AppState>>,
) -> reqwest::Result<f64> {
    set_phase(state, "upload");
    let start = Instant::now();
    let n_chunks = (UP_BYTES as usize).div_ceil(UP_CHUNK);
    let st = state.clone();

    let body_stream = stream::iter(0..n_chunks).map(move |i| {
        let sent = ((i + 1) * UP_CHUNK).min(UP_BYTES as usize) as u64;
        update(&st, sent as f64 / UP_BYTES as f64, mbps(sent, start.elapsed()));
        Ok::<Vec<u8>, std::io::Error>(vec![0u8; UP_CHUNK])
    });

    client
        .post(UP_URL)
        .body(reqwest::Body::wrap_stream(body_stream))
        .send()
        .await?
        .error_for_status()?;
    Ok(mbps(UP_BYTES, start.elapsed()))
}

fn mbps(bytes: u64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64().max(0.001);
    (bytes as f64 * 8.0) / 1_000_000.0 / secs
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
