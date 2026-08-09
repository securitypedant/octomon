//! On-demand down/up speed test against Cloudflare's public endpoints
//! (`speed.cloudflare.com`, no API key). Triggered by the user (`s` key) via a
//! [`Notify`]; deliberately not automatic, since an active test consumes real
//! bandwidth and would skew the passive throughput panel while it runs.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use tokio::sync::Notify;

use crate::app::{AppState, SpeedStatus, SpeedTest};

const DOWN_URL: &str = "https://speed.cloudflare.com/__down";
const UP_URL: &str = "https://speed.cloudflare.com/__up";
const DOWN_BYTES: u64 = 25 * 1024 * 1024; // 25 MiB
const UP_BYTES: usize = 10 * 1024 * 1024; // 10 MiB

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
        set_status(&state, SpeedStatus::Running);

        let result = run_once(&client).await;

        let mut s = state.lock().unwrap();
        match result {
            Ok((down, up)) => {
                s.speedtest = SpeedTest {
                    status: SpeedStatus::Done,
                    down_mbps: Some(down),
                    up_mbps: Some(up),
                    last_run: Some(Instant::now()),
                };
            }
            Err(e) => {
                s.speedtest.status = SpeedStatus::Failed(e);
                s.speedtest.last_run = Some(Instant::now());
            }
        }
    }
}

async fn run_once(client: &reqwest::Client) -> Result<(f64, f64), String> {
    let down = measure_download(client).await.map_err(|e| e.to_string())?;
    let up = measure_upload(client).await.map_err(|e| e.to_string())?;
    Ok((down, up))
}

/// Streams `DOWN_BYTES` from Cloudflare and returns throughput in megabits/sec.
async fn measure_download(client: &reqwest::Client) -> reqwest::Result<f64> {
    let start = Instant::now();
    let resp = client
        .get(DOWN_URL)
        .query(&[("bytes", DOWN_BYTES.to_string())])
        .send()
        .await?
        .error_for_status()?;

    let mut stream = resp.bytes_stream();
    let mut total: u64 = 0;
    while let Some(chunk) = stream.next().await {
        total += chunk?.len() as u64;
    }
    Ok(mbps(total, start.elapsed()))
}

/// Uploads `UP_BYTES` to Cloudflare and returns throughput in megabits/sec.
async fn measure_upload(client: &reqwest::Client) -> reqwest::Result<f64> {
    let body = vec![0u8; UP_BYTES];
    let start = Instant::now();
    client
        .post(UP_URL)
        .body(body)
        .send()
        .await?
        .error_for_status()?;
    Ok(mbps(UP_BYTES as u64, start.elapsed()))
}

fn mbps(bytes: u64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64().max(0.001);
    (bytes as f64 * 8.0) / 1_000_000.0 / secs
}

fn set_status(state: &Arc<Mutex<AppState>>, status: SpeedStatus) {
    state.lock().unwrap().speedtest.status = status;
}
