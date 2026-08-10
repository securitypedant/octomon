//! M-Lab NDT7 speed test over WebSockets.
//!
//! Flow: query M-Lab's locate service for a nearby server (returns tokenised
//! `wss://` download/upload URLs), then run each test for a fixed duration.
//! Download throughput is the bytes received; upload is the bytes sent (the
//! socket applies backpressure, so this tracks what actually goes on the wire).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{Bytes, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

use crate::app::AppState;
use crate::collectors::speedtest::{Report, TICK, mbps, set_phase, update};

const SUBPROTOCOL: &str = "net.measurementlab.ndt.v7";
const DURATION: Duration = Duration::from_secs(10);
const UP_MSG: usize = 1 << 16; // 64 KiB upload messages

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub async fn run(
    client: &reqwest::Client,
    state: &Arc<Mutex<AppState>>,
    locate_url: &str,
) -> Result<Report, String> {
    set_phase(state, "M-Lab · locate");
    let (down_url, up_url) = locate(client, locate_url).await?;

    set_phase(state, "M-Lab · download");
    let down_mbps = download(state, &down_url).await?;

    set_phase(state, "M-Lab · upload");
    let up_mbps = upload(state, &up_url).await?;

    Ok(Report {
        provider: "M-Lab".to_string(),
        down_mbps,
        up_mbps,
        idle_ms: None,
        loaded_ms: None,
    })
}

/// Ask the locate service for a server, returning (download_url, upload_url).
async fn locate(client: &reqwest::Client, locate_url: &str) -> Result<(String, String), String> {
    let text = client
        .get(locate_url)
        .send()
        .await
        .map_err(|e| format!("locate: {e}"))?
        .text()
        .await
        .map_err(|e| format!("locate body: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("locate json: {e}"))?;

    let urls = v["results"][0]["urls"]
        .as_object()
        .ok_or("locate: no server returned")?;
    let get = |k: &str| urls.get(k).and_then(|x| x.as_str()).map(str::to_string);
    let down = get("wss:///ndt/v7/download").ok_or("locate: no download url")?;
    let up = get("wss:///ndt/v7/upload").ok_or("locate: no upload url")?;
    Ok((down, up))
}

async fn connect(url: &str) -> Result<Ws, String> {
    let mut req = url.into_client_request().map_err(|e| e.to_string())?;
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        SUBPROTOCOL.parse().expect("valid header value"),
    );
    let (ws, _resp) = connect_async(req).await.map_err(|e| e.to_string())?;
    Ok(ws)
}

/// Count bytes received over the download socket for DURATION.
async fn download(state: &Arc<Mutex<AppState>>, url: &str) -> Result<f64, String> {
    let mut ws = connect(url).await?;
    let start = Instant::now();
    let mut bytes = 0u64;
    let mut last = Instant::now();

    let deadline = tokio::time::sleep(DURATION);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            msg = ws.next() => match msg {
                Some(Ok(Message::Binary(b))) => bytes += b.len() as u64,
                Some(Ok(_)) => {} // text measurement / ping
                _ => break,      // closed or error
            },
        }
        if last.elapsed() >= TICK {
            let secs = start.elapsed();
            update(
                state,
                secs.as_secs_f64() / DURATION.as_secs_f64(),
                mbps(bytes, secs),
            );
            last = Instant::now();
        }
    }
    Ok(mbps(bytes, start.elapsed()))
}

/// Send binary messages as fast as the socket accepts for DURATION.
async fn upload(state: &Arc<Mutex<AppState>>, url: &str) -> Result<f64, String> {
    let ws = connect(url).await?;
    let (mut write, mut read) = ws.split();
    // Drain the server's measurement/control frames so the socket stays healthy.
    let reader = tokio::spawn(async move { while read.next().await.is_some() {} });

    let payload = Bytes::from(vec![0u8; UP_MSG]);
    let start = Instant::now();
    let mut sent = 0u64;
    let mut last = Instant::now();

    let deadline = tokio::time::sleep(DURATION);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            r = write.send(Message::Binary(payload.clone())) => match r {
                Ok(()) => sent += UP_MSG as u64,
                Err(_) => break,
            },
        }
        if last.elapsed() >= TICK {
            let secs = start.elapsed();
            update(
                state,
                secs.as_secs_f64() / DURATION.as_secs_f64(),
                mbps(sent, secs),
            );
            last = Instant::now();
        }
    }
    let _ = write.close().await;
    reader.abort();
    Ok(mbps(sent, start.elapsed()))
}
