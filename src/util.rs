//! Small networking helpers with a hard cap on response size, so a hostile or
//! compromised third-party endpoint (public-IP service, M-Lab locate,
//! community-run LibreSpeed servers) can't exhaust memory with a huge body.

use futures_util::StreamExt;

/// The release version with the build stamp from `build.rs` when there is
/// one: `0.5.2 · build 143 (b91da39+)` from a checkout, plain `0.5.2` from a
/// crates.io build. What every "which octomon is this?" surface prints.
pub const VERSION: &str = env!("OCTOMON_VERSION_FULL");

/// GET `url` and return the body as text, failing if it exceeds `max_bytes`.
pub async fn fetch_text_capped(
    client: &reqwest::Client,
    url: &str,
    max_bytes: usize,
) -> Result<String, String> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?;
    let buf = read_capped(resp, max_bytes).await?;
    String::from_utf8(buf).map_err(|_| "non-UTF-8 response".to_string())
}

/// Read a response body, failing as soon as it would exceed `max_bytes` —
/// while streaming, so an oversized body never lands in memory. For callers
/// that need to shape the request themselves (extra headers, the final URL
/// after redirects) before handing the response over.
pub async fn read_capped(resp: reqwest::Response, max_bytes: usize) -> Result<Vec<u8>, String> {
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| e.to_string())?;
        if buf.len() + chunk.len() > max_bytes {
            return Err("response exceeded size limit".to_string());
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Drain (and discard) a response body up to `max_bytes`, used by latency
/// probes that only care about round-trip time, not the content.
pub async fn drain_capped(resp: reqwest::Response, max_bytes: usize) {
    let mut stream = resp.bytes_stream();
    let mut total = 0usize;
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(c) => {
                total += c.len();
                if total > max_bytes {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}
