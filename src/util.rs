//! Small networking helpers with a hard cap on response size, so a hostile or
//! compromised third-party endpoint (public-IP service, M-Lab locate,
//! community-run LibreSpeed servers) can't exhaust memory with a huge body.

use futures_util::StreamExt;

/// The release version with the build stamp from `build.rs` when there is
/// one: `0.5.2 · build 143 (b91da39+)` from a checkout, plain `0.5.2` from a
/// crates.io build. What every "which octomon is this?" surface prints.
pub const VERSION: &str = env!("OCTOMON_VERSION_FULL");

/// A reqwest error with its cause chain flattened: "error sending request …"
/// on its own says nothing; the source underneath ("dns error: no such
/// host", "certificate verify failed", "connection refused", "timed out") is
/// the part a person can act on. The URL is dropped — the caller knows it.
pub fn describe_error(e: &reqwest::Error) -> String {
    use std::error::Error as _;
    let mut parts: Vec<String> = Vec::new();
    let top = if e.is_timeout() {
        "timed out".to_string()
    } else if e.is_connect() {
        "could not connect".to_string()
    } else if e.is_status() {
        format!("HTTP {}", e.status().map(|s| s.as_u16()).unwrap_or(0))
    } else if e.is_decode() {
        "bad response".to_string()
    } else if e.is_request() {
        "request failed".to_string()
    } else {
        e.to_string()
    };
    parts.push(top);
    let mut src = e.source();
    while let Some(s) = src {
        let msg = s.to_string();
        // hyper wraps its own layers; keep each distinct message once.
        if !parts.iter().any(|p| p == &msg)
            && !msg.starts_with("error sending request")
            && !msg.starts_with("client error")
        {
            parts.push(msg);
        }
        src = s.source();
    }
    parts.join(": ")
}

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
        .map_err(|e| describe_error(&e))?
        .error_for_status()
        .map_err(|e| describe_error(&e))?;
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

#[cfg(test)]
mod tests {
    /// Against the network: an unresolvable host and a closed port each yield
    /// a reason a person can read, not just "error sending request".
    #[tokio::test]
    #[ignore = "requires network access"]
    async fn live_describe_error_names_the_cause() {
        let c = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap();
        let e = c
            .get("https://does-not-exist.invalid/")
            .send()
            .await
            .unwrap_err();
        let d = super::describe_error(&e);
        println!("{d}");
        assert!(!d.contains("error sending request"), "{d}");
        assert!(
            d.to_lowercase().contains("dns") || d.contains("resolve"),
            "{d}"
        );
        let e = c.get("http://127.0.0.1:9/").send().await.unwrap_err();
        let d = super::describe_error(&e);
        println!("{d}");
        assert!(d.contains("connect") || d.contains("refused"), "{d}");
    }
}
