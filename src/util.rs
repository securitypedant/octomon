//! Small networking helpers with a hard cap on response size, so a hostile or
//! compromised third-party endpoint (public-IP service, M-Lab locate,
//! community-run LibreSpeed servers) can't exhaust memory with a huge body.

use futures_util::StreamExt;

/// The release version with the build stamp from `build.rs` when there is
/// one: `0.5.2 · build 143 (b91da39+)` from a checkout, plain `0.5.2` from a
/// crates.io build. What every "which octomon is this?" surface prints.
pub const VERSION: &str = env!("OCTOMON_VERSION_FULL");

/// How octomon identifies itself on every HTTP(S) request it makes — probes,
/// speed tests, RDAP, the public-IP lookup. A monitoring tool that hits
/// endpoints on a timer owes their operators an honest name and somewhere to
/// look it up, not reqwest's silence or a browser costume.
pub const USER_AGENT: &str = concat!(
    "octomon/",
    env!("CARGO_PKG_VERSION"),
    " (network monitoring tool; +https://octomon.dev)"
);

/// A throughput in Mb/s as people read one: gigabit links say "1.24 Gb/s"
/// instead of "1240 Mb/s" (loopback iPerf3 runs say 90 Gb/s, not 90000).
pub fn fmt_mbps(mbps: f64) -> String {
    if mbps >= 1000.0 {
        format!("{:.2} Gb/s", mbps / 1000.0)
    } else if mbps >= 100.0 {
        format!("{mbps:.0} Mb/s")
    } else {
        format!("{mbps:.1} Mb/s")
    }
}

/// A count of minutes as people read time: "40m", "5h 20m", "2d 10h".
/// "3458 min" asks the reader to do arithmetic mid-glance; two units are
/// plenty, so days drop the minutes.
pub fn fmt_minutes(mins: u64) -> String {
    let (d, h, m) = (mins / 1440, (mins % 1440) / 60, mins % 60);
    match (d, h, m) {
        (0, 0, m) => format!("{m}m"),
        (0, h, 0) => format!("{h}h"),
        (0, h, m) => format!("{h}h {m}m"),
        (d, 0, _) => format!("{d}d"),
        (d, h, _) => format!("{d}d {h}h"),
    }
}

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

/// Drop characters that could steer a terminal rather than be read on one:
/// control characters (other than newline), and the Unicode bidi overrides and
/// isolates that make text render in a different order than it is stored. An
/// SSID, interface or process name is chosen by someone else and reaches
/// stdout in `--check`, `--doctor` and every `--watch` line, which are printed
/// raw and meant to be pasted elsewhere. The TUI is already protected —
/// ratatui skips control characters when it fills a cell. `--json` needs
/// nothing: serde escapes them.
pub fn strip_control(text: &str) -> String {
    text.chars()
        .filter(|c| *c == '\n' || !(c.is_control() || is_bidi_control(*c)))
        .collect()
}

fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// A duration typed on the command line, as seconds: `900`, `900s`, `15m`,
/// `1h`, or a sum of those (`1h30m`). The unit is optional because the flag
/// took bare seconds for a long time and scripts still pass them; it is
/// accepted because "run it for 15 minutes" is what a forum reply says, and
/// `15m` is what the person reading it will type.
pub fn parse_duration_secs(text: &str) -> Result<u64, String> {
    let bad = || format!("expected seconds or a time like 90s, 15m or 1h, not {text:?}");
    let text = text.trim();
    if text.is_empty() {
        return Err(bad());
    }
    let mut total: u64 = 0;
    let mut digits = String::new();
    let mut units_seen = false;
    for c in text.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let n: u64 = digits.parse().map_err(|_| bad())?;
        digits.clear();
        let mul = match c.to_ascii_lowercase() {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            _ => return Err(bad()),
        };
        units_seen = true;
        total = n
            .checked_mul(mul)
            .and_then(|v| total.checked_add(v))
            .ok_or_else(bad)?;
    }
    if !digits.is_empty() {
        // Trailing bare digits: plain seconds, whether alone (`900`) or after
        // a unit (`1m30`).
        let n: u64 = digits.parse().map_err(|_| bad())?;
        total = total.checked_add(n).ok_or_else(bad)?;
    } else if !units_seen {
        return Err(bad());
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    #[test]
    fn strip_control_keeps_newlines_drops_escapes_and_bidi() {
        let hostile = "cafe\x1b]0;pwned\x07\u{202E}evil\nnext";
        assert_eq!(super::strip_control(hostile), "cafe]0;pwnedevil\nnext");
        assert_eq!(super::strip_control("plain ☕ text"), "plain ☕ text");
    }

    #[test]
    fn observe_window_accepts_seconds_and_units() {
        use super::parse_duration_secs as p;
        assert_eq!(p("900"), Ok(900));
        assert_eq!(p("90s"), Ok(90));
        assert_eq!(p("15m"), Ok(900));
        assert_eq!(p("15M"), Ok(900));
        assert_eq!(p("1h"), Ok(3600));
        assert_eq!(p("1h30m"), Ok(5400));
        assert_eq!(p("1m30"), Ok(90));
        assert_eq!(p(" 20 "), Ok(20));
        for bad in [
            "",
            "m",
            "15 m",
            "15min",
            "1.5h",
            "-5",
            "abc",
            "99999999999999999999h",
        ] {
            assert!(p(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn minutes_read_like_time_not_arithmetic() {
        use super::fmt_minutes;
        assert_eq!(fmt_minutes(0), "0m");
        assert_eq!(fmt_minutes(40), "40m");
        assert_eq!(fmt_minutes(60), "1h");
        assert_eq!(fmt_minutes(320), "5h 20m");
        assert_eq!(fmt_minutes(1440), "1d");
        // The screenshot case: 3458 min was unreadable.
        assert_eq!(fmt_minutes(3458), "2d 9h");
    }

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
