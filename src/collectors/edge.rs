//! The edge check: ask octomon.dev's `/edge` endpoint how the Cloudflare
//! edge sees this connection — which PoP answers, whose AS the request came
//! from, and the edge's own TCP RTT measurement of this client. The one
//! octomon-operated endpoint; it stores nothing about the caller (the
//! website's /privacy page shows everything its operator can see), and
//! `edge_check_url = ""` disables it entirely.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;

use crate::app::{AppState, EdgeInfo};
use crate::config::Config;

/// Refresh cadence between network changes: the answer only moves when the
/// path does, so a slow tick is plenty — and it is what makes the public
/// request-count graph on /privacy interpretable (4 refresh calls ≈ 1 hour of
/// octomon running).
const REFRESH: Duration = Duration::from_secs(15 * 60);

pub async fn run(state: Arc<Mutex<AppState>>, cfg: Config, changed: Arc<Notify>) {
    let url = cfg.edge_check_url.trim().to_string();
    if url.is_empty() {
        return;
    }
    let client = match reqwest::Client::builder()
        .user_agent(crate::util::USER_AGENT)
        .timeout(Duration::from_secs(10))
        .no_proxy()
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            crate::errlog::log("edge", format!("could not build an HTTP client: {e}"));
            return;
        }
    };
    // Each call names its reason with one of three constant labels — every
    // octomon in the world sends the identical strings, so the label links
    // nothing to anyone, but it lets the /privacy page turn call counts into
    // an honest usage estimate: refreshes tick every 15 minutes, so
    // refresh-calls ÷ 4 ≈ hours of octomon running that day, no identifiers
    // needed.
    let mut why = "start";
    loop {
        // A failed refresh keeps the last answer — stale edge facts beat
        // none, and the panel row shows measurements, not health. A
        // *network change* is different: the old answer describes the old
        // path, so it is cleared below before the re-fetch.
        if let Some((info, latest)) = fetch(&client, &with_reason(&url, why)).await {
            let mut s = state.lock().unwrap();
            s.edge = Some(info);
            // A newer release exists: say so once per version, on the
            // timeline where it keeps. Mentioning is the whole feature —
            // octomon never updates itself.
            if newer_than(&latest, env!("CARGO_PKG_VERSION"))
                && s.update_available.as_deref() != Some(latest.as_str())
            {
                s.push_event(
                    crate::verdict::Severity::Info,
                    crate::app::EventCategory::Logging,
                    format!(
                        "octomon v{latest} is available (you run v{}) — github.com/securitypedant/octomon/releases",
                        env!("CARGO_PKG_VERSION")
                    ),
                );
                s.update_available = Some(latest);
            }
        }
        tokio::select! {
            _ = changed.notified() => {
                state.lock().unwrap().edge = None;
                why = "netchange";
                // Let the new network settle before asking.
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            _ = tokio::time::sleep(REFRESH) => { why = "refresh"; }
        }
    }
}

/// `url` with the call's reason as a query parameter, whatever the base URL
/// already carries.
fn with_reason(url: &str, why: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}why={why}")
}

async fn fetch(client: &reqwest::Client, url: &str) -> Option<(EdgeInfo, String)> {
    // The panel keeps the previous answer on failure, so nothing on screen
    // says the fetch stopped working — hence the log line.
    let text = match crate::util::fetch_text_capped(client, url, 4096).await {
        Ok(text) => text,
        Err(e) => {
            crate::errlog::log("edge", format!("{url}: {e}"));
            return None;
        }
    };
    let latest = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v["latest"].as_str().map(str::to_string))
        .unwrap_or_default();
    let parsed = parse(&text).map(|info| (info, latest));
    if parsed.is_none() {
        crate::errlog::log("edge", format!("{url}: the answer did not parse"));
    }
    parsed
}

/// Strictly newer, on x.y.z triples; malformed strings are never "newer",
/// so a broken answer can't nag anyone.
fn newer_than(latest: &str, current: &str) -> bool {
    fn triple(v: &str) -> Option<(u64, u64, u64)> {
        let mut it = v.trim().trim_start_matches('v').split('.');
        Some((
            it.next()?.parse().ok()?,
            it.next()?.parse().ok()?,
            it.next()?.parse().ok()?,
        ))
    }
    matches!((triple(latest), triple(current)), (Some(l), Some(c)) if l > c)
}

/// The `/edge` JSON into [`EdgeInfo`]; `None` when it isn't the expected
/// shape (a captive portal answering for us, an old worker).
pub fn parse(text: &str) -> Option<EdgeInfo> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    let s = |k: &str| v[k].as_str().unwrap_or_default().to_string();
    // `colo` is the field that proves this is really the edge answering.
    let colo = v["colo"].as_str()?.to_string();
    Some(EdgeInfo {
        ip: s("ip"),
        asn: v["asn"].as_u64().unwrap_or(0) as u32,
        isp: s("isp"),
        colo,
        colo_city: s("colo_city"),
        tcp_rtt_ms: v["tcp_rtt_ms"].as_f64(),
    })
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn reasons_ride_the_query_string_either_way() {
        use super::with_reason;
        assert_eq!(
            with_reason("https://octomon.dev/edge", "start"),
            "https://octomon.dev/edge?why=start"
        );
        // A custom edge_check_url that already carries a query keeps it.
        assert_eq!(
            with_reason("https://example.com/edge?token=x", "refresh"),
            "https://example.com/edge?token=x&why=refresh"
        );
    }

    #[test]
    fn newer_only_when_strictly_newer_and_well_formed() {
        use super::newer_than;
        assert!(newer_than("0.9.1", "0.9.0"));
        assert!(newer_than("1.0.0", "0.9.9"));
        assert!(newer_than("v0.10.0", "0.9.1"), "0.10 beats 0.9 numerically");
        assert!(!newer_than("0.9.1", "0.9.1"));
        assert!(!newer_than("0.9.0", "0.9.1"));
        // Junk never nags.
        assert!(!newer_than("", "0.9.1"));
        assert!(!newer_than("latest", "0.9.1"));
    }

    #[test]
    fn edge_answers_parse_and_junk_does_not() {
        let info = parse(
            r#"{"ip":"203.0.113.9","asn":8075,"isp":"Microsoft Corporation",
                "colo":"IAD","colo_city":"Ashburn","city":"Washington","country":"US",
                "tcp_rtt_ms":9,"http":"HTTP/2","tls":"TLSv1.3","ts":1756240000}"#,
        )
        .expect("parses");
        assert_eq!(info.colo, "IAD");
        assert_eq!(info.colo_city, "Ashburn");
        assert_eq!(info.asn, 8075);
        assert_eq!(info.tcp_rtt_ms, Some(9.0));

        // A captive portal's HTML, or an old worker's 404 body: no colo, no
        // EdgeInfo — never a garbage row in the Network panel.
        assert!(parse("<html>sign in</html>").is_none());
        assert!(parse(r#"{"error":"not found"}"#).is_none());
    }
}
