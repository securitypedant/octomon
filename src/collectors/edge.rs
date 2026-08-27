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
/// request-count graph on /privacy interpretable (calls/hour ≈ 4× fleet).
const REFRESH: Duration = Duration::from_secs(15 * 60);

pub async fn run(state: Arc<Mutex<AppState>>, cfg: Config, changed: Arc<Notify>) {
    let url = cfg.edge_check_url.trim().to_string();
    if url.is_empty() {
        return;
    }
    let Ok(client) = reqwest::Client::builder()
        .user_agent(crate::util::USER_AGENT)
        .timeout(Duration::from_secs(10))
        .no_proxy()
        .build()
    else {
        return;
    };
    // Each call names its reason with one of three constant labels — every
    // octomon in the world sends the identical strings, so the label links
    // nothing to anyone, but it lets the /privacy page turn call counts into
    // an honest fleet estimate: refreshes tick every 15 minutes, so
    // refresh-calls ÷ 96 ≈ instances running that day, no identifiers needed.
    let mut why = "start";
    loop {
        // A failed refresh keeps the last answer — stale edge facts beat
        // none, and the panel row shows measurements, not health. A
        // *network change* is different: the old answer describes the old
        // path, so it is cleared below before the re-fetch.
        if let Some(info) = fetch(&client, &with_reason(&url, why)).await {
            state.lock().unwrap().edge = Some(info);
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

async fn fetch(client: &reqwest::Client, url: &str) -> Option<EdgeInfo> {
    let text = crate::util::fetch_text_capped(client, url, 4096)
        .await
        .ok()?;
    parse(&text)
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
    fn edge_answers_parse_and_junk_does_not() {
        let info = parse(
            r#"{"ip":"203.0.113.9","asn":8075,"isp":"Microsoft Corporation",
                "colo":"IAD","city":"Washington","country":"US",
                "tcp_rtt_ms":9,"http":"HTTP/2","tls":"TLSv1.3","ts":1756240000}"#,
        )
        .expect("parses");
        assert_eq!(info.colo, "IAD");
        assert_eq!(info.asn, 8075);
        assert_eq!(info.tcp_rtt_ms, Some(9.0));

        // A captive portal's HTML, or an old worker's 404 body: no colo, no
        // EdgeInfo — never a garbage row in the Network panel.
        assert!(parse("<html>sign in</html>").is_none());
        assert!(parse(r#"{"error":"not found"}"#).is_none());
    }
}
