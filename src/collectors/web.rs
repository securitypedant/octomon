//! Per-target HTTP(S) reachability and time-to-first-byte.
//!
//! The ICMP view says how far away a target is; this says how its *web service*
//! is doing — a different thing, and for a hostname target (bbc.co.uk) usually
//! the thing the user actually cares about. Not every target serves HTTP:
//! 8.8.8.8 refuses, mid-path hops time out, and neither is a fault. Each target
//! is classified once ([`WebStatus`]) and only demonstrated web servers are
//! held to a standard afterwards.
//!
//! One HEAD request, redirects not followed, body discarded, any HTTP status
//! counts as up. Certificate errors are tolerated (`danger_accept_invalid_certs`)
//! because this is a timing instrument that sends nothing sensitive and reads
//! nothing back — an IP-literal probe of 9.9.9.9 should measure the handshake,
//! not fail on a name mismatch.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::app::{AppState, WebStatus};

/// How often a confirmed web server is timed.
const WEB_EVERY: Duration = Duration::from_secs(15);
/// How often a NoService / Filtered verdict is re-examined.
const RECHECK_EVERY: Duration = Duration::from_secs(600);
/// Unclassified targets retry quickly until they land in a bucket.
const UNKNOWN_EVERY: Duration = Duration::from_secs(10);

/// What one probe attempt observed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// Any HTTP response at all, however unhappy its status code.
    Response,
    /// Connection actively refused — proof of reachability, absence of service.
    Refused,
    /// Nothing came back at all.
    Timeout,
}

/// The state machine, pure so the whole table is testable. `icmp_ok` is
/// whether ICMP to the same target currently works — the only thing that can
/// disambiguate a timeout (filtered web vs host simply down).
pub fn transition(status: WebStatus, outcome: Outcome, icmp_ok: bool) -> WebStatus {
    match (status, outcome) {
        (_, Outcome::Response) => WebStatus::Web,
        // A demonstrated web server keeps its status on failure — the failure
        // count, not a reclassification, carries "it stopped answering".
        (WebStatus::Web, _) => WebStatus::Web,
        (_, Outcome::Refused) => WebStatus::NoService,
        (_, Outcome::Timeout) if icmp_ok => WebStatus::Filtered,
        // Host unreachable at every layer: nothing web-specific to conclude.
        (status, Outcome::Timeout) => status,
    }
}

/// The URL a target is probed at: the hostname when it was added as one
/// (SNI + certificates + CDN routing all need it), else the bare address.
pub fn probe_url(hostname: Option<&str>, addr: IpAddr) -> String {
    match (hostname, addr) {
        (Some(h), _) => format!("https://{h}/"),
        (None, IpAddr::V6(v6)) => format!("https://[{v6}]/"),
        (None, IpAddr::V4(v4)) => format!("https://{v4}/"),
    }
}

/// Walk an error chain looking for a definitive connection refusal.
fn is_refused(e: &reqwest::Error) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = source {
        if let Some(io) = err.downcast_ref::<std::io::Error>()
            && io.kind() == std::io::ErrorKind::ConnectionRefused
        {
            return true;
        }
        source = err.source();
    }
    false
}

async fn probe(client: &reqwest::Client, url: &str) -> (Outcome, f64) {
    let start = Instant::now();
    let result = client.head(url).send().await;
    let ms = start.elapsed().as_secs_f64() * 1000.0;
    match result {
        Ok(_) => (Outcome::Response, ms),
        Err(e) if is_refused(&e) => (Outcome::Refused, ms),
        Err(_) => (Outcome::Timeout, ms),
    }
}

pub async fn run(state: Arc<Mutex<AppState>>) {
    let client = match reqwest::Client::builder()
        .user_agent(crate::util::USER_AGENT)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(4))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            crate::errlog::log(
                "web-probe",
                format!("could not build an HTTP client: {e} — no TCP :443 column this session"),
            );
            return;
        }
    };

    // Per-target schedule, keyed by stable id; entries for deleted targets
    // just stop being consulted.
    let mut due: std::collections::HashMap<u64, Instant> = std::collections::HashMap::new();
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    loop {
        ticker.tick().await;
        let now = Instant::now();

        // Snapshot who needs probing. Hops are path infrastructure, not web
        // destinations; the gateway and the user's targets are fair game.
        let candidates: Vec<(u64, Option<String>, IpAddr)> = {
            let s = state.lock().unwrap();
            s.targets
                .iter()
                .filter(|t| !t.is_path_hop())
                .map(|t| (t.id, t.hostname.clone(), t.addr))
                .collect()
        };

        // Probe everything due concurrently: serially, one dead target's 4s
        // timeout would delay every probe queued behind it.
        let probes = candidates
            .into_iter()
            .filter(|(id, _, _)| !due.get(id).is_some_and(|d| *d > now))
            .map(|(id, hostname, addr)| {
                let client = client.clone();
                async move {
                    let url = probe_url(hostname.as_deref(), addr);
                    let (outcome, ms) = probe(&client, &url).await;
                    (id, outcome, ms)
                }
            });
        let results = futures_util::future::join_all(probes).await;

        for (id, outcome, ms) in results {
            let mut s = state.lock().unwrap();
            let Some(t) = s.targets.iter_mut().find(|t| t.id == id) else {
                continue;
            };
            let icmp_ok =
                t.window.len() >= 5 && t.recent_loss_pct(crate::verdict::thresholds::RECENT) < 50.0;
            let next = transition(t.web.status, outcome, icmp_ok);
            t.web.status = next;
            match outcome {
                Outcome::Response => {
                    t.web.last_ttfb_ms = Some(ms);
                    t.web.hist.push(ms);
                    t.web.fails = 0;
                }
                _ => {
                    t.web.last_ttfb_ms = None;
                    if next == WebStatus::Web {
                        t.web.fails += 1;
                    }
                }
            }
            due.insert(
                id,
                now + match next {
                    WebStatus::Web => WEB_EVERY,
                    WebStatus::Unknown => UNKNOWN_EVERY,
                    WebStatus::NoService | WebStatus::Filtered => RECHECK_EVERY,
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn absence_of_a_web_server_is_a_fact_not_a_fault() {
        // 8.8.8.8-style: reachable, refuses — classified and left alone.
        let s = transition(WebStatus::Unknown, Outcome::Refused, true);
        assert_eq!(s, WebStatus::NoService);
        // Corporate-firewall-style: ping answers, TCP vanishes.
        let s = transition(WebStatus::Unknown, Outcome::Timeout, true);
        assert_eq!(s, WebStatus::Filtered);
        // Host entirely down: a timeout proves nothing about web capability.
        let s = transition(WebStatus::Unknown, Outcome::Timeout, false);
        assert_eq!(s, WebStatus::Unknown);
    }

    #[test]
    fn a_demonstrated_server_is_held_to_its_standard() {
        // Once Web, always Web — failures accumulate on the counter instead,
        // because "it answered before and stopped" is the actual finding.
        assert_eq!(
            transition(WebStatus::Web, Outcome::Timeout, true),
            WebStatus::Web
        );
        assert_eq!(
            transition(WebStatus::Web, Outcome::Refused, true),
            WebStatus::Web
        );
        // And any bucket recovers the moment a response arrives.
        for from in [
            WebStatus::NoService,
            WebStatus::Filtered,
            WebStatus::Unknown,
        ] {
            assert_eq!(transition(from, Outcome::Response, false), WebStatus::Web);
        }
    }

    #[test]
    fn probe_urls_prefer_the_hostname_and_bracket_v6() {
        let v4: IpAddr = Ipv4Addr::new(1, 1, 1, 1).into();
        assert_eq!(probe_url(Some("bbc.co.uk"), v4), "https://bbc.co.uk/");
        assert_eq!(probe_url(None, v4), "https://1.1.1.1/");
        let v6: IpAddr = "2606:4700::1111".parse().unwrap();
        assert_eq!(probe_url(None, v6), "https://[2606:4700::1111]/");
    }
}
