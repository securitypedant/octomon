//! HTTP-layer reachability: probe a well-known connectivity-check endpoint the
//! way a browser would, once per address family.
//!
//! ICMP can be perfect while browsing is broken — captive portals, proxy
//! failures and half-broken IPv6 all live above the layer ping tests. Every OS
//! runs an endpoint for exactly this purpose; the default is *this* OS's own
//! (the machine already polls it constantly, so octomon adds zero new parties
//! learning it is online). Plain HTTP on purpose: portals must be able to
//! intercept the request, that's the test.
//!
//! A failing/captive answer is verified against a second, independent provider
//! before it stands — one endpoint having a bad day must not read as "your
//! network is broken" (same philosophy as multi-anchor ping consensus).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use futures_util::StreamExt;
use tokio::sync::Notify;

use crate::app::{AppState, FamilyProbe};
use crate::config::Config;

/// What the endpoint answers when the internet is actually reachable.
#[derive(Clone, Copy)]
pub enum Expect {
    /// An empty 204 (or empty 200).
    Empty,
    /// A 200 whose body contains this needle.
    Body(&'static str),
}

pub struct Provider {
    pub name: &'static str,
    pub url: &'static str,
    pub expects: Expect,
}

/// The well-known connectivity-check endpoints, both flavours.
pub static PROVIDERS: &[Provider] = &[
    Provider {
        name: "Apple",
        url: "http://captive.apple.com/hotspot-detect.html",
        expects: Expect::Body("Success"),
    },
    Provider {
        name: "Microsoft",
        url: "http://www.msftconnecttest.com/connecttest.txt",
        expects: Expect::Body("Microsoft Connect Test"),
    },
    Provider {
        name: "Ubuntu",
        url: "http://connectivity-check.ubuntu.com",
        expects: Expect::Empty,
    },
    Provider {
        name: "Cloudflare",
        url: "http://cp.cloudflare.com/generate_204",
        expects: Expect::Empty,
    },
    Provider {
        name: "Google",
        url: "http://connectivitycheck.gstatic.com/generate_204",
        expects: Expect::Empty,
    },
];

/// The OS's own endpoint — the one this machine already talks to.
fn os_native() -> &'static Provider {
    let name = if cfg!(target_os = "macos") {
        "Apple"
    } else if cfg!(windows) {
        "Microsoft"
    } else {
        "Ubuntu"
    };
    by_name(name).expect("native provider is in the table")
}

fn by_name(name: &str) -> Option<&'static Provider> {
    let norm = |s: &str| s.to_lowercase();
    PROVIDERS.iter().find(|p| norm(p.name) == norm(name))
}

/// Resolve the configured provider: a known name, "auto"/empty for the OS's
/// own, anything else is ignored in favour of the default.
fn primary(cfg: &Config) -> &'static Provider {
    match cfg.http_probe_provider.as_str() {
        "" | "auto" => os_native(),
        name => by_name(name).unwrap_or_else(os_native),
    }
}

/// A different operator for the second opinion, so one company's outage can't
/// condemn the network.
fn second_opinion(p: &Provider) -> &'static Provider {
    if p.name == "Cloudflare" {
        by_name("Google").unwrap()
    } else {
        by_name("Cloudflare").unwrap()
    }
}

/// Classify one response. Pure, so the whole decision table is testable.
pub fn classify(
    expects: Expect,
    status: u16,
    location: Option<String>,
    body: &str,
    rtt_ms: f64,
) -> FamilyProbe {
    match status {
        204 if body.trim().is_empty() => FamilyProbe::Ok(rtt_ms),
        // A redirect is the classic portal move; so is HTTP 511, which exists
        // precisely to mean "network sign-in required".
        300..=399 | 511 => FamilyProbe::Captive(location),
        200 => match expects {
            Expect::Empty if body.trim().is_empty() => FamilyProbe::Ok(rtt_ms),
            Expect::Body(needle) if body.contains(needle) => FamilyProbe::Ok(rtt_ms),
            // The expected boring answer was replaced by *something* — whatever
            // is intercepting HTTP is the diagnosis.
            _ => FamilyProbe::Captive(location),
        },
        s => FamilyProbe::Fail(format!("HTTP {s}")),
    }
}

/// Whether this machine has IPv6 that is *supposed* to work: a global address,
/// not just the automatic link-local (fe80::) or a ULA-only setup.
pub fn has_global_v6(addrs: &[String]) -> bool {
    addrs.iter().any(|a| {
        let Some(ip) = a.split('/').next().and_then(|s| s.parse::<Ipv6Addr>().ok()) else {
            return false;
        };
        let seg = ip.segments();
        let link_local = (seg[0] & 0xffc0) == 0xfe80;
        let unique_local = (seg[0] & 0xfe00) == 0xfc00;
        !link_local && !unique_local && !ip.is_loopback() && !ip.is_unspecified()
    })
}

/// One probe over one family-pinned client. Also returns the local clock's
/// offset from the server's `Date` header when the answer carried one — the
/// coarse fallback for the clock check when NTP is filtered.
async fn probe(client: &reqwest::Client, p: &Provider) -> (FamilyProbe, Option<f64>) {
    let start = Instant::now();
    let resp = match client.get(p.url).send().await {
        Ok(r) => r,
        Err(e) => return (FamilyProbe::Fail(short_reason(&e)), None),
    };
    let rtt_ms = start.elapsed().as_secs_f64() * 1000.0;
    let status = resp.status().as_u16();
    let date_skew = resp
        .headers()
        .get(reqwest::header::DATE)
        .and_then(|v| v.to_str().ok())
        .and_then(date_skew_ms);
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    // Only a prefix is needed to match the expected needle or detect a portal
    // page; cap it so a hostile network can't feed us a huge body.
    let mut body = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(Ok(chunk)) = stream.next().await {
        body.extend_from_slice(&chunk);
        if body.len() >= 1024 {
            break;
        }
    }
    let body = String::from_utf8_lossy(&body);
    let result = classify(p.expects, status, location, &body, rtt_ms);
    // Only a genuine answer from the provider dates the world; a portal's
    // page carries the portal's clock.
    let skew = match result {
        FamilyProbe::Ok(_) => date_skew,
        _ => None,
    };
    (result, skew)
}

/// Local clock minus the server's `Date` (RFC 7231 / RFC 2822 form), in ms;
/// positive = local clock ahead. `Date` has one-second resolution, so this is
/// coarse by design.
pub fn date_skew_ms(date: &str) -> Option<f64> {
    let server = chrono::DateTime::parse_from_rfc2822(date).ok()?;
    let now = chrono::Utc::now();
    Some((now.timestamp_millis() - server.timestamp_millis()) as f64)
}

/// Compress reqwest's error chains into something a status line can carry.
fn short_reason(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "timeout".to_string()
    } else if e.is_connect() {
        "connect failed".to_string()
    } else {
        "request failed".to_string()
    }
}

/// Probe, and on a bad answer let an independent provider arbitrate. The third
/// element is the `Date`-header clock skew, when an answer carried one.
async fn probe_verified(
    client: &reqwest::Client,
    p: &'static Provider,
) -> (FamilyProbe, Option<String>, Option<f64>) {
    let (first, skew) = probe(client, p).await;
    match first {
        FamilyProbe::Ok(_) => (first, None, skew),
        _ => {
            let sec = second_opinion(p);
            match probe(client, sec).await {
                (FamilyProbe::Ok(ms), skew2) => (
                    FamilyProbe::Ok(ms),
                    Some(format!(
                        "{} endpoint misbehaving — verified ok via {}",
                        p.name, sec.name
                    )),
                    skew2,
                ),
                // Two independent operators agree: the finding stands.
                _ => (first, None, None),
            }
        }
    }
}

/// A client that sends everything through `proxy` (an `http://host:port` or
/// `socks5://` URL). Direct clients are built with reqwest's proxy support
/// off, so the environment cannot silently route them; this one is the
/// deliberate exception.
fn proxy_client(proxy: &str) -> Option<reqwest::Client> {
    let proxy = reqwest::Proxy::all(proxy).ok()?;
    reqwest::Client::builder()
        .proxy(proxy)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(4))
        .build()
        .ok()
}

fn family_client(local: IpAddr) -> Option<reqwest::Client> {
    reqwest::Client::builder()
        .local_address(local)
        // Direct by definition: the probe measures the network, not whatever
        // `https_proxy` happens to be set to in this shell.
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(4))
        .build()
        .ok()
}

pub async fn run(state: Arc<Mutex<AppState>>, cfg: Config, changed: Arc<Notify>) {
    // Binding the local address pins the family at connect time — no resolver
    // surgery needed to test v4 and v6 separately.
    let v4 = family_client(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let v6 = family_client(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    let p = primary(&cfg);

    let mut ticker = tokio::time::interval(cfg.http_probe_interval());
    loop {
        // Re-probe on the cadence, or immediately on a network change —
        // captive detection matters most seconds after joining a network.
        tokio::select! {
            _ = ticker.tick() => {}
            _ = changed.notified() => {}
        }

        let (v6_applicable, proxy_url) = {
            let s = state.lock().unwrap();
            (
                has_global_v6(&s.netinfo.ipv6),
                s.proxy.as_ref().and_then(|p| p.https_url()),
            )
        };
        // Through the system's fixed proxy as well, when there is one: that is
        // the path a browser takes, and it can be up while direct is blocked
        // (a corporate network) or dead while direct works (a stale setting).
        let via_proxy = match proxy_url.as_deref().and_then(proxy_client) {
            Some(c) => probe(&c, p).await.0,
            None => FamilyProbe::NotRun,
        };

        let (r4, note4, skew4) = match &v4 {
            Some(c) => probe_verified(c, p).await,
            None => (FamilyProbe::Fail("no v4 client".into()), None, None),
        };
        let (r6, note6, skew6) = if !v6_applicable {
            (FamilyProbe::NotApplicable, None, None)
        } else {
            match &v6 {
                Some(c) => probe_verified(c, p).await,
                None => (FamilyProbe::Fail("no v6 client".into()), None, None),
            }
        };

        let mut s = state.lock().unwrap();
        if let Some(skew) = skew4.or(skew6) {
            s.clock.record_http_skew(skew);
        }
        // Mutate in place: the histories accumulate across probes.
        if let FamilyProbe::Ok(ms) = r4 {
            s.http.v4_hist.push(ms);
        }
        if let FamilyProbe::Ok(ms) = r6 {
            s.http.v6_hist.push(ms);
        }
        s.http.provider = p.name.to_string();
        s.http.v4 = r4;
        s.http.v6 = r6;
        s.http.via_proxy = via_proxy;
        s.http.note = note4.or(note6);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_ok(p: &FamilyProbe) -> bool {
        matches!(p, FamilyProbe::Ok(_))
    }

    #[test]
    fn classify_covers_both_endpoint_flavours() {
        // The empty-204 flavour.
        assert!(is_ok(&classify(Expect::Empty, 204, None, "", 10.0)));
        assert!(is_ok(&classify(Expect::Empty, 200, None, "  \n", 10.0)));
        // A body where none belongs: something is intercepting.
        assert!(matches!(
            classify(Expect::Empty, 200, None, "<html>Sign in</html>", 10.0),
            FamilyProbe::Captive(None)
        ));

        // The known-answer flavour.
        let apple = Expect::Body("Success");
        assert!(is_ok(&classify(
            apple,
            200,
            None,
            "<HTML><BODY>Success</BODY></HTML>",
            10.0
        )));
        assert!(matches!(
            classify(apple, 200, None, "<html>Hotel Wi-Fi</html>", 10.0),
            FamilyProbe::Captive(None)
        ));
        // A 204 is success even where a body was expected — nobody serves a
        // sign-in page as an empty 204.
        assert!(is_ok(&classify(apple, 204, None, "", 10.0)));
    }

    #[test]
    fn redirects_and_511_read_as_captive_with_the_target_kept() {
        let r = classify(
            Expect::Empty,
            302,
            Some("http://portal.hotel/login".into()),
            "",
            10.0,
        );
        assert_eq!(
            r,
            FamilyProbe::Captive(Some("http://portal.hotel/login".into()))
        );
        assert!(matches!(
            classify(Expect::Empty, 511, None, "", 10.0),
            FamilyProbe::Captive(_)
        ));
    }

    #[test]
    fn server_errors_are_failures_not_portals() {
        assert_eq!(
            classify(Expect::Empty, 500, None, "oops", 10.0),
            FamilyProbe::Fail("HTTP 500".into())
        );
    }

    /// fe80:: (automatic, always present) and ULA must not make a v4-only LAN
    /// read as "IPv6 broken".
    #[test]
    fn v6_applicability_requires_a_global_address() {
        assert!(!has_global_v6(&[]));
        assert!(!has_global_v6(&["fe80::1c2a:ffee/64".into()]));
        assert!(!has_global_v6(&["fd00:abcd::5/64".into()]));
        assert!(!has_global_v6(&["not-an-ip".into()]));
        assert!(has_global_v6(&[
            "fe80::1/64".into(),
            "2a00:23c5:dd80:1::42/64".into()
        ]));
    }

    #[test]
    fn the_second_opinion_is_always_a_different_operator() {
        for p in PROVIDERS {
            assert_ne!(second_opinion(p).name, p.name);
        }
    }

    #[test]
    fn every_platform_has_a_native_provider() {
        // Would panic if the table were missing this OS's entry.
        let p = os_native();
        assert!(!p.url.is_empty());
    }
}
