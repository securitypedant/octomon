//! Who owns an address — the [W] overlay.
//!
//! When a hop on the path is the one dropping packets, the next question is
//! "whose router is that?" — your ISP's, a transit carrier's, the destination's
//! own edge. That decides who to call. RDAP is the registries' JSON successor to
//! whois and answers the same question with structure: network range, name,
//! country, the registrant and the abuse contact. `rdap.org` is the IANA
//! bootstrap front door and redirects to whichever RIR holds the block, so one
//! URL covers ARIN, RIPE, APNIC, LACNIC and AFRINIC.
//!
//! The system `whois` is the fallback when RDAP is unreachable — a captive
//! portal or a proxy that only passes port 53 and 443 to a few hosts. It is
//! present on macOS and most Linux installs, absent on Windows by default, and
//! its output is free text that varies by registry, so it is shown raw.
//!
//! Registration is not routing: the RIR says who was allocated the block, and
//! the BGP table says who announces it — for a transit hop the two often differ,
//! and the announcing ASN is the name an operator recognises. RIPEstat's
//! prefix-overview gives that (ASN, holder, announced prefix) for any address,
//! not only RIPE's, so it is fetched alongside and shown as its own rows.

use std::net::IpAddr;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::process::Command;

use crate::app::{AppState, Whois};

const RDAP_URL: &str = "https://rdap.org/ip/";
const RIPESTAT_URL: &str = "https://stat.ripe.net/data/prefix-overview/data.json?resource=";
const TIMEOUT: Duration = Duration::from_secs(10);
/// RDAP answers are a few KB; a registry that sends more is not answering.
const MAX_BODY: usize = 256 * 1024;

/// Begin a lookup for `addr`, replacing any previous result. Skipped when the
/// last lookup was for the same address and succeeded — reopening the overlay
/// should not re-query the registry.
pub fn start(state: Arc<Mutex<AppState>>, addr: IpAddr) {
    {
        let mut s = state.lock().unwrap();
        if s.whois
            .as_ref()
            .is_some_and(|w| w.addr == addr && !w.running && w.error.is_none())
        {
            return;
        }
        s.whois = Some(Whois {
            addr,
            running: true,
            fields: Vec::new(),
            raw: Vec::new(),
            source: String::new(),
            error: None,
        });
    }

    // Through the system's fixed proxy when there is one — on a network that
    // requires it, that is the only way out, and a browser on the same
    // machine would use it.
    let proxy = state
        .lock()
        .unwrap()
        .proxy
        .as_ref()
        .and_then(|p| p.https_url());
    tokio::spawn(async move {
        // Registration and routing are independent lookups; ask both at once.
        let (reg, asn) = tokio::join!(
            rdap(addr, proxy.as_deref()),
            ripestat_asn(addr, proxy.as_deref())
        );
        let outcome = match reg {
            Ok((fields, source)) => Ok((fields, Vec::new(), source)),
            Err(rdap_err) => match system_whois(addr).await {
                Ok(raw) => Ok((Vec::new(), raw, "whois".to_string())),
                Err(whois_err) => Err(format!("RDAP: {rdap_err}; whois: {whois_err}")),
            },
        };
        // The ASN rows ride along whichever way registration went; a failed
        // ASN lookup just leaves them out.
        let asn_rows = asn.unwrap_or_default();

        let mut s = state.lock().unwrap();
        // The user may have asked about a different address meanwhile.
        let Some(w) = s.whois.as_mut().filter(|w| w.addr == addr) else {
            return;
        };
        w.running = false;
        match outcome {
            Ok((mut fields, raw, source)) => {
                fields.extend(asn_rows);
                w.fields = fields;
                w.raw = raw;
                w.source = source;
            }
            Err(e) => {
                // Routing may still have answered when registration did not.
                w.fields = asn_rows;
                w.error = Some(e);
            }
        }
    });
}

/// The announcing ASN for `addr` from RIPEstat: `asn` and `prefix` rows, or
/// nothing when the address is not announced.
async fn ripestat_asn(addr: IpAddr, proxy: Option<&str>) -> Result<Vec<(String, String)>, String> {
    let client = client(proxy)?;
    let resp = client
        .get(format!("{RIPESTAT_URL}{addr}"))
        .send()
        .await
        .map_err(|e| crate::util::describe_error(&e))?
        .error_for_status()
        .map_err(|e| crate::util::describe_error(&e))?;
    let body = crate::util::read_capped(resp, MAX_BODY).await?;
    let json: Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    Ok(fields_from_ripestat(&json))
}

/// `asn` ("AS13335 · CLOUDFLARENET, US") and `prefix` rows from a RIPEstat
/// prefix-overview answer. Several ASNs (a multi-origin prefix) all list.
pub fn fields_from_ripestat(json: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Some(data) = json.get("data") else {
        return out;
    };
    let announced = data
        .get("announced")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let asns: Vec<String> = data
        .get("asns")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|e| {
                    let n = e.get("asn").and_then(Value::as_u64)?;
                    let holder = e
                        .get("holder")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|h| !h.is_empty());
                    Some(match holder {
                        Some(h) => format!("AS{n} · {h}"),
                        None => format!("AS{n}"),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    if !announced || asns.is_empty() {
        return out;
    }
    out.push(("asn".to_string(), asns.join("; ")));
    if let Some(p) = data
        .get("resource")
        .and_then(Value::as_str)
        .filter(|p| p.contains('/'))
    {
        out.push(("prefix".to_string(), p.to_string()));
    }
    out
}

/// RDAP lookup: the structured fields and the registry that answered.
async fn rdap(
    addr: IpAddr,
    proxy: Option<&str>,
) -> Result<(Vec<(String, String)>, String), String> {
    let client = client(proxy)?;
    let url = format!("{RDAP_URL}{addr}");
    let resp = client
        .get(&url)
        .header("accept", "application/rdap+json, application/json")
        .send()
        .await
        .map_err(|e| crate::util::describe_error(&e))?;
    // The registry that finally answered, after rdap.org's redirect.
    let source = resp.url().host_str().unwrap_or("rdap.org").to_string();
    let resp = resp
        .error_for_status()
        .map_err(|e| crate::util::describe_error(&e))?;
    let body = crate::util::read_capped(resp, MAX_BODY).await?;
    let json: Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    Ok((fields_from_rdap(&json), source))
}

/// The HTTP client for the registry lookups: direct, or via the system's
/// fixed proxy when one is configured.
fn client(proxy: Option<&str>) -> Result<reqwest::Client, String> {
    let mut b = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .user_agent(concat!("octomon/", env!("CARGO_PKG_VERSION")));
    b = match proxy {
        Some(url) => b.proxy(reqwest::Proxy::all(url).map_err(|e| e.to_string())?),
        None => b.no_proxy(),
    };
    b.build().map_err(|e| e.to_string())
}

/// Pull the fields a person actually reads out of an RDAP IP-network object.
/// Registries fill these unevenly (RIPE has no `cidr0_cidrs`, ARIN rarely sets
/// `country`), so every field is optional and absent ones are simply not shown.
pub fn fields_from_rdap(json: &Value) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let str_of = |v: &Value| {
        v.as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
    };
    let mut push = |k: &str, v: Option<String>| {
        if let Some(v) = v {
            out.push((k.to_string(), v));
        }
    };

    // Range first: "is this one box or a whole /18?" is the first question.
    let start = json.get("startAddress").and_then(str_of);
    let end = json.get("endAddress").and_then(str_of);
    let cidrs: Vec<String> = json
        .get("cidr0_cidrs")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|c| {
                    let prefix = c
                        .get("v4prefix")
                        .or_else(|| c.get("v6prefix"))
                        .and_then(str_of)?;
                    let len = c.get("length").and_then(Value::as_u64)?;
                    Some(format!("{prefix}/{len}"))
                })
                .collect()
        })
        .unwrap_or_default();
    let range = match (start, end) {
        (Some(s), Some(e)) if s == e => Some(s),
        (Some(s), Some(e)) => Some(format!("{s} – {e}")),
        (s, e) => s.or(e),
    };
    push(
        "network",
        match (range, cidrs.is_empty()) {
            (Some(r), false) => Some(format!("{r}  ({})", cidrs.join(", "))),
            (Some(r), true) => Some(r),
            (None, false) => Some(cidrs.join(", ")),
            (None, true) => None,
        },
    );
    push("name", json.get("name").and_then(str_of));
    push("handle", json.get("handle").and_then(str_of));
    push("type", json.get("type").and_then(str_of));
    push("country", json.get("country").and_then(str_of));

    // Entities carry the people: registrant / administrative / abuse, each a
    // vCard. Nested entities (ARIN puts abuse under the registrant) count too.
    let mut registrant = None;
    let mut abuse = None;
    let visit = |e: &Value, registrant: &mut Option<String>, abuse: &mut Option<String>| {
        let roles: Vec<&str> = e
            .get("roles")
            .and_then(Value::as_array)
            .map(|r| r.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let (fn_, email) = vcard(e.get("vcardArray"));
        if roles.contains(&"registrant") && registrant.is_none() {
            *registrant = fn_.clone().or_else(|| e.get("handle").and_then(str_of));
        }
        if roles.contains(&"abuse") && abuse.is_none() {
            *abuse = email.or(fn_);
        }
    };
    if let Some(entities) = json.get("entities").and_then(Value::as_array) {
        for e in entities {
            visit(e, &mut registrant, &mut abuse);
            if let Some(nested) = e.get("entities").and_then(Value::as_array) {
                for n in nested {
                    visit(n, &mut registrant, &mut abuse);
                }
            }
        }
    }
    push("registrant", registrant);
    push("abuse", abuse);

    // Remarks are where a carrier writes "peering router, do not report".
    if let Some(remarks) = json.get("remarks").and_then(Value::as_array) {
        for r in remarks.iter().take(3) {
            let text: Vec<&str> = r
                .get("description")
                .and_then(Value::as_array)
                .map(|d| d.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let text = text.join(" ").trim().to_string();
            if !text.is_empty() {
                out.push(("remarks".to_string(), text));
            }
        }
    }
    out
}

/// The `fn` (display name) and first email from a jCard, if any.
fn vcard(v: Option<&Value>) -> (Option<String>, Option<String>) {
    let Some(props) = v.and_then(|v| v.get(1)).and_then(Value::as_array) else {
        return (None, None);
    };
    let mut name = None;
    let mut email = None;
    for p in props {
        let Some(kind) = p.get(0).and_then(Value::as_str) else {
            continue;
        };
        let val = p.get(3).and_then(Value::as_str).map(str::trim);
        match kind {
            "fn" if name.is_none() => name = val.filter(|s| !s.is_empty()).map(String::from),
            "email" if email.is_none() => email = val.filter(|s| !s.is_empty()).map(String::from),
            _ => {}
        }
    }
    (name, email)
}

/// Fallback: the system `whois`, comment lines stripped, capped in length.
async fn system_whois(addr: IpAddr) -> Result<Vec<String>, String> {
    let run = Command::new("whois")
        .arg(addr.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    let out = tokio::time::timeout(TIMEOUT, run)
        .await
        .map_err(|_| "timed out".to_string())?
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<String> = text
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty() && !l.starts_with('%') && !l.starts_with('#'))
        .take(60)
        .map(String::from)
        .collect();
    if lines.is_empty() {
        return Err("no answer".to_string());
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Shape of an ARIN answer, trimmed: cidr0 range, no country, abuse nested
    /// under the registrant.
    #[test]
    fn arin_style_answer_yields_the_readable_fields() {
        let j = json!({
            "handle": "NET-75-101-0-0-1",
            "startAddress": "75.101.0.0",
            "endAddress": "75.101.63.255",
            "name": "SONIC-NET",
            "type": "DIRECT ALLOCATION",
            "cidr0_cidrs": [{"v4prefix": "75.101.0.0", "length": 18}],
            "entities": [{
                "handle": "SONIC",
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Sonic.net, LLC"]]],
                "entities": [{
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"], ["email", {}, "text", "abuse@sonic.net"]]]
                }]
            }],
            "remarks": [{"description": ["Peering router.", "Report issues to noc."]}]
        });
        let f = fields_from_rdap(&j);
        let get = |k: &str| f.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.as_str());
        assert_eq!(
            get("network"),
            Some("75.101.0.0 – 75.101.63.255  (75.101.0.0/18)")
        );
        assert_eq!(get("name"), Some("SONIC-NET"));
        assert_eq!(get("registrant"), Some("Sonic.net, LLC"));
        assert_eq!(get("abuse"), Some("abuse@sonic.net"));
        assert_eq!(
            get("remarks"),
            Some("Peering router. Report issues to noc.")
        );
        assert_eq!(get("country"), None, "absent fields are not shown");
        // Range leads: it is the first thing a person wants to know.
        assert_eq!(f[0].0, "network");
    }

    /// RIPE-style: no cidr0, country set, registrant given only by handle.
    #[test]
    fn a_sparse_answer_still_produces_something() {
        let j = json!({
            "handle": "1.1.1.0 - 1.1.1.255",
            "startAddress": "1.1.1.0",
            "endAddress": "1.1.1.255",
            "name": "APNIC-LABS",
            "country": "AU",
            "entities": [{"handle": "AR302-AP", "roles": ["registrant"]}]
        });
        let f = fields_from_rdap(&j);
        let get = |k: &str| f.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.as_str());
        assert_eq!(get("network"), Some("1.1.1.0 – 1.1.1.255"));
        assert_eq!(get("country"), Some("AU"));
        assert_eq!(get("registrant"), Some("AR302-AP"));
    }

    #[test]
    fn ripestat_gives_the_announcing_asn_and_prefix() {
        let j = json!({"data": {
            "resource": "75.101.32.0/19",
            "announced": true,
            "asns": [{"asn": 46375, "holder": "AS-SONICTELECOM - Sonic Telecom LLC"}]
        }});
        let f = fields_from_ripestat(&j);
        assert_eq!(
            f[0],
            (
                "asn".to_string(),
                "AS46375 · AS-SONICTELECOM - Sonic Telecom LLC".to_string()
            )
        );
        assert_eq!(f[1], ("prefix".to_string(), "75.101.32.0/19".to_string()));

        // Not announced (bogon, unrouted space): nothing to say.
        let j = json!({"data": {"resource": "10.0.0.0/8", "announced": false, "asns": []}});
        assert!(fields_from_ripestat(&j).is_empty());
        assert!(fields_from_ripestat(&json!({})).is_empty());
    }

    /// Against the real registries. Ignored by default — needs the network.
    /// Run with: `cargo test -- --ignored --nocapture live_rdap`
    #[tokio::test]
    #[ignore = "requires network access"]
    async fn live_rdap() {
        for a in ["75.101.33.185", "1.1.1.1", "2606:4700:4700::1111"] {
            let addr: IpAddr = a.parse().unwrap();
            let (fields, source) = rdap(addr, None).await.expect("rdap answers");
            println!("{addr} via {source}");
            for (k, v) in &fields {
                println!("  {k:<12}{v}");
            }
            assert!(!fields.is_empty(), "{addr}: no fields");
            let asn = ripestat_asn(addr, None).await.expect("ripestat answers");
            for (k, v) in &asn {
                println!("  {k:<12}{v}");
            }
            assert!(asn.iter().any(|(k, _)| k == "asn"), "{addr}: no asn");
        }
    }

    #[test]
    fn garbage_yields_nothing_rather_than_a_panic() {
        assert!(fields_from_rdap(&json!({})).is_empty());
        assert!(fields_from_rdap(&json!([1, 2])).is_empty());
        assert!(fields_from_rdap(&json!({"entities": "nope", "vcardArray": 3})).is_empty());
    }
}
