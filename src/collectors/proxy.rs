//! Is a system-level web proxy configured?
//!
//! Browsers follow the OS proxy settings; octomon's probes go direct. On a
//! network that requires the proxy, the direct HTTP check fails while the
//! browser is fine — and the reverse when the proxy is dead. Knowing a proxy
//! is configured turns "web blocked" into "web via proxy X, direct blocked
//! (expected here)", and lets the HTTP check be repeated *through* a manual
//! proxy so both paths are measured. A PAC file or WPAD can only be reported:
//! evaluating one needs a JavaScript engine.
//!
//! System level only, deliberately: Firefox and some apps carry their own
//! settings, and chasing them is a different tool.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::app::{AppState, ProxyConfig, ProxyKind};

/// Re-read cadence; proxy settings change with the network profile, so a
/// network change also triggers a re-read.
const PERIOD: Duration = Duration::from_secs(5 * 60);

pub async fn run(state: Arc<Mutex<AppState>>, changed: Arc<tokio::sync::Notify>) {
    loop {
        let cfg = tokio::task::spawn_blocking(detect)
            .await
            .unwrap_or_default();
        state.lock().unwrap().proxy = cfg;
        tokio::select! {
            _ = changed.notified() => { tokio::time::sleep(Duration::from_secs(3)).await; }
            _ = tokio::time::sleep(PERIOD) => {}
        }
    }
}

/// The system proxy configuration, or `None` when nothing is set. Environment
/// variables are consulted on every platform first — a shell-level
/// `https_proxy` affects octomon's own reqwest clients — then the OS's store.
pub fn detect() -> Option<ProxyConfig> {
    if let Some(p) = from_env() {
        return Some(p);
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("scutil")
            .arg("--proxy")
            .output()
            .ok()?;
        return parse_scutil(&String::from_utf8_lossy(&out.stdout));
    }
    #[cfg(target_os = "linux")]
    {
        return from_gsettings();
    }
    #[cfg(windows)]
    {
        return from_windows_registry();
    }
    #[allow(unreachable_code)]
    None
}

/// `http_proxy` / `https_proxy` / `all_proxy` (either case), which reqwest and
/// curl honour — so these describe octomon's own path as well as the shell's.
fn from_env() -> Option<ProxyConfig> {
    let get = |k: &str| {
        std::env::var(k)
            .ok()
            .or_else(|| std::env::var(k.to_uppercase()).ok())
            .filter(|v| !v.trim().is_empty())
    };
    let https = get("https_proxy").or_else(|| get("all_proxy"));
    let http = get("http_proxy").or_else(|| get("all_proxy"));
    match (http, https) {
        (None, None) => None,
        (http, https) => Some(ProxyConfig {
            kind: ProxyKind::Manual {
                http: http.clone().unwrap_or_default(),
                https: https.or(http).unwrap_or_default(),
            },
            source: "environment".to_string(),
            bypass: get("no_proxy").unwrap_or_default(),
        }),
    }
}

/// `scutil --proxy` prints a flat dictionary:
///
/// ```text
/// <dictionary> {
///   HTTPEnable : 1
///   HTTPProxy : proxy.corp
///   HTTPPort : 8080
///   ProxyAutoConfigEnable : 1
///   ProxyAutoConfigURLString : http://wpad/wpad.dat
///   ProxyAutoDiscoveryEnable : 1
///   ExceptionsList : <array> { 0 : *.local  1 : 169.254/16 }
/// }
/// ```
pub fn parse_scutil(text: &str) -> Option<ProxyConfig> {
    let mut kv = std::collections::HashMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(" : ") {
            kv.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    let on = |k: &str| kv.get(k).is_some_and(|v| v == "1");
    let hostport = |h: &str, p: &str| {
        let host = kv.get(h)?;
        let port = kv.get(p).map(|p| format!(":{p}")).unwrap_or_default();
        Some(format!("{host}{port}"))
    };
    let bypass = {
        // The exceptions array: lines like "    0 : *.local" between the
        // ExceptionsList braces.
        let mut in_list = false;
        let mut items = Vec::new();
        for line in text.lines() {
            if line.contains("ExceptionsList") {
                in_list = true;
                continue;
            }
            if in_list {
                if line.trim() == "}" {
                    break;
                }
                if let Some((_, v)) = line.split_once(" : ") {
                    items.push(v.trim().to_string());
                }
            }
        }
        items.join(", ")
    };
    if on("ProxyAutoConfigEnable")
        && let Some(url) = kv.get("ProxyAutoConfigURLString")
    {
        return Some(ProxyConfig {
            kind: ProxyKind::Pac(url.clone()),
            source: "System Settings".to_string(),
            bypass,
        });
    }
    if on("ProxyAutoDiscoveryEnable") {
        return Some(ProxyConfig {
            kind: ProxyKind::Wpad,
            source: "System Settings".to_string(),
            bypass,
        });
    }
    let http = on("HTTPEnable")
        .then(|| hostport("HTTPProxy", "HTTPPort"))
        .flatten();
    let https = on("HTTPSEnable")
        .then(|| hostport("HTTPSProxy", "HTTPSPort"))
        .flatten();
    let socks = on("SOCKSEnable")
        .then(|| hostport("SOCKSProxy", "SOCKSPort"))
        .flatten();
    match (http, https, socks) {
        (None, None, None) => None,
        (http, https, socks) => Some(ProxyConfig {
            kind: ProxyKind::Manual {
                http: http
                    .clone()
                    .or_else(|| socks.clone().map(|s| format!("socks5://{s}")))
                    .unwrap_or_default(),
                https: https
                    .or(http)
                    .or(socks.map(|s| format!("socks5://{s}")))
                    .unwrap_or_default(),
            },
            source: "System Settings".to_string(),
            bypass,
        }),
    }
}

#[cfg(target_os = "linux")]
fn from_gsettings() -> Option<ProxyConfig> {
    let get = |schema: &str, key: &str| {
        std::process::Command::new("gsettings")
            .args(["get", schema, key])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .trim_matches('\'')
                    .to_string()
            })
    };
    let mode = get("org.gnome.system.proxy", "mode")?;
    match mode.as_str() {
        "manual" => {
            let host = get("org.gnome.system.proxy.http", "host").unwrap_or_default();
            let port = get("org.gnome.system.proxy.http", "port").unwrap_or_default();
            if host.is_empty() {
                return None;
            }
            let hp = format!("{host}:{port}");
            Some(ProxyConfig {
                kind: ProxyKind::Manual {
                    http: hp.clone(),
                    https: hp,
                },
                source: "GNOME settings".to_string(),
                bypass: get("org.gnome.system.proxy", "ignore-hosts").unwrap_or_default(),
            })
        }
        "auto" => Some(ProxyConfig {
            kind: get("org.gnome.system.proxy", "autoconfig-url")
                .filter(|u| !u.is_empty())
                .map(ProxyKind::Pac)
                .unwrap_or(ProxyKind::Wpad),
            source: "GNOME settings".to_string(),
            bypass: String::new(),
        }),
        _ => None,
    }
}

/// `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` is what
/// Edge, Chrome and WinINET follow. Read with `reg query` rather than the
/// registry API: no new API surface, and the tool is on every Windows.
#[cfg(windows)]
fn from_windows_registry() -> Option<ProxyConfig> {
    let out = std::process::Command::new("reg")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        ])
        .output()
        .ok()?;
    parse_reg_query(&String::from_utf8_lossy(&out.stdout))
}

/// `reg query` prints `    Name    REG_TYPE    value` per value.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn parse_reg_query(text: &str) -> Option<ProxyConfig> {
    let mut kv = std::collections::HashMap::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[1].starts_with("REG_") {
            kv.insert(parts[0].to_string(), parts[2..].join(" "));
        }
    }
    if let Some(url) = kv.get("AutoConfigURL").filter(|u| !u.is_empty()) {
        return Some(ProxyConfig {
            kind: ProxyKind::Pac(url.clone()),
            source: "Windows Internet Settings".to_string(),
            bypass: kv.get("ProxyOverride").cloned().unwrap_or_default(),
        });
    }
    let enabled = kv
        .get("ProxyEnable")
        .is_some_and(|v| v == "0x1" || v == "1");
    if enabled && let Some(server) = kv.get("ProxyServer").filter(|s| !s.is_empty()) {
        // "host:port" or "http=host:port;https=host:port".
        let pick = |scheme: &str| {
            server
                .split(';')
                .find_map(|part| part.strip_prefix(&format!("{scheme}=")))
                .map(str::to_string)
        };
        let http = pick("http").unwrap_or_else(|| server.clone());
        let https = pick("https").unwrap_or_else(|| http.clone());
        return Some(ProxyConfig {
            kind: ProxyKind::Manual { http, https },
            source: "Windows Internet Settings".to_string(),
            bypass: kv.get("ProxyOverride").cloned().unwrap_or_default(),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scutil_manual_and_pac_and_none_parse() {
        let none = "<dictionary> {\n  ExceptionsList : <array> {\n    0 : *.local\n    1 : 169.254/16\n  }\n  FTPPassive : 1\n}\n";
        assert!(parse_scutil(none).is_none());

        let manual = "<dictionary> {\n  HTTPEnable : 1\n  HTTPPort : 8080\n  HTTPProxy : proxy.corp\n  HTTPSEnable : 1\n  HTTPSPort : 8443\n  HTTPSProxy : proxy.corp\n  ExceptionsList : <array> {\n    0 : *.local\n  }\n}\n";
        let p = parse_scutil(manual).unwrap();
        assert_eq!(
            p.kind,
            ProxyKind::Manual {
                http: "proxy.corp:8080".into(),
                https: "proxy.corp:8443".into()
            }
        );
        assert_eq!(p.bypass, "*.local");

        let pac = "<dictionary> {\n  ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://wpad.corp/proxy.pac\n}\n";
        assert_eq!(
            parse_scutil(pac).unwrap().kind,
            ProxyKind::Pac("http://wpad.corp/proxy.pac".into())
        );
        let wpad = "<dictionary> {\n  ProxyAutoDiscoveryEnable : 1\n}\n";
        assert_eq!(parse_scutil(wpad).unwrap().kind, ProxyKind::Wpad);
    }

    #[test]
    fn windows_reg_query_parses() {
        let text = "\r\nHKEY_CURRENT_USER\\Software\\...\\Internet Settings\r\n    ProxyEnable    REG_DWORD    0x1\r\n    ProxyServer    REG_SZ    proxy.corp:3128\r\n    ProxyOverride    REG_SZ    <local>;*.corp\r\n";
        let p = parse_reg_query(text).unwrap();
        assert_eq!(
            p.kind,
            ProxyKind::Manual {
                http: "proxy.corp:3128".into(),
                https: "proxy.corp:3128".into()
            }
        );
        let off = "    ProxyEnable    REG_DWORD    0x0\r\n    ProxyServer    REG_SZ    proxy.corp:3128\r\n";
        assert!(parse_reg_query(off).is_none());
        let per_scheme = "    ProxyEnable    REG_DWORD    0x1\r\n    ProxyServer    REG_SZ    http=a:1;https=b:2\r\n";
        assert_eq!(
            parse_reg_query(per_scheme).unwrap().kind,
            ProxyKind::Manual {
                http: "a:1".into(),
                https: "b:2".into()
            }
        );
    }
}
