//! Traceroute for a selected target, by streaming the system `traceroute`
//! (unprivileged: UDP probes on macOS/Linux). Hops are parsed and pushed into
//! the shared state as they arrive, so the panel fills in live.

use std::net::IpAddr;
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::app::{AppState, Hop, Traceroute};

/// Begin a traceroute to `addr`, replacing any previous result.
pub fn start(state: Arc<Mutex<AppState>>, addr: IpAddr, label: String) {
    tokio::spawn(async move {
        {
            let mut s = state.lock().unwrap();
            s.traceroute = Some(Traceroute {
                target: format!("{label} ({addr})"),
                running: true,
                hops: Vec::new(),
            });
        }

        let child = Command::new("traceroute")
            .args(["-n", "-q", "1", "-w", "1", "-m", "20", &addr.to_string()])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();

        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                finish(&state, Some(format!("traceroute unavailable: {e}")));
                return;
            }
        };

        if let Some(stdout) = child.stdout.take() {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if let Some(hop) = parse_hop(&line) {
                    let mut s = state.lock().unwrap();
                    if let Some(tr) = s.traceroute.as_mut() {
                        tr.hops.push(hop);
                    }
                }
            }
        }
        let _ = child.wait().await;
        finish(&state, None);
    });
}

fn finish(state: &Arc<Mutex<AppState>>, err: Option<String>) {
    let mut s = state.lock().unwrap();
    if let Some(tr) = s.traceroute.as_mut() {
        tr.running = false;
    }
    if let Some(e) = err {
        s.notice = Some(e);
    }
}

/// Parse a hop line like ` 5  157.131.209.65  187.819 ms` or ` 6  *`.
/// The header ("traceroute to …") and blanks return `None`.
fn parse_hop(line: &str) -> Option<Hop> {
    let mut it = line.split_whitespace();
    let ttl: u8 = it.next()?.parse().ok()?;
    let second = it.next()?;
    if second == "*" {
        return Some(Hop {
            ttl,
            addr: None,
            rtt_ms: None,
        });
    }
    let rtt_ms = it.next().and_then(|v| v.parse::<f64>().ok());
    Some(Hop {
        ttl,
        addr: Some(second.to_string()),
        rtt_ms,
    })
}
