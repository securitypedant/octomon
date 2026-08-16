//! Traceroute for a selected target, by streaming the system `traceroute`
//! (unprivileged: UDP probes on macOS/Linux). Hops are parsed and pushed into
//! the shared state as they arrive, so the panel fills in live.

use std::net::IpAddr;
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::app::{AppState, Traceroute};
use crate::platform::traceroute as tr;

/// Hops beyond this are rarely actionable, and each costs a probe.
const MAX_HOPS: usize = 20;

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

        let child = Command::new(tr::PROGRAM)
            .args(tr::args(MAX_HOPS, &addr.to_string()))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();

        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                finish(&state, Some(format!("{} unavailable: {e}", tr::PROGRAM)));
                return;
            }
        };

        if let Some(stdout) = child.stdout.take() {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if let Some(hop) = tr::parse_hop(&line) {
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
