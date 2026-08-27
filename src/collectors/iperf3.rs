//! iPerf3 as a speed-test provider: raw TCP throughput against a server the
//! user runs (a homelab box, an office rack, a VPS) — no third party at all.
//! Shells out to the `iperf3` binary with `-J` rather than reimplementing the
//! protocol: the reference client is the compatibility story, and it is one
//! `brew install iperf3` / `apt install iperf3` away where it isn't already.
//!
//! Two runs: `-R` first (server → us: download), then plain (upload). No
//! idle/loaded latency pair is measured — the ping columns above tell that
//! story live while the transfer saturates the link.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::app::AppState;

use super::speedtest::{Report, set_phase, update};

/// Seconds per direction: matches the HTTP providers' measure window closely
/// enough that the histories compare like with like.
const SECONDS: u32 = 8;

pub async fn run(
    state: &Arc<Mutex<AppState>>,
    name: &str,
    host: &str,
    port: u16,
) -> Result<Report, String> {
    set_phase(state, &format!("iPerf3 {name} · download"));
    let down_mbps = run_dir(state, host, port, true, 0.0).await?;
    set_phase(state, &format!("iPerf3 {name} · upload"));
    let up_mbps = run_dir(state, host, port, false, 0.5).await?;
    Ok(Report {
        provider: format!("iPerf3 · {name}"),
        down_mbps,
        up_mbps,
        idle_ms: None,
        loaded_ms: None,
        server: Some(format!("{host}:{port}")),
    })
}

/// One direction; `base` is where this run's share of the progress bar
/// starts (download owns the first half, upload the second).
async fn run_dir(
    state: &Arc<Mutex<AppState>>,
    host: &str,
    port: u16,
    reverse: bool,
    base: f64,
) -> Result<f64, String> {
    let mut cmd = tokio::process::Command::new("iperf3");
    cmd.args([
        "-c",
        host,
        "-p",
        &port.to_string(),
        "-J",
        "-t",
        &SECONDS.to_string(),
    ]);
    if reverse {
        cmd.arg("-R");
    }
    cmd.stdin(std::process::Stdio::null());
    // `-J` prints nothing until the run ends, so the bar advances on the
    // clock while the child works; the Bandwidth graphs show the live truth.
    let started = std::time::Instant::now();
    let mut ticker = tokio::time::interval(Duration::from_millis(250));
    let mut child = std::pin::pin!(cmd.output());
    let out = loop {
        tokio::select! {
            out = &mut child => break out,
            _ = ticker.tick() => {
                let frac = (started.elapsed().as_secs_f64() / SECONDS as f64).min(1.0);
                // Live rate from octomon's own interface counters — the same
                // truth the Bandwidth graphs draw — since `-J` says nothing
                // until the run ends.
                let bps = {
                    let s = state.lock().unwrap();
                    if reverse { s.throughput.down_bps } else { s.throughput.up_bps }
                };
                update(state, base + frac * 0.5, bps * 8.0 / 1e6);
            }
        }
    };
    let out = match out {
        Ok(out) => out,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(
                "iperf3 binary not found — install it (brew install iperf3 / apt install iperf3)"
                    .to_string(),
            );
        }
        Err(e) => return Err(format!("iperf3: {e}")),
    };
    // iperf3 -J reports its own errors as JSON on stdout with a nonzero
    // exit; parse either way and prefer the JSON's story.
    parse_mbps(&String::from_utf8_lossy(&out.stdout), reverse)
}

/// Mb/s out of `iperf3 -J` output. Download runs use `-R`, so the client is
/// the receiving side and `sum_received` is the number; uploads read
/// `sum_sent` — what actually left this machine, retransmits excluded.
pub fn parse_mbps(json: &str, reverse: bool) -> Result<f64, String> {
    let v: serde_json::Value =
        serde_json::from_str(json.trim()).map_err(|e| format!("iperf3 output: {e}"))?;
    if let Some(err) = v["error"].as_str() {
        return Err(format!("iperf3: {err}"));
    }
    let sum = if reverse {
        &v["end"]["sum_received"]
    } else {
        &v["end"]["sum_sent"]
    };
    sum["bits_per_second"]
        .as_f64()
        .map(|b| b / 1e6)
        .ok_or_else(|| "iperf3: no throughput in the result".to_string())
}

#[cfg(test)]
mod tests {
    use super::parse_mbps;

    /// The whole runner against a real local server. Ignored: needs the
    /// iperf3 binary and a free port — run it by hand with `-- --ignored`.
    #[tokio::test]
    #[ignore = "needs the iperf3 binary installed"]
    async fn live_localhost_roundtrip() {
        use std::sync::{Arc, Mutex};
        let mut server = std::process::Command::new("iperf3")
            .args(["-s", "-p", "5277"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("iperf3 -s starts");
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        let state = Arc::new(Mutex::new(crate::app::AppState::new(vec![])));
        let report = super::run(&state, "local", "127.0.0.1", 5277).await;
        let _ = server.kill();
        let _ = server.wait();
        let report = report.expect("test ran");
        assert!(
            report.down_mbps > 100.0,
            "loopback down: {}",
            report.down_mbps
        );
        assert!(report.up_mbps > 100.0, "loopback up: {}", report.up_mbps);
        assert_eq!(report.provider, "iPerf3 · local");
        assert_eq!(report.server.as_deref(), Some("127.0.0.1:5277"));
    }

    #[test]
    fn iperf3_json_parses_throughput_and_surfaces_errors() {
        let ok = r#"{"start":{},"intervals":[],"end":{
            "sum_sent":{"bits_per_second":94123456.0,"retransmits":12},
            "sum_received":{"bits_per_second":93000000.0}}}"#;
        assert_eq!(parse_mbps(ok, false).unwrap().round(), 94.0);
        assert_eq!(parse_mbps(ok, true).unwrap().round(), 93.0);

        // The busy-server case every public iperf3 host hits constantly.
        let busy = r#"{"error":"the server is busy running a test. try again later"}"#;
        let e = parse_mbps(busy, true).unwrap_err();
        assert!(e.contains("busy"), "{e}");

        assert!(parse_mbps("not json", true).is_err());
    }
}
