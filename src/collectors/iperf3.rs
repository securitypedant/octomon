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

use tokio::io::AsyncBufReadExt as _;

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
///
/// Runs with `-i 1 --forceflush` and streams the interval lines as they
/// print, so the live figure is iperf3's own per-second measurement — the
/// interface counters were tried first and lied whenever the test didn't
/// cross the default interface (a loopback server most of all). The final
/// number is the summary's *receiver* rate: what was actually delivered,
/// whichever end that was.
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
        "-t",
        &SECONDS.to_string(),
        "-i",
        "1",
        "--forceflush",
    ]);
    if reverse {
        cmd.arg("-R");
    }
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(
                "iperf3 binary not found — install it (brew install iperf3 / apt install iperf3)"
                    .to_string(),
            );
        }
        Err(e) => return Err(format!("iperf3: {e}")),
    };
    let stdout = child.stdout.take().expect("piped");
    let mut lines = tokio::io::BufReader::new(stdout).lines();

    let started = std::time::Instant::now();
    let mut ticker = tokio::time::interval(Duration::from_millis(250));
    let mut live = 0.0f64;
    let mut receiver: Option<f64> = None;
    let mut sender: Option<f64> = None;
    loop {
        let frac = (started.elapsed().as_secs_f64() / SECONDS as f64).min(1.0);
        tokio::select! {
            line = lines.next_line() => match line {
                Ok(Some(l)) => {
                    let Some(mbps) = rate_mbps(&l) else { continue };
                    if l.contains("receiver") {
                        receiver = Some(mbps);
                    } else if l.contains("sender") {
                        sender = Some(mbps);
                    } else {
                        live = mbps;
                        update(state, base + frac * 0.5, live);
                    }
                }
                Ok(None) => break,
                Err(e) => return Err(format!("iperf3 output: {e}")),
            },
            _ = ticker.tick() => update(state, base + frac * 0.5, live),
        }
    }
    let status = child.wait().await.map_err(|e| format!("iperf3: {e}"))?;
    if let Some(mbps) = receiver.or(sender) {
        return Ok(mbps);
    }
    // No summary: the run failed — iperf3 puts the reason on stderr
    // ("iperf3: error - unable to connect…", "…server is busy…").
    let mut err = String::new();
    if let Some(mut se) = child.stderr.take() {
        use tokio::io::AsyncReadExt as _;
        let _ = se.read_to_string(&mut err).await;
    }
    let err = err.trim();
    if err.is_empty() {
        Err(format!("iperf3 exited ({status}) with no result"))
    } else {
        Err(err.trim_start_matches("iperf3: ").to_string())
    }
}

/// The Mb/s out of one iperf3 line, `None` for lines that carry no rate
/// (headers, separators, the connect banner). Works on interval and summary
/// lines alike: the number sits immediately before the "…bits/sec" token.
///   [  5]   1.00-2.00   sec  1.10 GBytes  9.46 Gbits/sec
///   [  5]   0.00-8.00   sec  10.9 GBytes  11.7 Gbits/sec   receiver
fn rate_mbps(line: &str) -> Option<f64> {
    let mut prev: Option<&str> = None;
    for tok in line.split_whitespace() {
        if let Some(unit) = tok.strip_suffix("bits/sec") {
            let value: f64 = prev?.parse().ok()?;
            let factor = match unit {
                "G" => 1000.0,
                "M" => 1.0,
                "K" => 0.001,
                "T" => 1_000_000.0,
                "" => 0.000_001,
                _ => return None,
            };
            return Some(value * factor);
        }
        prev = Some(tok);
    }
    None
}

#[cfg(test)]
mod tests {

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
    fn iperf3_lines_parse_to_mbps_and_noise_does_not() {
        use super::rate_mbps;
        // Interval and summary lines, across the unit ladder.
        assert_eq!(
            rate_mbps("[  5]   1.00-2.00   sec  1.10 GBytes  9.46 Gbits/sec"),
            Some(9460.0)
        );
        assert_eq!(
            rate_mbps("[  5]   2.00-3.00   sec  11.2 MBytes  94.1 Mbits/sec    0    331 KBytes"),
            Some(94.1)
        );
        assert_eq!(
            rate_mbps("[  5]   0.00-8.00   sec  10.9 GBytes  11.7 Gbits/sec  receiver"),
            Some(11700.0)
        );
        assert_eq!(
            rate_mbps("[  5]   3.00-4.00   sec  32.0 KBytes   262 Kbits/sec"),
            Some(0.262)
        );
        // Headers, separators and the banner carry no rate.
        assert_eq!(
            rate_mbps("- - - - - - - - - - - - - - - - - - - - - - - - -"),
            None
        );
        assert_eq!(
            rate_mbps("[ ID] Interval           Transfer     Bitrate"),
            None
        );
        assert_eq!(rate_mbps("Connecting to host 127.0.0.1, port 5277"), None);
    }
}
