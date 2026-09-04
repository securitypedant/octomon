//! Continuous per-hop path monitoring — the MTR-style view.
//!
//! A one-shot traceroute tells you the path; it does not tell you *where* the
//! path hurts. This discovers the path, then keeps an ICMP probe running against
//! every hop, so loss and latency accumulate per hop and the first bad hop is
//! obvious. The path is re-discovered periodically, since routes change.
//!
//! Hops reuse [`TargetStat`], inheriting the same distribution / jitter / loss
//! maths as ordinary targets.

use std::net::IpAddr;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use surge_ping::{PingIdentifier, PingSequence};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use super::ping;
use crate::app::{AppState, HopMonitor, MonitoredHop, TargetStat};
use crate::config::Config;
use crate::platform::traceroute as tr;

/// Hops beyond this are rarely actionable and cost a probe each.
const MAX_HOPS: usize = 20;
/// How often the path is re-walked to pick up route changes.
const REDISCOVER: Duration = Duration::from_secs(60);

/// Probe identifier for a hop. The high bit keeps hops clear of target probes,
/// and the generation keeps a superseded run from stealing the new run's replies
/// during the moment before its task notices and exits.
fn ping_id(generation: u64, ttl: u8) -> u16 {
    0x8000 | (((generation as u16) & 0x7f) << 8) | ttl as u16
}

/// Begin (or restart) continuous monitoring of the path to `dest`.
pub fn start(
    state: Arc<Mutex<AppState>>,
    clients: ping::Clients,
    cfg: Config,
    dest: IpAddr,
    label: String,
) {
    let generation = {
        let mut s = state.lock().unwrap();
        let generation = s.hop_monitor.as_ref().map_or(1, |m| m.generation + 1);
        s.hop_monitor = Some(HopMonitor {
            target: format!("{label} ({dest})"),
            dest,
            hops: Vec::new(),
            discovering: true,
            generation,
            selected: 0,
        });
        generation
    };

    tokio::spawn(async move {
        loop {
            discover(&state, &clients, &cfg, dest, generation).await;
            if superseded(&state, generation) {
                return;
            }
            tokio::time::sleep(REDISCOVER).await;
            if superseded(&state, generation) {
                return;
            }
            // Mark the re-walk so the UI can show it without clearing stats.
            let mut s = state.lock().unwrap();
            if let Some(m) = s
                .hop_monitor
                .as_mut()
                .filter(|m| m.generation == generation)
            {
                m.discovering = true;
            }
        }
    });
}

/// True once a newer monitor run (or none at all) owns the state.
fn superseded(state: &Arc<Mutex<AppState>>, generation: u64) -> bool {
    state
        .lock()
        .unwrap()
        .hop_monitor
        .as_ref()
        .is_none_or(|m| m.generation != generation)
}

/// Walk the path once, merging what is found into the live hop list and starting
/// a probe for each newly resolved hop. Streams so hops appear as they arrive.
async fn discover(
    state: &Arc<Mutex<AppState>>,
    clients: &ping::Clients,
    cfg: &Config,
    dest: IpAddr,
    generation: u64,
) {
    let program = tr::program(&dest.to_string());
    let child = Command::new(program)
        .args(tr::args(MAX_HOPS, &dest.to_string()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            crate::errlog::log(
                "hopmon",
                format!("could not run {program} toward {dest}: {e}"),
            );
            let mut s = state.lock().unwrap();
            if let Some(m) = s
                .hop_monitor
                .as_mut()
                .filter(|m| m.generation == generation)
            {
                m.discovering = false;
            }
            s.notice_event(
                crate::verdict::Severity::Info,
                crate::app::EventCategory::Path,
                format!("{program} could not be run — cannot discover the hops toward the target"),
            );
            return;
        }
    };

    if let Some(stdout) = child.stdout.take() {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let Some(hop) = tr::parse_hop(&line) else {
                continue;
            };
            let addr = hop.addr.as_ref().and_then(|a| a.parse::<IpAddr>().ok());
            // Applying under the lock keeps the hop list and the probe tasks in
            // agreement about which address each ttl currently has.
            let spawn = {
                let mut s = state.lock().unwrap();
                let Some(m) = s
                    .hop_monitor
                    .as_mut()
                    .filter(|m| m.generation == generation)
                else {
                    return; // superseded mid-walk
                };
                merge_hop(m, hop.ttl, addr)
            };
            if let Some(addr) = spawn {
                spawn_probe(
                    state.clone(),
                    clients.clone(),
                    cfg.clone(),
                    generation,
                    hop.ttl,
                    addr,
                );
            }
            // The first answer from the destination ends the path, as in mtr.
            // traceroute itself only stops on port-unreachable, so a network
            // whose edge answers time-exceeded from the destination's own
            // address (Cloudflare's anycast does this) would otherwise show
            // the destination twice with an internal hop between — and since
            // hops are probed by address, both rows would be the same ping.
            if addr == Some(dest) {
                let _ = child.start_kill();
                break;
            }
        }
    }
    let _ = child.wait().await;

    // A walk that never reached the destination still gets an endpoint row: a
    // hop's loss only means something next to the destination's, and edges that
    // drop traceroute's UDP probes usually still answer ping.
    let spawn = {
        let mut s = state.lock().unwrap();
        let Some(m) = s
            .hop_monitor
            .as_mut()
            .filter(|m| m.generation == generation)
        else {
            return;
        };
        m.discovering = false;
        if m.hops.iter().any(|h| h.addr == Some(dest)) {
            None
        } else {
            merge_hop(m, MonitoredHop::DEST_TTL, Some(dest))
        }
    };
    if let Some(addr) = spawn {
        spawn_probe(
            state.clone(),
            clients.clone(),
            cfg.clone(),
            generation,
            MonitoredHop::DEST_TTL,
            addr,
        );
    }
}

/// Fold a discovered hop into the monitor. Returns the address to start probing
/// when this hop is new or has moved; `None` when nothing changed, so an
/// established hop keeps accumulating history across re-walks.
///
/// A hop that answers as the destination is the last one: anything previously
/// known beyond it (a longer path from an earlier walk, or a duplicate of the
/// destination) is dropped, and its probes exit on their next tick.
fn merge_hop(m: &mut HopMonitor, ttl: u8, addr: Option<IpAddr>) -> Option<IpAddr> {
    let label = if ttl == MonitoredHop::DEST_TTL {
        "dest".to_string()
    } else {
        format!("hop {ttl}")
    };
    let spawn = match m.hops.iter_mut().find(|h| h.ttl == ttl) {
        Some(existing) => {
            if existing.addr == addr {
                None // unchanged — keep its statistics
            } else {
                existing.addr = addr;
                existing.stat = addr.map(|a| TargetStat::new(label, a));
                addr
            }
        }
        None => {
            m.hops.push(MonitoredHop {
                ttl,
                addr,
                stat: addr.map(|a| TargetStat::new(label, a)),
            });
            m.hops.sort_by_key(|h| h.ttl);
            addr
        }
    };
    if addr == Some(m.dest) {
        m.hops.retain(|h| h.ttl <= ttl);
    }
    spawn
}

/// Keep one hop measured until its monitor run ends or its address changes.
fn spawn_probe(
    state: Arc<Mutex<AppState>>,
    clients: ping::Clients,
    cfg: Config,
    generation: u64,
    ttl: u8,
    addr: IpAddr,
) {
    // Hops on a v6 path need the v6 client and vice versa; a hop whose family
    // has no client just stays unmeasured rather than reading as loss.
    let Some(client) = clients.for_addr(addr) else {
        return;
    };
    tokio::spawn(async move {
        let mut pinger = client
            .pinger(addr, PingIdentifier(ping_id(generation, ttl)))
            .await;
        pinger.timeout(cfg.ping_timeout());
        let payload = [0u8; 56];
        let mut seq: u16 = 0;

        // Spread hops across the interval so a 20-hop path doesn't fire twenty
        // probes on the same tick.
        let offset = cfg.ping_interval_ms.saturating_mul(ttl as u64 % 10) / 10;
        tokio::time::sleep(Duration::from_millis(offset)).await;

        let mut ticker = tokio::time::interval(cfg.ping_interval());
        loop {
            ticker.tick().await;
            seq = seq.wrapping_add(1);
            let result = pinger.ping(PingSequence(seq), &payload).await;

            let mut s = state.lock().unwrap();
            let Some(m) = s
                .hop_monitor
                .as_mut()
                .filter(|m| m.generation == generation)
            else {
                break; // monitor stopped or restarted
            };
            let Some(hop) = m.hops.iter_mut().find(|h| h.ttl == ttl) else {
                break;
            };
            if hop.addr != Some(addr) {
                break; // the path moved; a fresh probe owns this ttl now
            }
            let Some(stat) = hop.stat.as_mut() else { break };
            match result {
                Ok((_pkt, dur)) => stat.record_reply(dur.as_secs_f64() * 1000.0),
                Err(_) => stat.record_loss(),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn monitor() -> HopMonitor {
        HopMonitor {
            target: "t".into(),
            dest: IpAddr::V4(Ipv4Addr::LOCALHOST),
            hops: Vec::new(),
            discovering: true,
            generation: 1,
            selected: 0,
        }
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    #[test]
    fn hops_keep_their_stats_across_rediscovery() {
        let mut m = monitor();
        assert_eq!(merge_hop(&mut m, 1, Some(ip(1))), Some(ip(1)));
        m.hops[0].stat.as_mut().unwrap().record_reply(5.0);

        // Same address on the next walk: no new probe, history preserved.
        assert_eq!(merge_hop(&mut m, 1, Some(ip(1))), None);
        assert_eq!(m.hops[0].stat.as_ref().unwrap().sent, 1);

        // Route change: fresh statistics, and a probe for the new address.
        assert_eq!(merge_hop(&mut m, 1, Some(ip(2))), Some(ip(2)));
        assert_eq!(m.hops[0].stat.as_ref().unwrap().sent, 0);
    }

    #[test]
    fn unresponsive_hops_are_recorded_without_a_probe() {
        let mut m = monitor();
        assert_eq!(merge_hop(&mut m, 3, None), None);
        assert_eq!(m.hops.len(), 1);
        assert!(m.hops[0].stat.is_none());
    }

    #[test]
    fn hops_stay_ordered_by_ttl_regardless_of_arrival() {
        let mut m = monitor();
        merge_hop(&mut m, 3, Some(ip(3)));
        merge_hop(&mut m, 1, Some(ip(1)));
        merge_hop(&mut m, 2, Some(ip(2)));
        assert_eq!(
            m.hops.iter().map(|h| h.ttl).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    /// Cloudflare's edge answers time-exceeded from 1.1.1.1 itself, so a raw
    /// traceroute reads `13 1.1.1.1 / 14 172.68.x.x / 15 1.1.1.1`. The path
    /// ends at the first destination answer, and a shorter path on a re-walk
    /// sheds the hops beyond it.
    #[test]
    fn the_path_ends_at_the_first_destination_answer() {
        let mut m = monitor();
        let dest = m.dest;
        merge_hop(&mut m, 1, Some(ip(1)));
        merge_hop(&mut m, 2, Some(ip(2)));
        merge_hop(&mut m, 3, Some(dest));
        assert_eq!(m.hops.len(), 3);

        // Next walk finds the destination one hop sooner: hop 3 goes.
        merge_hop(&mut m, 1, Some(ip(1)));
        merge_hop(&mut m, 2, Some(dest));
        assert_eq!(m.hops.iter().map(|h| h.ttl).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(m.hops[1].addr, Some(dest));
    }

    /// A walk that stops short still ends in the destination, and that row
    /// gives way to the real last hop when a later walk gets there.
    #[test]
    fn an_unreached_destination_is_appended_then_replaced() {
        let mut m = monitor();
        let dest = m.dest;
        merge_hop(&mut m, 1, Some(ip(1)));
        merge_hop(&mut m, 2, None);
        // What discover() does after the walk: no dest seen → placeholder.
        assert!(!m.hops.iter().any(|h| h.addr == Some(dest)));
        assert_eq!(
            merge_hop(&mut m, MonitoredHop::DEST_TTL, Some(dest)),
            Some(dest)
        );
        assert!(m.hops.last().unwrap().is_dest_placeholder());
        assert_eq!(m.hops.last().unwrap().stat.as_ref().unwrap().label, "dest");
        // Unchanged next time: its statistics survive the re-walk.
        assert_eq!(merge_hop(&mut m, MonitoredHop::DEST_TTL, Some(dest)), None);

        // The next walk reaches the destination at ttl 3: placeholder gone.
        merge_hop(&mut m, 3, Some(dest));
        assert_eq!(
            m.hops.iter().map(|h| h.ttl).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    /// End-to-end against the real network: walks the path to 1.1.1.1 and waits
    /// for hops to accumulate samples. Ignored by default — it needs ICMP, DNS
    /// and `traceroute`, none of which belong in CI. Run with:
    /// `cargo test -- --ignored --nocapture live_path_monitor`
    #[tokio::test]
    #[ignore = "requires network access"]
    async fn live_path_monitor() {
        let state = Arc::new(Mutex::new(AppState::new(vec![])));
        let (clients, err) = ping::Clients::open();
        assert!(err.is_none(), "ICMP unavailable: {err:?}");
        let dest: IpAddr = "1.1.1.1".parse().unwrap();
        start(
            state.clone(),
            clients,
            Config::default(),
            dest,
            "Cloudflare".into(),
        );

        // Path discovery walks up to 20 hops at ~1s each, then probes need a
        // few ticks before any statistics exist.
        tokio::time::sleep(Duration::from_secs(25)).await;

        let s = state.lock().unwrap();
        let m = s.hop_monitor.as_ref().expect("monitor should be running");
        println!("path to {} ({} hops)", m.target, m.hops.len());
        for h in &m.hops {
            match &h.stat {
                Some(st) => println!(
                    "  {:>2}  {:<16} loss {:>3.0}%  last {:?}  sent {}",
                    h.ttl,
                    h.addr.map(|a| a.to_string()).unwrap_or_default(),
                    st.recent_loss_pct(usize::MAX),
                    st.last_rtt_ms,
                    st.sent
                ),
                None => println!("  {:>2}  *", h.ttl),
            }
        }
        assert!(!m.hops.is_empty(), "no hops discovered");
        let probed = m.hops.iter().filter(|h| h.stat.is_some()).count();
        assert!(probed > 0, "no hop was probed");
        let sampled: usize = m
            .hops
            .iter()
            .filter_map(|h| h.stat.as_ref())
            .filter(|st| st.sent > 0)
            .count();
        assert!(sampled > 0, "hops discovered but never probed");
    }

    /// Hop probes must not collide with target probes, or with a previous run's
    /// tasks in the moment before they notice they are superseded.
    #[test]
    fn probe_ids_are_distinct() {
        assert_ne!(ping_id(1, 1), ping_id(2, 1));
        assert_ne!(ping_id(1, 1), ping_id(1, 2));
        // High bit set keeps the whole hop range clear of target identifiers,
        // which are allocated from a small ascending counter.
        assert!(ping_id(0, 0) >= 0x8000);
        assert!(ping_id(u64::MAX, 255) >= 0x8000);
    }
}
