//! Per-network baselines: what *normal* looks like on this network, learned
//! only while the verdict is fully healthy and persisted per location.
//!
//! "45 ms to the gateway" is meaningless in isolation — the question is "is
//! this normal *for me, here*?". Each network the machine joins is
//! fingerprinted (SSID + gateway MAC on Wi-Fi, gateway MAC on a cable), so a
//! laptop that moves between home, office and café keeps a separate notion of
//! normal for each, and the verdict can say "gateway 41ms vs ~9ms normal at
//! Home". The healthy-only gate is the anti-poisoning rule: an incident never
//! contaminates the baseline it will be judged against.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::app::{AppState, LinkMedium, NetInfo};
use crate::verdict::thresholds as th;

/// EWMA weight for folding a new observation in: slow enough that one odd
/// minute barely moves it, fast enough to converge within an evening.
const ALPHA: f64 = 0.2;

/// Baseline comparisons stay quiet until this many healthy folds.
pub const MIN_SAMPLES: u32 = 5;

/// Learned normals for one network. All values are EWMAs of windowed
/// aggregates, folded in once per healthy minute.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Baseline {
    /// Auto label: the SSID, or the gateway address on a cable.
    pub label: String,
    /// User-given name ("Home", "Office"), set with [N].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// How the machine was attached when this was learned ("Wi-Fi",
    /// "Ethernet (wired)") — the same LAN over a cable and over the radio is
    /// two different normals, and two entries, so this tells them apart.
    #[serde(default)]
    pub medium: String,
    /// Healthy folds so far — confidence in the baseline itself.
    pub samples: u32,
    /// When the machine was last attached to this network (unix seconds) —
    /// orders the locations overlay by recency. Stamped on every attach and
    /// fold; absent in files from before the field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<i64>,
    pub gateway_ms: Option<f64>,
    pub gateway_p95_ms: Option<f64>,
    pub anchor_ms: Option<f64>,
    /// Learned ICMP loss (per cent). Plane, hotel and hotspot networks run
    /// double-digit loss as their permanent weather; grading against these
    /// keeps their colours meaningful instead of solid red. Absent in files
    /// from before the fields existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_loss_pct: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_loss_pct: Option<f64>,
    /// TCP connect and web TTFB normals (best anchor) — the ICMP-free view
    /// of "how far away is the internet here". On networks that blackhole
    /// ICMP these are the *only* latency normals a location can learn.
    /// Absent in files from before the fields existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_tcp_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_ttfb_ms: Option<f64>,
    pub dns_ms: Option<f64>,
    pub rssi_dbm: Option<f64>,
    pub down_mbps: Option<f64>,
    pub up_mbps: Option<f64>,
}

impl Baseline {
    /// Whether comparisons against this baseline are worth voicing.
    pub fn established(&self) -> bool {
        self.samples >= MIN_SAMPLES
    }

    /// The name to use in verdicts: the user's, else the auto label.
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.label)
    }
}

/// One minute's healthy aggregates, computed under the state lock.
#[derive(Clone, Default)]
pub struct Sample {
    pub medium: String,
    pub gateway_ms: Option<f64>,
    pub gateway_p95_ms: Option<f64>,
    pub anchor_ms: Option<f64>,
    pub gateway_loss_pct: Option<f64>,
    pub anchor_loss_pct: Option<f64>,
    pub anchor_tcp_ms: Option<f64>,
    pub web_ttfb_ms: Option<f64>,
    pub dns_ms: Option<f64>,
    pub rssi_dbm: Option<f64>,
}

impl Sample {
    /// Read the current windowed aggregates out of shared state.
    pub fn take(s: &AppState) -> Sample {
        let n = 60;
        // The same resolution the verdict uses — address first, discovery
        // label as fallback. Matching only the routing table's gateway_ip
        // missed the gateway entirely on VPNs, where that is the tunnel's
        // own address and not the hop discovery pings, so the location never
        // learned a gateway normal.
        let gw = crate::verdict::gateway_target(s);
        let (gateway_ms, gateway_p95_ms) = gw
            .map(|g| {
                let st = g.stats(n);
                (st.mean, st.p95)
            })
            .unwrap_or_default();
        let gateway_loss_pct = gw
            .filter(|g| !g.window.is_empty())
            .map(|g| g.recent_loss_pct(n));
        // Best (lowest-mean) anchor: "how far away is the internet at its best".
        let anchor_ms = s
            .targets
            .iter()
            .filter(|t| !t.discovered)
            .filter_map(|t| t.stats(n).mean)
            .min_by(f64::total_cmp);
        // Best (lowest-loss) anchor, same reasoning: on a network whose *best*
        // path still drops packets, that loss is the location's weather.
        let anchor_loss_pct = s
            .targets
            .iter()
            .filter(|t| !t.discovered && !t.window.is_empty())
            .map(|t| t.recent_loss_pct(n))
            .min_by(f64::total_cmp);
        // The ICMP-free latency normals, same "best anchor" reasoning: TCP
        // connect and web TTFB both work where ping is blackholed, so a
        // location's learning never comes back empty-handed.
        let anchor_tcp_ms = s
            .targets
            .iter()
            .filter(|t| !t.discovered)
            .filter_map(|t| t.tcp.stats(n).mean)
            .min_by(f64::total_cmp);
        let web_ttfb_ms = s
            .targets
            .iter()
            .filter(|t| !t.discovered)
            .filter_map(|t| {
                let recent: Vec<f64> = t.web.hist.successes().rev().take(n).collect();
                (!recent.is_empty()).then(|| recent.iter().sum::<f64>() / recent.len() as f64)
            })
            .min_by(f64::total_cmp);
        // This network's own resolvers; the reference resolver is contrast.
        let dns: Vec<f64> = s
            .dns
            .iter()
            .filter(|p| !p.reference)
            .filter_map(|p| p.mean_ms())
            .collect();
        let dns_ms = (!dns.is_empty()).then(|| dns.iter().sum::<f64>() / dns.len() as f64);
        let rssi_dbm = s.signal.present.then_some(s.signal.rssi_dbm as f64);
        Sample {
            medium: s.netinfo.medium.label().to_string(),
            gateway_ms,
            gateway_p95_ms,
            anchor_ms,
            gateway_loss_pct,
            anchor_loss_pct,
            anchor_tcp_ms,
            web_ttfb_ms,
            dns_ms,
            rssi_dbm,
        }
    }
}

fn ewma(prev: Option<f64>, new: Option<f64>) -> Option<f64> {
    match (prev, new) {
        (Some(p), Some(n)) => Some(p + ALPHA * (n - p)),
        (None, n) => n,
        (p, None) => p,
    }
}

impl Baseline {
    /// Fold one healthy minute in.
    pub fn fold(&mut self, sample: Sample) {
        if !sample.medium.is_empty() {
            self.medium = sample.medium;
        }
        self.gateway_ms = ewma(self.gateway_ms, sample.gateway_ms);
        self.gateway_p95_ms = ewma(self.gateway_p95_ms, sample.gateway_p95_ms);
        self.anchor_ms = ewma(self.anchor_ms, sample.anchor_ms);
        self.gateway_loss_pct = ewma(self.gateway_loss_pct, sample.gateway_loss_pct);
        self.anchor_loss_pct = ewma(self.anchor_loss_pct, sample.anchor_loss_pct);
        self.anchor_tcp_ms = ewma(self.anchor_tcp_ms, sample.anchor_tcp_ms);
        self.web_ttfb_ms = ewma(self.web_ttfb_ms, sample.web_ttfb_ms);
        self.dns_ms = ewma(self.dns_ms, sample.dns_ms);
        self.rssi_dbm = ewma(self.rssi_dbm, sample.rssi_dbm);
        self.samples += 1;
        self.last_seen = Some(chrono::Utc::now().timestamp());
    }
}

/// netdev reports an unresolved neighbour as 00:00:00:00:00:00, which must not key a location.
pub fn mac_is_known(mac: &str) -> bool {
    mac.chars().any(|c| c.is_ascii_hexdigit() && c != '0')
}

/// The address that names a tunnel config: the first IPv4, else the first
/// non-link-local IPv6 — macOS gives every utun a link-local of its own,
/// which says nothing about the config. Prefix lengths are dropped.
fn tunnel_identity_addr<'a>(addrs: impl IntoIterator<Item = &'a String>) -> Option<&'a str> {
    let bare: Vec<&str> = addrs
        .into_iter()
        .map(|a| a.split('/').next().unwrap_or(a))
        .collect();
    bare.iter()
        .copied()
        .find(|a| a.parse::<std::net::Ipv4Addr>().is_ok())
        .or_else(|| {
            bare.iter().copied().find(|a| {
                a.parse::<std::net::Ipv6Addr>()
                    .is_ok_and(|v6| (v6.segments()[0] & 0xffc0) != 0xfe80)
            })
        })
}

/// WireGuard names the software, not the server: two configs for two
/// different exits would share one location. A WireGuard config carries its
/// own address (`Address =`), fixed until the file is edited, so it tells the
/// configs apart where the vendor alone cannot. No other protocol gets this:
/// OpenVPN and every corporate client are handed an address from a pool per
/// session, and keyed on that, each connect would mint a new location.
fn self_hosted_tunnel_addr<'a>(
    vendor: &str,
    addrs: impl IntoIterator<Item = &'a String>,
) -> Option<&'a str> {
    if vendor != "WireGuard" {
        return None;
    }
    tunnel_identity_addr(addrs)
}

/// The identity of a tunnel no vendor could be named for: the constant "VPN",
/// and nothing else. The device name is no identity on macOS, where utunN
/// renumbers across connects; the tunnel's address is none either, since an
/// unidentified VPN is usually a corporate one that assigns from a pool. Either
/// would mint a new location per connect, losing the normals and the name.
/// So two unknown VPNs used from one network share a location, which is the
/// rarer and smaller harm.
const UNIDENTIFIED: &str = "VPN";

/// Fingerprint "which network is this" → (stable key, human label).
///
/// Wi-Fi keys on SSID + gateway MAC: the pair survives DHCP renewals and mesh
/// roaming, distinguishes two networks sharing a generic SSID, and needs no
/// Location permission (when macOS redacts the SSID, the gateway MAC still
/// identifies the network). A cable keys on the gateway MAC alone. No gateway
/// at all → no baseline, rather than a garbage key.
///
/// VPNs make their own locations, because a tunnel changes what the internet
/// looks like regardless of the room — and per *underlying network*, since the
/// uplink and the exit PoP both shape the normal: "HomeNet via Cloudflare
/// WARP" ≠ "HotelNet via Cloudflare WARP". Split tunnels key on the physical
/// network's own identity; full tunnels on the gatewayed physical interface
/// found beneath the tunnel. A WireGuard config adds its own address to the
/// identity, full or split, so two configs from one LAN are two exits (see
/// [`self_hosted_tunnel_addr`]); an unidentified tunnel is one "VPN" per
/// network (see [`UNIDENTIFIED`]). With no underlay visible at all, the VPN
/// half alone is the location.
pub fn fingerprint(n: &NetInfo) -> Option<(String, String)> {
    let mac_known = mac_is_known(&n.gateway_mac);
    let ip_known = !n.gateway_ip.is_empty() && n.gateway_ip != "-";
    // macOS returns the literal "<redacted>" without Location Services; that is
    // not an identity.
    let ssid = n
        .wifi
        .as_ref()
        .map(|w| w.ssid.as_str())
        .filter(|s| !s.is_empty() && !s.contains("redacted"))
        .unwrap_or("");
    // A full-tunnel VPN (the tunnel itself holds the default route) is its own
    // place, whatever LAN sits underneath: latency, DNS and loss all describe
    // the tunnel, not the room. Keyed on the vendor (plus a WireGuard
    // config's own address), so reconnecting — or macOS renumbering utunN —
    // comes back to the same location instead of minting a new one each
    // time. This is also the
    // only identity a tunnel like WARP on Windows has: a /32, no gateway, no
    // MAC — nothing below would key on it at all.
    let full_tunnel = n.medium == LinkMedium::Tunnel && n.tunnel.is_some();
    if !mac_known && !ip_known && ssid.is_empty() && !full_tunnel {
        return None;
    }

    let (raw, label) = if full_tunnel {
        let vendor = n.tunnel.as_deref().unwrap_or("");
        // The tunnel is the link here, so its addresses are `ipv4`/`ipv6`.
        let (vkey, vshown) = if vendor.is_empty() {
            (UNIDENTIFIED.to_string(), UNIDENTIFIED.to_string())
        } else if let Some(addr) = self_hosted_tunnel_addr(vendor, n.ipv4.iter().chain(&n.ipv6)) {
            (format!("{vendor}|{addr}"), format!("{vendor} {addr}"))
        } else {
            (vendor.to_string(), vendor.to_string())
        };
        let u_mac = mac_is_known(&n.underlay_gateway_mac);
        let u_ip = !n.underlay_gateway_ip.is_empty() && n.underlay_gateway_ip != "-";
        if u_mac || u_ip {
            // The physical network underneath is known: this VPN *here* is
            // the place — "Home via WARP" ≠ "Hotel via WARP" (different
            // uplink, different exit PoP, different normals).
            let ukey = if u_mac {
                &n.underlay_gateway_mac
            } else {
                &n.underlay_gateway_ip
            };
            (
                format!("{ukey}|{}|via|{vkey}", n.underlay_medium as u8),
                format!(
                    "{} via {vshown}",
                    if u_ip {
                        n.underlay_gateway_ip.as_str()
                    } else {
                        n.underlay_gateway_mac.as_str()
                    }
                ),
            )
        } else {
            (format!("vpn|{vkey}|{}", n.medium as u8), vshown)
        }
    } else if n.medium == LinkMedium::WiFi && !ssid.is_empty() {
        (
            format!(
                "{ssid}|{}|wifi",
                if mac_known { &n.gateway_mac } else { "" }
            ),
            ssid.to_string(),
        )
    } else if mac_known {
        (
            format!("{}|{}", n.gateway_mac, n.medium as u8),
            n.gateway_ip.clone(),
        )
    } else if ip_known {
        (
            format!("{}|{}|{}", n.gateway_ip, n.iface, n.medium as u8),
            n.gateway_ip.clone(),
        )
    } else {
        // v6-only carrier hotspots can expose no routable gateway at all;
        // the SSID is then the only identity available — and "iPhone" is
        // exactly the location a hotspot baseline should be keyed to.
        (format!("{ssid}|nogw|{}", n.medium as u8), ssid.to_string())
    };

    // A split tunnel (kernel default route on the physical NIC, internet
    // traffic egressing via the tunnel — WARP on macOS) still changes what
    // "the internet" looks like from here: anchor latency is the tunnel's,
    // DNS is the tunnel's, speed is the tunnel's. So it is its own location —
    // but *per underlying network*: "Home via WARP" and "Hotel via WARP"
    // differ in uplink and nearest exit PoP, and mixing their normals would
    // poison both. Hence the LAN identity computed above, suffixed.
    let (raw, label) = if let Some(vendor) = n.tunnel.as_deref().filter(|_| n.tunnel_is_split) {
        // An unidentified vendor is still its own place (see `UNIDENTIFIED`)
        // rather than VPN minutes folded into the bare network's normal. A
        // WireGuard config is one exit among possibly several from this LAN,
        // so it keys on its address exactly as a full tunnel does; the
        // tunnel's own addresses live in `tunnel_addrs`, since `ipv4`/`ipv6`
        // are the physical NIC's here.
        let (key, shown) = if vendor.is_empty() {
            (UNIDENTIFIED.to_string(), UNIDENTIFIED.to_string())
        } else if let Some(addr) = self_hosted_tunnel_addr(vendor, &n.tunnel_addrs) {
            (format!("{vendor}|{addr}"), format!("{vendor} {addr}"))
        } else {
            (vendor.to_string(), vendor.to_string())
        };
        (format!("{raw}|via|{key}"), format!("{label} via {shown}"))
    } else {
        (raw, label)
    };

    // Hash the identity so the on-disk keys don't spell out SSIDs; the label
    // field stays human-readable for display.
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut h = DefaultHasher::new();
    raw.hash(&mut h);
    Some((format!("{:016x}", h.finish()), label))
}

/// All known baselines, keyed by fingerprint hash.
pub type Store = HashMap<String, Baseline>;

fn path() -> Option<std::path::PathBuf> {
    crate::store::data_dir().map(|d| d.join("baselines.json"))
}

/// The store's path for a message, or its bare name when there is no data
/// directory to put it in.
pub fn file_name() -> String {
    path().map_or_else(|| "baselines.json".to_string(), |p| p.display().to_string())
}

/// Every stored baseline, for display. Any error is logged and read as
/// empty, which is all a display needs; only a save ([`update_at`]) acts on
/// a file that won't parse.
pub fn load() -> Store {
    path().map(|p| load_from(&p)).unwrap_or_default()
}

fn load_from(p: &std::path::Path) -> Store {
    read_store(p).unwrap_or_else(|e| {
        crate::errlog::log("baseline", format!("could not read {}: {e}", p.display()));
        Store::new()
    })
}

/// The stored baselines, exactly as on disk; the file is never touched. Only
/// a missing file is an empty store. One that exists but can't be read
/// (permissions, I/O) is an error, so a save never writes a one-network
/// store over every network it couldn't see. One that doesn't parse, as
/// UTF-8 or as JSON, is an `InvalidData` error.
fn read_store(p: &std::path::Path) -> std::io::Result<Store> {
    let bytes = match std::fs::read(p) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Store::new()),
        Err(e) => return Err(e),
    };
    serde_json::from_slice(&bytes).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("did not parse: {e}"),
        )
    })
}

/// How many earlier corrupt copies may be kept beside the store.
const ASIDE_SLOTS: usize = 10;

/// Move a store that won't parse to the first free `baselines.json.corrupt`,
/// `.corrupt.1` … slot, so it can be repaired by hand and an earlier one is
/// never replaced. Called with the file's lock held, so no other octomon
/// moves or rewrites it meanwhile. With every slot taken, nothing moves and
/// the save fails: the file is still somebody's history.
fn set_aside(p: &std::path::Path, why: &std::io::Error) -> std::io::Result<()> {
    let first = p.with_extension("json.corrupt");
    let aside = (0..ASIDE_SLOTS)
        .map(|i| {
            if i == 0 {
                first.clone()
            } else {
                p.with_extension(format!("json.corrupt.{i}"))
            }
        })
        .find(|a| std::fs::symlink_metadata(a).is_err())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "{why}, and it could not be moved aside: {} and its {} numbered slots are taken",
                    first.display(),
                    ASIDE_SLOTS - 1
                ),
            )
        })?;
    std::fs::rename(p, &aside).map_err(|m| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{why}, and it could not be moved aside: {m}"),
        )
    })?;
    crate::errlog::log(
        "baseline",
        format!(
            "{} {why} — moved to {} and starting over",
            p.display(),
            aside.display()
        ),
    );
    Ok(())
}

/// Change the stored baselines in place: load, `edit`, save, all under the
/// file's [`crate::store::FileLock`]. Two octomon processes (the dashboard and
/// a `--watch` service, or two watchers) save at the same moments — startup,
/// a network change — and unlocked they share one temporary file, so one
/// rename fails, and whichever save lands last drops the network the other
/// just learned. Loading after the lock is taken keeps both. (Two processes
/// saving the *same* network still each write their own copy of it; the last
/// one stands.) Errors are logged here and returned for callers that tell
/// the user.
fn update(edit: impl FnOnce(&mut Store)) -> std::io::Result<()> {
    let Some(p) = path() else {
        crate::errlog::log("baseline", "no data directory — learned networks not saved");
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no data directory",
        ));
    };
    update_at(&p, edit).inspect_err(|e| {
        crate::errlog::log(
            "baseline",
            format!("{}: {e} — learned networks not saved", p.display()),
        );
    })
}

/// `Ok` means the edited store was written and renamed into place. Nothing
/// is written when the directory, the lock or the file can't be had. A
/// store that doesn't parse is first set aside ([`set_aside`]); if the save
/// then fails, `baselines.json` is gone and its old contents are in the
/// `.corrupt` copy.
fn update_at(p: &std::path::Path, edit: impl FnOnce(&mut Store)) -> std::io::Result<()> {
    if let Some(dir) = p.parent() {
        crate::store::create_dir_private(dir)?;
    }
    let _held = crate::store::FileLock::acquire(p)?;
    let mut all = match read_store(p) {
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            set_aside(p, &e)?;
            Store::new()
        }
        r => r?,
    };
    edit(&mut all);
    save_to(p, &all)
}

/// Whole-file rewrite — a handful of networks × ~200 bytes. Only
/// [`update_at`] calls this, with the file's lock held and the file just read,
/// so there is nothing on disk it could write over unseen.
fn save_to(p: &std::path::Path, store: &Store) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(store).map_err(std::io::Error::other)?;
    crate::store::write_private(p, json)
}

/// Load one network's baseline (blocking file read — call off the state
/// lock). `Ok(None)` is a network not seen before. A store that doesn't
/// parse counts as empty too, since the next save sets it aside; any other
/// read error is returned, so the caller doesn't take a network it simply
/// couldn't read for a new one and save over what it had learned.
pub fn load_one(key: &str) -> std::io::Result<Option<Baseline>> {
    let Some(p) = path() else {
        return Ok(None);
    };
    match read_store(&p) {
        Ok(all) => Ok(all.get(key).cloned()),
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => Ok(None),
        Err(e) => Err(e),
    }
}

/// Replace one network's stored baseline (blocking — off the state lock).
/// The stored name is kept: names change only through [`name_network`], so
/// an older in-memory copy in another octomon can't undo a rename.
pub fn save_one(key: &str, b: &Baseline) {
    let _ = update(|all| put_keeping_name(all, key, b));
}

/// The learner lock, held for the life of the process once taken: see
/// [`save_learned`]. A sibling of the baselines file rather than the file's
/// own lock, which is held only across one save.
static LEARNER: parking_lot::Mutex<Option<crate::store::FileLock>> = parking_lot::Mutex::new(None);

/// What became of a learned sample offered for saving.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Learned {
    /// Written to the store.
    Saved,
    /// Another octomon process holds the learner lock and saves what it
    /// learns from this same network; this one only watches.
    LeftToPeer,
}

/// Save what the analysis loop learned about a network — but only from the
/// one process that holds the learner lock. A dashboard and a `--watch`
/// service (or two of either) on the same network each learn the same
/// minutes; saved by both, the stored copy flipped between two in-memory
/// ones on every fold. The first process to reach a save takes the lock
/// and keeps it; the others learn in memory and skip the save, and try
/// again at each fold, so when the holder exits the next one takes over.
/// Renames, deletes and the visit stamp are not learning, and go through
/// [`save_one`] from any process.
pub fn save_learned(key: &str, b: &Baseline) -> Learned {
    match path() {
        Some(p) => save_learned_at(&p, &LEARNER, key, b),
        // Nothing to lock: `update` logs the missing directory.
        None => {
            save_one(key, b);
            Learned::Saved
        }
    }
}

fn save_learned_at(
    p: &std::path::Path,
    holder: &parking_lot::Mutex<Option<crate::store::FileLock>>,
    key: &str,
    b: &Baseline,
) -> Learned {
    let mut held = holder.lock();
    if held.is_none() {
        let learner = p.with_file_name("baselines.json.learner");
        match crate::store::FileLock::acquire_now(&learner) {
            Ok(lock) => *held = Some(lock),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                static TOLD: std::sync::Once = std::sync::Once::new();
                TOLD.call_once(|| {
                    crate::errlog::log(
                        "baseline",
                        "another octomon is saving what is learned here — this one only watches",
                    );
                });
                return Learned::LeftToPeer;
            }
            // A lock that can't be had for any other reason (an unwritable
            // directory, no locking on this platform) must not stop learning
            // from being saved at all: save as before, unlocked.
            Err(e) => {
                crate::errlog::log(
                    "baseline",
                    format!(
                        "{}: saving without the learner lock: {e}",
                        learner.display()
                    ),
                );
            }
        }
    }
    let _ = update_at(p, |all| put_keeping_name(all, key, b)).inspect_err(|e| {
        crate::errlog::log(
            "baseline",
            format!("{}: {e} — learned networks not saved", p.display()),
        );
    });
    Learned::Saved
}

fn put_keeping_name(all: &mut Store, key: &str, b: &Baseline) {
    let name = all.get(key).and_then(|old| old.name.clone());
    all.insert(key.to_string(), Baseline { name, ..b.clone() });
}

/// Remove one network's stored baseline (blocking — off the state lock). Its
/// incident history is deliberately kept: if the network is ever visited
/// again, "3 outages this week" is still true and still useful.
pub fn forget(key: &str) -> std::io::Result<()> {
    update(|all| {
        all.remove(key);
    })
}

/// Set the user's name for a network, keeping any learned stats.
pub fn name_network(key: &str, label: &str, name: &str) -> std::io::Result<()> {
    update(|all| {
        let entry = all.entry(key.to_string()).or_insert_with(|| Baseline {
            label: label.to_string(),
            ..Default::default()
        });
        entry.name = if name.trim().is_empty() {
            None
        } else {
            Some(name.trim().to_string())
        };
    })
}

/// A location not visited for this long is marked stale in the locations
/// list: a candidate for [d]elete, since a re-keyed or one-off network is
/// never matched again and would otherwise sit there indefinitely.
pub const STALE_AFTER_DAYS: i64 = 90;

/// Whether a location last seen at `last_seen` has gone [`STALE_AFTER_DAYS`]
/// without a visit, as of `now` (both unix seconds).
pub fn is_stale(last_seen: i64, now: i64) -> bool {
    (now - last_seen) / 86_400 >= STALE_AFTER_DAYS
}

/// When a location was last visited, for a human: "seen today", "seen 3
/// days ago", "seen 2 weeks ago", and past the stale mark "not seen for 5
/// months", so the entries that have gone quiet read as such at a glance
/// instead of as a date to subtract from today's.
pub fn seen_ago(last_seen: i64, now: i64) -> String {
    let days = ((now - last_seen) / 86_400).max(0);
    match days {
        0 => "seen today".to_string(),
        1 => "seen yesterday".to_string(),
        2..=13 => format!("seen {days} days ago"),
        14..=59 => format!("seen {} weeks ago", days / 7),
        _ if days < STALE_AFTER_DAYS => format!("seen {} months ago", days / 30),
        _ if days < 730 => format!("not seen for {} months", days / 30),
        _ => format!("not seen for {} years", days / 365),
    }
}

/// "current is way above normal": the abnormality test used for confidence
/// bumps. Both a ratio and an absolute margin, so a 2 ms → 7 ms gateway
/// (noise) doesn't count but 9 ms → 41 ms does.
pub fn well_above(current: f64, normal: f64) -> bool {
    current > (normal * th::RTT_INFLATED_FACTOR).max(normal + 20.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::WifiInfo;

    fn wifi_net(ssid: &str, gw_mac: &str) -> NetInfo {
        NetInfo {
            iface: "en0".into(),
            gateway_ip: "192.168.1.1".into(),
            gateway_mac: gw_mac.into(),
            medium: LinkMedium::WiFi,
            wifi: Some(WifiInfo {
                ssid: ssid.into(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// On a VPN the routing table's gateway is the tunnel's own address
    /// (10.5.0.2) while discovery pings the far end (10.5.0.1): the sample
    /// must find the gateway by its discovery label, or the location never
    /// learns a gateway normal — exactly the "gateway —" the locations
    /// overlay used to show for a VPN whose gateway answered at 15 ms.
    #[test]
    fn a_vpn_gateway_still_teaches_the_baseline() {
        use crate::app::{AppState, TargetStat};
        let mut s = AppState::new(vec![]);
        s.netinfo.gateway_ip = "10.5.0.2".into();
        let mut gw = TargetStat::new("gateway".into(), "10.5.0.1".parse().unwrap());
        gw.discovered = true;
        for _ in 0..20 {
            gw.record_reply(15.0);
        }
        s.targets.push(gw);
        let sample = Sample::take(&s);
        assert_eq!(sample.gateway_ms, Some(15.0));
        assert_eq!(sample.gateway_loss_pct, Some(0.0));
    }

    #[test]
    fn fingerprint_distinguishes_locations_and_survives_dhcp() {
        let home = fingerprint(&wifi_net("HomeNet", "aa:bb:cc:dd:ee:ff")).unwrap();
        let cafe = fingerprint(&wifi_net("HomeNet", "11:22:33:44:55:66")).unwrap();
        assert_ne!(home.0, cafe.0, "same generic SSID, different routers");
        assert_eq!(home.1, "HomeNet", "label is the SSID");

        // A DHCP renewal changes the local IP but neither key ingredient.
        let mut renewed = wifi_net("HomeNet", "aa:bb:cc:dd:ee:ff");
        renewed.ipv4 = vec!["192.168.1.200/24".into()];
        assert_eq!(home.0, fingerprint(&renewed).unwrap().0);
    }

    #[test]
    fn redacted_ssid_falls_back_to_the_gateway_mac() {
        let n = wifi_net("<redacted>", "aa:bb:cc:dd:ee:ff");
        let (key, label) = fingerprint(&n).unwrap();
        // Still identifiable, labelled by gateway instead of the hidden SSID.
        assert_eq!(label, "192.168.1.1");
        // ...and identical to the same network seen without wifi details yet.
        let mut no_wifi = n.clone();
        no_wifi.wifi = None;
        no_wifi.medium = LinkMedium::WiFi;
        // Different path (no ssid): falls to mac|medium — consistent with above.
        assert_eq!(key, fingerprint(&no_wifi).unwrap().0);
    }

    #[test]
    fn wired_and_wifi_on_the_same_router_are_different_networks() {
        let wifi = fingerprint(&wifi_net("HomeNet", "aa:bb:cc:dd:ee:ff")).unwrap();
        let mut wired = wifi_net("", "aa:bb:cc:dd:ee:ff");
        wired.wifi = None;
        wired.medium = LinkMedium::Ethernet;
        let wired = fingerprint(&wired).unwrap();
        assert_ne!(wifi.0, wired.0, "different medium, different baseline");
    }

    /// A full-tunnel VPN is its own location, keyed on the vendor: WARP on
    /// Windows exposes a /32 with no gateway and no MAC — nothing else
    /// identifies it — and on macOS the same VPN must map to the same
    /// location whether it came up as utun4 or utun6.
    #[test]
    fn a_full_tunnel_vpn_is_its_own_location() {
        let warp = NetInfo {
            iface: "CloudflareWARP".into(),
            ipv4: vec!["100.96.0.1/32".into()],
            gateway_ip: "-".into(),
            gateway_mac: "-".into(),
            medium: LinkMedium::Tunnel,
            tunnel: Some("Cloudflare WARP".into()),
            tunnel_iface: "CloudflareWARP".into(),
            ..Default::default()
        };
        let (key, label) = fingerprint(&warp).expect("tunnel fingerprint");
        assert_eq!(label, "Cloudflare WARP");

        // Same VPN on another device name (macOS utun renumbering): same key.
        let mut renumbered = warp.clone();
        renumbered.iface = "utun6".into();
        renumbered.tunnel_iface = "utun6".into();
        renumbered.ipv4 = vec!["100.96.0.7/32".into()];
        assert_eq!(key, fingerprint(&renumbered).unwrap().0);

        // An unidentified tunnel still gets a location, apart from the named
        // one, and the device name plays no part in it.
        let mut unknown = warp.clone();
        unknown.tunnel = Some(String::new());
        let (ukey, ulabel) = fingerprint(&unknown).unwrap();
        assert_ne!(key, ukey);
        assert_eq!(ulabel, "VPN");
    }

    /// A VPN no vendor can be named for keys on neither its device nor its
    /// address: macOS renumbers utunN across connects, and a corporate VPN
    /// hands out a pool address per connect, so either would mint a new
    /// location each time, losing the normals and the name. One "VPN" per
    /// network, whatever it is called or numbered today.
    #[test]
    fn an_unidentified_tunnel_keys_on_neither_its_device_nor_its_address() {
        let vpn = |iface: &str, addrs: &[&str], underlay: &str| NetInfo {
            iface: iface.into(),
            ipv4: addrs
                .iter()
                .filter(|a| !a.contains(':'))
                .map(|a| format!("{a}/32"))
                .collect(),
            gateway_ip: "-".into(),
            gateway_mac: "-".into(),
            medium: LinkMedium::Tunnel,
            tunnel: Some(String::new()),
            tunnel_iface: iface.into(),
            tunnel_addrs: addrs.iter().map(|a| a.to_string()).collect(),
            underlay_gateway_ip: underlay.into(),
            ..Default::default()
        };
        let (a, label) = fingerprint(&vpn("utun4", &["10.20.0.5"], "")).unwrap();
        assert_eq!(label, "VPN");
        // Renumbered device, same VPN: same place.
        assert_eq!(a, fingerprint(&vpn("utun6", &["10.20.0.5"], "")).unwrap().0);
        // Fresh pool address on reconnect: still the same place.
        assert_eq!(a, fingerprint(&vpn("utun4", &["10.77.0.9"], "")).unwrap().0);
        // No address at all: likewise.
        assert_eq!(a, fingerprint(&vpn("utun4", &[], "")).unwrap().0);

        // Over a visible underlay it is that network's one unknown VPN.
        let (home, label) = fingerprint(&vpn("utun4", &["10.20.0.5"], "192.168.10.1")).unwrap();
        assert_eq!(label, "192.168.10.1 via VPN");
        assert_eq!(
            home,
            fingerprint(&vpn("utun9", &["10.77.0.9"], "192.168.10.1"))
                .unwrap()
                .0
        );
        assert_ne!(home, a, "the underlay still tells places apart");
    }

    /// Two WireGuard configs from the same LAN are two exits, not one: the
    /// tunnel address separates them, and reconnecting the same config on a
    /// renumbered utun comes back to the same location.
    #[test]
    fn self_hosted_tunnels_key_on_their_address() {
        let wg = |iface: &str, addr: &str| NetInfo {
            iface: iface.into(),
            ipv4: vec![addr.into()],
            gateway_ip: "-".into(),
            gateway_mac: "-".into(),
            medium: LinkMedium::Tunnel,
            tunnel: Some("WireGuard".into()),
            tunnel_iface: iface.into(),
            underlay_gateway_ip: "192.168.10.1".into(),
            underlay_gateway_mac: "00:e0:67:1b:1b:67".into(),
            underlay_medium: LinkMedium::WiFi,
            ..Default::default()
        };
        let (home, label) = fingerprint(&wg("utun10", "10.9.8.10/32")).unwrap();
        assert_eq!(label, "192.168.10.1 via WireGuard 10.9.8.10");
        let (vps, _) = fingerprint(&wg("utun10", "10.13.13.2/32")).unwrap();
        assert_ne!(home, vps, "different exit, different location");
        assert_eq!(home, fingerprint(&wg("utun6", "10.9.8.10/32")).unwrap().0);

        let mut no_underlay = wg("utun10", "10.9.8.10/32");
        no_underlay.underlay_gateway_ip = String::new();
        no_underlay.underlay_gateway_mac = String::new();
        let mut other = no_underlay.clone();
        other.ipv4 = vec!["10.13.13.2/32".into()];
        assert_ne!(
            fingerprint(&no_underlay).unwrap().0,
            fingerprint(&other).unwrap().0
        );

        // IPv6-only configs: the utun's own link-local is skipped, the
        // config's address keys the location.
        let v6 = |addr: &str| {
            let mut n = wg("utun10", "");
            n.ipv4 = Vec::new();
            n.ipv6 = vec!["fe80::1234/64".into(), addr.into()];
            n
        };
        let (a, label) = fingerprint(&v6("fd00:9::10/128")).unwrap();
        assert_eq!(label, "192.168.10.1 via WireGuard fd00:9::10");
        assert_ne!(a, fingerprint(&v6("fd00:13::2/128")).unwrap().0);

        // OpenVPN is handed its address from the server's pool per session,
        // so it stays on the vendor key: 10.8.0.6 today and 10.8.0.14
        // tomorrow are one location.
        let ovpn = |addr: &str| {
            let mut n = wg("utun10", addr);
            n.tunnel = Some("OpenVPN".into());
            n
        };
        let (today, label) = fingerprint(&ovpn("10.8.0.6/24")).unwrap();
        assert_eq!(label, "192.168.10.1 via OpenVPN");
        assert_eq!(today, fingerprint(&ovpn("10.8.0.14/24")).unwrap().0);
    }

    /// netdev reports an unresolved neighbour as 00:00:00:00:00:00. Keyed on
    /// that, every full tunnel shared one location; it has to fall back to
    /// the underlay's gateway address.
    #[test]
    fn an_unresolved_underlay_mac_falls_back_to_the_gateway_ip() {
        let over = |gw_ip: &str| NetInfo {
            iface: "utun8".into(),
            ipv4: vec!["100.64.0.1/16".into()],
            gateway_ip: "-".into(),
            gateway_mac: "-".into(),
            medium: LinkMedium::Tunnel,
            tunnel: Some("Zscaler".into()),
            tunnel_iface: "utun8".into(),
            underlay_gateway_ip: gw_ip.into(),
            underlay_gateway_mac: "00:00:00:00:00:00".into(),
            underlay_medium: LinkMedium::WiFi,
            ..Default::default()
        };
        let home = fingerprint(&over("192.168.10.1")).unwrap();
        let class = fingerprint(&over("10.21.21.1")).unwrap();
        assert_ne!(home.0, class.0, "zero MAC must not merge networks");
        assert_eq!(home.1, "192.168.10.1 via Zscaler");
    }

    /// A full tunnel with a visible physical network underneath keys on that
    /// underlay: the same VPN over the office Ethernet and over hotel Wi-Fi
    /// is two places with two normals. The per-vendor bucket above is only
    /// the fallback for setups where no underlay is discoverable.
    #[test]
    fn a_full_tunnel_keys_on_the_underlay_when_one_is_visible() {
        let over = |gw_ip: &str, gw_mac: &str, medium: LinkMedium| NetInfo {
            iface: "CloudflareWARP".into(),
            ipv4: vec!["100.96.0.1/32".into()],
            gateway_ip: "-".into(),
            gateway_mac: "-".into(),
            medium: LinkMedium::Tunnel,
            tunnel: Some("Cloudflare WARP".into()),
            tunnel_iface: "CloudflareWARP".into(),
            underlay_gateway_ip: gw_ip.into(),
            underlay_gateway_mac: gw_mac.into(),
            underlay_medium: medium,
            ..Default::default()
        };
        let office = fingerprint(&over(
            "10.90.0.1",
            "aa:aa:aa:aa:aa:01",
            LinkMedium::Ethernet,
        ))
        .expect("underlay fingerprint");
        let hotel = fingerprint(&over("192.168.1.1", "bb:bb:bb:bb:bb:02", LinkMedium::WiFi))
            .expect("underlay fingerprint");
        assert_ne!(office.0, hotel.0, "same VPN, different places");
        assert_eq!(office.1, "10.90.0.1 via Cloudflare WARP");
        assert_eq!(hotel.1, "192.168.1.1 via Cloudflare WARP");

        // A DHCP renewal changing nothing identifying returns the same key,
        // and the underlay MAC (not the IP) is what the key rides on.
        let renewed = fingerprint(&over(
            "10.90.0.1",
            "aa:aa:aa:aa:aa:01",
            LinkMedium::Ethernet,
        ));
        assert_eq!(office.0, renewed.unwrap().0);

        // No underlay at all (the Azure-VM shape when the NIC has no
        // gateway): falls back to the per-vendor bucket.
        let mut bare = over("", "", LinkMedium::Unknown);
        bare.underlay_gateway_ip = String::new();
        bare.underlay_gateway_mac = String::new();
        assert_eq!(fingerprint(&bare).unwrap().1, "Cloudflare WARP");
    }

    /// A split tunnel is its own location *per underlying network*: the VPN
    /// changes what the internet looks like (anchor latency, DNS, speed all
    /// ride the tunnel), and "Home via WARP" differs from "Hotel via WARP" in
    /// uplink and exit PoP — so the LAN pairs each get an entry: Home,
    /// Home via WARP, Hotel, Hotel via WARP.
    #[test]
    fn a_split_tunnel_is_its_own_location_per_underlying_network() {
        let with_warp = |ssid: &str, mac: &str| {
            let mut n = wifi_net(ssid, mac);
            n.tunnel = Some("Cloudflare WARP".into());
            n.tunnel_iface = "utun4".into();
            n.tunnel_is_split = true;
            n
        };
        let home = fingerprint(&wifi_net("HomeNet", "aa:bb:cc:dd:ee:ff")).unwrap();
        let home_warp = fingerprint(&with_warp("HomeNet", "aa:bb:cc:dd:ee:ff")).unwrap();
        let hotel_warp = fingerprint(&with_warp("HotelNet", "11:22:33:44:55:66")).unwrap();

        assert_ne!(home.0, home_warp.0, "VPN on = a different place");
        assert_ne!(
            home_warp.0, hotel_warp.0,
            "same VPN over different uplinks = different normals"
        );
        assert_eq!(home_warp.1, "HomeNet via Cloudflare WARP");
        assert_eq!(hotel_warp.1, "HotelNet via Cloudflare WARP");

        // Toggling the VPN off and on returns to the same pair, and the utun
        // number is irrelevant while the vendor is known.
        let mut renumbered = with_warp("HomeNet", "aa:bb:cc:dd:ee:ff");
        renumbered.tunnel_iface = "utun7".into();
        assert_eq!(home_warp.0, fingerprint(&renumbered).unwrap().0);

        // A split tunnel carries the internet traffic too (the kernel's
        // default route merely stays on the NIC), so two split WireGuard
        // configs on one LAN are two exits with two normals, exactly as full
        // tunnels are. The tunnel's own addresses are `tunnel_addrs`; `ipv4`
        // is the NIC's.
        let split_wg = |iface: &str, addr: &str| {
            let mut n = with_warp("HomeNet", "aa:bb:cc:dd:ee:ff");
            n.tunnel = Some("WireGuard".into());
            n.tunnel_iface = iface.into();
            n.tunnel_addrs = vec!["fe80::1".into(), addr.into()];
            n
        };
        let (a, b) = (
            split_wg("utun4", "10.9.8.10"),
            split_wg("utun4", "10.7.0.2"),
        );
        assert_ne!(fingerprint(&a).unwrap().0, fingerprint(&b).unwrap().0);
        assert_eq!(
            fingerprint(&a).unwrap().1,
            "HomeNet via WireGuard 10.9.8.10"
        );
        assert_eq!(
            fingerprint(&a).unwrap().0,
            fingerprint(&split_wg("utun7", "10.9.8.10")).unwrap().0,
            "a renumbered utun is the same config"
        );

        // An unidentified split tunnel still separates from the bare LAN and
        // from a named one, and is the same place whatever device it is on
        // and whatever address it was handed this time.
        let unknown = |iface: &str, addr: &str| {
            let mut n = with_warp("HomeNet", "aa:bb:cc:dd:ee:ff");
            n.tunnel = Some(String::new());
            n.tunnel_iface = iface.into();
            n.tunnel_addrs = vec!["fe80::1".into(), addr.into()];
            n
        };
        let (ukey, ulabel) = fingerprint(&unknown("utun4", "10.20.0.5")).unwrap();
        assert_ne!(ukey, home.0);
        assert_ne!(ukey, home_warp.0);
        assert_eq!(ulabel, "HomeNet via VPN");
        assert_eq!(ukey, fingerprint(&unknown("utun7", "10.20.0.5")).unwrap().0);
        assert_eq!(ukey, fingerprint(&unknown("utun4", "10.77.0.9")).unwrap().0);
        let mut unaddressed = unknown("utun4", "10.20.0.5");
        unaddressed.tunnel_addrs.clear();
        assert_eq!(ukey, fingerprint(&unaddressed).unwrap().0);
    }

    /// A v6-only carrier hotspot exposes no routable gateway; the SSID alone
    /// still identifies the location ("iPhone" IS the place).
    #[test]
    fn gatewayless_wifi_falls_back_to_the_ssid_alone() {
        let mut n = wifi_net("iPhone", "-");
        n.gateway_ip = "-".into();
        let (_, label) = fingerprint(&n).expect("ssid-only fingerprint");
        assert_eq!(label, "iPhone");

        // With no SSID either there is genuinely nothing to key on.
        let mut bare = wifi_net("", "-");
        bare.gateway_ip = "-".into();
        assert!(fingerprint(&bare).is_none());
    }

    #[test]
    fn ewma_converges_and_missing_readings_do_not_erase() {
        let mut b = Baseline::default();
        for _ in 0..40 {
            b.fold(Sample {
                gateway_ms: Some(10.0),
                ..Default::default()
            });
        }
        let g = b.gateway_ms.unwrap();
        assert!((g - 10.0).abs() < 0.1, "converged to ~10, got {g}");
        assert_eq!(b.samples, 40);
        assert!(b.established());

        // A fold with no gateway reading must not wipe what was learned.
        b.fold(Sample::default());
        assert!((b.gateway_ms.unwrap() - 10.0).abs() < 0.1);
    }

    #[test]
    fn loss_is_learned_like_any_other_normal_and_old_files_still_parse() {
        let mut b = Baseline::default();
        b.fold(Sample {
            medium: "Wi-Fi (wireless)".into(),
            gateway_loss_pct: Some(100.0),
            anchor_loss_pct: Some(30.0),
            ..Default::default()
        });
        assert_eq!(b.gateway_loss_pct, Some(100.0));
        assert_eq!(b.anchor_loss_pct, Some(30.0));
        // The EWMA moves toward new weather instead of snapping.
        b.fold(Sample {
            anchor_loss_pct: Some(10.0),
            ..Default::default()
        });
        let a = b.anchor_loss_pct.unwrap();
        assert!(a < 30.0 && a > 10.0, "got {a}");

        // Baseline files written before the loss fields existed load as
        // "never measured", not as an error that drops the whole store.
        let legacy: Baseline = serde_json::from_str(
            r#"{"label":"Home","samples":9,"gateway_ms":2.5,"gateway_p95_ms":4.0,
                "anchor_ms":12.0,"dns_ms":8.0,"rssi_dbm":-52.0,
                "down_mbps":400.0,"up_mbps":40.0}"#,
        )
        .expect("legacy baseline parses");
        assert_eq!(legacy.gateway_loss_pct, None);
        assert_eq!(legacy.anchor_loss_pct, None);
    }

    #[test]
    fn abnormality_needs_both_ratio_and_margin() {
        assert!(!well_above(7.0, 2.0), "3.5x of nothing is still nothing");
        assert!(!well_above(25.0, 9.0), "under the ratio");
        assert!(well_above(41.0, 9.0));
        assert!(well_above(400.0, 100.0));
    }

    /// Two watchers starting together both save their network at once.
    /// Unlocked, they shared one temporary file (a rename failed with ENOENT)
    /// and the last save dropped the other's network. Threads stand in for
    /// processes: each takes the lock through its own open, which flock
    /// treats as a separate holder. Runs in a scratch directory, never the
    /// real data directory.
    #[test]
    fn concurrent_saves_keep_every_network() {
        let dir = std::env::temp_dir().join(format!("octomon-baseline-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = dir.join("baselines.json");

        let start = std::sync::Arc::new(std::sync::Barrier::new(4));
        let writers: Vec<_> = (0..4)
            .map(|i| {
                let (p, start) = (p.clone(), start.clone());
                std::thread::spawn(move || {
                    start.wait();
                    for j in 0..5 {
                        assert!(
                            update_at(&p, |all| {
                                all.insert(
                                    format!("net-{i}-{j}"),
                                    Baseline {
                                        label: format!("Net {i}"),
                                        ..Default::default()
                                    },
                                );
                            })
                            .is_ok()
                        );
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().unwrap();
        }

        assert_eq!(load_from(&p).len(), 20);
        assert!(!dir.join(".baselines.json.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A baselines.json that exists but can't be read is not an empty store:
    /// saving one network over it would erase every other one.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_store_is_not_overwritten() {
        use std::os::unix::fs::PermissionsExt as _;
        if crate::platform::tools::is_privileged() {
            return; // root reads it regardless of the mode
        }
        let dir = std::env::temp_dir().join(format!(
            "octomon-baseline-unreadable-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("baselines.json");
        let mut two = Store::new();
        for name in ["home", "office"] {
            two.insert(name.into(), Baseline::default());
        }
        std::fs::write(&p, serde_json::to_string(&two).unwrap()).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();

        let r = update_at(&p, |all| {
            all.insert("hotel".into(), Baseline::default());
        });
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(r.is_err());
        assert_eq!(load_from(&p).len(), 2, "both stored networks survive");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A store directory where `blocked` is taken by a non-empty directory,
    /// so nothing can be moved or written to that name, even as root.
    fn store_with_blocked(
        tag: &str,
        contents: &str,
        blocked: &str,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("octomon-baseline-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(blocked).join("x")).unwrap();
        let p = dir.join("baselines.json");
        std::fs::write(&p, contents).unwrap();
        (dir, p)
    }

    /// The usual corrupt store: set aside, then saved over with the edit.
    /// Bytes that aren't UTF-8 count as corrupt too, not as unreadable.
    #[test]
    fn a_corrupt_store_is_set_aside_and_the_save_goes_ahead() {
        for (tag, bad) in [
            ("json", b"{ not json".as_slice()),
            ("utf8", b"\xff\xfe{}".as_slice()),
        ] {
            let (dir, p) = store_with_blocked(&format!("aside-{tag}"), "", "unused");
            std::fs::write(&p, bad).unwrap();
            assert!(load_from(&p).is_empty(), "a reader sees nothing");
            assert_eq!(std::fs::read(&p).unwrap(), bad, "and moves nothing");
            update_at(&p, |all| {
                all.insert("hotel".into(), Baseline::default());
            })
            .unwrap();
            assert_eq!(
                std::fs::read(dir.join("baselines.json.corrupt")).unwrap(),
                bad
            );
            assert_eq!(load_from(&p).into_keys().collect::<Vec<_>>(), ["hotel"]);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// A second corrupt store goes to the next slot; the first is kept.
    #[test]
    fn an_earlier_corrupt_copy_is_never_replaced() {
        let (dir, p) = store_with_blocked("slots", "{ first", "unused");
        update_at(&p, |_| {}).unwrap();
        std::fs::write(&p, "{ second").unwrap();
        update_at(&p, |_| {}).unwrap();
        let read = |n: &str| std::fs::read_to_string(dir.join(n)).unwrap();
        assert_eq!(read("baselines.json.corrupt"), "{ first");
        assert_eq!(read("baselines.json.corrupt.1"), "{ second");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A corrupt store with every slot taken is an error, and left as is.
    #[test]
    fn a_corrupt_store_that_cannot_be_moved_aside_is_an_error() {
        let (dir, p) = store_with_blocked("stuck", "{ not json", "baselines.json.corrupt");
        for i in 1..ASIDE_SLOTS {
            std::fs::write(dir.join(format!("baselines.json.corrupt.{i}")), "").unwrap();
        }
        let r = update_at(&p, |all| {
            all.insert("hotel".into(), Baseline::default());
        });
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{ not json");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A save from an older in-memory copy doesn't undo a rename made since.
    #[test]
    fn a_save_keeps_the_stored_name() {
        let (dir, p) = store_with_blocked("name", "", "unused");
        std::fs::remove_file(&p).unwrap();
        update_at(&p, |all| {
            all.insert(
                "home".into(),
                Baseline {
                    name: Some("Den".into()),
                    ..Default::default()
                },
            );
        })
        .unwrap();
        let stale = Baseline {
            samples: 7,
            ..Default::default()
        };
        update_at(&p, |all| put_keeping_name(all, "home", &stale)).unwrap();
        let home = &load_from(&p)["home"];
        assert_eq!((home.name.as_deref(), home.samples), (Some("Den"), 7));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A save that can't be written is reported, not taken for success.
    #[test]
    fn a_save_that_cannot_be_written_is_an_error() {
        let one: Store = [("home".to_string(), Baseline::default())]
            .into_iter()
            .collect();
        let (dir, p) = store_with_blocked(
            "unwritable",
            &serde_json::to_string(&one).unwrap(),
            ".baselines.json.tmp",
        );
        let r = update_at(&p, |all| {
            all.insert("hotel".into(), Baseline::default());
        });
        assert!(r.is_err());
        assert_eq!(load_from(&p).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two processes learning the same network: only the one holding the
    /// learner lock writes, the other leaves it to its peer, and takes over
    /// once the holder lets go. Two holders stand in for two processes,
    /// since each lock is its own open.
    #[test]
    fn only_one_process_saves_what_it_learns() {
        let dir =
            std::env::temp_dir().join(format!("octomon-baseline-learner-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("baselines.json");
        let dashboard = parking_lot::Mutex::new(None);
        let watcher = parking_lot::Mutex::new(None);
        let learned = |samples| Baseline {
            samples,
            ..Default::default()
        };
        assert_eq!(
            save_learned_at(&p, &dashboard, "home", &learned(1)),
            Learned::Saved
        );
        assert_eq!(
            save_learned_at(&p, &watcher, "home", &learned(7)),
            Learned::LeftToPeer
        );
        assert_eq!(
            load_from(&p)["home"].samples,
            1,
            "the peer's copy did not land"
        );
        // The holder keeps saving without taking the lock again.
        assert_eq!(
            save_learned_at(&p, &dashboard, "home", &learned(2)),
            Learned::Saved
        );
        // The holder exits: the lock goes with it, and the watcher takes over.
        *dashboard.lock() = None;
        assert_eq!(
            save_learned_at(&p, &watcher, "home", &learned(8)),
            Learned::Saved
        );
        assert_eq!(load_from(&p)["home"].samples, 8);
        assert!(dir.join(".baselines.json.learner.lock").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_save_never_runs_while_someone_else_holds_the_lock() {
        let dir =
            std::env::temp_dir().join(format!("octomon-baseline-held-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("baselines.json");

        let held = crate::store::FileLock::acquire(&p).expect("free to start with");
        let busy = update_at(&p, |all| {
            all.insert("blocked".into(), Baseline::default());
        });
        assert_eq!(busy.unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        assert!(!p.exists(), "wrote without the lock");
        drop(held);

        assert!(
            update_at(&p, |all| {
                all.insert("after".into(), Baseline::default());
            })
            .is_ok()
        );
        assert!(load_from(&p).contains_key("after"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
