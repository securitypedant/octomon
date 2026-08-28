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
                let recent: Vec<f64> = t.web.hist.data.iter().rev().take(n).copied().collect();
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
/// found beneath the tunnel, falling back to one per-vendor location when no
/// underlay is visible at all.
pub fn fingerprint(n: &NetInfo) -> Option<(String, String)> {
    let mac_known = !n.gateway_mac.is_empty() && n.gateway_mac != "-";
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
    // the tunnel, not the room. Keyed on the vendor so reconnecting — or a
    // different exit server, or macOS renumbering utunN — comes back to the
    // same location instead of minting a new one each time. This is also the
    // only identity a tunnel like WARP on Windows has: a /32, no gateway, no
    // MAC — nothing below would key on it at all.
    let full_tunnel = n.medium == LinkMedium::Tunnel && n.tunnel.is_some();
    if !mac_known && !ip_known && ssid.is_empty() && !full_tunnel {
        return None;
    }

    let (raw, label) = if full_tunnel {
        let vendor = n.tunnel.as_deref().unwrap_or("");
        let (vkey, vshown) = if vendor.is_empty() {
            // Unidentified tunnels fall back to the device name — less stable
            // (utun4 today, utun6 tomorrow) but better than no location.
            (n.tunnel_iface.as_str(), "VPN")
        } else {
            (vendor, vendor)
        };
        let u_mac = !n.underlay_gateway_mac.is_empty() && n.underlay_gateway_mac != "-";
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
        } else if vendor.is_empty() {
            (
                format!("vpn|{}|{}", n.tunnel_iface, n.medium as u8),
                format!("VPN ({})", n.tunnel_iface),
            )
        } else {
            (
                format!("vpn|{vendor}|{}", n.medium as u8),
                vendor.to_string(),
            )
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
        // An unidentified vendor keys on the device name — less stable
        // (utunN renumbers) but better than folding VPN minutes into the
        // bare network's normal.
        let key = if vendor.is_empty() {
            &n.tunnel_iface
        } else {
            vendor
        };
        let shown = if vendor.is_empty() { "VPN" } else { vendor };
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

/// Best-effort load; a corrupt or missing file is an empty map, never a crash.
pub fn load() -> Store {
    let Some(p) = path() else {
        return Store::new();
    };
    std::fs::read_to_string(p)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// Best-effort whole-file rewrite — a handful of networks × ~200 bytes.
/// A failure here means every learned normal is lost at exit, which shows up
/// much later as "it forgot my networks", so it goes on the record.
pub fn save(store: &Store) {
    let Some(p) = path() else {
        crate::errlog::log("baseline", "no data directory — learned networks not saved");
        return;
    };
    if let Some(dir) = p.parent() {
        let _ = crate::store::create_dir_private(dir);
    }
    match serde_json::to_string_pretty(store) {
        Ok(json) => {
            if let Err(e) = crate::store::write_private(&p, json) {
                crate::errlog::log(
                    "baseline",
                    format!(
                        "could not write {}: {e} — learned networks not saved",
                        p.display()
                    ),
                );
            }
        }
        Err(e) => crate::errlog::log("baseline", format!("not serializable: {e}")),
    }
}

/// Load one network's baseline (blocking file read — call off the lock).
pub fn load_one(key: &str) -> Option<Baseline> {
    load().get(key).cloned()
}

/// Merge one network's baseline back in and persist (blocking — off the lock).
pub fn save_one(key: &str, b: &Baseline) {
    let mut all = load();
    all.insert(key.to_string(), b.clone());
    save(&all);
}

/// Remove one network's stored baseline (blocking — off the lock). Its
/// incident history is deliberately kept: if the network is ever visited
/// again, "3 outages this week" is still true and still useful.
pub fn forget(key: &str) {
    let mut all = load();
    all.remove(key);
    save(&all);
}

/// Set the user's name for a network, keeping any learned stats.
pub fn name_network(key: &str, label: &str, name: &str) {
    let mut all = load();
    let entry = all.entry(key.to_string()).or_insert_with(|| Baseline {
        label: label.to_string(),
        ..Default::default()
    });
    entry.name = if name.trim().is_empty() {
        None
    } else {
        Some(name.trim().to_string())
    };
    save(&all);
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

        // An unidentified tunnel still gets a location, named by its device.
        let mut unknown = warp.clone();
        unknown.tunnel = Some(String::new());
        let (ukey, ulabel) = fingerprint(&unknown).unwrap();
        assert_ne!(key, ukey);
        assert_eq!(ulabel, "VPN (CloudflareWARP)");
    }

    /// A full tunnel with a visible physical network underneath keys on that
    /// underlay: the same VPN over the office Ethernet and over hotel Wi-Fi
    /// is two places with two normals. The vendor-only bucket above is only
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

        // An unidentified split tunnel still separates from the bare LAN.
        let mut unknown = with_warp("HomeNet", "aa:bb:cc:dd:ee:ff");
        unknown.tunnel = Some(String::new());
        let (ukey, ulabel) = fingerprint(&unknown).unwrap();
        assert_ne!(ukey, home.0);
        assert_ne!(ukey, home_warp.0);
        assert_eq!(ulabel, "HomeNet via VPN");
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
}
