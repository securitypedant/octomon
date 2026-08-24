//! `--demo`: everything measures for real, but the screen shows nothing that
//! identifies this network or machine — for recording a demo without a
//! redaction pass afterwards.
//!
//! The disguise is applied to a *copy* of the state just before each draw,
//! never to the state the collectors write, and it is deterministic: the same
//! real address becomes the same fake address for the whole session, so
//! targets, hops, remotes and events stay consistent with each other. What is
//! rewritten:
//!
//! - MAC addresses → locally-administered `02:xx:…` values.
//! - Private / link-local / CGNAT IPv4 → `192.168.0.x`; the gateway is always
//!   `192.168.0.1`. Every IPv6 → the documentation prefix `2001:db8::/32`.
//! - Public addresses that are *ours or about us* — the public IP, discovered
//!   hops, remote addresses, path-monitor hops, resolvers — → TEST-NET ranges
//!   (`203.0.113.x`, `198.51.100.x`). Well-known public resolvers (1.1.1.1,
//!   8.8.8.8, 9.9.9.9 and kin) are kept: they identify nobody and are the
//!   default targets.
//! - SSIDs → `DemoNet` (ours) and stored location labels that were SSIDs; the
//!   names a user gave ("Home") are kept — they were chosen to be shareable.
//! - Whois answers → an example registry record; proxy hosts → `proxy.example`.
//! - Free text (events, network history, notices, the recording path) gets the
//!   same substitutions, and the home directory becomes `~`.
//!
//! Hostnames of targets the user added by name, process names and interface
//! names are left alone: they are what a demo is about, and the user chose
//! them.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::app::AppState;

/// Consistent real → fake mapping for one session.
#[derive(Default)]
pub struct Disguise {
    /// Every rewritten string, real → fake, for the free-text pass.
    subs: HashMap<String, String>,
    home: Option<String>,
}

fn h64(s: &str) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

/// Public resolvers that are nobody's secret and are the default targets.
fn well_known(ip: IpAddr) -> bool {
    const KEEP: &[&str] = &[
        "1.1.1.1",
        "1.0.0.1",
        "8.8.8.8",
        "8.8.4.4",
        "9.9.9.9",
        "149.112.112.112",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001",
        "2001:4860:4860::8888",
        "2001:4860:4860::8844",
        "2620:fe::fe",
        "2620:fe::9",
    ];
    KEEP.iter().any(|k| k.parse::<IpAddr>().ok() == Some(ip))
}

impl Disguise {
    pub fn new() -> Self {
        Self {
            subs: HashMap::new(),
            home: directories::BaseDirs::new().map(|b| b.home_dir().display().to_string()),
        }
    }

    fn remember(&mut self, real: &str, fake: &str) {
        if real != fake && !real.is_empty() {
            self.subs.insert(real.to_string(), fake.to_string());
        }
    }

    /// The fake for `ip`. Loopback and well-known public resolvers pass
    /// through; the gateway is pinned to `192.168.0.1` by the caller.
    pub fn ip(&mut self, ip: IpAddr) -> IpAddr {
        if ip.is_loopback() || well_known(ip) {
            return ip;
        }
        let key = ip.to_string();
        if let Some(f) = self.subs.get(&key) {
            return f.parse().unwrap_or(ip);
        }
        let h = h64(&key);
        let fake = match ip {
            IpAddr::V4(v4) => {
                let shared = v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]);
                if v4.is_private() || v4.is_link_local() || shared {
                    // Avoid .0, .1 (gateway) and .255.
                    IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2 + (h % 250) as u8))
                } else {
                    // TEST-NET-3 and TEST-NET-2, RFC 5737.
                    let net = if h & 1 == 0 {
                        [203, 0, 113]
                    } else {
                        [198, 51, 100]
                    };
                    IpAddr::V4(Ipv4Addr::new(net[0], net[1], net[2], 1 + (h % 250) as u8))
                }
            }
            IpAddr::V6(v6) => {
                let link_local = (v6.segments()[0] & 0xffc0) == 0xfe80;
                let (a, b, c) = ((h >> 32) as u16, (h >> 16) as u16, h as u16);
                if link_local {
                    IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, a, b, c, 1))
                } else {
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, a, b, 0, 0, 0, c.max(1)))
                }
            }
        };
        self.remember(&key, &fake.to_string());
        fake
    }

    /// `"192.168.1.20/24"` and bare forms.
    pub fn cidr(&mut self, s: &str) -> String {
        let (ip, len) = match s.split_once('/') {
            Some((ip, len)) => (ip, Some(len)),
            None => (s, None),
        };
        let Ok(addr) = ip.trim().parse::<IpAddr>() else {
            return s.to_string();
        };
        let fake = self.ip(addr).to_string();
        let out = match len {
            Some(l) => format!("{fake}/{l}"),
            None => fake,
        };
        self.remember(s, &out);
        out
    }

    pub fn mac(&mut self, mac: &str) -> String {
        if mac.is_empty() || mac == "-" {
            return mac.to_string();
        }
        if let Some(f) = self.subs.get(mac) {
            return f.clone();
        }
        let h = h64(mac).to_be_bytes();
        let fake = format!(
            "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            h[1], h[2], h[3], h[4], h[5]
        );
        self.remember(mac, &fake);
        fake
    }

    pub fn ssid(&mut self, ssid: &str) -> String {
        if ssid.is_empty() || ssid.contains("redacted") {
            return ssid.to_string();
        }
        if let Some(f) = self.subs.get(ssid) {
            return f.clone();
        }
        // The first SSID seen is "ours"; any other becomes a numbered guest.
        let n = self
            .subs
            .values()
            .filter(|v| v.starts_with("DemoNet"))
            .count();
        let fake = if n == 0 {
            "DemoNet".to_string()
        } else {
            format!("DemoNet-{}", n + 1)
        };
        self.remember(ssid, &fake);
        fake
    }

    /// Free text: every substitution recorded so far, longest first (so an
    /// address is replaced before a prefix of it), then the home directory.
    pub fn text(&self, s: &str) -> String {
        let mut keys: Vec<&String> = self.subs.keys().collect();
        keys.sort_by_key(|k| std::cmp::Reverse(k.len()));
        let mut out = s.to_string();
        for k in keys {
            if out.contains(k.as_str()) {
                out = out.replace(k.as_str(), &self.subs[k]);
            }
        }
        if let Some(home) = &self.home
            && out.contains(home.as_str())
        {
            out = out.replace(home.as_str(), "~");
        }
        out
    }
}

/// A copy of `s` with everything identifying rewritten. `d` accumulates the
/// mapping across frames so the fakes stay stable for the whole session.
pub fn disguise(s: &AppState, d: &mut Disguise) -> AppState {
    let mut v = s.clone();

    // Network identity first: the gateway pins to .1 before anything else can
    // claim it, and the mapping it creates feeds every later substitution.
    let gw_real = v.netinfo.gateway_ip.clone();
    if let Ok(gw) = gw_real.parse::<IpAddr>() {
        let fake = match gw {
            IpAddr::V4(_) => "192.168.0.1".to_string(),
            IpAddr::V6(_) => "fe80::1".to_string(),
        };
        d.remember(&gw_real, &fake);
        v.netinfo.gateway_ip = fake;
    }
    v.netinfo.gateway_mac = d.mac(&v.netinfo.gateway_mac);
    v.netinfo.mac = d.mac(&v.netinfo.mac);
    v.netinfo.ipv4 = v.netinfo.ipv4.iter().map(|a| d.cidr(a)).collect();
    v.netinfo.ipv6 = v.netinfo.ipv6.iter().map(|a| d.cidr(a)).collect();
    if !v.netinfo.gateway_ipv6.is_empty() {
        v.netinfo.gateway_ipv6 = d.cidr(&v.netinfo.gateway_ipv6);
    }
    v.netinfo.dns = v.netinfo.dns.iter().map(|a| d.cidr(a)).collect();
    if !v.netinfo.dhcp_server.is_empty() {
        v.netinfo.dhcp_server = d.cidr(&v.netinfo.dhcp_server);
    }
    if let Some(w) = v.netinfo.wifi.as_mut() {
        w.ssid = d.ssid(&w.ssid);
    }
    if let Some(p) = v.proxy.as_mut() {
        use crate::app::ProxyKind;
        p.kind = match &p.kind {
            ProxyKind::Manual { .. } => ProxyKind::Manual {
                http: "proxy.example:8080".into(),
                https: "proxy.example:8080".into(),
            },
            ProxyKind::Pac(_) => ProxyKind::Pac("http://proxy.example/proxy.pac".into()),
            ProxyKind::Wpad => ProxyKind::Wpad,
        };
        p.bypass = String::new();
    }

    // Targets: discovered ones (gateway, hops, public IP) and anything on a
    // private range are ours; well-known anchors pass through untouched.
    for t in v.targets.iter_mut() {
        t.addr = d.ip(t.addr);
        if let Some(h) = t.hostname.as_mut()
            && h.parse::<IpAddr>().is_ok()
        {
            *h = d.text(h);
        }
        t.label = d.text(&t.label);
    }
    for p in v.dns.iter_mut() {
        p.server = d.ip(p.server);
    }
    for r in v.remotes.iter_mut() {
        r.addr = d.ip(r.addr);
    }
    // Pinned remotes follow their rows' fakes, or the pin highlight would
    // vanish in demo mode — and the drawn copy would still hold a real
    // address. (Pinned process names are left alone, like process names.)
    v.pinned_remotes = v.pinned_remotes.iter().map(|a| d.ip(*a)).collect();
    if let Some(m) = v.hop_monitor.as_mut() {
        for h in m.hops.iter_mut() {
            h.addr = h.addr.map(|a| d.ip(a));
            if let Some(st) = h.stat.as_mut() {
                st.addr = d.ip(st.addr);
            }
        }
        m.dest = d.ip(m.dest);
        m.target = d.text(&m.target);
    }
    if let Some(t) = v.traceroute.as_mut() {
        for h in t.hops.iter_mut() {
            if let Some(a) = h.addr.as_mut()
                && let Ok(ip) = a.parse::<IpAddr>()
            {
                *a = d.ip(ip).to_string();
            }
        }
        t.target = d.text(&t.target);
    }
    if let Some(p) = v.pmtu.as_mut() {
        p.target = d.ip(p.target);
    }
    if let Some(w) = v.whois.as_mut() {
        w.addr = d.ip(w.addr);
        if !w.fields.is_empty() {
            w.fields = vec![
                (
                    "network".into(),
                    "203.0.113.0 – 203.0.113.255  (203.0.113.0/24)".into(),
                ),
                ("name".into(), "EXAMPLE-NET".into()),
                ("country".into(), "XX".into()),
                ("registrant".into(), "Example Networks".into()),
                ("abuse".into(), "abuse@example.net".into()),
                ("asn".into(), "AS64500 · Example Networks".into()),
            ];
        }
        w.raw = w.raw.iter().map(|l| d.text(l)).collect();
    }
    if let Some(e) = v.egress.as_mut() {
        for r in e.results.iter_mut() {
            r.check.host = d.text(&r.check.host);
        }
    }

    // Locations: labels that were SSIDs or gateways; user-given names stay.
    if let Some(b) = v.baseline.as_mut() {
        b.label = d.ssid_or_text(&b.label);
    }
    if let Some(all) = v.locations.as_mut() {
        for (_, b) in all.iter_mut() {
            b.label = d.ssid_or_text(&b.label);
        }
    }

    // Free text last, once every mapping exists.
    for e in v.events.iter_mut() {
        e.message = d.text(&e.message);
    }
    for c in v.net_history.iter_mut() {
        c.summary = d.text(&c.summary);
        c.detail = c.detail.iter().map(|l| d.text(l)).collect();
    }
    if let Some(n) = v.notice.as_mut() {
        *n = d.text(n);
    }
    if let Some(l) = v.log.as_mut() {
        l.path = std::path::PathBuf::from(d.text(&l.path.display().to_string()));
    }
    for f in v.verdict.triage.findings.iter_mut() {
        f.summary = d.text(&f.summary);
        f.evidence = f.evidence.iter().map(|l| d.text(l)).collect();
    }
    for r in v.verdict.triage.rungs.iter_mut() {
        r.detail = d.text(&r.detail);
    }
    for c in v.verdict.triage.checks.iter_mut() {
        c.detail = d.text(&c.detail);
    }
    if let crate::verdict::Verdict::Problems(fs) = &mut v.verdict.current {
        for f in fs.iter_mut() {
            f.summary = d.text(&f.summary);
            f.evidence = f.evidence.iter().map(|l| d.text(l)).collect();
        }
    }
    v
}

/// A copy of `s` with only what identifies *this machine* rewritten — its MAC
/// address, plus any IPv6 address that embeds that MAC (EUI-64). Everything
/// about the network itself — gateway, SSID, resolvers, addresses, hops —
/// stays real. This is `--demo-mac`: for screenshots of a network that isn't
/// private (a hotel, an airport) taken from a machine that is.
pub fn disguise_machine(s: &AppState, d: &mut Disguise) -> AppState {
    let mut v = s.clone();
    let real_mac = v.netinfo.mac.clone();
    v.netinfo.mac = d.mac(&real_mac);
    // An EUI-64 interface identifier is the MAC, byte for byte, inside the
    // address. Modern macOS and Windows randomise theirs; older stacks and
    // plenty of Linux configs do not, so hiding the MAC while printing such
    // an address would hide nothing.
    v.netinfo.ipv6 = v
        .netinfo
        .ipv6
        .iter()
        .map(|a| {
            if embeds_mac(a, &real_mac) {
                d.cidr(a)
            } else {
                a.clone()
            }
        })
        .collect();
    // The free-text pass replaces only what is in the mapping — here, just
    // the machine's own identifiers — so network history entries like
    // "before: … mac 22:dd:…" stop carrying the real hardware address.
    for e in v.events.iter_mut() {
        e.message = d.text(&e.message);
    }
    for c in v.net_history.iter_mut() {
        c.summary = d.text(&c.summary);
        c.detail = c.detail.iter().map(|l| d.text(l)).collect();
    }
    if let Some(n) = v.notice.as_mut() {
        *n = d.text(n);
    }
    v
}

/// Whether a v6 address (bare or CIDR) carries `mac` as its EUI-64
/// interface identifier: `..:{m0^02}{m1}:{m2}ff:fe{m3}:{m4}{m5}`.
fn embeds_mac(cidr: &str, mac: &str) -> bool {
    let ip = cidr.split('/').next().unwrap_or(cidr);
    let Ok(v6) = ip.parse::<Ipv6Addr>() else {
        return false;
    };
    let bytes: Vec<u8> = mac
        .split(':')
        .filter_map(|p| u8::from_str_radix(p, 16).ok())
        .collect();
    if bytes.len() != 6 {
        return false;
    }
    let o = v6.octets();
    o[8] == bytes[0] ^ 0x02
        && o[9] == bytes[1]
        && o[10] == bytes[2]
        && o[11] == 0xff
        && o[12] == 0xfe
        && o[13] == bytes[3]
        && o[14] == bytes[4]
        && o[15] == bytes[5]
}

impl Disguise {
    /// A baseline label is the SSID, or the gateway address for a wired
    /// network: whichever it is, it identifies the place.
    fn ssid_or_text(&mut self, label: &str) -> String {
        if label.parse::<IpAddr>().is_ok() || self.subs.contains_key(label) {
            return self.text(label);
        }
        if label.is_empty() || label.starts_with("DemoNet") {
            return label.to_string();
        }
        self.ssid(label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::TargetStat;

    #[test]
    fn addresses_are_rewritten_consistently_and_anchors_kept() {
        let mut d = Disguise::new();
        let a: IpAddr = "192.168.1.77".parse().unwrap();
        let f1 = d.ip(a);
        let f2 = d.ip(a);
        assert_eq!(f1, f2, "same real, same fake");
        assert!(f1.to_string().starts_with("192.168.0."), "{f1}");
        assert_ne!(f1, a);
        let public: IpAddr = "23.93.34.5".parse().unwrap();
        let fp = d.ip(public);
        assert!(
            fp.to_string().starts_with("203.0.113.") || fp.to_string().starts_with("198.51.100."),
            "{fp}"
        );
        assert_eq!(d.ip("1.1.1.1".parse().unwrap()).to_string(), "1.1.1.1");
        let v6: IpAddr = "2601:640:c000:1234:abcd::1".parse().unwrap();
        assert!(d.ip(v6).to_string().starts_with("2001:db8:"));
        assert!(d.mac("aa:bb:cc:11:22:33").starts_with("02:"));
        assert_eq!(d.ssid("MySecretWifi"), "DemoNet");
        assert_eq!(d.ssid("MySecretWifi"), "DemoNet");
        assert_eq!(d.ssid("CafeGuest"), "DemoNet-2");
        // Free text picks up everything mapped so far.
        let t = d.text("gateway 192.168.1.77 (aa:bb:cc:11:22:33) on MySecretWifi");
        assert!(
            !t.contains("192.168.1.77") && !t.contains("aa:bb") && !t.contains("MySecret"),
            "{t}"
        );
    }

    #[test]
    fn demo_mac_hides_the_machine_and_nothing_else() {
        let mut s = AppState::new(vec![]);
        s.netinfo.mac = "22:dd:6a:a3:0d:f9".into();
        s.netinfo.gateway_ip = "172.31.0.1".into();
        s.netinfo.gateway_mac = "b4:0c:25:e3:00:10".into();
        s.netinfo.dns = vec!["8.8.8.8".into(), "1.1.1.1".into()];
        s.netinfo.ipv6 = vec![
            // EUI-64 of the MAC above (22^02=20, then dd:6a, ff:fe, a3:0d:f9):
            // embeds the hardware address and must be rewritten…
            "fe80::20dd:6aff:fea3:df9/64".into(),
            // …while a randomised (privacy) address says nothing and stays.
            "fe80::1031:259c:bc37:2a61/64".into(),
        ];
        s.netinfo.wifi = Some(crate::app::WifiInfo {
            ssid: "Hotel Guest".into(),
            ..Default::default()
        });
        s.push_event(
            crate::verdict::Severity::Info,
            crate::app::EventCategory::Network,
            "interface en0 up · mac 22:dd:6a:a3:0d:f9".into(),
        );

        let mut d = Disguise::new();
        let v = disguise_machine(&s, &mut d);
        // The machine: gone.
        assert!(v.netinfo.mac.starts_with("02:"));
        assert_ne!(v.netinfo.ipv6[0], s.netinfo.ipv6[0], "EUI-64 v6 rewritten");
        assert!(
            !v.events.back().unwrap().message.contains("22:dd:6a"),
            "MAC scrubbed from free text"
        );
        // The network: exactly as measured.
        assert_eq!(v.netinfo.gateway_ip, "172.31.0.1");
        assert_eq!(v.netinfo.gateway_mac, "b4:0c:25:e3:00:10");
        assert_eq!(v.netinfo.dns[0], "8.8.8.8");
        assert_eq!(v.netinfo.wifi.unwrap().ssid, "Hotel Guest");
        assert_eq!(v.netinfo.ipv6[1], s.netinfo.ipv6[1], "privacy v6 kept");
    }

    #[test]
    fn a_state_comes_out_with_nothing_real_left() {
        let mut s = AppState::new(vec![TargetStat::new(
            "Cloudflare".into(),
            "1.1.1.1".parse().unwrap(),
        )]);
        s.netinfo.iface = "en0".into();
        s.netinfo.ipv4 = vec!["10.20.30.40/24".into()];
        s.netinfo.gateway_ip = "10.20.30.1".into();
        s.netinfo.mac = "de:ad:be:ef:00:01".into();
        s.netinfo.gateway_mac = "de:ad:be:ef:00:02".into();
        s.netinfo.dns = vec!["10.20.30.1".into(), "1.1.1.1".into()];
        s.netinfo.wifi = Some(crate::app::WifiInfo {
            ssid: "SecretNet".into(),
            ..Default::default()
        });
        s.netinfo.dhcp_server = "10.27.88.200".into();
        s.pinned_remotes.push("23.93.34.5".parse().unwrap());
        let mut hop = TargetStat::new("hop 2→1.1.1.1".into(), "76.14.0.9".parse().unwrap());
        hop.discovered = true;
        s.targets.push(hop);
        s.push_event(
            crate::verdict::Severity::Info,
            crate::app::EventCategory::Network,
            "network changed → en0 · gateway 10.20.30.1".into(),
        );
        // A location named by its SSID label, as the join/loss history writes.
        s.push_event(
            crate::verdict::Severity::Info,
            crate::app::EventCategory::Network,
            "known location → SecretNet".into(),
        );
        let mut d = Disguise::new();
        let v = disguise(&s, &mut d);
        assert_eq!(v.netinfo.gateway_ip, "192.168.0.1");
        assert!(v.netinfo.ipv4[0].starts_with("192.168.0.") && v.netinfo.ipv4[0].ends_with("/24"));
        assert!(v.netinfo.mac.starts_with("02:"));
        assert_eq!(v.netinfo.wifi.unwrap().ssid, "DemoNet");
        assert_eq!(
            v.netinfo.dns[0], "192.168.0.1",
            "the gateway resolver maps like the gateway"
        );
        assert_eq!(v.netinfo.dns[1], "1.1.1.1");
        assert_eq!(v.targets[0].addr.to_string(), "1.1.1.1", "anchor kept");
        assert!(!v.targets[1].addr.to_string().starts_with("76.14."));
        assert!(
            v.netinfo.dhcp_server.starts_with("192.168.0."),
            "{}",
            v.netinfo.dhcp_server
        );
        assert_ne!(v.pinned_remotes[0].to_string(), "23.93.34.5");
        assert_eq!(
            v.pinned_remotes[0],
            d.ip("23.93.34.5".parse().unwrap()),
            "pins carry the same fake as their rows"
        );
        assert!(
            v.events
                .iter()
                .all(|e| !e.message.contains("SecretNet") && !e.message.contains("10.20.30.1")),
            "location names and addresses scrubbed from event text"
        );
        assert!(
            v.events
                .iter()
                .any(|e| e.message.contains("192.168.0.1")),
            "the substitution, not deletion"
        );
        // The live state is untouched.
        assert_eq!(s.netinfo.gateway_ip, "10.20.30.1");
    }
}
