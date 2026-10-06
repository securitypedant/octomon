//! `--demo`: everything measures for real, but the screen shows nothing that
//! identifies this network or machine — for recording a demo without a
//! redaction pass afterwards.
//!
//! The disguise is applied to a *copy* of the state just before each draw,
//! never to the state the collectors write, and it is deterministic: the same
//! real value becomes the same fake value for the whole session, so every
//! place it appears stays consistent. What is rewritten is a short, fixed
//! list of things that place a person or a machine:
//!
//! - MAC addresses (ours, the gateway's, the underlay gateway's) →
//!   locally-administered `02:xx:…` values.
//! - The public IPv4 and IPv6 addresses — the discovered "public IP" rows,
//!   the edge's view of us, and the global-scope IPv6 addresses on the
//!   interface and its router, which are public-facing by construction →
//!   TEST-NET ranges (`203.0.113.x`, `198.51.100.x`) and the documentation
//!   prefix `2001:db8::/32`.
//! - The SSID → `DemoNet`, and stored location labels that were SSIDs; the
//!   names a user gave ("Home") are kept — they were chosen to be shareable.
//! - Free text (events, network history, notices, the recording path, whois
//!   output, the routing table) gets the same substitutions, and the home
//!   directory becomes `~`.
//!
//! Everything else is real: the LAN (`192.168.1.x` says nothing about who
//! you are), the resolvers, every hop of every path, the remote addresses
//! the machine talks to, and whois answers for any address but our own. An
//! earlier version rewrote all of those too, and a demo of "which server is
//! the game on" showed `203.0.113.105`, whose whois said Example Networks —
//! a disguise that hides the thing the demo is about is not useful.
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

/// A public, globally routable address — the kind a distant hop shows and
/// nobody needs hidden. Private, link-local, CGNAT and ULA ranges are not.
fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let shared = o[0] == 100 && (64..=127).contains(&o[1]);
            !(v4.is_private() || v4.is_link_local() || v4.is_loopback() || shared)
        }
        IpAddr::V6(v6) => {
            let s0 = v6.segments()[0];
            let link_local = (s0 & 0xffc0) == 0xfe80;
            let ula = (s0 & 0xfe00) == 0xfc00;
            !(link_local || ula || v6.is_loopback())
        }
    }
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

    /// The fake for `ip`, remembered so free text and every later sighting
    /// agree. Loopback and well-known public resolvers pass through. Only
    /// the sensitive values go through here (see the module doc); the rest
    /// of the state is drawn through [`Self::known_ip`].
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

    /// `ip` as it should be drawn: its fake when it is one of the sensitive
    /// values already learned, itself otherwise. The pass learns the public
    /// addresses first, then draws everything else through this, so a
    /// remote row or an event that happens to carry our public address is
    /// consistent with the Network panel — and a remote that is simply
    /// some server stays that server.
    pub fn known_ip(&self, ip: IpAddr) -> IpAddr {
        self.subs
            .get(&ip.to_string())
            .and_then(|f| f.parse().ok())
            .unwrap_or(ip)
    }

    /// Whether `ip` is one of the learned sensitive values.
    pub fn is_known(&self, ip: IpAddr) -> bool {
        self.subs.contains_key(&ip.to_string())
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

/// Drop every process command line. Both demo modes exist so a screen can be
/// recorded, and argv is the one thing on screen that routinely carries a
/// secret outright — a `--token=…`, a `-p` password, a signed URL. There is no
/// disguise for it that keeps it useful, so the zoom detail simply loses the
/// `cmd` row (the executable path above it still answers "what is this?").
fn drop_command_lines(v: &mut AppState) {
    for d in v.proc_details.values_mut() {
        d.cmd.clear();
    }
}

/// A global-scope IPv6 (bare or CIDR): the kind that is public-facing.
fn global_v6(cidr: &str) -> bool {
    let ip = cidr.split('/').next().unwrap_or(cidr).trim();
    matches!(ip.parse::<IpAddr>(), Ok(ip @ IpAddr::V6(_)) if is_global(ip))
}

/// A copy of `s` with the sensitive values rewritten — see the module doc
/// for the list. `d` accumulates the mapping across frames so the fakes
/// stay stable for the whole session.
pub fn disguise(s: &AppState, d: &mut Disguise) -> AppState {
    let mut v = s.clone();

    // First the sensitive values themselves, so the mapping exists before
    // anything is drawn through it.
    v.netinfo.mac = d.mac(&v.netinfo.mac);
    v.netinfo.gateway_mac = d.mac(&v.netinfo.gateway_mac);
    if !v.netinfo.underlay_gateway_mac.is_empty() {
        v.netinfo.underlay_gateway_mac = d.mac(&v.netinfo.underlay_gateway_mac);
    }
    if let Some(w) = v.netinfo.wifi.as_mut() {
        w.ssid = d.ssid(&w.ssid);
    }
    // The public IPv4 lives in the discovered "public IP" target rows (and
    // the label names it); the public IPv6 in its own field; the edge check
    // reports what the edge saw us as, over each family.
    for t in v.targets.iter_mut() {
        if t.discovered && t.label.contains("public") {
            t.addr = d.ip(t.addr);
            if let Some(h) = t.hostname.as_mut()
                && h.parse::<IpAddr>().is_ok()
            {
                *h = d.text(h);
            }
        }
    }
    v.public_ipv6 = v.public_ipv6.map(|ip| d.ip(ip));
    for e in [v.edge.as_mut(), v.edge6.as_mut()].into_iter().flatten() {
        if let Ok(ip) = e.ip.parse::<IpAddr>() {
            e.ip = d.ip(ip).to_string();
        }
    }
    // Global-scope IPv6 on the interface and its router is public-facing:
    // the prefix is the ISP's allocation to this line. Link-local and ULA
    // say no more than 192.168.x does, and stay.
    v.netinfo.ipv6 = v
        .netinfo
        .ipv6
        .iter()
        .map(|a| if global_v6(a) { d.cidr(a) } else { a.clone() })
        .collect();
    if global_v6(&v.netinfo.gateway_ipv6) {
        v.netinfo.gateway_ipv6 = d.cidr(&v.netinfo.gateway_ipv6);
    }

    // Everything else is drawn as measured, with the mapping applied where
    // one of those values turns up again (the router's v6 as a target row,
    // our public address in an event).
    for t in v.targets.iter_mut() {
        t.addr = d.known_ip(t.addr);
        t.label = d.text(&t.label);
    }
    for p in v.dns.iter_mut() {
        p.server = d.known_ip(p.server);
    }
    for r in v.remotes.iter_mut() {
        r.addr = d.known_ip(r.addr);
    }
    v.pinned_remotes = v.pinned_remotes.iter().map(|a| d.known_ip(*a)).collect();
    if let Some(m) = v.hop_monitor.as_mut() {
        for h in m.hops.iter_mut() {
            h.addr = h.addr.map(|a| d.known_ip(a));
            if let Some(st) = h.stat.as_mut() {
                st.addr = d.known_ip(st.addr);
            }
        }
        m.dest = d.known_ip(m.dest);
        m.target = d.text(&m.target);
    }
    if let Some(t) = v.traceroute.as_mut() {
        for h in t.hops.iter_mut() {
            if let Some(a) = h.addr.as_mut()
                && let Ok(ip) = a.parse::<IpAddr>()
            {
                *a = d.known_ip(ip).to_string();
            }
        }
        t.target = d.text(&t.target);
    }
    if let Some(p) = v.pmtu.as_mut() {
        p.target = d.known_ip(p.target);
    }
    // Whois: a record about our own public address names the ISP and the
    // city, so that one is replaced with an example record. Any other
    // address's record is the point of asking, and stays.
    if let Some(w) = v.whois.as_mut() {
        if d.is_known(w.addr) {
            w.addr = d.known_ip(w.addr);
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
        }
        w.raw = w.raw.iter().map(|l| d.text(l)).collect();
    }
    // The routing table is real; neighbour entries can carry a MAC and the
    // interface's global v6, which the mapping covers.
    if let Some(routes) = v.routes.as_mut() {
        *routes = routes.iter().map(|l| d.text(l)).collect();
    }
    if let Some(e) = v.egress.as_mut() {
        for r in e.results.iter_mut() {
            r.check.host = d.text(&r.check.host);
        }
    }
    if let Some(m) = v.egress_monitor.as_mut() {
        for r in m.rows.iter_mut() {
            r.check.host = d.text(&r.check.host);
            r.addr = r
                .addr
                .map(|a| std::net::SocketAddr::new(d.known_ip(a.ip()), a.port()));
        }
    }

    // Locations: labels that were SSIDs; user-given names stay.
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
    drop_command_lines(&mut v);
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
    // The public v6 is this machine's own global address, and on a stack
    // that does not randomise it the MAC sits inside it just the same.
    if let Some(ip) = v.public_ipv6
        && embeds_mac(&ip.to_string(), &real_mac)
    {
        v.public_ipv6 = Some(d.ip(ip));
    }
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
    // The routing table can carry the machine's own MAC in neighbour entries
    // and its EUI-64 v6 addresses; the mapping built above covers both.
    if let Some(routes) = v.routes.as_mut() {
        *routes = routes.iter().map(|l| d.text(l)).collect();
    }
    if let Some(n) = v.notice.as_mut() {
        *n = d.text(n);
    }
    drop_command_lines(&mut v);
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
        // Split-tunnel locations read "HomeNet via Cloudflare WARP": the
        // network half identifies the place and gets disguised; the vendor
        // half identifies software and stays.
        if let Some((net, vpn)) = label.split_once(" via ") {
            return format!("{} via {vpn}", self.ssid_or_text(net));
        }
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

    /// argv is the one thing in the zoom detail that can carry a secret
    /// outright, and both demo modes exist so the screen can be recorded.
    /// The path stays: it answers "what is this?" and names no secret.
    #[test]
    fn neither_demo_mode_shows_a_command_line() {
        let mut s = AppState::new(vec![]);
        s.proc_details.insert(
            4242,
            crate::app::ProcDetail {
                exe: "/usr/local/bin/sync".into(),
                cmd: "/usr/local/bin/sync --token=hunter2 --host=db.internal".into(),
                user: "simon".into(),
                parent: "login (1)".into(),
                started: "08-27 10:00".into(),
            },
        );
        for view in [
            disguise(&s, &mut Disguise::new()),
            disguise_machine(&s, &mut Disguise::new()),
        ] {
            let d = &view.proc_details[&4242];
            assert!(d.cmd.is_empty(), "command line survived: {}", d.cmd);
            assert_eq!(
                d.exe, "/usr/local/bin/sync",
                "the path still answers 'what'"
            );
        }
    }

    /// Simon, after a demo of "which server is the game on" showed a
    /// TEST-NET address whose whois said Example Networks: "--demo should
    /// ONLY hide any IP that is sensitive. My local 192.168. isn't, but my
    /// public IP and MAC address is. Maybe the SSID should also be masked."
    #[test]
    fn only_the_public_addresses_macs_and_ssid_are_hidden() {
        let mut s = AppState::new(vec![TargetStat::new(
            "Cloudflare".into(),
            "1.1.1.1".parse().unwrap(),
        )]);
        s.netinfo.iface = "en0".into();
        s.netinfo.ipv4 = vec!["10.20.30.40/24".into()];
        s.netinfo.ipv6 = vec![
            "fe80::1031:259c:bc37:2a61/64".into(),
            "2601:646:8f00:1234:1031:259c:bc37:2a61/64".into(),
        ];
        s.netinfo.gateway_ip = "10.20.30.1".into();
        s.netinfo.gateway_ipv6 = "fe80::1".into();
        s.netinfo.mac = "de:ad:be:ef:00:01".into();
        s.netinfo.gateway_mac = "de:ad:be:ef:00:02".into();
        s.netinfo.dns = vec!["10.20.30.1".into(), "1.1.1.1".into()];
        s.netinfo.wifi = Some(crate::app::WifiInfo {
            ssid: "SecretNet".into(),
            ..Default::default()
        });
        s.netinfo.dhcp_server = "10.27.88.200".into();
        s.public_ipv6 = Some("2601:646:8f00:1234::5".parse().unwrap());
        // The game server the demo is about, and a pin on it.
        s.remotes.push(crate::app::RemoteBandwidth {
            addr: "34.46.39.183".parse().unwrap(),
            port: 9012,
            ports: 1,
            process: "FortniteClient".into(),
            down_bytes: 1,
            up_bytes: 1,
            total_bytes: 2,
            share: 1.0,
            down_bps: 0.0,
            up_bps: 0.0,
        });
        s.pinned_remotes.push("34.46.39.183".parse().unwrap());
        let mut hop = TargetStat::new("hop 2→1.1.1.1".into(), "76.14.0.9".parse().unwrap());
        hop.discovered = true;
        s.targets.push(hop);
        let mut public = TargetStat::new("public IP".into(), "23.93.34.5".parse().unwrap());
        public.discovered = true;
        s.targets.push(public);
        s.push_event(
            crate::verdict::Severity::Info,
            crate::app::EventCategory::Network,
            "network changed → en0 · gateway 10.20.30.1 · public 23.93.34.5".into(),
        );
        s.push_event(
            crate::verdict::Severity::Info,
            crate::app::EventCategory::Network,
            "known location → SecretNet".into(),
        );

        let mut d = Disguise::new();
        let v = disguise(&s, &mut d);

        // Hidden: MACs, SSID, the public addresses, the global v6.
        assert!(v.netinfo.mac.starts_with("02:"));
        assert!(v.netinfo.gateway_mac.starts_with("02:"));
        assert_eq!(v.netinfo.wifi.unwrap().ssid, "DemoNet");
        let public_row = v.targets.iter().find(|t| t.label == "public IP").unwrap();
        assert!(
            !public_row.addr.to_string().starts_with("23.93."),
            "{}",
            public_row.addr
        );
        let v6 = v.public_ipv6.unwrap().to_string();
        assert!(v6.starts_with("2001:db8:"), "public v6 rewritten: {v6}");
        assert!(
            v.netinfo.ipv6[1].starts_with("2001:db8:"),
            "global v6 rewritten: {}",
            v.netinfo.ipv6[1]
        );
        let event = &v.events[v.events.len() - 2].message;
        assert!(
            !event.contains("23.93.34.5"),
            "public address scrubbed from text: {event}"
        );
        assert!(
            !v.events.back().unwrap().message.contains("SecretNet"),
            "SSID scrubbed from text"
        );

        // Real: the LAN, the router, the resolvers, the hops, the remotes.
        assert_eq!(v.netinfo.gateway_ip, "10.20.30.1");
        assert_eq!(v.netinfo.ipv4[0], "10.20.30.40/24");
        assert_eq!(
            v.netinfo.ipv6[0], "fe80::1031:259c:bc37:2a61/64",
            "link-local v6 kept"
        );
        assert_eq!(v.netinfo.gateway_ipv6, "fe80::1");
        assert_eq!(v.netinfo.dns, vec!["10.20.30.1", "1.1.1.1"]);
        assert_eq!(v.netinfo.dhcp_server, "10.27.88.200");
        assert_eq!(v.targets[0].addr.to_string(), "1.1.1.1");
        assert_eq!(
            v.targets[1].addr.to_string(),
            "76.14.0.9",
            "the ISP hop is not about me"
        );
        assert_eq!(
            v.remotes[0].addr.to_string(),
            "34.46.39.183",
            "the game server is the point"
        );
        assert_eq!(v.pinned_remotes[0].to_string(), "34.46.39.183");
        assert!(
            event.contains("gateway 10.20.30.1"),
            "LAN addresses stay in text: {event}"
        );
        // The live state is untouched.
        assert_eq!(s.netinfo.mac, "de:ad:be:ef:00:01");
    }

    /// Whois is the point of asking about a server; about our own address
    /// it names the ISP and the town.
    #[test]
    fn whois_is_real_for_anyone_but_us() {
        let mut s = AppState::new(vec![]);
        let mut public = TargetStat::new("public IP".into(), "23.93.34.5".parse().unwrap());
        public.discovered = true;
        s.targets.push(public);
        let record = |addr: &str| crate::app::Whois {
            addr: addr.parse().unwrap(),
            running: false,
            fields: vec![("name".into(), "SONIC-NET".into())],
            raw: vec![format!("inetnum: {addr}")],
            source: "rdap.arin.net".into(),
            error: None,
        };
        s.whois = Some(record("34.46.39.183"));
        let v = disguise(&s, &mut Disguise::new());
        let w = v.whois.unwrap();
        assert_eq!(w.addr.to_string(), "34.46.39.183");
        assert_eq!(w.fields[0].1, "SONIC-NET", "someone else's record is real");

        s.whois = Some(record("23.93.34.5"));
        let v = disguise(&s, &mut Disguise::new());
        let w = v.whois.unwrap();
        assert!(!w.addr.to_string().starts_with("23.93."));
        assert_eq!(w.fields[1].1, "EXAMPLE-NET", "our own record is canned");
        assert!(!w.raw[0].contains("23.93.34.5"), "{:?}", w.raw);
    }
}
