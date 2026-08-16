//! The system traceroute, abstracted over its two incompatible dialects.
//!
//! Unix `traceroute` and Windows `tracert` differ in the flag names, in the
//! units (`-w` is seconds on unix and milliseconds on Windows), in the probe
//! count — tracert always sends three per hop and offers no way to ask for
//! fewer — and in the output shape, where the address comes last rather than
//! first. Three collectors need a trace, so the divergence is resolved once
//! here rather than three times over.

use crate::app::Hop;

/// The system traceroute binary.
#[cfg(windows)]
pub const PROGRAM: &str = "tracert";
#[cfg(not(windows))]
pub const PROGRAM: &str = "traceroute";

/// Arguments for a numeric trace of at most `max_hops` hops toward `dest`.
pub fn args(max_hops: usize, dest: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        // `-d` is the unix `-n`, and `-h` bounds the ttl. `-w` is per *probe*
        // and in milliseconds, and there is no `-q`, so a dead hop costs three
        // timeouts rather than one — hence 800ms rather than the unix second,
        // which keeps a stalled trace to about the same wall time. tracert
        // infers the address family from a literal address, so no `-4`/`-6`.
        vec![
            "-d".to_string(),
            "-h".to_string(),
            max_hops.to_string(),
            "-w".to_string(),
            "800".to_string(),
            dest.to_string(),
        ]
    }
    #[cfg(not(windows))]
    {
        vec![
            "-n".to_string(),
            "-q".to_string(),
            "1".to_string(),
            "-w".to_string(),
            "1".to_string(),
            "-m".to_string(),
            max_hops.to_string(),
            dest.to_string(),
        ]
    }
}

/// Parse a hop line like ` 5  157.131.209.65  187.819 ms` or ` 6  *`.
/// The header ("traceroute to …") and blanks return `None`.
#[cfg(not(windows))]
pub fn parse_hop(line: &str) -> Option<Hop> {
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

/// Parse one `tracert` hop line.
///
/// tracert sends three probes and prints the address *last*:
///
/// ```text
///   4    12 ms    <1 ms    11 ms  1.1.1.1
///   3     *        *        *     Request timed out.
/// ```
///
/// The trailing text on a dead hop is localized — a German install prints
/// "Zeitüberschreitung der Anforderung." — so it is never matched against: a hop
/// has an address only if some token parses as one. The rtt comes from the first
/// probe that answered, since `*` and `<1` both turn up mid-line. Header and
/// trailer lines fail the leading-integer test and fall out as `None`.
#[cfg(windows)]
pub fn parse_hop(line: &str) -> Option<Hop> {
    let mut it = line.split_whitespace();
    let ttl: u8 = it.next()?.parse().ok()?;
    let mut rtt_ms = None;
    let mut addr = None;
    // The number preceding an "ms" token, held until that token confirms it was
    // a probe time rather than part of an address.
    let mut pending = None;
    for tok in it {
        if tok == "ms" {
            rtt_ms = rtt_ms.or(pending.take());
            continue;
        }
        // Belt and braces: without `-d`, tracert prints "host.name [1.2.3.4]".
        let bare = tok.trim_matches(['[', ']']);
        if bare.parse::<std::net::IpAddr>().is_ok() {
            addr = Some(bare.to_string());
            continue;
        }
        // "<1" is tracert's sub-millisecond marker and does not parse as-is.
        pending = tok.strip_prefix('<').unwrap_or(tok).parse::<f64>().ok();
    }
    Some(Hop { ttl, addr, rtt_ms })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_program_is_named_for_the_platform() {
        assert_eq!(
            PROGRAM,
            if cfg!(windows) {
                "tracert"
            } else {
                "traceroute"
            }
        );
        // Whichever dialect, the destination is always last so the caller can
        // append it without knowing the flag order.
        let a = args(4, "1.1.1.1");
        assert_eq!(a.last().unwrap(), "1.1.1.1");
        assert!(a.contains(&"4".to_string()));
    }

    #[cfg(not(windows))]
    #[test]
    fn a_unix_hop_line_parses() {
        let hop = parse_hop(" 5  157.131.209.65  187.819 ms").unwrap();
        assert_eq!(hop.ttl, 5);
        assert_eq!(hop.addr.as_deref(), Some("157.131.209.65"));
        assert_eq!(hop.rtt_ms, Some(187.819));

        // A hop that did not answer still holds its place in the path.
        let dead = parse_hop(" 6  *").unwrap();
        assert_eq!(dead.ttl, 6);
        assert!(dead.addr.is_none());
        assert!(dead.rtt_ms.is_none());

        // The header and blank lines are not hops.
        assert!(parse_hop("traceroute to 1.1.1.1 (1.1.1.1), 4 hops max").is_none());
        assert!(parse_hop("").is_none());
    }

    #[cfg(windows)]
    #[test]
    fn real_tracert_output_parses() {
        // Verbatim `tracert -d -h 4 -w 800 1.1.1.1`, including the blank lines.
        let out = "\r
Tracing route to 1.1.1.1 over a maximum of 4 hops\r
\r
  1     1 ms     1 ms     1 ms  192.168.1.1\r
  2    10 ms     9 ms    11 ms  10.0.0.1\r
  3     *        *        *     Request timed out.\r
  4    12 ms    <1 ms    11 ms  1.1.1.1\r
\r
Trace complete.\r
";
        let hops: Vec<Hop> = out.lines().filter_map(parse_hop).collect();
        assert_eq!(hops.len(), 4, "header and trailer must not parse as hops");

        // The address is the last column, not the second.
        assert_eq!(hops[0].ttl, 1);
        assert_eq!(hops[0].addr.as_deref(), Some("192.168.1.1"));
        assert_eq!(hops[0].rtt_ms, Some(1.0));

        // A dead hop keeps its ttl so the path stays contiguous.
        assert_eq!(hops[2].ttl, 3);
        assert!(hops[2].addr.is_none());
        assert!(hops[2].rtt_ms.is_none());

        assert_eq!(hops[3].addr.as_deref(), Some("1.1.1.1"));
    }

    #[cfg(windows)]
    #[test]
    fn sub_millisecond_probes_are_not_dropped() {
        // "<1" does not parse as a float, so a fast LAN hop would otherwise
        // report no rtt at all.
        let hop = parse_hop("  4    <1 ms    <1 ms    <1 ms  192.168.1.1").unwrap();
        assert_eq!(hop.rtt_ms, Some(1.0));
        assert_eq!(hop.addr.as_deref(), Some("192.168.1.1"));
    }

    #[cfg(windows)]
    #[test]
    fn the_first_answering_probe_supplies_the_rtt() {
        let hop = parse_hop("  2     *       9 ms     8 ms  10.0.0.1").unwrap();
        assert_eq!(hop.rtt_ms, Some(9.0));
        assert_eq!(hop.addr.as_deref(), Some("10.0.0.1"));
    }

    #[cfg(windows)]
    #[test]
    fn a_localized_timeout_line_is_still_a_dead_hop() {
        // Why the parser never matches on the timeout text: it is translated.
        let hop = parse_hop("  3     *        *        *     Zeitüberschreitung der Anforderung.")
            .unwrap();
        assert_eq!(hop.ttl, 3);
        assert!(hop.addr.is_none());
        assert!(hop.rtt_ms.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn crlf_line_endings_do_not_leak_into_fields() {
        // Pins rather than fixes: `str::lines` and tokio's `Lines` both strip
        // the \r, but an address with a trailing \r would fail to parse much
        // later and for no obvious reason.
        let line = "  1     1 ms     1 ms     1 ms  192.168.1.1\r\n";
        let hop = line.lines().next().and_then(parse_hop).unwrap();
        assert_eq!(hop.addr.as_deref(), Some("192.168.1.1"));
    }
}
