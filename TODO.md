# TODO

Ideas agreed as worth doing but not yet built. Roughly in the order they are
likely to matter.

## Multiple active paths (Ethernet + Wi-Fi both up)

Show which interface holds the default route and let the user pin probes to
an interface (bind the ICMP/HTTP sockets to a chosen local address) so "Wi-Fi
vs cable" is measured side by side rather than guessed. Today octomon reports
a second interface coming up but measures only over the default route.

## "Is it just me?"

Cross-check a wide-internet finding against a public status signal, or at
least persist "N of my anchors dropped simultaneously" as its own event with a
plain-language "this looks upstream of your ISP".

## Ping the IPv6 gateway

The v6 default router is almost always link-local (`fe80::…`), which
`surge-ping` cannot address without an interface scope. Bind a dedicated v6
client to the interface's own link-local address so the gateway rung can be
judged for v6 as well as v4. Until then "IPv6 broken" localises via the
presence of a v6 route and the v6 resolvers only.

## Path MTU on Windows

`IcmpSendEcho` / `IP_DONTFRAGMENT` honour DF on Windows; wire the probe there.
(macOS cannot: the kernel fragments regardless of DF on unprivileged sockets,
its own `ping -D` included, and octomon reports the check as unavailable.)

## QUIC egress on other hosts / QUIC in the reachability probe

The port scan checks QUIC to one host via version negotiation. A fuller check
would try HTTP/3 to the connectivity endpoint so "browsers negotiate QUIC here"
is answered directly.

## PAC / WPAD evaluation

A configured PAC script is reported but not evaluated (it needs a JavaScript
engine). A tiny evaluator for the common `PROXY host:port; DIRECT` shapes
would let the via-proxy web check run under PAC as well.

## DoH / DoT detection

Browsers using DNS-over-HTTPS bypass what octomon measures. Detecting it
reliably (per browser) is out of scope; a heuristic — connections to known DoH
endpoints on 443 in the talkers table — could at least note it.

## Long-term history views

`history.jsonl` now records finished incidents per network. Beyond the doctor
line and the locations overlay, a full-screen view (episodes by day and hour,
availability per week) would make the evening-congestion case visible at a
glance.
