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

## Path MTU on Windows

`IcmpSendEcho` / `IP_DONTFRAGMENT` honour DF on Windows; wire the probe there.
(macOS cannot: the kernel fragments regardless of DF on unprivileged sockets,
its own `ping -D` included, and octomon reports the check as unavailable.)

## HTTP/3 in the reachability probe

The egress monitor checks that QUIC leaves the network (a version-negotiation
exchange over v4 and v6). A fuller check would fetch the connectivity endpoint
over HTTP/3 so "browsers negotiate QUIC here" is answered directly.

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
