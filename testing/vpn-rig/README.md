# VPN rig

Real Linux VPN clients in containers, each watched by octomon, each checked
against what octomon is supposed to say about it. The rig exists because
tunnel classification, naming and location keying (the identity a learned
normal is filed under) are the parts of octomon that are hardest to test with
unit tests and easiest to get subtly wrong: 0.12.0 re-keyed three tunnel
shapes after a review found that unnamed tunnels minted a location per
connect.

It is run by hand, on a developer machine with Docker. It is never part of CI:
the containers need `NET_ADMIN` and `/dev/net/tun`, and some clients need a
real account.

## Run it

```sh
testing/vpn-rig/run.sh                  # every client; account-backed ones skip without secrets
testing/vpn-rig/run.sh wireguard openvpn
OBSERVE=30 testing/vpn-rig/run.sh       # longer --doctor observe (default 15 s)
```

The first run builds octomon from the checkout (release profile, a few
minutes, cached afterwards) into `octomon-rig-base`. Reports land in
`testing/vpn-rig/out/`: one JSON per phase (`--check` output, the unredacted
`--doctor --json`, routes, errors.log) and each client's final errors.log.

## What a client run does

For each client under `clients/<name>/`:

1. Start the servers it needs (`compose.yml`), on the `octomon-rig` network.
   That bridge is "the LAN" every client shares.
2. Start the client container from `octomon-rig-base` plus the client.
3. For each phase in `expect.json`: run `vpn <cmd>` (connect, reconnect, a
   second profile), wait for the tunnel interface, then `rig-probe`:
   `octomon --check` and `octomon --doctor --json --full --observe 15s`.
4. Assert: `network.tunnel` matches the expected name, `location.label`
   matches the expected pattern, `location.key` is unchanged across a phase
   marked `"key": "same"` and changed across one marked `"different"`, and
   errors.log has no panic or supervisor line. A phase can add free-form
   `asserts`: a jq path on the probe's JSON and a regex its value must
   `match`, or must have `absent`.
5. Disconnect, keep errors.log, remove the container.

`location.key` is the identity itself; the rig is why `--doctor --json --full`
exposes it.

## Clients

| client | needs | expects |
|---|---|---|
| `wireguard` | nothing | kernel device via `wg-quick`, named WireGuard, label carries the tunnel address; same key after a reconnect, a different key with the second profile (WireGuard keys on its address by design) |
| `openvpn` | nothing | tun device, named OpenVPN, label without an address; same key after reconnecting to the rig's second server, which hands out a different pool |
| `nordvpn` | `secrets/nordvpn.token` | NordVPN's own Linux client (6.x) over NordLynx: kernel WireGuard device `nordlynx`, named NordVPN by its address block and running daemon, label without an address; same key after reconnecting to another country; the client's resolvers (103.86.96.100, 103.86.99.100) are in the system list |
| `tailscale` | `secrets/tailscale.authkey` | Tailscale as a resident mesh client (tun `tailscale0`, only its own routes): octomon lists it as a bypassed tunnel and the LAN keeps its own location; a wg-quick tunnel brought up beside it is named WireGuard, not Tailscale (the bystander rule with real process names); the LAN key comes back unchanged when the tunnel drops. Then with MagicDNS on (100.100.100.100 as the system resolver): the mixed case again, the resolver naming Tailscale and not the WireGuard tunnel beside it; wg-quick's policy rule then swallows the v4 route to MagicDNS, and the phase asserts octomon calls that a dead first resolver, not a blocked web |
| `unnamed` | nothing | a plain GRE tunnel to `servers/gre`, made with `ip(8)`, no VPN software: octomon knows it is a tunnel only from the kernel's device type, calls it "unidentified VPN / tunnel", labels it "… via VPN", and keeps one key when it is re-created with another address |
| `warp` | nothing (consumer WARP, `--accept-tos`) | Cloudflare's Linux client over WireGuard: tun device `CloudflareWARP` at 172.16.0.2/32 (the fixed address every WARP device gets under that protocol) plus a 2606:4700::/32 address, named by that v6 block; the label carries the underlay gateway ("… via Cloudflare WARP"); same key after a reconnect and after deleting and re-creating the device registration, which hands out a new v6 address; the client's resolvers (127.0.2.2, 127.0.2.3) are in the system list; with the v6 flushed from the device, 172.16.0.2 alone still names WARP through the running daemon and the resolvers |
| `warp-team` | `secrets/warp-team.env` | the same client enrolled in a Zero Trust organisation through a service token (`mdm.xml`): named Cloudflare WARP, with the address shape the org hands out (its protocol and per-device IP setting decide: 172.16.0.2 under plain WireGuard, the device's own 100.96/12 address under MASQUE or with unique device IPs on; `warp-cli tunnel protocol` is consumer-only, so the rig records rather than chooses); same key after a reconnect, after deleting the registration (the daemon re-enrols itself from `mdm.xml` and gets the next addresses) and with the v6 flushed |
| `crowded` | `secrets/nordvpn.token`, `secrets/tailscale.authkey` (each optional) | every client installed at once with nordvpnd, warp-svc and tailscaled all resident: nothing connected (Tailscale bypassed, the LAN is the location); NordVPN, WARP, wg-quick and OpenVPN connected one at a time, each named as itself with the other daemons as bystanders; WARP connected over a wg-quick tunnel (WARP the tunnel, WireGuard listed beside it); NordVPN then WARP, which on Linux ends with WARP giving up and octomon reporting NordVPN alone; the LAN key restored at the end. Phases needing a missing secret are skipped |

### Faults, not tunnels

`faults` is a client with no VPN at all. Each phase breaks the container's
own network one way (`tc netem` loss or delay, `iptables` dropping DNS, the
web, ICMP or everything beyond the LAN, a local "sign in" page answering
every HTTP request) and the phase asserts on octomon's analysis: `status`,
`exit_code` and the finding causes, which are fixed slugs (`dns`, `internet`,
`captive-portal`, …). Its first phase is a clean 460 s so that octomon learns
the network's normal first (a baseline needs five healthy minutes after a two
minute warm-up); the location-aware judgements only speak against a normal.

Planned, same harness: the UDM profiles against a real router, and Mullvad
(its `wg0-mullvad` on 10.64.x is the "private block plus running client"
naming rule, which only WARP's 172.16.0.2 exercises here).

### Secrets

`secrets/` is git-ignored except for its `.gitignore`, its README and the
`*.example` files. A client's `expect.json` names the file it needs
(`"secret": "nordvpn.token"`); when the file is absent the client is skipped
and the run still passes. A client that lists several (`"secrets": [...]`)
runs with those present, and a phase marked `"needs"` with a missing one is
skipped, recorded as not run.

`secrets/README.md` says, per client, what the file is and where to get it;
copy each `.example` without the suffix and replace the placeholder.

### Fixtures are not secrets

`servers/wireguard/wg0.conf`, `clients/wireguard/wg*.conf` and the OpenVPN
certificates under `servers/openvpn/` and `clients/openvpn/` are checked in
on purpose. They only ever secure traffic between two containers on the
rig's own bridge, and a reader must be able to run the rig from a clone.
Do not reuse them anywhere.

## Publishing a run

```sh
testing/vpn-rig/run.sh && testing/vpn-rig/publish.sh
```

`run.sh` leaves `out/report.json`, a summary built from an allow-list: octomon
version, date, host, commit, and per client its status and per phase the
device name, what octomon called the tunnel, whether the label carries an
address, the key rule (first / same / different) and the four checks. No
address, key, hostname, server, route or log line is in it. `publish.sh`
applies the same allow-list again, writes the run as
`website/testing/vpn-rig.json` (replacing the previous run: the page records
what the current release was checked for, it keeps no history) and renders
`website/testing.html`, which is `octomon.dev/testing`. Review the diff under
`website/testing/` before committing; the rest of `out/` never leaves the
machine.

## What it cannot test

- macOS: utun renumbering, the WireGuard app's routes, Network Extension
  clients. Windows: everything. The rig is Linux by construction.
- Wi-Fi, RSSI and a real LAN underlay. Every location here is "the Docker
  bridge via <tunnel>", so the underlay half of a key never varies.
- Zscaler, GlobalProtect, AnyConnect and other corporate clients.
- Never create an `ipip` device in a container: Docker Desktop's kernel
  (7.0.14-linuxkit) oopses in `ipip_newlink` and the whole VM goes down. GRE
  is fine, which is why `unnamed` uses it.
- Replies from Docker Desktop's NAT reach a container over its veth with the
  TCP checksum left unfilled. Forwarded into a tun or GRE device as-is, the
  client drops them as checksum errors: ping works, web does not, and
  octomon says so. The rig's OpenVPN and GRE servers recompute TCP checksums
  on egress into the tunnel (`tc … action csum`); WireGuard does not need it.
- `wg-quick` and WARP on Linux both use fwmark policy routing: the main
  table's default route stays on `eth0`. Whether octomon reads that as a split
  or a full tunnel is recorded per phase (`network.medium` in `out/*.json`),
  not asserted. As of 0.12.0 wg-quick reads as a full tunnel ("Tunnel (VPN)")
  and WARP as a split tunnel over the wired link, so the WARP label carries
  the underlay gateway, as it does on a Mac.
