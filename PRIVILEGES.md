# Privileges

octomon is built to run without elevation, and says at startup what that costs
on the machine you are on. It never asks for a password and never refuses to
start; where a measurement genuinely needs privilege, the affected panel says
so rather than the whole tool gating itself behind a prompt.

What that means in practice differs sharply by platform, so the detail is here
rather than cluttering the [README](README.md).

| Platform | Unprivileged | To get everything |
|---|---|---|
| macOS | everything | nothing to do |
| Linux | latency often needs a one-line sysctl; per-process bandwidth sees only your own processes | open the ping-socket range once, and `sudo octomon` for the full process view |
| Windows | everything except per-process bandwidth | join Performance Log Users once |

## Why octomon runs unprivileged

octomon never asks for `sudo`, and that is a deliberate design constraint rather
than an accident of what was easy to build.

A network monitor is exactly the kind of tool you reach for when something is
already wrong — often on a machine that isn't yours, or a work laptop where you
don't have admin, or over SSH on a box you'd rather not escalate on. A tool that
demands root at that moment is a tool you don't run. Requiring privilege also
changes what the tool *is*: a root process that opens raw sockets and reads every
process's traffic is a much larger thing to trust, needs a much closer audit, and
turns a diagnostic you run casually into a decision you have to think about.

So the rule is: if a measurement can only be had with elevated privilege, octomon
does without it and says so, rather than gating the whole tool behind a password
prompt. On [macOS](#macos) this costs nothing — every panel populates without
root.

Linux is where the principle meets its limits, and it is worth being blunt about
it: unprivileged ICMP depends on a sysctl that distributions often ship closed,
and per-process bandwidth genuinely cannot see other users' sockets without
root. octomon still runs, still tells you exactly what is degraded and why, and
never silently pretends — but `sudo octomon` is the honest recommendation there.
See [Linux](#linux).

Windows sits between the two. Everything except per-process bandwidth is
unprivileged, and that one panel needs an ETW session — but the rights to open
one can be granted *once*, by joining Performance Log Users, rather than
re-elevating every run. That fits the rule better than `sudo` does: the elevated
capability is a property of the account, not of the process you launch. See
[Windows](#windows).

## macOS

Nothing to do. Latency uses unprivileged datagram ICMP, path discovery uses
UDP-probe `traceroute`, per-process bandwidth uses `nettop`, and Wi-Fi comes
from CoreWLAN and `system_profiler`. Every panel populates without root.

Two limits are worth knowing, and neither is fixed by `sudo`: `nettop` reports
only your own processes, and it is TCP-only, so QUIC and HTTP/3 traffic is not
attributed. Neighbouring-network SSIDs additionally need Location Services;
without it macOS redacts them, so airspace congestion counts networks per
channel but cannot weight them by signal.

## Linux

**The short version: run `sudo octomon` on Linux.** Two things are narrower or
broken without it, and only one of them can be fixed by configuration.

| Feature | Unprivileged | With `sudo` |
|---|---|---|
| Latency, path monitor, traceroute targets | Broken on many distributions, fixable — see below | Works |
| Per-process bandwidth | Your own processes only | Every process |
| Everything else | Works | Works |

octomon starts by telling you which of these apply on your machine.

**ICMP.** Latency uses *unprivileged ping sockets* rather than raw sockets, so
in principle no root is needed — but that depends on `net.ipv4.ping_group_range`,
which several distributions (Ubuntu among them) ship closed. If Connection
Quality stays empty and adding a target reports "ICMP unavailable", that is why.
Fix it once, for everyone, which is what macOS does by default:

```sh
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
# persist across reboots
echo 'net.ipv4.ping_group_range=0 2147483647' | sudo tee /etc/sysctl.d/99-ping.conf
```

Or grant the capability to the binary alone:

```sh
sudo setcap cap_net_raw+ep "$(which octomon)"
```

**Per-process bandwidth.** This one has no unprivileged workaround. `ss` cannot
report other users' sockets without root, so unprivileged octomon sees only your
own processes — system daemons and anything running as another user are simply
invisible. Note that `ss` is also TCP-only regardless of privileges: QUIC and
HTTP/3 traffic, which is much of modern browsing, carries no per-socket byte
counters and cannot be attributed at all. (Windows is the exception here: its
ETW provider does report UDP — see
[Windows](#windows).)

So: fix the sysctl and run as yourself if you mainly care about latency and the
path monitor; use `sudo` if you want the full picture.

### External tools

Several probes shell out to a system tool, and which of those ship by default
varies sharply by distribution. octomon probes for them at startup and tells you
what is missing and which package provides it (also listed under `?`):

| Tool | Package | Needed for | Ships by default? |
|---|---|---|---|
| `traceroute` | `traceroute` | path discovery, `[t]`, `[m]` path monitor | Debian yes; Ubuntu and Fedora no |
| `ss` | `iproute2` / `iproute` | per-process bandwidth (TCP only) | Yes |
| `nmcli` | `network-manager` / `NetworkManager` | Wi-Fi details, airspace congestion | Desktop yes, server no |
| `iw` | `iw` | Wi-Fi details (fallback for `nmcli`) | Varies |

```sh
sudo apt install traceroute iw     # Debian / Ubuntu
sudo dnf install traceroute iw     # Fedora / RHEL
```

## Windows

Everything except per-process bandwidth works unprivileged. That one panel
needs an ETW session on `Microsoft-Windows-Kernel-Network` — the provider Task
Manager's own Network column reads — and Windows gates opening one.

| Feature | Unprivileged | With the ETW session |
|---|---|---|
| Latency, path monitor, DNS, throughput, vitals | full | full |
| Wi-Fi signal, channel, tx rate | full | full |
| Neighbouring networks / airspace congestion | needs Location services on | same |
| Per-process bandwidth | unavailable | full, **including QUIC and HTTP/3** |

There are two ways to get it, and the first is better:

```powershell
# Add yourself to Performance Log Users once, then sign out and back in.
net localgroup "Performance Log Users" "%USERNAME%" /add
```

After that octomon attributes traffic per process every run, unelevated. The
alternative is to start it from an elevated terminal, which works but has to be
done every time.

This is the one place Windows is *ahead* of the other platforms. Linux's `ss`
and macOS's `nettop` are both TCP-only, so QUIC and HTTP/3 — much of modern
browsing — cannot be attributed there at all. The ETW provider reports UDP too,
so an elevated Windows build sees traffic the others structurally cannot.

Wi-Fi neighbour scanning is a separate matter: it needs **Location services**
enabled (Settings → Privacy & security → Location), which is Windows' own
restriction on `WlanGetNetworkBssList`, not a privilege question. Without it the
signal reading falls back from the beacon's exact dBm to Windows' documented
quality-percentage mapping, and the congestion view goes quiet.

## What privileges would unlock


We may add an *optional* privileged mode later — strictly opt-in, never required,
and never the default. These are the things currently left on the table, and what
each would need:

| Capability | Needs | What it would add |
|---|---|---|
| Packet capture (BPF / libpcap) | root or BPF device access | Latency and loss of your *real* traffic instead of synthetic probes; per-flow and per-connection breakdown; DNS timing measured from actual queries rather than a probe |
| System-wide per-process attribution (macOS, Linux) | root | `nettop` and `ss` only report the current user's processes, so traffic from system daemons and other users is missing today. Windows already has this via ETW |
| Live per-process sampling | root / NetworkExtension entitlement | `nettop -L 1` takes ~5s per sample, which is why the Processes list updates slowly |
| Which process owns a tunnel | root | `lsof` exposes `utun` ownership, but only for root-owned VPN daemons — so VPNs are identified from the tunnel's address ranges instead |
| Neighbour SSIDs and their signal strength | Location Services permission | macOS redacts SSIDs without it, so airspace congestion counts networks per channel but cannot weight them by how loud each one is |
| True channel airtime utilisation | root (monitor mode) | Counting nearby APs approximates congestion; measuring actual airtime busy-ratio would quantify it — but monitor mode disassociates the radio |
| Raw sockets | root | ICMP traceroute rather than UDP probes, DSCP/ToS-marked probes to measure per-class queuing, and path-MTU discovery with the DF bit |
| eBPF socket tracing (Linux) | `CAP_BPF` / root | Per-socket retransmits and latency attributed to the owning process, without sampling |
| System-wide TCP state (Linux) | root | `/proc/net/tcp` and `ss` show your own sockets unprivileged; everything else needs elevation |

If any of this lands, it will be behind an explicit flag, will degrade cleanly to
the unprivileged path when it isn't available, and the unprivileged build will
stay fully functional on its own.
