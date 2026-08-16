# octomon

**A `btop`-style terminal dashboard for your network.** Think `btop`, `trippy`, and
`bandwhich` in a single view — so you can tell at a glance whether it's the
network, the Wi-Fi, the ISP, or your own machine that's misbehaving.

[![CI](https://github.com/securitypedant/octomon/actions/workflows/ci.yml/badge.svg)](https://github.com/securitypedant/octomon/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/octomon.svg)](https://crates.io/crates/octomon)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

![octomon screenshot](https://raw.githubusercontent.com/securitypedant/octomon/main/screenshot.png)

## What it shows

Four panels, all updating live. On macOS everything works unprivileged. On
Linux, plain `sudo octomon` is the path of least resistance — see
[Linux: privileges](#linux-privileges) for what needs it and why, and how to
avoid it if you would rather. On Windows everything works unprivileged except
per-process bandwidth, which is a one-time group membership away — see
[Windows: privileges](#windows-privileges):

- **Connection Quality** — ICMP latency to configurable targets with a full
  distribution (last / avg / p95 / max), **jitter**, **packet loss**, and a
  **bufferbloat** grade (latency inflation under load). Auto-discovers your
  **gateway and the next hops** on startup, can **traceroute** any target, and
  can **continuously monitor every hop** on the path (MTR-style) with per-hop
  loss, latency and an inline trace.
- **Bandwidth** — live up/down throughput, an on-demand **speed test** with a
  choice of provider (**Cloudflare / M-Lab / LibreSpeed**), and **per-process**
  talkers showing which apps are using the network (with retransmit rate and
  session totals). Speed-test history is kept and browsable.
- **Network** — interface, **connection type** (Wi-Fi / Ethernet / cellular /
  VPN tunnel), IP/DHCP, gateway, DNS, Wi-Fi SSID/PHY/channel, and a link graph
  matched to the medium: a **live Wi-Fi signal graph** (RSSI / noise / tx-rate)
  on wireless, or **link utilisation against negotiated capacity** on a cable.
  A **tunnelled default route** (Cloudflare WARP, Tailscale, WireGuard…) is
  detected and named, so missing traceroute hops and an unreachable gateway
  read as "the VPN is encapsulating the path" rather than a fault. Each **DNS
  resolver is timed** — slow DNS is invisible to ICMP but is one of the most
  common causes of "the internet feels broken" — and **Wi-Fi airspace
  congestion** counts how many nearby networks share or overlap your channel.
- **Machine** — framed only as "is my box the bottleneck?": CPU with the
  busiest core called out, **per-core meters** (full-screen), **memory
  pressure** rather than a misleading used/total, **load average**, **interface
  errors and drops** as a share of packets carried, and **thermal throttling**
  (macOS), which collapses throughput while CPU reads idle.

Any session can be **recorded to CSV** with `l` — tidy one-measurement-per-row
data that pivots straight into pandas, Excel or Grafana.

## Platform support

- **macOS** — fully supported (this is the v1 target).
- **Linux** — supported. Latency, path monitoring, DNS, throughput, machine
  vitals and recording are fully cross-platform. The platform-specific probes
  read `/proc/net/wireless` for signal, `iw dev <if> link` for Wi-Fi details,
  `nmcli` for the neighbour scan (NetworkManager's cache is readable
  unprivileged, unlike `iw scan`), and `ss -tinp` for per-process bandwidth.
  Each degrades to "unavailable" rather than failing if its tool is missing.
  Note that `ss` covers **TCP only** — UDP and QUIC traffic (much of modern
  browsing) carries no per-socket byte counters and cannot be attributed — and
  only your own processes unless run as root (see
  [Linux: privileges](#linux-privileges)).
- **Windows** — supported. Wi-Fi (signal, channel, airspace congestion) comes
  from the Native Wifi API rather than parsing `netsh`, whose field *names* are
  translated on a non-English install. Path discovery uses the built-in
  `tracert`. Power source comes from `GetSystemPowerStatus`; there is no
  thermal-throttle verdict to read, and no load average, so neither is shown.
  Per-process bandwidth needs privilege — see
  [Windows: privileges](#windows-privileges) — but it is the *only* platform
  where it covers QUIC and HTTP/3.

### Linux: external tools

octomon shells out to a few system tools. Which of these ship by default varies
sharply by distribution, so octomon probes for them at startup and tells you
what's missing and which package provides it (see `[?]` help).

| Tool | Package | Needed for | Ships by default? |
|---|---|---|---|
| `traceroute` | `traceroute` | path discovery, `[t]`, `[m]` path monitor | Debian yes (priority `standard`); **Ubuntu and Fedora no** |
| `ss` | `iproute2` / `iproute` | per-process bandwidth (TCP only) | Yes, effectively everywhere |
| `nmcli` | `network-manager` / `NetworkManager` | Wi-Fi details, airspace congestion | Fedora yes (in Core); Ubuntu/Debian desktop yes, server no |
| `iw` | `iw` | Wi-Fi details (fallback for `nmcli`) | Debian desktop yes; **Ubuntu and Fedora no** |

The ones worth installing up front are `traceroute` and `iw`:

```sh
sudo apt install traceroute iw     # Debian / Ubuntu
sudo dnf install traceroute iw     # Fedora / RHEL
```

Everything else degrades to "unavailable" rather than failing, and octomon tells
you at startup what is missing and which package provides it. Live Wi-Fi signal
reads `/proc/net/wireless` directly and needs no package at all.

### Linux: privileges

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
[Windows: privileges](#windows-privileges).)

So: fix the sysctl and run as yourself if you mainly care about latency and the
path monitor; use `sudo` if you want the full picture.

### Windows: privileges

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

## Install

### Homebrew (macOS)

```sh
brew tap securitypedant/octomon
brew trust securitypedant/octomon   # one-time: acknowledge this third-party tap
brew install octomon
```

Then just `octomon`. Upgrade later with `brew upgrade octomon`.

### Linux

Pre-built binaries are statically linked against musl, so one download runs on
any distribution — Alpine through RHEL — with no glibc-version matching.

The installer script picks the right architecture and drops the binary in
`~/.cargo/bin`:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/securitypedant/octomon/releases/latest/download/octomon-installer.sh | sh
```

Or take the tarball directly, if you would rather not pipe a script to a shell:

```sh
# x86_64 (most desktops and servers); use aarch64- for ARM machines
curl -LO https://github.com/securitypedant/octomon/releases/latest/download/octomon-x86_64-unknown-linux-musl.tar.xz
tar xf octomon-x86_64-unknown-linux-musl.tar.xz
sudo install -m755 octomon /usr/local/bin/octomon
```

Install `traceroute` as well if your distribution omits it — see
[Linux: external tools](#linux-external-tools) — and read
[Linux: privileges](#linux-privileges): on Linux you will most likely want to
run `sudo octomon`.

### Windows

Binaries are published for both x64 and ARM64. The PowerShell installer picks
the right one and puts it in `~\.cargo\bin`:

```powershell
irm https://github.com/securitypedant/octomon/releases/latest/download/octomon-installer.ps1 | iex
```

Or take the zip directly:

```powershell
# Use octomon-aarch64-pc-windows-msvc.zip on ARM64 (Snapdragon, Surface Pro X).
curl.exe -LO https://github.com/securitypedant/octomon/releases/latest/download/octomon-x86_64-pc-windows-msvc.zip
Expand-Archive octomon-x86_64-pc-windows-msvc.zip -DestinationPath .
```

The binary is unsigned, so SmartScreen will warn on first run until the release
builds reputation. Windows Terminal is recommended over the legacy console —
the box-drawing characters and glyphs render correctly there without fiddling.

Read [Windows: privileges](#windows-privileges) if you want the per-process
bandwidth panel.

### crates.io (any platform)

If you already have Rust, this works everywhere and needs no tap or installer:

```sh
cargo install octomon
```

It builds from source, so it needs a Rust 1.88+ toolchain and takes a minute or
two — the Homebrew and Linux routes above ship a prebuilt binary instead.
Upgrade later with `cargo install octomon --force`.

### From source

Requires a recent Rust toolchain (1.88+):

```sh
git clone https://github.com/securitypedant/octomon
cd octomon
cargo build --release
./target/release/octomon
```

## Usage

```sh
octomon                      # launch the dashboard
octomon -t Home=192.168.1.1  # add extra ICMP targets (repeatable)
octomon --no-speedtest       # disable the speed test
octomon --ping-interval 500  # override the ping interval (ms)
octomon --log                # start recording to CSV immediately (headless recorder)
octomon --check              # print a one-shot text snapshot and exit (no TUI)
octomon --help
```

### Keyboard shortcuts

| Key | Action |
|-----|--------|
| `Tab` / `Shift+Tab` | Cycle panel focus (forward / back) |
| `f` | Full-screen the focused panel |
| `s` | Run a speed test |
| `p` | Pause auto-refresh |
| `r` | Re-probe network info |
| `w` | Cycle the stats window (30 / 60 / 300s) |
| `n` | Move between sub-panes of the focused panel |
| `l` | Start / stop recording the session to CSV |
| `?` | Help overlay |
| `Esc` | Back out of a view / leave full-screen |
| `q` / `Ctrl+C` | Quit |
| **Navigation** | |
| `↑` `↓` (or `j` `k`) | Move the cursor |
| `PgUp` / `PgDn` | Move by ten |
| `←` `→` · `Enter` · `Space` | Move sort column · sort · toggle direction |
| `Shift+R` | Reset everything this panel has accumulated |
| **Connection Quality** | |
| `a` / `d` | Add / delete a target (add accepts an IP or DNS name) |
| `g` | Graph the selected target's latency |
| `t` | Traceroute the selected target once |
| `m` | Continuously monitor every hop to the target (MTR-style) |
| **Bandwidth** | |
| `v` | Cycle the speed-test provider (saved to config) |
| `n` | Switch between Processes and Speed Test History (full-screen) |

## Speed-test providers

`v` cycles between three providers, all working out of the box:

- **Cloudflare** — `speed.cloudflare.com`.
- **M-Lab** — NDT7 over WebSockets; a nearby server is chosen via M-Lab's
  locate service.
- **LibreSpeed** — a public server is picked automatically from the community
  server list (or point at your own with `librespeed_server`).

Each run measures download, upload, and **loaded-latency bufferbloat**, and is
saved to disk (see below).

## Configuration

On first run octomon writes a config file you can edit:

- **Config:** `~/.config/octomon/config.toml` (honours `$XDG_CONFIG_HOME`).
  Targets, ping timing, the selected speed-test provider, and endpoint URLs.
- **Data:** `~/.local/share/octomon/speedtests.jsonl` (honours
  `$XDG_DATA_HOME`). Timestamped speed-test history, one JSON object per line;
  the recent runs are shown in the full-screen Bandwidth view.
- **Recordings:** `~/.local/share/octomon/octomon-<timestamp>.csv`, written
  while recording is on. Tidy format — `timestamp,category,subject,metric,value,unit`
  — one measurement per row, so targets, hops and resolvers appearing or
  disappearing mid-session never produce a ragged file.

## How it works

Independent async collectors (Tokio) each sample on their own cadence and write
into a shared state that a Ratatui render loop draws — so a slow speed test
never stalls the UI. Latency uses unprivileged datagram ICMP (`surge-ping`);
per-process bandwidth reads `nettop`; Wi-Fi signal reads CoreWLAN directly; the
rest comes from `sysinfo` and `netdev`. Latency is validated to match the
system `ping`, so the jitter you see is the network's, not the tool's.

## Why everything runs unprivileged

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
prompt. On macOS this costs nothing — latency uses unprivileged datagram ICMP
(`SOCK_DGRAM`), path discovery uses UDP-probe `traceroute`, per-process bandwidth
uses `nettop`, and Wi-Fi comes from CoreWLAN and `system_profiler`. Every panel
is fully populated without root.

Linux is where the principle meets its limits, and it is worth being blunt about
it: unprivileged ICMP depends on a sysctl that distributions often ship closed,
and per-process bandwidth genuinely cannot see other users' sockets without
root. octomon still runs, still tells you exactly what is degraded and why, and
never silently pretends — but `sudo octomon` is the honest recommendation there.
See [Linux: privileges](#linux-privileges).

Windows sits between the two. Everything except per-process bandwidth is
unprivileged, and that one panel needs an ETW session — but the rights to open
one can be granted *once*, by joining Performance Log Users, rather than
re-elevating every run. That fits the rule better than `sudo` does: the elevated
capability is a property of the account, not of the process you launch. See
[Windows: privileges](#windows-privileges).

### What privileges would unlock

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

## Network & privacy

octomon is a read-only monitor, but as a *network* tool it does make outbound
requests. For transparency, here's everything it contacts and why:

| Endpoint | When | Why | Data sent |
|----------|------|-----|-----------|
| Your configured ICMP targets (default 1.1.1.1, 8.8.8.8, 9.9.9.9) | continuously | latency/loss | ICMP echo |
| `api.ipify.org` | once at startup | discover your public IP to add as a target | none (a GET) |
| `speed.cloudflare.com` | only when you press `s` (Cloudflare provider) | speed test | filler bytes |
| `locate.measurementlab.net` + a nearby M-Lab server | only when you press `s` (M-Lab provider) | speed test | filler bytes |
| `librespeed.org` server list + a public LibreSpeed server | only when you press `s` (LibreSpeed provider) | speed test | filler bytes |

Notes:

- **Speed tests are on-demand only** — octomon never runs them automatically, so
  it won't hammer public infrastructure.
- Third-party responses are read with a hard size cap.
- Nothing is sent to any octomon-operated service (there isn't one), and no
  telemetry is collected.
- Turn off public-IP discovery with `public_ip_url = ""`, or swap any endpoint,
  in `~/.config/octomon/config.toml`.

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). `cargo fmt`,
`cargo clippy`, and `cargo test` should all be clean (CI enforces this). Please
follow the [Code of Conduct](CODE_OF_CONDUCT.md); report security issues per
[SECURITY.md](SECURITY.md).

## License

Licensed under either of

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.
