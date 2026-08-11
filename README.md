# octomon

**A `btop`-style terminal dashboard for your network.** Think `btop`, `trippy`, and
`bandwhich` in a single view — so you can tell at a glance whether it's the
network, the Wi-Fi, the ISP, or your own machine that's misbehaving.

[![CI](https://github.com/securitypedant/octomon/actions/workflows/ci.yml/badge.svg)](https://github.com/securitypedant/octomon/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

![octomon screenshot](https://raw.githubusercontent.com/securitypedant/octomon/main/screenshot.png)

## What it shows

Four panels, all updating live, all **unprivileged** (no `sudo`):

- **Connection Quality** — ICMP latency to configurable targets with a full
  distribution (last / avg / p95 / max), **jitter**, **packet loss**, and a
  **bufferbloat** grade (latency inflation under load). Auto-discovers your
  **gateway and the next hops** on startup, and can **traceroute** any target.
- **Bandwidth** — live up/down throughput, an on-demand **speed test** with a
  choice of provider (**Cloudflare / M-Lab / LibreSpeed**), and **per-process**
  talkers showing which apps are using the network (with retransmit rate and
  session totals).
- **Network** — interface, **connection type** (Wi-Fi / Ethernet / cellular /
  VPN tunnel), IP/DHCP, gateway, DNS, Wi-Fi SSID/PHY/channel, and a link graph
  matched to the medium: a **live Wi-Fi signal graph** (RSSI / noise / tx-rate)
  on wireless, or **link utilisation against negotiated capacity** on a cable.
  A **tunnelled default route** (Cloudflare WARP, Tailscale, WireGuard…) is
  detected and named, so missing traceroute hops and an unreachable gateway
  read as "the VPN is encapsulating the path" rather than a fault.
- **Machine** — CPU and memory, framed only as a "is my box the bottleneck?"
  signal.

## Platform support

- **macOS** — fully supported (this is the v1 target).
- **Linux** — supported. Latency, path monitoring, DNS, throughput, machine
  vitals and recording are fully cross-platform. The platform-specific probes
  read `/proc/net/wireless` for signal, `iw dev <if> link` for Wi-Fi details,
  `nmcli` for the neighbour scan (NetworkManager's cache is readable
  unprivileged, unlike `iw scan`), and `ss -tinp` for per-process bandwidth.
  Each degrades to "unavailable" rather than failing if its tool is missing.
  Note that `ss` covers **TCP only**, and only your own processes — Linux has no
  unprivileged per-process byte counter (see
  [Why everything runs unprivileged](#why-everything-runs-unprivileged)).
- **Windows** — later.

### Linux: external tools

octomon shells out to a few system tools. Which of these ship by default varies
sharply by distribution, so octomon probes for them at startup and tells you
what's missing and which package provides it (see `[?]` help).

| Tool | Package | Needed for | Ships by default? |
|---|---|---|---|
| `traceroute` | `traceroute` | path discovery, `[t]`, `[m]` path monitor | Debian yes (priority `standard`); **Ubuntu and Fedora no** |
| `ss` | `iproute2` / `iproute` | per-process bandwidth | Yes, effectively everywhere |
| `nmcli` | `network-manager` / `NetworkManager` | Wi-Fi details, airspace congestion | Fedora yes (in Core); Ubuntu/Debian desktop yes, server no |
| `iw` | `iw` | Wi-Fi details (fallback for `nmcli`) | Debian desktop yes; **Ubuntu and Fedora no** |

The one worth installing up front is `traceroute`:

```sh
sudo apt install traceroute     # Debian / Ubuntu
sudo dnf install traceroute     # Fedora / RHEL
```

Everything else degrades to "unavailable" rather than failing. Live Wi-Fi signal
reads `/proc/net/wireless` directly and needs no package at all.

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
[Linux: external tools](#linux-external-tools) above.

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
| `?` | Help overlay |
| `q` / `Esc` | Quit |
| **Connection Quality** | |
| `a` / `d` | Add / delete a target (add accepts an IP or DNS name) |
| `↑` `↓` (or `j` `k`) | Select a target |
| `g` | Graph the selected target's latency |
| `t` | Traceroute the selected target |
| `←` `→` · `Enter` · `Space` | Move sort column · sort · toggle direction |
| `Shift+R` | Reset this panel's data |
| **Bandwidth** | |
| `v` | Cycle the speed-test provider (saved to config) |
| `←` `→` · `Enter` · `Space` | Sort top talkers by column |
| `Shift+R` | Reset this panel's data |

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
prompt. In practice this costs less than you'd expect — latency uses unprivileged
datagram ICMP (`SOCK_DGRAM`), path discovery uses UDP-probe `traceroute`,
per-process bandwidth uses `nettop`, and Wi-Fi comes from CoreWLAN and
`system_profiler`. Everything in the dashboard today is measured this way.

### What privileges would unlock

We may add an *optional* privileged mode later — strictly opt-in, never required,
and never the default. These are the things currently left on the table, and what
each would need:

| Capability | Needs | What it would add |
|---|---|---|
| Packet capture (BPF / libpcap) | root or BPF device access | Latency and loss of your *real* traffic instead of synthetic probes; per-flow and per-connection breakdown; DNS timing measured from actual queries rather than a probe |
| System-wide per-process attribution | root | `nettop` only reports the current user's processes, so traffic from system daemons and other users is missing today |
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
