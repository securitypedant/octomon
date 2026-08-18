# octomon

**A `btop`-style terminal dashboard for your network.** Think `btop`, `trippy`, and
`bandwhich` in a single view — so you can tell at a glance whether it's the
network, the Wi-Fi, the ISP, or your own machine that's misbehaving.

[![CI](https://github.com/securitypedant/octomon/actions/workflows/ci.yml/badge.svg)](https://github.com/securitypedant/octomon/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/octomon.svg)](https://crates.io/crates/octomon)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

![octomon screenshot](https://raw.githubusercontent.com/securitypedant/octomon/main/screenshot.png)

## What it shows

Four panels, all updating live — plus, as of v0.5.0, **an actual answer**. A
**verdict line** at the bottom of the screen synthesizes everything octomon
measures into one headline ("`▲ gateway unresponsive — likely (+1 more)`" or
"`● connection healthy`"), and it never bluffs: press **`y`** ("why") for the
**triage ladder** — every subsystem from your machine outward (machine → link →
gateway → DNS → ISP path → internet → web → destinations) with its status *and
the data behind it*, healthy rungs included. Simultaneous causes are all
reported and ranked; a busy CPU is never allowed to hide a dead gateway, and a
VPN is called out as a caveat on everything measured through it.

Supporting that verdict:

- **Per-network baselines** — octomon learns what *normal* looks like on each
  network you use (gateway latency, DNS, signal, speed-test results), keyed by
  a location fingerprint (SSID + gateway MAC), learned only from healthy
  minutes so an incident never poisons the baseline it's judged against. Name
  the current network with **`N`** ("Home", "Office") and the analysis reads
  "gateway 41ms vs ~9ms normal at Home"; **`L`** lists every stored location
  and its learned normals. Everything stays on your machine.
- **Event timeline** (**`e`**) — the retroactive answer to "what happened
  during that call ten minutes ago?": verdict findings raising and clearing
  (with durations), network/SSID/DNS changes, VPN up/down, speed-test results,
  all timestamped. Also drained into the CSV recording.
- **HTTP reachability** — ICMP can be perfect while browsing is broken, so
  octomon also probes a connectivity-check endpoint the way a browser would,
  once per address family. Detects **captive portals** ("open the sign-in
  page"), **web-blocked-while-ping-works** (proxy/firewall), and **broken IPv6
  with working IPv4** — the classic "pages stall then load". Defaults to your
  OS's own check endpoint (zero new parties learn you're online) and verifies
  any failure against a second, independent provider before raising a finding.
- **Doctor mode** — `octomon --doctor` observes headless for ~20 seconds
  (tune with `--observe SECS`, add `--speedtest` for a full workup) and prints
  the analysis, this network's learned normal, the raw measurements and recent
  events; `--json` emits the same report for machines. **Redacted by default**
  (SSID, IPs, MACs masked; ISP-side hop detail kept) so it's safe to paste
  straight into a forum post or ISP ticket — `--full` prints everything. Exit
  codes for scripting: `0` healthy, `1` problems found, `3` couldn't measure.

The four panels — everything below works unprivileged on macOS; Linux and
Windows each hold one thing back, covered in [Privileges](#privileges):

- **Connection Quality** — ICMP latency to configurable targets with a full
  distribution (last / avg / p95 / max), **jitter**, **packet loss**, and a
  **bufferbloat** grade (latency inflation under load). Auto-discovers your
  **gateway and the next hops** on startup, can **traceroute** any target, and
  can **continuously monitor every hop** on the path (MTR-style) with per-hop
  loss, latency and an inline trace.
- **Bandwidth** — live up/down throughput, an on-demand **speed test** with a
  choice of provider (**Cloudflare / M-Lab / LibreSpeed**), and **per-process**
  talkers ranked by bytes moved this session (down/up/share, current rate and
  retransmits) — or, with `n`, the same traffic **by remote address**, so
  the one host eating your link stands out, and can be whois'd (`W`) or added
  as a ping target (`a`) on the spot. Speed-test history is kept and browsable.
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
  [privileges: Linux](PRIVILEGES.md#linux)).
- **Windows** — supported. Wi-Fi (signal, channel, airspace congestion) comes
  from the Native Wifi API rather than parsing `netsh`, whose field *names* are
  translated on a non-English install. Path discovery uses the built-in
  `tracert`. Power source comes from `GetSystemPowerStatus`; there is no
  thermal-throttle verdict to read, and no load average, so neither is shown.
  Per-process bandwidth needs privilege — see
  [privileges: Windows](PRIVILEGES.md#windows) — but it is the *only* platform
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

## Privileges

octomon runs unprivileged by design, and tells you at startup what that costs on
your machine. The short version:

| Platform | Unprivileged | To get everything |
|---|---|---|
| macOS | everything | nothing to do |
| Linux | latency often needs a one-line sysctl; per-process bandwidth sees only your own processes | open the ping-socket range once, and `sudo octomon` for the full process view |
| Windows | everything except per-process bandwidth | join Performance Log Users once |

Per-platform detail, the exact commands, and the reasoning behind the design:
**[PRIVILEGES.md](PRIVILEGES.md)**.

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
[privileges: Linux](PRIVILEGES.md#linux): on Linux you will most likely want to
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

If the charts come out as rows of empty boxes, the console is using a font with
no braille glyphs — the raster fonts legacy `conhost` still defaults to have
none, and note that an elevated window keeps its own font setting separately
from an ordinary one. Either switch the font to Consolas or Cascadia Mono, or
plot with block glyphs instead by setting this in
`%APPDATA%\octomon\config.toml`:

```toml
graph_marker = "halfblock"
```

Read [privileges: Windows](PRIVILEGES.md#windows) if you want the per-process
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
| `p` | Pause the display (collection continues; cursors, whois etc. still work) |
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
| `W` | Who owns the selected address (target or hop) — RDAP/whois lookup |
| **Bandwidth** | |
| `v` | Cycle the speed-test provider (saved to config) |
| `n` | Cycle the lower panes: processes → remote addresses → Speed Test History (full-screen; a wide terminal shows both talker tables at once) |
| `W` / `a` | Whois the selected remote address / add it as a target |

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
