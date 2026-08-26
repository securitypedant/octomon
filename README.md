# octomon

**A `btop`-style terminal dashboard for your network.** I got sick of having
to use multiple tools to diagnose network issues, so I built this. Think `btop`,
`trippy`, and `bandwhich` in a single view, so you can tell at a glance 
whether it's the network, the Wi-Fi, the ISP, or your own machine that's the problem.

[![CI](https://github.com/securitypedant/octomon/actions/workflows/ci.yml/badge.svg)](https://github.com/securitypedant/octomon/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/octomon.svg)](https://crates.io/crates/octomon)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

![octomon screenshot](https://raw.githubusercontent.com/securitypedant/octomon/main/screenshot.png)

▶️ **[Watch the intro video](https://www.youtube.com/watch?v=sHPd2LeYvaw)** — why octomon exists and a tour of what it does.

## What it shows

Four live panels plus **an actual answer**: a one-line analysis at the bottom
of the screen ("`▲ gateway unresponsive`" or "`● connection healthy`"), and
**`y`** for the **triage ladder** behind it — every subsystem from your machine
outward (link → gateway → DNS → ISP path → internet → web → destinations) with
its status and the data behind it, healthy rungs included. Simultaneous causes
are all reported; a symptom (DNS timing out because the gateway is dead) is
ranked below its cause rather than shouting over it, and a busy CPU or a VPN is
a caveat, never a way to hide a fault. Every finding shows how long it has been
going on.

Things it checks:

- **Not connected at all** — no default route, a self-assigned 169.254 address
  (no DHCP lease), an address with no gateway: named as such, not blamed on
  whatever failed first downstream.
- **Captive portals**, **web blocked while ping works**, **IPv6 broken while
  IPv4 works** (and where along the way it breaks), the mirror case, and a
  **system web proxy** — detected, and the web check repeated through it, so
  "browsers work but direct doesn't" reads as the network it is.
- **DNS honesty, not just speed** — a public reference resolver probed
  alongside yours (yours failing while it works means "switch DNS"; it failing
  while yours work means this network forces its own), and a once-a-minute
  check that non-existent names come back NXDOMAIN rather than an ad page.
- **System clock skew** via NTP (HTTPS breaks while every network measurement
  is fine), **CGNAT / double NAT** read off the first hops, **path-MTU black
  holes** where the OS lets it be measured, and **outbound port filtering**
  (`c`): SSH, mail, DNS-over-TLS, NTP, QUIC, each against a host that answers.
- **Per-network memory** — a learned *normal* for each network you use (name
  it with `N`, list them with `L`), and a persistent **incident history**, so
  the report can say "worse than usual here" and "3 outages this week,
  clustering 20–23h".
- **Event timeline** (`e`, export with `x`) and a **network history** of every
  join, roam, address, route and VPN change (full-screen Network panel, `n`).
- **Doctor mode** — `octomon --doctor` observes headless for ~20 s and prints
  the analysis, this network's normal, its history, the measurements and recent
  events; `--json` for machines. Redacted by default (SSID, IPs, MACs) so it is
  safe to paste into a forum or ISP ticket; `--full` prints everything. Exit
  codes: `0` healthy, `1` problems found, `3` couldn't measure.

The panels:

- **Connection Quality** — ICMP latency to configurable targets (last / avg /
  p95 / max), jitter, loss, and a bufferbloat grade — plus the same columns
  measured over TCP connects to port 443 (`i` toggles; full screen shows both),
  which keep working on networks that blackhole ping. Auto-discovers the gateway
  and next hops, traceroutes any target (`t`), and monitors every hop on a path
  MTR-style (`m`) with per-hop loss and latency; `W` asks who owns any address.
- **Bandwidth** — live throughput, an on-demand speed test (`s`) with a choice
  of provider (Cloudflare / M-Lab / LibreSpeed), and per-process talkers or the
  same traffic by remote address (`n`). Speed-test history is kept.
- **Network** — interface, connection type (Wi-Fi / Ethernet / cellular / VPN
  tunnel), addresses, gateway (v4 and v6), DNS with each resolver timed, Wi-Fi
  SSID/channel/signal graph and airspace congestion, and — only when notable —
  the proxy, clock, path MTU and NAT rows above.
- **Machine** — "is my box the bottleneck?": CPU with the busiest core, memory
  pressure, load, interface errors, thermal throttling.

Any session can be **recorded to CSV** with `l`.

## Platform support

- **macOS** — everything works unprivileged. Path MTU cannot be measured
  (the OS fragments regardless of the Don't-Fragment flag on unprivileged
  sockets); octomon says so rather than guessing.
- **Linux** — supported. Wi-Fi details use `iw` / `nmcli`, per-process
  bandwidth uses `ss` (TCP only, and only your own processes unless root).
  Latency often needs a one-line sysctl; see [PRIVILEGES.md](PRIVILEGES.md).
- **Windows** — supported. Wi-Fi via the Native Wifi API, path discovery via
  `tracert`, per-process bandwidth via ETW (needs a one-time group membership;
  see [PRIVILEGES.md](PRIVILEGES.md)). Path MTU is not measured yet.

### Linux: external tools

octomon probes for these at startup and tells you what's missing and which
package provides it (see `[?]` help):

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

## Privileges

octomon runs unprivileged by design and never asks for a password; it tells you
at startup what that costs on your machine.

| Platform | Unprivileged | To get everything |
|---|---|---|
| macOS | everything | nothing to do |
| Linux | latency often needs a one-line sysctl; per-process bandwidth sees only your own processes | open the ping-socket range once, and `sudo octomon` for the full process view |
| Windows | everything except per-process bandwidth | join Performance Log Users once |

Detail, commands and reasoning: **[PRIVILEGES.md](PRIVILEGES.md)**.

## Install

### Homebrew (macOS)

```sh
brew tap securitypedant/octomon
brew trust securitypedant/octomon   # one-time: acknowledge this third-party tap
brew install octomon
```

### Linux

#### apt (Debian & Ubuntu)

Signed repository at [octomon.dev](https://octomon.dev), amd64 and arm64:

```sh
curl -fsSL https://octomon.dev/apt/octomon.gpg | sudo tee /usr/share/keyrings/octomon.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/octomon.gpg] https://octomon.dev/apt stable main" | sudo tee /etc/apt/sources.list.d/octomon.list
sudo apt update && sudo apt install octomon
```

#### Installer script (any distribution)

Static musl binaries run on any distribution. The installer picks the right
architecture and drops the binary in `~/.cargo/bin`:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/securitypedant/octomon/releases/latest/download/octomon-installer.sh | sh
```

Or take the tarball directly:

```sh
# x86_64 shown; use aarch64- for ARM machines
curl -LO https://github.com/securitypedant/octomon/releases/latest/download/octomon-x86_64-unknown-linux-musl.tar.xz
tar xf octomon-x86_64-unknown-linux-musl.tar.xz
sudo install -m755 octomon /usr/local/bin/octomon
```

Install `traceroute` if your distribution omits it, and read
[privileges: Linux](PRIVILEGES.md#linux).

### Windows

Binaries for x64 and ARM64. The PowerShell installer puts the right one in
`~\.cargo\bin`:

```powershell
irm https://github.com/securitypedant/octomon/releases/latest/download/octomon-installer.ps1 | iex
```

Or take the zip directly (`octomon-aarch64-pc-windows-msvc.zip` on ARM64):

```powershell
curl.exe -LO https://github.com/securitypedant/octomon/releases/latest/download/octomon-x86_64-pc-windows-msvc.zip
Expand-Archive octomon-x86_64-pc-windows-msvc.zip -DestinationPath .
```

The binary is unsigned, so SmartScreen warns on first run. Windows Terminal is
recommended.

### crates.io / from source

```sh
cargo install octomon            # needs Rust 1.88+
# or
git clone https://github.com/securitypedant/octomon && cd octomon && cargo build --release
```

## Usage

```sh
octomon                      # launch the dashboard
octomon -t Home=192.168.1.1  # add extra ICMP targets (repeatable)
octomon --no-speedtest       # disable the speed test
octomon --ping-interval 500  # override the ping interval (ms)
octomon --log                # start recording to CSV immediately (headless recorder)
octomon --check              # print a one-shot text snapshot and exit (no TUI)
octomon --demo               # real measurements, fake MACs/addresses/SSIDs — safe to screen-record
octomon --doctor [--json] [--full] [--speedtest] [--observe SECS]
octomon --help
```

### Keyboard shortcuts

| Key | Action |
|-----|--------|
| `Tab` / `Shift+Tab` | Cycle panel focus |
| `f` | Full-screen the focused panel |
| `n` | Move between sub-panes of the focused panel |
| `s` | Run a speed test |
| `p` | Pause the display (collection continues) |
| `r` | Re-probe network info |
| `w` | Cycle the stats window (1 / 5 / 15 min) |
| `l` | Start / stop recording the session to CSV |
| `y` | Connection analysis: the triage ladder and findings |
| `e` | Event timeline; `x` inside it exports the events to a CSV in the config folder |
| `M` | Drop a marker into the event timeline ("moved rooms", "call just dropped") |
| `c` | Scan outbound ports (which protocols this network lets out); `r` inside it rescans |
| `T` | The OS routing table, verbatim (split tunnels, VPN `0.0.0.0/1` overrides, a missing default); `r` inside it re-reads |
| `?` | Help |
| `Esc` | Back out of a view / leave full-screen |
| `q` / `Ctrl+C` | Quit |
| **Navigation** | |
| `↑` `↓` (or `j` `k`) · `PgUp` / `PgDn` | Move the cursor · by ten |
| `←` `→` · `Enter` · `Space` | Move sort column · sort · toggle direction |
| `Shift+R` | Reset everything this panel has accumulated |
| `Ctrl+R` | Total reset: erase **all** octomon config and stored data (baselines, history, speed tests) — asks you to type `ERASE` to confirm |
| **Connection Quality** | |
| `a` / `d` | Add / delete a target (add accepts an IP or DNS name) |
| `i` | Toggle the stats between ICMP and TCP connect (`:443`) — full screen shows both side by side |
| `g` | Graph the selected target's latency |
| `t` | Traceroute the selected target once |
| `m` | Continuously monitor every hop to the target (MTR-style) |
| `W` | Who owns the selected address (target or hop) — RDAP/whois |
| **Bandwidth** | |
| `v` | Cycle the speed-test provider (saved to config) |
| `n` | Processes → remote addresses → speed-test history (full-screen) |
| `W` / `a` | Whois the selected remote address / add it as a target |
| `d` | Delete the selected speed test from the history (full-screen history pane) |
| `z` | Zoom the active table to 80% of the screen: every column, full names/addresses, per-process pid + path + command line, per-test server + network |
| **Network** | |
| `N` | Name this network ("Home", "Office") |
| `L` | Saved network locations, their normals and incident history |
| `f` then `n` | Full-screen: DNS graphs, and the network history pane |

## Speed-test providers

`v` cycles between **Cloudflare** (`speed.cloudflare.com`), **M-Lab** (NDT7,
nearest server via M-Lab's locate service) and **LibreSpeed** (a public server
from the community list, or your own via `librespeed_server`). Each run
measures download, upload and loaded-latency bufferbloat, and is saved.

## Configuration

On first run octomon writes a config file you can edit:

- **Config:** `~/.config/octomon/config.toml` (honours `$XDG_CONFIG_HOME`;
  `%APPDATA%\octomon\` on Windows). Targets, timings, endpoints, the reference
  resolver, the NTP server, the egress-scan list.
- **Light terminals:** octomon asks the terminal its background colour at
  startup and adapts. If yours guesses wrong, set `theme = "light"` (or
  `"dark"`) in the config, or pass `--theme light` for one run.
- **Data** (`~/.local/share/octomon/`, honours `$XDG_DATA_HOME`):
  `speedtests.jsonl` (speed-test history), `baselines.json` (each network's
  learned normal), `history.jsonl` (finished incidents per network, kept 90
  days), and `octomon-<timestamp>.csv` recordings while recording is on.

## Network & privacy

octomon only measures — it changes nothing on the network and listens on no
port — but as a *network* tool it does make outbound requests. Everything it
contacts, and why:

| Endpoint | When | Why | Data sent |
|----------|------|-----|-----------|
| Your ICMP targets (default 1.1.1.1, 8.8.8.8, 9.9.9.9, octomon.dev), plus the gateway and first hops found by a startup `traceroute` toward `discovery_probe` | continuously | latency/loss | ICMP echo |
| Your ICMP targets, over HTTPS | every 5 s | is the web service up (HEAD, no body, no redirects, certificate errors tolerated — a timing probe) | a `HEAD /` |
| Your anchor targets, TCP port 443 | every second | connect-time latency/loss that works where ICMP is blocked (a handshake, closed immediately; no data sent) | a TCP handshake |
| `octomon.dev/edge` (`edge_check_url`) | at startup, on network change, then every 15 min | how the Cloudflare edge sees this connection: serving PoP, your ISP's AS, the edge's own TCP RTT to you | a GET with octomon's User-Agent; the endpoint stores nothing about you — see [octomon.dev/privacy](https://octomon.dev/privacy) |
| Your system's DNS resolvers, and the reference resolver (`dns_reference_resolver`, default 1.1.1.1) | every 5 s; once a minute a random non-existent name | resolver latency; hijack check | one A query for `dns_probe_name` (default `example.com`) |
| Your OS's own connectivity-check URL (`captive.apple.com`, `msftconnecttest.com` or `connectivity-check.ubuntu.com`), and through the system proxy when one is set | every 12 s | HTTP reachability, captive-portal detection, clock skew fallback | a GET |
| `time.cloudflare.com` (`ntp_server`) | at startup, then every 15 min | is the system clock right | one NTP packet |
| `1.1.1.1:443` (QUIC) | once after startup / network change | path-MTU probe (Linux) | padded QUIC version-negotiation packets |
| `api.ipify.org` | once at startup and on network change | discover your public IP to add as a target | none (a GET) |
| `rdap.org` (→ ARIN, RIPE, APNIC, LACNIC, AFRINIC) and `stat.ripe.net`; the system `whois` as fallback | only when you press `W` | who owns that address / which ASN announces it | the address you asked about |
| `github.com:22`, `smtp.gmail.com:25/465/587`, `imap.gmail.com:993`, `cloudflare.com:80/443`, `1.1.1.1:53/853/443` (`egress_checks`) | only when you press `c` | which ports this network lets out | a TCP handshake or one datagram; nothing further |
| `speed.cloudflare.com` · `locate.measurementlab.net` + an M-Lab server · `librespeed.org` list + a LibreSpeed server | only when you press `s` | speed test | filler bytes |

Notes:

- Speed tests and the port scan are on-demand only.
- Third-party responses are read with a hard size cap, and text that arrives
  from outside (SSIDs, registry records, process names) has control characters
  stripped before it reaches your terminal.
- The only octomon-operated endpoint is `octomon.dev/edge`, which exists
  purely to deepen the monitoring: it returns your connection's edge view *to
  you* and **stores nothing about you** — no logs, no identifiers. The single
  thing it counts is requests per octomon version, and that count is
  published, in full, at [octomon.dev/privacy](https://octomon.dev/privacy) —
  the only dashboard that exists. Set `edge_check_url = ""` to never call it.
  No other telemetry of any kind is collected.
- Turn any of it off or point it elsewhere in `config.toml`: `public_ip_url`,
  `discovery_probe`, `dns_reference_resolver`, `ntp_server` (`""` disables),
  `http_probe_provider`, `egress_checks`, `edge_check_url`.
- The CSV recordings, baselines and history include your SSID, gateway and
  addresses; treat them as you would any other file about your network.

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
