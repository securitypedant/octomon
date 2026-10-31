# Security Policy

## Supported versions

octomon is pre-1.0; security fixes are made against the latest release and
`main`.

| Version | Supported |
| ------- | --------- |
| 0.11.x  | ✅        |
| < 0.11  | ❌ — upgrade |

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately using GitHub's **[Report a vulnerability](https://github.com/securitypedant/octomon/security/advisories/new)**
feature (Security → Advisories → Report a vulnerability). This opens a private
channel with the maintainers.

Please include:

- a description of the issue and its impact,
- steps to reproduce (or a proof of concept),
- affected version(s) and platform.

You can expect an initial acknowledgement within a few days. Once fixed, we'll
coordinate a release and credit you if you'd like.

## Scope notes

What octomon is, from a security point of view — so you can judge what a report
is about and what is by design.

**Privilege.** octomon runs unprivileged by design, never asks for a password,
and says at startup what running unprivileged costs on this machine. Started
elevated (`sudo`, an admin console, Performance Log Users on Windows) it takes
no different code path — the same calls simply see more: every process's
sockets rather than your own, and ICMP on a Linux box whose ping-socket range
is closed. Details per platform are in [PRIVILEGES.md](PRIVILEGES.md).

Two things an elevated run does differently, both because `sudo` can leave
`$HOME` pointing at the invoking user's directories (macOS does by default):
it never writes through a symlink or re-permissions a file or directory root
does not own, and it ignores an `[alert] command` from a `config.toml` root
does not own (`--alert-cmd` on root's own command line still runs). Otherwise
a link or a line planted in the user's home would have root act on it.

**Network.** octomon listens on no port and runs no service. Everything it
contacts is listed, with why and how often, in the README's
[Network & privacy](README.md#network--privacy) table: your ICMP targets, your
resolvers plus a public reference resolver, your OS's own connectivity-check
URL (also through the system proxy when one is configured), an NTP server, a
public-IP endpoint, a QUIC-speaking host for the path-MTU probe, the
speed-test provider you pick, and — on request — RDAP/RIPEstat for "who owns
this address" and a short list of reference hosts for the outbound port scan
(a TCP handshake or one datagram each). All HTTP goes over rustls; direct
probes are built with proxy support off so a shell `https_proxy` cannot
silently reroute them, and the one probe that deliberately uses the system
proxy says so. One deliberate exception to strict TLS: the per-target web
probe (a `HEAD /`, no body read, redirects not followed) tolerates certificate
errors, because it times the handshake to an IP literal and sends nothing.
Nothing is sent to any octomon-operated service and there is no telemetry.
When a container runtime is present, octomon also reads its local API over
the Unix socket or named pipe (`DOCKER_HOST`/`CONTAINER_HOST`, else the usual
Docker, Podman, Colima, OrbStack, Rancher Desktop and Lima paths), read-only
and two endpoints: the container list and one-shot stats. A `tcp://` endpoint
is never used, and `containers = false` in config.toml turns the whole thing
off; on Linux the same figures come from `/proc` without the socket.

**Local files.** octomon writes, under the XDG / `%APPDATA%` directories,
`config.toml`, `speedtests.jsonl`, `baselines.json`, `history.jsonl`,
`net_history.jsonl`, `whois.log`, `errors.log`, event exports and support
bundles on request, and CSV recordings while recording is on (see
[Configuration](README.md#configuration)). The baselines, history and
recordings contain your SSID, gateway, addresses and process names. On unix,
files are created owner-only (0600) in owner-only directories (0700), and a
startup pass tightens anything an older version wrote under the umask; the
directory named by `--config` is left with whatever mode it had. Windows
inherits the profile directory's ACL and octomon sets nothing further. A
config.toml that does not parse is never rewritten, and config and baselines
are written to a temporary file and renamed into place.

**Subprocesses.** octomon runs standard system tools as child processes,
each executed directly with a fixed argument array — never through a shell,
so nothing is subject to word-splitting or `sh -c` interpolation: `traceroute` (`tracert` on
Windows), `whois`, `ps`, `iperf3`, and per platform `nettop`, `pmset`,
`system_profiler`, `scutil --proxy`, `ipconfig getoption`, `netstat` (macOS),
`iw`, `nmcli`, `ss`, `ip route`, `gsettings` (Linux) or `reg query` (Windows).
Dynamic arguments are IP-address literals and interface names from the OS,
with two exceptions from your own `config.toml`: `discovery_probe`, the host
traced at startup, and an iPerf3 server's host. Children abandoned on a
timeout are killed, not left running. The one shell octomon ever starts is
the alert hook: `[alert] command` (or `--alert-cmd`) is your own string, run
as written through `sh -c` (`cmd /C` on Windows), and the alert's text — which
can carry an SSID or hostname this machine did not choose — reaches it only
through `OCTOMON_*` environment variables, never substituted into the
command. Desktop notifications (`osascript`, `terminal-notifier`,
`notify-send`, `powershell`) likewise get the text as an argument or an
environment variable, not as script.

**Untrusted input.** Responses from third-party endpoints are read under a
hard size cap while streaming, so an oversized body is never held in memory.
Hand-built protocol clients (DNS, NTP, the QUIC probe) validate lengths and
transaction ids before trusting a reply.
Text that arrives from the environment — SSIDs, registry records, process
names, captive-portal redirects — is control-character-stripped (bidi
overrides included) before it reaches a terminal, in the TUI, in `--check` /
`--doctor` output, and in every `--watch` and alert line alike. Error log
entries name a webhook by host only, never the full URL.

**`--doctor` redaction.** The default report masks your SSID, own addresses,
public IP, gateway, MACs and LAN-side resolvers so it can be pasted into a
forum or ticket; `--full` prints everything. Addresses of hops beyond your
gateway are kept — they are the useful part of an ISP ticket — so a report is
"safe to paste" in the sense of not naming you or your LAN, not anonymous.
