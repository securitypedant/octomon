# Security Policy

## Supported versions

octomon is pre-1.0; security fixes are made against the latest release and
`main`.

| Version | Supported |
| ------- | --------- |
| 0.6.x   | ✅        |
| < 0.6   | ❌ — upgrade |

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

**Local files.** octomon writes, under the XDG / `%APPDATA%` directories,
`config.toml`, `speedtests.jsonl`, `baselines.json`, `history.jsonl`, event
exports on request, and CSV recordings while recording is on (see
[Configuration](README.md#configuration)). The baselines, history and
recordings contain your SSID, gateway, addresses and process names. Files are
created with your umask; octomon does not tighten their permissions.

**Subprocesses.** octomon runs standard system tools as child processes,
each executed directly with a fixed argument array — never through a shell,
so nothing is subject to word-splitting or `sh -c` interpolation: `traceroute` (`tracert` on
Windows), `whois`, `ps`, and per platform `nettop`, `pmset`, `system_profiler`,
`scutil --proxy` (macOS), `iw`, `nmcli`, `ss`, `gsettings` (Linux) or `reg
query` (Windows). Dynamic arguments are IP-address literals, with one
exception: `discovery_probe`, the host traced at startup, is passed as written
in your own `config.toml`.

**Untrusted input.** Responses from third-party endpoints are read under a
hard size cap while streaming, so an oversized body is never held in memory.
Hand-built protocol clients (DNS, NTP, the QUIC probe) validate lengths and
transaction ids before trusting a reply.
Text that arrives from the environment — SSIDs, registry records, process
names, captive-portal redirects — is control-character-stripped before it
reaches a terminal, in the TUI and in `--check` / `--doctor` output alike.

**`--doctor` redaction.** The default report masks your SSID, own addresses,
public IP, gateway, MACs and LAN-side resolvers so it can be pasted into a
forum or ticket; `--full` prints everything. Addresses of hops beyond your
gateway are kept — they are the useful part of an ISP ticket — so a report is
"safe to paste" in the sense of not naming you or your LAN, not anonymous.
