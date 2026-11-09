---
title: Changelog
description: Every octomon release, newest first, with what changed and why.
---

Every release since the first one, newest first. Each version is also a
[GitHub release](https://github.com/securitypedant/octomon/releases) with
binaries for macOS, Linux and Windows. From 0.12.0 on, each release is also
run against real VPN clients before it ships; the results are on the
[testing page](/testing).

## 0.12.1 · I built a simple testing rig that allows me to configure several different VPN clients and test octomon to correctly identify them, also I had one container test faults and that octomon correctly discovers them. Results of [testing here](/testing). While building the rig, I found some bugs... which is kinda the point!

- A full-tunnel VPN no longer comes back as a second location with the same label. The network underneath a full tunnel is identified by its gateway's MAC address, read from the neighbour cache, and under a full tunnel nothing keeps that entry alive: octomon's own gateway pings have no gateway to go to, and a WireGuard peer on the LAN never touches the router at all. Once the entry had aged out the location keyed on the gateway's IP instead, so "172.19.0.1 via WireGuard 10.13.13.2" existed twice, one copy per state of the cache. octomon now resolves the gateway itself (one UDP datagram to the discard port, no privilege needed) before it reads the MAC. Found by the [VPN test rig](/testing), which now also runs Cloudflare WARP.
- Latency is judged against the location's learned normal, not only against the session's own best. octomon compared each path's recent latency with the lowest it had seen this session, so a session started while the network was already slow had nothing to compare with: a gateway at 272 ms sat green beside "~0 ms normal here" in its own ladder detail. An established normal is now a second floor, and the finding says which one it compared with ("gateway latency inflated (272ms vs ~0ms normal here)"). First visits to a network are judged as before.
- Pings that stop being answered on a network that normally answers them are a note, not an outage. Every ping unanswered while the web check and TCP to every built-in target succeed is a firewall or router policy, and on a network with no learned normal octomon already said so; on a network whose normal was clean it still raised "gateway unresponsive" as down, with exit code 1, while its own ladder said ICMP was blocked and web traffic crossed the gateway. It now says "pings stopped being answered on this network", with web and TCP traffic noted as unaffected, as information.
- A DNS outage is one finding, not two. The web check resolves a hostname like a browser does, so when every resolver is dead it fails too, and that failure was read as a second fault, "web traffic blocked while ping works", blamed on a proxy or firewall: a story that sent people looking at the wrong thing. octomon now tells a connection that was refused from a name that never resolved ("name lookup failed" in the ladder), and a lookup failure beside dead resolvers is the DNS finding's own evidence. A lookup that fails while the resolvers answer octomon's direct queries is reported for what it is: this machine's resolver path (a local stub, search domains), not the network's DNS and not a firewall.
- A dead resolver that the OS asks first is a degradation, not a footnote. Applications wait on the first resolver's timeout before the next is tried, so with it dead every lookup is seconds late and pages stall, while octomon said "1 of 2 resolvers failing, others fine" and, when the web check ran out of time, blamed a firewall. It now names the resolver ("first DNS resolver 100.100.100.100 not answering: every lookup waits on its timeout, fd7a:115c:a1e0::53 works") with the web timeout as its evidence, and the same for a LAN resolver asked first. A dead resolver the OS never waits on stays a footnote. Found by the rig with Tailscale's MagicDNS beside a wg-quick tunnel: wg-quick's policy rule swallows the v4 route to MagicDNS, a real conflict on real machines.
- VPN clients are also recognised by the resolvers they configure. A client that pushes its own DNS writes it into the system's resolver list when it connects and takes it back when it disconnects, which says the client is active in a way a resident process cannot: NordVPN's 103.86.96.100, Cloudflare WARP's 127.0.2.2, Tailscale's MagicDNS at 100.100.100.100, Mullvad's 10.64.0.1, Proton's 10.2.0.1, Surfshark's, PIA's and Windscribe's. It is the third witness beside the tunnel's address and the running clients: it confirms a match in a shared or private address block, breaks a tie between two resident clients, and stands in when no process is visible. Like the process table it is narrowed by the tunnel's own addresses, so Tailscale's resolver never names a WireGuard tunnel beside it. Resolvers a server pushes (OpenVPN, WireGuard, corporate clients) and resolvers networks use on their own (Cloudflare Gateway's 172.64.36.x) are not in the table.
- `--doctor --json --full` reports the location's key beside its label, the identity the learned normal is filed under. It names the gateway, which is why it is a `--full` field.
- Cloudflare WARP is recognised without its IPv6 address. Over the WireGuard protocol (consumer WARP, and Zero Trust organisations that do not assign each device its own local IP) every WARP device's interface is 172.16.0.2; the 100.96/12 address octomon knew is on the interface only under MASQUE or with that setting on. octomon named WARP from the 2606:4700 v6 beside it, so with IPv6 off the device would have fallen to "unidentified VPN / tunnel". 172.16.0.2 now counts for WARP the way a private block counts for any client: only with its daemon running or its resolvers in use.
- The VPN test rig covers more: Tailscale beside a WireGuard tunnel, with and without MagicDNS as the system resolver, Cloudflare WARP as a consumer (172.16.0.2) and enrolled in a Zero Trust organisation (a per-device 100.96/12 address), each also with its IPv6 flushed, a plain GRE tunnel with no client (the unnamed-tunnel case), a "crowded" machine with NordVPN, WARP, Tailscale, wg-quick and OpenVPN all installed and their daemons resident while one tunnel at a time, or two, is connected, and a fault-injection client that breaks its own network eight ways (loss, latency, DNS, web, ICMP, the internet, a captive portal) and checks the analysis. The analysis fixes above came out of it, and it asserts on the resolvers it sees under NordVPN, WARP and Tailscale. The [testing page](/testing) now records the latest run only, a statement of what the current release was checked for, instead of a history of runs.

## 0.12.0 · 2026-11-07

The largest outside contribution so far. jrelax ran octomon across several WireGuard tunnels on Linux and macOS, audited how it handles files, panics and `sudo`, and sent the fixes as one pull request (#37). This release is that work plus what came out of reviewing it in detail. Thank you, jrelax. One consequence to know about up front: some locations get new identities and are learned again, see the first point.

- Two VPN configs used from one network are now two locations. A full-tunnel location was keyed on the network underneath plus the vendor's name, so every WireGuard config connected from home was "home via WireGuard" and they shared one name and one normal. A WireGuard config carries its own fixed address, so WireGuard locations, full and split, now key on it as well: "192.168.1.1 via WireGuard 10.9.8.10". Nothing else keys on an address. OpenVPN and every corporate client hand out an address from a pool per session, so OpenVPN keys on its vendor, and a VPN octomon cannot name is one "VPN" per network, whatever device or address it has (macOS renumbers `utunN` on every connect, and the old key followed it, so the same VPN was a new location each time). A gateway whose MAC netdev reports as all zeros is treated as unknown and the gateway IP keys the location instead; before, every full tunnel with such a gateway shared one location. Re-keyed and learned afresh: full-tunnel WireGuard, unidentified tunnels, full tunnels behind an all-zero gateway MAC, and NetworkManager WireGuard on Linux (the next point). The old entries stay in the locations list until deleted, and the list now helps you find them: each entry says how long ago it was seen ("seen 3 days ago", "not seen for 5 months") and anything unseen for 90 days is marked `stale`.
- Linux tunnels are recognised by what the kernel says they are, not by their name. NetworkManager names a WireGuard device after the connection (`home`, `Trevor`), which no name test can match, so a full tunnel through it was taken for a plain link: `--doctor` said "has an address but no gateway" and exited 1 on a working connection. octomon now asks sysfs: `DEVTYPE=wireguard`, a `tun_flags` file, or a PPP, GRE, SIT or IP-in-IP type. A kernel WireGuard device is named "WireGuard" unless a vendor's own address block names it, or exactly one running client that drives kernel WireGuard (NordVPN, Mullvad, Proton, PIA, Surfshark, Windscribe) can claim it. A client running for some other reason, Tailscale for instance, never lends its name, and tunnel naming in general now works by elimination: a vendor whose address blocks the tunnel is not in is out of the running. Zscaler, whose /16 sits inside the 100.64.0.0/10 space Tailscale and WARP also use, was shown as Tailscale; a running Zscaler client wins that match now. The vendor cache is keyed on each tunnel's addresses as well as its device name, because macOS hands a freed `utunN` to whichever VPN connects next and the old name stuck.
- A tunnel octomon cannot name gets one clue in the Network panel: "unidentified VPN / tunnel · exit via Datacamp Limited", the operator the edge sees the connection arrive from. It is a hint beside the row, never the vendor and never part of the location, since the exit changes with the server.
- A collector that panics is restarted instead of ending silently. Each collector was a bare task whose handle was dropped, so a panic froze its panel, and a panic in the analysis loop stopped a `--watch` from alerting. Now the crash goes to `errors.log` and the timeline and the collector restarts after 5, 15 and 45 seconds; a fourth crash stops it for the session and the panel it feeds says so in its title (`Machine · stopped: vitals`). Every panic, in every mode and on every thread, is logged with its thread and file:line, and a panic off the UI thread no longer tears the dashboard out of the alternate screen. When the previous session crashed internally, the next start says so once, in a notice on the dashboard or one line under `--watch`, and asks for the log to be attached to an issue. These are octomon's bugs, not the network's.
- Two copies of octomon on one machine no longer lose each other's writes. A dashboard and a `--watch` started together both saved `baselines.json` through one shared temporary file, so one rename failed and the last save dropped the network the other had just learned. History appends and rewrites, speed-test history, the `errors.log` roll and every `baselines.json` load-edit-save now take a lock on a sidecar `.<name>.lock` file, through the standard library's file locking. One process at a time saves what it learns about a network (the first to take `.baselines.json.learner.lock`; the others watch and learn for their own session), a save keeps the stored name so a watcher cannot undo a rename made in the dashboard, a file that does not parse is moved aside to the first free `.corrupt` slot rather than over an earlier copy, and a file that exists but cannot be read is learned in memory and not saved, with the timeline naming the file and the fix. History files are pruned hourly during long runs, not only at startup.
- `sudo octomon` no longer leaves the user's own files owned by root. macOS keeps `$HOME` under `sudo`, and because every write goes through a temporary file and a rename, one elevated save turned baselines, history and config root-owned, and later unprivileged runs could not read or write them. Files octomon creates or rewrites under its own directories are handed back to the invoking user, every check made through the open file descriptor, and only when those directories sit inside that user's home: Linux's default `sudo`, which sets `HOME=/root`, writes under `/root` and hands nothing back, quietly. Only what the elevated run itself created is given away, never a file that was already there: a rule the pre-release security audit asked for, since root chowning whatever it found in octomon's directory would have let a user take ownership of a root-owned file by renaming it in. Files an older version's `sudo` run left root-owned are therefore not repaired on sight; the next unprivileged run says so once at startup and gives the `chown` to run. SECURITY.md describes the design.
- `--demo` hides a public tunnel address wherever a location label is quoted: the locations list, stored speed tests, and the events and network history written by earlier sessions.
- On Ubuntu 26.04 path discovery found no hops. The release makes GNU inetutils' traceroute the `traceroute` alternative, ranked above the real one even when both are installed, and inetutils rejects `-n`. octomon now runs `/usr/bin/traceroute.db`, the Linux traceroute's own name on Debian and Ubuntu, when it exists.
- The `/edge` call octomon makes carries the build's platform alongside the version: one of `macos-arm64`, `macos-x64`, `windows-x64`, `windows-arm64`, `linux-x64`, `linux-arm64`, or `other`. The [privacy page](/privacy.html) shows the split next to the version graph, and its wording now reads "version, platform, reason and count only". The Worker memoizes the stats an hour per isolate instead of querying Analytics Engine on every hit, and the page says "loading" or "the query is failing" instead of "no requests yet" when that is what is happening.
- The Windows exe now carries version information, a manifest and the icon. The release exe had no resource section at all, and a bare PE is one of the cheap signals Defender's cloud classifier weighs; it flagged 0.11.4 and 0.11.9 as `Trojan:Win32/Bearfoos.A!ml`. This does not replace a signature, but it removes one reason to look like malware and gives Explorer, Task Manager and the firewall prompt a proper name. I really want to get proper code signing, but can't afford it right now.
- Build and CI: `rust-version` is 1.95, which the locked dependencies already required. sysinfo 0.40 and netdev 0.47; on Windows the load average now reads as unsupported rather than as zeros. Every GitHub Action is pinned to a commit SHA, `release.yml` is generated by dist and CI checks it stays that way, the Worker's tests run in CI, and the Debian packaging workflow refuses a ref that is not a release tag.

## 0.11.9 · 2026-11-02

Four fixes, three of them for VPNs and Wi-Fi reporting the wrong thing, and one for a probe that was impacting the measurements. Thanks to squidly and Wlodarski for the detailed reports and for testing the builds.

- A split tunnel beside the link is no longer taken for the link (issue #27). With a FortiGate or similar corporate VPN up, octomon reported the tunnel (`ppp0`) as the link, found no gateway, learned the location as "via VPN" and fired VPN up/down on every reconnect, while internet traffic never touched the tunnel. The cause was how the default interface was chosen: by routing to 10.254.254.254, an address a tunnel pushing 10.0.0.0/8 claims. octomon now picks the link by routing a public address in the same way `ip route get` works. A tunnel that carries only its own routes is a new kind of entry, "split tunnel: openfortivpn (ppp0), only its own routes go through it", in the Network panel, `--doctor` and the JSON output. It comes and goes on the timeline as an interface event, and it is left out of the location identity, so a VPN reconnect doesn't reset the stats. Full tunnels and WARP-style split tunnels keep their existing behaviour. openfortivpn joins the vendor table.
- On Windows the Wi-Fi line said every network was 20MHz wide, and the congestion count treated every neighbour as 20MHz too (issue #26). The Native Wifi API gives only the primary channel, so the bonded width is now read from the beacon information elements each network carries: 40MHz from HT, 80 and 160 from VHT, 6GHz widths from HE, 320 from EHT. The value refreshes within a minute of the access point changing it, as soon as Windows next hears the beacon. octomon never asks the radio to scan, on any platform, because a scan takes it off-channel and would show up in the latency figures.
- On a Mac on Wi-Fi, octomon was inflating its own latency readings. The Wi-Fi details probe ran `system_profiler` every minute, and that command scans for about 18 seconds, so for a third of every minute the gateway median went from 4ms to 20ms with spikes past 200ms. The details now come from CoreWLAN, which the signal graph already used: channel, width, band, PHY mode, signal and rate from the interface, and the neighbour list from the scan cache macOS keeps for roaming and the Wi-Fi menu. No scan is requested and the probe takes no air time. The ping test with the new probe is back at the control level. `system_profiler` leaves the tools list, `ipconfig getsummary` joins it to name the SSID. Also: `r` now reliably wakes the Wi-Fi collector (it shared a notifier with the network collector and only one of them woke), and `--check` no longer waits 17 seconds for the probe.
- The Bandwidth graph no longer shows about double the real rate with some VPNs (issue #19). When neither the link nor the adapter under it has counters, octomon sums every adapter, and with a VPN up that counted the same bytes twice: in the clear on the tunnel and encrypted on the adapter beneath. The sum now leaves out tunnel-named adapters, and the tunnel name list gains the Windows aliases it lacked: `WireGuard Tunnel`, `OpenVPN Wintun`, `Mullvad`, `ZeroTier One`. Loopback was also skipped by a test that never matched Windows's `Loopback Pseudo-Interface 1`; it does now.

## 0.11.8 · 2026-10-30

Containers join the processes table and a fix for a terminal that cannot draw the dashboard due to font issues.

- Docker and Podman containers are now talkers. Each running container is a row of the Bandwidth panel's processes table, named `app (docker)`, with total, down, up and share columns, and everything that works on a process row works on it: sort, the `/` filter (typing `docker` keeps every container), pin, follow, the stacked graph and the zoom, whose detail line shows the container's id, image and, on Linux, init pid. The figures are the container's own interface counters, so they say how much it moved and not to who. Container rows never appear in the remote-addresses table, and octomon does not split the bytes across connections by guesswork.
- On Linux this needs no root and we see every user's containers. A container's processes name it in `/proc/<pid>/cgroup` and its namespace's counters are in `/proc/<pid>/net/dev`, both world-readable; the inode of that file identifies the namespace, so two containers sharing one (`--network container:X`, a pod) count once and a host-network container, whose counters are the host's, is skipped. Without the runtime's socket the row carries the short container id.
- Names and images come from the Docker or Podman API when its Unix socket or Windows named pipe is reachable (`DOCKER_HOST` and `CONTAINER_HOST` first, then the Docker, Podman, Colima, OrbStack, Rancher Desktop and Lima paths; never `tcp://`). On macOS and Windows, where the containers live in a VM, the API also supplies the counters. Two read-only endpoints, the container list and one-shot stats, each a few milliseconds. `containers = false` in config.toml turns it off; `container_socket` names an endpoint. One caveat on a Mac: the VM's own process (`com.docker.backend`) carries the same bytes on the host side, so the share column counts container traffic twice, it's mentioned in the FAQ.
- A container starting or stopping is a timeline event, and a finding that raises within a minute of one says so ("8 seconds after container media (docker) started"), as it already does for a Wi-Fi roam or a VPN coming up. The Machine panel and `--doctor` carry a presence line, `containers 3 running · docker`, so an idle box still shows that detection worked, and processes.csv in the support bundle gains a `container_id` column. The speed-test load attribution reads the same table, so a container uploading during a test is named in the finding without any further work.
- `--observe` takes a time with a unit: `90s`, `15m`, `1h`, up to an hour (bare seconds still work). `octomon --observe 15m --doctor` is now the report to paste when asking for help, in the README, the howto page and the bug-report template: twenty seconds catches a hard fault and misses the intermittent one the person is asking about.
- A terminal that is not in UTF-8 mode is called out at startup, in the notice bar, the timeline and errors.log, with the fix in the message. An xterm started from an X session without `LANG` decodes every border as three Latin-1 letters and the layout collapses; nothing in octomon can fix that from the inside, but it can say what is wrong. xterm with a good locale gets a softer hint about its default bitmap font, which has box drawing but no braille or block glyphs.
- `#` switches the graphs between the fine glyph set (braille line charts, eighth-block bars) and a plain set every monospace font has, and saves the choice. For the fonts that draw the graphs as boxes.

## 0.11.7 · 2026-10-24

A security release reviewing the whole codebase using Cloudflare's [security audit skill](https://github.com/cloudflare/security-audit-skill). No changes to what octomon measures; it changes what it does with files, with input text, and when it runs as root.

- Dependencies: rustls-webpki 0.103.16 and webpki-roots 1.0.11, for RUSTSEC-2026-0381 and 0382 (published this week): the previous versions could accept a certificate chain through an intermediate that has [since been distrusted](https://blog.cloudflare.com/emudhra-certificate-compromise/). Every HTTPS check octomon makes goes through this code, so this is the reason for the release. Also tokio 1.53.3, which closes the unsound-API advisory RUSTSEC-2026-0386 (an API octomon does not call), plus serde_json 1.0.154 and zip 9.0.4.
- `--config` with a path whose file does not exist yet no longer makes the file's directory owner-only. Before, `sudo octomon --config /etc/octomon.toml` on a first run would have set `/etc` to mode 0700.
- Run as root with the invoking user's home directory (what `sudo` does by default on macOS), octomon no longer follows symlinks when it writes or re-permissions files in its config and data directories, and ignores an `[alert] command` from a config file root does not own. A link or a line in a user's home could otherwise have had root act on it. `--alert-cmd` on the command line still runs.
- The alert webhook URL no longer appears in the errors.log when a delivery fails; only its host does. Error log lines are echoed into the `--doctor` report and the support bundle, and a Slack or Discord hook URL is the credential. A config.toml that does not parse is likewise logged by message, without quoting the offending line.
- Every `--watch` line and alert notification has control characters and bidi overrides removed, as `--check` and `--doctor` already did. The network name on an alert is the SSID when the location has no name of its own, and an access point can call itself anything, including a terminal escape sequence.
- Three HTTPS clients (the per-target web probe, the speed test, and the webhook) now ignore a shell `https_proxy`, as the rest already did. Through a proxy the web probe timed the proxy's CONNECT rather than the target, and the speed test measured the proxy.
- `--demo` disguises the network name stored with each past speed test. The Bandwidth panel showed the real SSID there while hiding it everywhere else.
- A config.toml with a syntax error is left alone. Before, octomon ran on defaults (as logged) and the next change made from the keyboard ([a], [v], [I], or dismissing the first-run explainer) wrote those defaults back over the file, so a typo cost every hand-made setting. The same for baselines.json: a file that does not parse is moved aside to `baselines.json.corrupt` instead of being overwritten with only the current network. Both files are now written to a temporary file and renamed into place, so a crash mid-write cannot leave a truncated one.
- Traceroute, path-monitor, discovery, whois and iperf3 children are killed when octomon stops waiting for them. A traceroute that outlived its timeout used to keep running to its own end.

## 0.11.6 · 2026-10-18

Some minor quality of life improvements. Bandwidth graph now reflects what's being filtered, event entry when the monitored path changes, and a word at startup when a newer octomon is out.

- The Bandwidth graphs follow the `/` filter. When filtering processes
or remote targets, their respective bandwidth is now highlighted
on the bandwidth graph with the current total still displayed, but dimmed.
- When the path monitor's minute-by-minute re-walk finds the route changed, it now records an event which shows on the timeline (e).
- When a newer octomon is out, the startup version check now says so in a notice over the dashboard.

## 0.11.5 · 2026-10-16

While writing the [technical paper](/blog/technical-paper/), I re-evaluated some decisions and found some bugs.

- The ISP path rung no longer sits grey saying "no path monitor" while the hop rows it needed were in the table all along. Without a monitor it grades hops 2 to 4 from the rows discovery found at startup, with the built-in targets standing in as the far end, and the detail ends "[m] for every hop". Start a monitor and it reads the whole path instead. It is grey only when discovery found no answering hop past the gateway.
- The same rung grades the IPv4 and IPv6 paths apart. A bug caused the v6 twins of the hop rows to be counted as extra hops, so the detail read "hops 2-7" on a three-hop path, and a v6 hop that dropped every probe could be excused as "silent" because a v4 hop beyond it answered. Now each family has its own path and its own far end. The rung takes the worse of the two and names v6 in a clause, so a v6-only fault reads as one.
- Interface errors are judged as a share of frames over the last 20 seconds, and only once 100 frames have crossed the link in that window. One corrupted frame among fifty on an idle link used to read as 2% for that second and flash the link rung red. The lines now differ by medium, because the counters mean different things: a wire is amber from 0.1% and red from 1%, since a healthy cable runs at zero; Wi-Fi is amber from 2.5% and red from 5%, since radios count decryption failures and edge-of-range frames as errors. Cable errors have their own cause, "wired link", so the history and the alert JSON no longer call an Ethernet fault "Wi-Fi". The errs row says "too few frames to rate" on a quiet link instead of a percentage of nothing, and the report's `link_error_pct` is null until there is enough to rate.
- Machine stats had too much power over the analysis. Thermal throttling was a degraded finding on its own, and as the only finding it painted the footer amber on a warm laptop, or on Windows whenever battery saver was on. A capped CPU can hold a speed test or an encrypted tunnel below line rate, but it does not lose or delay packets, so it is now a note, "cpu held back by the OS", like the other machine notes. The machine rung goes red only when the CPU is pegged and the machine is also swapping or held back: then the three notes collapse into one degraded finding, "machine saturated", because a pegged CPU is the one machine condition that disturbs the network readings themselves.
- The edge check shows the network's AS number even when Cloudflare has no operator name for the prefix. Over IPv4 some prefixes carry the number only, and the missing name used to take the number with it. When the v6 answer names the same AS, that name is used for both.
- Dependencies: rustls 0.23.46 and zip 9.0.1, for the advisories published this week (RUSTSEC-2026-0346 to 0349 and 0367 to 0369). octomon never extracts an archive, so the zip findings did not reach it; the rustls ones concern the HTTPS client, so the update matters.

## 0.11.4 · 2026-10-05

What is eating the CPU.

- Machine panel, full screen: the busiest processes, up to ten, with CPU and memory, beside the summary lines. `←`/`→` pick the cpu or mem column and `Enter` sorts by it or flips the direction, as in the talkers tables. The CPU figure is per core, the convention of Activity Monitor, top and htop, so it reads the same as the tool you would check it against. The "machine under load" finding names the busiest three, and the doctor and bundle text carry them too.
- Three more lines under the gauges in full screen: octomon's own footprint (so a monitor on a struggling machine can show it is not the problem), the connection count (remotes active now, remotes seen this session, processes talking), and the uptime.

## 0.11.3 · 2026-09-26

The bandwidth graph behind a VPN on Windows, a leaner demo mode, and octomon on winget.

- The Bandwidth graph drew a few bars and then sat at zero for the whole session when NordVPN was up on Windows. The tunnel adapter that holds the default route has no byte counters under the name the network probe reports, and the collector counted nothing at all. It now reads the physical adapter underneath the tunnel, which carries the same bytes encrypted, and falls back to summing every adapter only when that is missing too. Each step down is logged once, and shows on the Machine panel's errs row.
- `--demo` rewrites the gateway and the first three hops and leaves the rest of a path alone. A backbone router in another city places nobody, and the far path is what a traceroute demo is showing. Private and carrier-grade NAT addresses are still rewritten at any distance.
- `--demo` now rewrites the public IPv6 address. It lives in its own field, unlike the public IPv4, and was the one address the disguise missed. `--demo-mac` gives it the same EUI-64 check as the local addresses.
- Windows: `winget install SimonThorpe.Octomon`. The package is in the winget community repository and each release submits its version bump automatically.
- Website: the install cards no longer come out in two sizes on iOS, and the hero stays centred on very wide displays.

## 0.11.2 · 2026-09-12

The session bar describes your connection, never the targets you added.

- A target you added is always a note, whatever it does. "Unreachable, your connection is fine" used to be a degradation, which painted the footer and the session bar amber while saying the connection was fine. Only a built-in anchor going unreachable still reads as a caution about the path, and only that turns the destinations rung red; your own targets make it amber at most.
- A quiet host whose web service answers is up. 0.11.1 read a never-pinged host as "unreachable" when its HTTPS probe succeeded, the wrong way round: three identical game servers gave two quiet notes and one degradation. The web answering is now evidence it is up, just quiet. A host whose site answered and has since gone dark still reads as gone.

## 0.11.1 · 2026-09-12

Your own targets no longer vote on whether the internet is up.

- Only the built-in anchors (1.1.1.1, 8.8.8.8, 9.9.9.9) decide "internet unreachable beyond the gateway". Targets you add are judged one at a time against that consensus. Found in the field: three Fortnite servers that never answer ICMP out-voted the anchors into "internet unreachable (3 of 6 anchors failing)" while the game played on. If you have removed every built-in anchor, your own targets stand in as before.
- A target that has never answered a ping on this network reads "doesn't answer pings, your connection is fine" as a note, not "unreachable" as a degradation: game servers, cloud VMs and load balancers routinely ignore ICMP. The destinations rung lists them under "never answered pings" and stays amber. A target that answered and then stopped is still a red disappearance.
- The performance grade is the anchors' median again: a host that was never going to answer no longer drags loss to 100% and the grade to poor.

## 0.11.0 · 2026-09-04

Filtered is not down, and IPv6 measured end to end.

- A network that drops every ping while the web works is no longer "degraded but usable": the ping-driven claims are dropped, the ladder says "not measurable" where it reported 100% loss, the Internet and destinations rungs are judged on the TCP 443 probes, and the footer is green. "Degraded but usable" is reserved for partial loss.
- Port 443 failing to every anchor is a state of its own, whatever pings and plain HTTP are doing. The connectivity check is plain HTTP on purpose (captive portals live there), so a rule blocking only 443 used to leave every rung green. Now: "HTTPS blocked on this network, port 80 still answers, port 443 does not".
- An egress monitor: while port 443 is dead everywhere, HTTP, QUIC, SSH, NTP and DNS are probed every 5 s against reference hosts to tell a filtered network from a dead one. It announces itself on the timeline both ways, has its own row in the analysis, and the Connection Quality table can show its rows (`i` cycles icmp, tcp, egress). The finding names the ports: "web blocked on this network, SSH, NTP and DNS get out; HTTP and QUIC blocked". `egress_monitor = false` turns it off.
- Two reference resolvers, 1.1.1.1 and 8.8.8.8 (`dns_reference_resolvers`; the old single key is migrated). Either answering proves the Internet path is up when pings and the web are not, and a network that assigns 1.1.1.1 as its own resolver no longer leaves octomon without a reference.
- IPv6, when the interface holds a global address: the built-in targets' v6 twins pinged and handshaked on 443 under their v4 rows, the v6 router as "gateway v6", a second traceroute for the v6 path, the public IPv6 address beside the v4 one, the path-MTU probe per family (a real reading on macOS for the first time, since v6 never fragments on path), the edge check per family, and five v6 rows in the port scan. An "IPv6" row in the analysis reads "works end to end", "address but no route", or "ICMPv6 filtered", and "IPv6 broken while IPv4 works" now says whether the break is at the router or beyond it. `probe_ipv6 = false` drops all of it.
- "IPv6 broken while IPv4 works" through a VPN tunnel is a note, not a degradation: a tunnel that carries only v4 is how it is built.
- The path-MTU probe speaks QUIC on UDP 443; silence at every size behind a 443 block used to read as a black hole and now reads "not judged".
- `t` and `m` on a v6 target work on macOS (traceroute6) and say `-6` on Linux and Windows.
- A middle hop that answered the walk but never answers a probe, while a later hop does, reads "silent" rather than 100% loss, with no red bars.
- avg, p95 and max are windowed by probes, not by successes: under heavy loss they no longer freeze on old replies. A lost link greys every row at once.
- The events timeline opened from the session bar brackets the episode's entries with dashed rules and a gutter block to aid readability.
- The Connection Quality title says "spread" where it said "sd"; the hop table's address column fits v6 addresses.
- Website: a how-to page, FAQ entries on ICMP blackholes and on what happens when pings and the web both fail, and a glossary entry for spread.

## 0.10.1 · 2026-08-30

A release of nothing but the session bar.

- The bar is the whole row at every age: stretched while the session is younger than the terminal is wide, rather than growing in from the right, and with no gray stub at the left for the seconds before the analysis can say anything.
- The cursor holds a moment, not a column. The bar shifts and recompresses every second the session grows, so a column index came to point at different seconds than the ones it was put on. It also covers its whole cell, steps by cell, and keeps its place through a zoom.
- Getting around: `[` and `]` jump to the next change of color, Home and End reach the session's start and now, and `z` zooms to the hour around the cursor. "The last hour" is then just zooming at the right-hand end, with no second mode to explain.
- Enter opens the episode, not the seconds under the cursor. The bar grades every second by the state standing at the time, while the timeline records only the moments that state changed, so asking a solidly amber stretch for details used to produce "nothing was recorded here". Each cell now keeps the finding behind it. The timeline cap rose to 1000 entries.
- Switching a VPN on no longer punches holes in the bar. That resets every probe window, and those seconds are octomon re-establishing its own footing, not the connection failing: the bar holds its state through them and only draws a gap once one outlasts the settling.

## 0.10.0 · 2026-08-29

Alerts for when nobody is watching, and a session bar you can walk.

- `--watch` runs headless until Ctrl-C or SIGTERM, printing each finding as it raises and again when it ends.
- `--alert` notifies the desktop, `--alert-cmd` runs a command, `--alert-url` POSTs JSON. Any combination, in watch mode or under the dashboard, persisted under `[alert]` in the config. Alerts fire from the analysis engine's own raise and clear transitions, so they inherit its hysteresis and flap grace. The payload reaches a command through the environment and a notifier through argv, never substituted into a script: a finding's summary can carry an SSID this machine did not choose.
- A finding that raises seconds after a Wi-Fi roam, a VPN coming up or the network moving now says so, on the timeline, in the analysis and in alerts. Correlation stated as correlation: when it started, not why.
- The latency graph stops lying during an outage. History held only successful probes, so the line froze on the last good reading and then spliced the two sides of an outage together until the gap had no width at all. Losses now hold their slot: the line breaks, the floor goes red for as long as nothing answers, and the title says how long. The same fix reaches the hop traces, the DNS traces and the web strip.

## 0.9.8 · 2026-08-28

The command line reaches the whole config, `--bundle` for scripts, and a `--help` you can read.

- `--bundle [PATH]` writes the `Shift+D` support zip from a script. It observes on the same window `--doctor` uses, so the capture holds real measurements rather than an empty session, then prints the path and nothing else, which is what makes `zip=$(octomon --bundle)` work.
- `--paths` prints where the config, data folder, error log and bundles live. That is the question behind every "edit your config" and "send me errors.log", and the answer moves with the platform and the XDG variables.
- New overrides: `--config` for a second profile, `--iperf3 NAME=host[:port]` for a run-only server, `--speedtest-provider`, `--ping-timeout`, `--bandwidth-units`, plus `--no-discovery` and `--no-edge`, which the README already documented as things you could only do by editing a file.
- A config named with `--config` is loaded differently from the default one: a missing file is still created, but a broken one is fatal rather than a silent fall back to defaults, which would look exactly like the file had been honored.
- `--help` advertised 15 options against a config file with 27 settings. It now covers all of them, grouped into Modes, Report options, Overrides, Turn things off and Screen recording, because a flat list of 22 is a wall.
- The DNS honesty check gets a website FAQ entry: why octomon looks up a name that cannot exist, and why a hijacking resolver is invisible to every other measurement.

## 0.9.7 · 2026-08-28

A lint fix, so the tagged source passes its own gate on Windows.

- `-D warnings` failed on both Windows runners: the mode block is `cfg`'d to unix, so the binding it mutates is never mutated there and `unused_mut` fires. The 0.9.6 binaries are unaffected, since a build is not a lint, but the tagged source did not pass CI, so this supersedes it rather than leaving that on crates.io.

## 0.9.6 · 2026-08-28

Security and privacy hardening: everything octomon stores is now owner-only.

- Every file octomon writes describes someone's network, so all of it is mode 0600 in 0700 directories: config, baselines, both histories, whois.log, errors.log, the session CSVs, the event export and the `Shift+D` bundle. Files an older version wrote under the umask are tightened at startup, since a creation mode does nothing for what is already on disk.
- `--demo` and `--demo-mac` drop process command lines. Both modes exist so a screen can be recorded, and argv is the one thing on show that routinely carries a secret outright. The path and user stay: they answer "what is this?" and name nothing.
- CSV fields starting with `=`, `+`, `-` or `@` are defused. A process name comes from whatever is running and an SSID from whoever owns the nearest access point, so a recording opened in a spreadsheet could otherwise run a formula that arrived in a beacon.
- whois.log is bounded: trimmed at 8 MB back to 6 MB on entry boundaries, which is tens of thousands of lookups. Cutting a byte count off the end lands mid-character on UTF-8 registry records, so the cut walks forward to a boundary first.
- The doctor report masks the home directory. The error log's "full log:" line and events naming an export had been dragging the account name into output advertised as safe to paste into a forum.
- Discovery re-checks the network sequence after every await, not only after its backoff sleeps: a traceroute started on the old network could otherwise land its hops minutes later, after the new network's walk had cleared them. A flapping network is now bounded to one live task instead of one per flap.
- The README is a third shorter. The shortcut table drops to essentials and points at `?`, which is exhaustive and cannot drift: it had gone stale on the pause key, the stats windows and a binding that no longer exists.

## 0.9.5 · 2026-08-27

The `/` talkers filter is per-table.

- Filtering processes no longer narrows the remotes, and vice versa.

## 0.9.4 · 2026-08-27

A talkers filter, a sortable split, and dates in the locations overlay.

- `/` filters both talkers tables live (process name or pid, remote address, port or process). Enter keeps the filter, Esc clears it. The panel title carries the filter, an empty match says so, and the support bundle's CSVs deliberately ignore it.
- The zoom's `now↑` column joins the sort cursor's walk, which had skipped it, and a combined `now↕` column brings the compact table's total rate back, sortable like the rest.
- The locations overlay dates every entry, in the slot "current" occupies on the active network.
- A paused session syncs the parked sort, column, zoom view and filter, so those keys respond while the display is frozen.

## 0.9.3 · 2026-08-27

The Network panel's edge row names the colo city.

- "MIA (Miami)" was in the analysis but the panel kept the bare code. Both show it now, pinned by a draw test.
- The Homebrew trust step joined the website's install block.

## 0.9.2 · 2026-08-27

Update mentions, a provider column that fits, TTFB in the glossary.

- `/edge` now carries the latest released version, and the client mentions it once, on the timeline and in the help title, when a newer build exists. It never acts on it.
- The zoomed speed history gives iPerf3 names a provider column they fit in.
- The website glossary explains TTFB.

## 0.9.1 · 2026-08-27

Speed history in human units, and the first public build of the 0.9.0 work.

- The history and zoom tables show compact speeds (943M, 1.2G) under bare arrow headers, and the zoom detail line says Gb/s where it earns it. A loopback iPerf3 run no longer prints 111718.8.

## 0.9.0 · 2026-08-27

iPerf3 servers as first-class speed-test providers. Tag and crates.io only: the release build was cancelled before any binary went public, so 0.9.1 above is the first version you could install.

- iPerf3 providers: add with `I` (Name=host[:port]), remove with `V`, cycle with `v`, and run against hardware you control. Live rates stream from iperf3's own per-second interval lines, because interface counters lied whenever the test did not cross the default interface, loopback most of all. Finals read the receiver summary, and every throughput surface adapts its units up to Gb/s.
- Sortable TCP columns and provably aligned dividers in the full-screen quality table, and per-cell grading in the Path table.
- Exact scroll clamping, a routing-table scrollbar, and a tidied locations overlay with readable speeds.
- An isp row, and a colo that names its city ("MIA (Miami)").
- Available memory drawn over the cpu history.
- A bufferbloat reading no longer votes against minutes of clean evidence.

## 0.8.2 · 2026-08-26

A fleet estimate, with no identifiers.

- Every `/edge` call names its reason with one of three constant labels (start, netchange, refresh) that every client sends identically, so the label links nothing to anyone. Refreshes tick every 15 minutes, which turns public call counts into an honest census of how much octomon is running.
- The graph on /privacy draws that over the version bars, with the math stated so anyone can recompute it from the same public data. The worker stores the reason as a second blob and nothing else.

## 0.8.1 · 2026-08-26

The quality panel names both probe families everywhere.

- The split view's title always says which family it is showing (`· icmp` or `· tcp :443`), the full-screen dual table labels the ICMP group with its own divider to match, and the Path panel says "Path · icmp".

## 0.8.0 · 2026-08-26

TCP metrics beside ICMP, the /edge check, and a public privacy dashboard.

- A second probe family: TCP connects to port 443 at ping cadence give last, avg, p95, max, jitter and loss that keep working where ICMP is blackholed. `i` toggles the split view between families, and a network with no ICMP defaults to TCP. Full screen shows both families side by side, and the max columns yield first on narrow terminals.
- Baselines learn tcp-connect and web-TTFB normals per location, and the performance grade uses TCP while ICMP is blind ("latency 12ms (tcp)").
- The /edge check: octomon.dev/edge answers with the Cloudflare edge's view of this connection, meaning the serving PoP, the ISP's AS, and the edge's own TCP RTT measurement of the client. It shows as an "edge" row in the Network panel and an analysis check, which also flags a public-IP disagreement. On by default, and `edge_check_url = ""` never calls it.
- The endpoint stores nothing about callers: no logs, no identifiers. The one thing counted is requests per octomon version family, and that count is published in full at [octomon.dev/privacy](/privacy), the only dashboard that exists.

## 0.7.7 · 2026-08-26

VPN locations know the network underneath, honest gateway labeling, light-mode teal.

- A VPN is its own location per underlying network. Split tunnels key the LAN's identity plus the vendor ("HomeNet via Cloudflare WARP"), and full tunnels find the gatewayed physical interface beneath the tunnel and key on that ("10.90.0.1 via Cloudflare WARP"). Home-via-WARP and hotel-via-WARP have different uplinks and exit PoPs, so they must not share a normal.
- Discovery no longer labels whatever answered at TTL 1 as "gateway". A hotel whose gateway stays silent puts the first answering hop upstream at a carrier router, and a VPN's walk starts at the vendor's edge. Both contradicted the Network panel and fed a stranger's router into the gateway baseline. TTL 1 earns the label only when it matches the routing-table gateway or sits on the private side.
- Cyan text, focused borders, key hints and the latency series render as dark teal on light backgrounds, because cyan on white was unreadable.

## 0.7.6 · 2026-08-26

WARP on Windows detected, per-VPN locations, the routing table, light terminals.

- Tunnel detection now checks the adapter's friendly name, because Windows reports the GUID as the name and "CloudflareWARP" was invisible, plus a heuristic for a MAC-less unknown adapter carrying a known VPN address. This kills the false "has an address but no gateway, nothing routes off the LAN" finding on WARP.
- Full-tunnel VPNs are their own location, keyed per vendor: one stable "Cloudflare WARP" or "NordVPN" entry across reconnects, exit servers and utun renumbering. Split tunnels keep the physical network's identity.
- Networks that blackhole ICMP read as "no ICMP" in the locations overlay instead of an eternal dash, and the quality panel title notes that web works.
- `Shift+T` shows the OS routing table verbatim as a global overlay, and support bundles include routes.txt.
- Light-background terminals: octomon asks the terminal its background (OSC 11, with a COLORFGBG fallback) and swaps the light-on-dark ramp for dark-on-light roles. `theme` in config and `--theme` override it.
- Quality-table stats dash out during a total outage instead of freezing at their last green values, and the title says the target is not answering.
- The VPN vendor list grew ExpressVPN, Surfshark, PIA, Windscribe, Zscaler and FortiClient.

## 0.7.5 · 2026-08-26

The octomon mark greets you on the welcome screen.

- Half-block art of the mark (green dome and legs, amber sixth leg, red eyes) sits left of the first-run welcome text on terminals 100 columns and wider. Narrower terminals keep the text-only layout.

## 0.7.4 · 2026-08-26

The VM feedback batch: site-local IPv6, weather baselines, live table colors.

- `fec0::/10` (site-local, as used by UTM and QEMU NAT) no longer counts as global IPv6, so there is no false "IPv6 broken" finding and the v6 probe reads n/a.
- Baseline fold gate: findings that skew nothing never block learning, and non-latency Degraded findings standing 10 minutes or more are the location's weather and fold in full. Poor-but-working connections finally establish a normal.
- The performance grade lets bufferbloat vote only while the speed test is under 5 minutes old, so a stale reading no longer pins "poor" under green rungs.
- The ISP path rung tells the truth when the monitor runs but early hops are ICMP-silent, instead of claiming no monitor exists.
- Loss figures honor the stats window everywhere. The outcome ring held only 100 probes, so every loss read as "last 1m40s" no matter what the header said.
- Per-cell grading in the quality table, and a marker on loss that is draining out of the window after recovery.
- The stats window ladder is 30s / 1m / 5m / 15m, defaulting to 30s.
- winget: portable-zip manifests and a post-release publish workflow.

## 0.7.3 · 2026-08-25

An absolute performance grade, a positional talkers cursor, and network history that persists.

- A performance line in the analysis and the footer: the same measurements graded on an absolute scale, blind to the location's learned normal. Latency, jitter and loss across anchors, plus speed-test bufferbloat, worst component wins. The [FAQ](/understand) explains the thresholds.
- Steady findings keep their finding but drop the "for 3m 12s" timer that just counted uptime on an always-on VPN.
- A network or VPN switch now opens an 8-second settling grace, so losses from the switchover are dropped and loss starts at 0% instead of reading around 30% and trickling down.
- VPN gateways teach the baseline again: the sampler resolves the gateway target the way the analysis does, instead of missing it behind the tunnel's own routing-table address.
- A jitter column in the target table, with the Path panel's columns reordered to match. Enter flips sort direction on repeat.
- The talkers cursor is positional: it holds its row while the sort re-ranks, and `o` follows the row under the cursor.
- Pause moved to `Shift+P` globally, and `p` and `u` pin everywhere including zooms.
- Every address in the Network panel is selectable and whois-able, and whois results append to whois.log in the data directory, riding into support bundles.
- Network history persists across sessions, capped and self-compacting.

## 0.7.2 · 2026-08-25

Ctrl+R erases everything octomon has learned.

- Ctrl+R, global and available from overlays, erases all config and stored data (the config directory, baselines, incident history, speed tests and session CSVs) after you type ERASE to confirm. In-memory learned state clears immediately, and a restart completes the fresh start.
- Also ships the post-0.7.1 fix: `d` deletes the selected speed test while the history is zoomed.

## 0.7.1 · 2026-08-25

Analysis learns what normal looks like at each location, and judges against it.

- Degraded but usable: an ICMP outage claim folds to a note when the web check proves traffic still flows, which is what plane and hotel Wi-Fi actually look like. That unlocks baseline learning on always-lossy networks.
- Baselines learn loss (gateway and anchor) alongside latency, and loss grading is relative with absolute floors, like RTT.
- The fold gate is refined so incidents only block the numbers they skew: latency-congested or loaded minutes fold latency-blind instead of never.
- One latency reference everywhere: a p10 usual-best floor feeds the table, the rungs and the findings, and the Internet rung grades latency rather than just loss.
- Access-link consensus: uniform inflation blames the shared first hop, with own-load attribution (quiet, busy or loaded, naming the top talker) and the location's episode-cluster history cited when the pattern recurs.
- The path-MTU black hole is gated on loss to the probe target, because loss is not MTU.
- `z` zooms the active talkers table across the bottom band: full names and addresses, pid, exe path, command line, user, parent and start time, on all platforms.
- Talker tables lead with a flexed name column and default-sort by "now", and `bandwidth_units` chooses bytes or bits.
- Each speed-test result records the network, the medium and the serving server, the history pane gains a detail block, and `d` deletes an unwanted result.
- Also: `Shift+M` event markers, DNS graphs colored per bar, and a Network title that shows baseline learning progress.
- Website: the /understand FAQ and glossary.

## 0.7.0 · 2026-08-24

Gateways that drop ICMP read as notes, not alarms. Plus an apt repo, support bundles and octomon.dev.

- Analysis: ICMP-silent gateways and hops beside clean anchors are policy, not outage. Baselines learn through note-class findings, and private or CGNAT targets never vote on Internet health.
- Locations are sorted by last seen with the current one pinned, join and loss events name known locations, and hotspot gateways are probed from the routing table.
- Network panel: DHCP server and static detection, a public IP row, and deduplicated resolver references.
- Events are dated, with a session-start marker, green clears and amber raises.
- `p` and `u` pin a process or remote to the top of the talkers.
- `Shift+D` writes a support bundle: a zip with the report, timeline, config, logs and baselines.
- `--demo-mac` hides only this machine's identifiers on non-private networks.
- Packaging: cargo-deb metadata and a workflow publishing a signed apt repo to octomon.dev/apt, plus the octomon.dev site itself.

## 0.6.5 · 2026-08-23

Local DNS outages get named, and DNS judgement gets faster.

- A failing LAN resolver is no longer a footnote. When the network's own resolver times out while public ones answer, the analysis raises a Degraded "local DNS is down, Internet OK, local names will not resolve" finding, lands it on the timeline, and names what is lost: the search domain, and why every lookup got slower when that resolver is first in order. A public resolver failing while the LAN's works stays an informational note.
- Resolvers are judged by streak before window share: three timeouts in a row is down, three answers in a row is back, roughly 15 seconds each way instead of half a minute.
- `←` and `→` walk the resolvers on the dns row, and `W` asks whois about the highlighted one.
- `d` deletes the selected location. The network you are on comes straight back as a blank entry tagged "learning from scratch". Monitoring time reads as "2d 9h healthy" rather than "3458 healthy min".
- `C` clears the events timeline, and the session counter stays honest.

## 0.6.4 · 2026-08-22

Long content wraps, narrow terminals survive, and added targets are remembered.

- Text that outgrows its space wraps inside its own column with a hanging indent, never under the timestamp and label columns to its left: the events overlay (also enlarged), the analysis overlay, the port-scan overlay, the Network panel rows, and the network history list and detail pane. Words wider than a line, such as paths and address lists, hard-split.
- Four crossed-bounds panics fixed. The analysis overlay crashed any terminal under about 80 columns, taking the collectors down with it; locations crashed under 86; the port-scan and whois overlays crashed on very short terminals. Every overlay is now drawn at degenerate sizes in tests.
- Targets added with `a` are saved to config.toml and probed on every start, and `d` deletes and forgets them. A new optional `host` key keeps name-targets re-resolving with real SNI across restarts, and old config files parse unchanged.

## 0.6.3 · 2026-08-21

octomon starts on Windows Server.

- octomon.exe imported wlanapi.dll at load time, and Windows Server ships without that DLL unless the optional Wireless LAN Service feature is installed, so on a stock server the loader killed the process before main and printed nothing. The import is now delay-loaded on MSVC targets, and the single funnel for every WLAN call checks the DLL exists first. Servers without wireless simply get no Wi-Fi details, which was already their reality.

## 0.6.2 · 2026-08-20

Legacy-console glyph fallback, speed-test attribution, a TLS provider that survives inspection.

- Bar graphs render correctly in the legacy Windows console. A new `bar_glyphs` config ("auto", "fine" or "coarse") switches sparklines to half or full blocks when the console font lacks the eighth-block glyphs, and auto-detection asks the actual console font via GDI, so a conhost set to Cascadia Mono keeps the fine set.
- A speed test no longer reads as the network failing. The Quality header is annotated while the test runs and while loaded samples remain in the stats window, and loss and latency findings the test's own load can fake are suppressed for that window. Bufferbloat and content-based findings still report.
- Session recordings log speed tests: a start event, then results as tidy metric rows.
- aws-lc-rs replaces ring as the rustls provider. Cloudflare Gateway's TLS-inspection intermediate signs ECDSA-SHA256 under a P-384 key, which ring refuses, killing every HTTPS check behind WARP.

## 0.6.1 · 2026-08-19

Latency colors judged relatively, locations gain a rename, and the OS trust store.

- Latency colors judge against the path's own reference floor (the session minimum, lowered to the learned normal) with the old absolute thresholds as floors. A VPN exit on another continent is no longer red for being far away, and mid-path hops that never answer ICMP read dim rather than red.
- Locations: each entry shows its connection type, Enter renames the selected one, and the current network is listed as learning before its first healthy minute is written.
- TLS trusts the OS certificate store alongside the bundled roots. Behind a TLS-inspecting proxy every HTTPS check had failed while the browser, which trusts the root installed in the OS store, was fine. The public-IP error also names its cause now instead of "error sending request".
- Bandwidth: each talkers table keeps and shows its own sort, and the column cursor only appears on the table holding the row cursor.
- A path monitor follows its target when the name re-resolves to a new address.

## 0.6.0 · 2026-08-19

The analysis ladder reworked, and a batch of new diagnostics.

- A bottom "not connected" rung (no route, self-assigned address, no gateway) that everything downstream is a symptom of, plus symptom-aware ranking so a dead gateway headlines over the DNS failure behind it.
- DNS is judged on a recent window, hop loss must persist downstream before it names the ISP, LAN targets are judged locally rather than as Internet anchors, bufferbloat load is measured against the network's learned WAN capacity, and findings show how long they have been active.
- New diagnostics: system clock skew via SNTP with an HTTP Date fallback; a public reference resolver alongside the system ones, with a once-a-minute NXDOMAIN hijack check; CGNAT and double NAT read from the first hops; a path-MTU probe using DF-bit QUIC version-negotiation packets, with black-hole detection and an honest "cannot measure here" on macOS; IPv6 breakage localized (no v6 route, v6 DNS, or upstream) plus the IPv4 mirror; and system web proxy detection, with the HTTP check repeated through it.
- Outbound port scan overlay on `c`.
- A network history pane (joins, roams, address, route and VPN changes) in the full-screen Network panel, and persistent per-network incident history with a 7-day summary in doctor, locations and the analysis.
- `--demo`: real measurements with a disguised identity, for screen recording.
- Also: control characters stripped from `--check` and `--doctor` output, RDAP bodies capped while streaming, and an events export on `x`.

## 0.5.3 · 2026-08-18

Session-total talkers, a pause that freezes the display, a build stamp.

- Session-total talkers with scrolling side-by-side tables.
- A pause that freezes the display.
- A build stamp in the version string.

## 0.5.2 · 2026-08-18

Utilization by remote address, and a whois overlay for any address.

- Utilization by remote address in the bandwidth panel.
- Ability to query whois and ASN for any address.
- Path monitor fixes from the field: anycast double-destination, unreached destinations, scroll cues.

## 0.5.1 · 2026-08-17

Field-test fixes: calmer thresholds, local DNS proxies handled.

- Calmer latency-inflation and loss thresholds.
- Local DNS-proxy resolvers handled properly on Windows: mapped-v6 unmapping, deduplication and honest naming.

## 0.5.0 · 2026-08-17

octomon starts answering its own question: an analysis engine, per-network baselines, an event timeline and doctor mode.

- A live analysis line in the footer synthesizes every collector into one headline, backed by a triage ladder on `y` showing each subsystem's status with its data, healthy rungs included, so the conclusion is auditable. Findings are ranked with hysteresis, simultaneous causes all show, and machine or VPN caveats never outrank network causes.
- Per-network baselines, fingerprinted by SSID and gateway MAC (SSID alone for gatewayless hotspots), learned only from healthy minutes, named with `N` and browsed with `L`. The analysis reads "41ms vs ~9ms normal at Home".
- An event timeline on `e`: finding raises and clears with durations and severity escalations, network, SSID, DNS and VPN changes, link lost and restored with an automatic stat reset, and speed tests. All of it also drains into CSV recordings.
- An HTTP layer: an Internet-level connectivity check with second-opinion verification and captive-portal, broken-IPv6 and filtered-web findings, plus per-target web probing with a TTFB strip for targets that demonstrably serve HTTP, with refused and filtered honestly distinguished from down.
- Hostname targets stay names: probed over HTTPS with SNI and re-resolved on network change, because CDNs answer per location, with a stats reset and a timeline entry when the answer moves.
- ICMPv6 with per-family ping clients, so v6-resolved targets work on v6-only carrier hotspots, and link-local resolvers are probed with the interface scope they require.
- Doctor mode: `octomon --doctor [--observe SECS] [--speedtest] [--json]` prints the analysis, this location's learned normal, measurements and events, redacted by default so it pastes safely into a ticket, with `--full` for local use. Exit codes are 0 healthy, 1 problems, 3 could not measure.
- A first-run welcome screen.

## 0.4.1 · 2026-08-17

Fixes from real Windows hardware.

- The path monitor scrolls to follow the selection. It rendered from the first row with no offset, so moving the cursor past the last visible hop made the selection vanish instead of revealing the rest of the path.
- The overflow hint no longer tells people already in full screen to press `f` for full screen. The counts moved into the panel title, which also gives back the row the footer was using.
- Charts can be plotted with block glyphs instead of braille via `graph_marker`, for consoles whose font has no braille and draws every point as an empty box.
- The stats window is an ascending 1m / 5m / 15m ladder rather than 30 / 60 / 300 cycling out of order, and it no longer claims more history than a target keeps.
- The privilege reference moved from the README into PRIVILEGES.md, which gains a macOS section that was previously only implied.

## 0.4.0 · 2026-08-16

Windows support, with binaries for x86_64 and aarch64.

- Wi-Fi via the Native Wifi API rather than parsing netsh, whose field names are translated on a non-English install and whose output arrives in the console's OEM codepage.
- Path discovery via the built-in tracert, with its own parser: the address comes last rather than second, and the timeout string is localized.
- Per-process bandwidth via an ETW session on the provider Task Manager reads. This is the only platform where that panel covers QUIC and HTTP/3, since ss and nettop are both TCP-only.
- Config in %APPDATA%, data in %LOCALAPPDATA%. The unix XDG layout is unchanged, so existing installs keep finding their files.
- Also fixes a latent bug: netdev names a Windows interface by adapter GUID while sysinfo keys its counters on the alias, so throughput would never have matched the default interface.

## 0.3.0 · 2026-08-11

Linux support, a restructured path monitor, and DNS responsiveness.

- Linux joins macOS: platform probes, `nmcli` preferred over `iw`, and a startup probe for the external tools each backend needs.
- Per-process bandwidth on Linux fixed. 
- The support probe treated "ran but found nothing" as "not supported", permanently disabling the feature on a machine that happened to have no open TCP sockets at launch.
- The path monitor is restructured into panels with sub-pane focus and DNS graphs, plus scrolling, overflow hints and per-sample bar color.
- DNS resolver responsiveness is measured, and Wi-Fi airspace congestion comes from the neighbour scan.
- Session recording to CSV on `l`.
- octomon reacts to network changes instead of trusting startup state, and Esc no longer quits.
- The help overlay is reworked into two columns with every binding, and fits 80x24.

## 0.2.1 · 2026-08-10

Split-tunnel VPNs detected, and identified from the tunnel itself.

- 0.2.0 shipped tunnel detection that never fired for Cloudflare WARP and could name the wrong VPN when it did. Detection picked the default interface by routing to an RFC1918 address, which split-tunnel VPNs deliberately keep off the tunnel, and WARP compounds this by leaving `default` on the physical NIC while installing two half-internet routes that win on specificity. octomon now probes TEST-NET-1 to find the interface Internet traffic actually leaves from, and describes the gateway as the real LAN gateway rather than the tunnel endpoint.
- Identification comes from the addresses the live tunnel carries (WARP, Tailscale, Mullvad, NordLynx, Proton), ordered most-specific first, because helper daemons stay resident whether or not a tunnel is up. The process scan remains a fallback and stays silent unless exactly one client matches: an unnamed tunnel beats a wrong name.

## 0.2.0 · 2026-08-10

Connection type, tunnel detection, and a link graph that knows the medium.

- The Network panel classifies the default route's medium (Wi-Fi, Ethernet, cellular or tunnel) rather than echoing the OS's interface description, and uses that to decide what is worth showing.
- A tunnelled default route is detected and named. The gateway is annotated as the tunnel endpoint, and the traceroute view explains why the encapsulated hops never answer instead of leaving a red address and a wall of asterisks.
- The Wi-Fi signal graph is suppressed when the radio is associated but is not the primary route. Wired links get utilization against negotiated line rate instead, which is the "is this link the limit?" signal RSSI provides on a radio.
- Speed-test failures wrap to the panel width instead of being clipped at 48 characters.
- The help overlay is titled with the running version and sized to its content, since the fixed 22-row box had been cutting off the Bandwidth section.

## 0.1.1 · 2026-08-10

The first pre-built binary, via cargo-dist.

- Apple Silicon macOS only for now. Intel build compiles cleanly but was unverified on Intel hardware.

## 0.1.0 · 2026-08-10

The first release: one terminal based dashboard to monitor connectivity to the Internet

- Latency distribution stats, a bufferbloat indicator, staggered sends and windowing.
- Multi-provider speed tests (Cloudflare, M-Lab NDT7, LibreSpeed) with result history and a config file.
- Per-process bandwidth, the top talkers, on macOS.
- macOS Wi-Fi details and a live signal graph via CoreWLAN.
- Traceroute, hop discovery, and a sortable quality table.
- Keyboard-driven throughout: full screen, target select, help, pause and a live speed test.
- Shipped as a source-build Homebrew formula, dual MIT and Apache-2.0 licensed.
