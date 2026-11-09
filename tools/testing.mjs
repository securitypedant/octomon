// Renders website/testing.html from website/testing/vpn-rig.json: the record
// of the VPN rig's latest run (testing/vpn-rig/) against the current release.
// The page is a coverage statement, not a history: it says which version was
// last tested and what that version was checked for. The JSON is written by
// testing/vpn-rig/publish.sh from an allow-list (no addresses, keys,
// hostnames or logs), so this page shows only what that file holds. Run by
// `npm run site`, and by publish.sh itself.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ORIGIN, REPO, DEFAULT_OG, PUBLISHER, esc, humanDate, page } from "./page.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SITE = join(ROOT, "website");
const DATA = join(SITE, "testing", "vpn-rig.json");
const URL_PATH = `${ORIGIN}/testing`;

if (!existsSync(DATA)) {
  console.log("tools/testing.mjs: no website/testing/vpn-rig.json yet, nothing to render");
  process.exit(0);
}
const { run } = JSON.parse(readFileSync(DATA, "utf8"));
if (!run?.clients?.length) {
  console.log("tools/testing.mjs: no run recorded, nothing to render");
  process.exit(0);
}

// Plain words for the record's field values.
const CLIENTS = {
  wireguard: "WireGuard (wg-quick, kernel device)",
  openvpn: "OpenVPN (tun)",
  unnamed: "Unnamed tunnel (plain GRE, no client)",
  nordvpn: "NordVPN app (NordLynx)",
  tailscale: "Tailscale (mesh client beside a WireGuard tunnel)",
  warp: "Cloudflare WARP (consumer)",
  "warp-team": "Cloudflare WARP (enrolled in a Zero Trust organisation)",
  crowded: "Several clients installed at once (NordVPN, WARP, Tailscale, wg-quick, OpenVPN)",
  faults: "Fault injection (no VPN)",
};
const KEY = {
  first: "first connection",
  same: "same location after reconnecting",
  different: "a new location, as designed",
  restored: "back to the first location",
};
// octomon's finding slugs, in words.
const CAUSES = {
  "no-link": "no link",
  "captive-portal": "captive portal",
  "degraded-usable": "degraded but usable",
  gateway: "gateway / LAN",
  link: "Wi-Fi link",
  "wired-link": "wired link",
  dns: "DNS",
  "local-dns": "local DNS",
  "dns-hijack": "DNS hijacked",
  isp: "ISP path",
  internet: "internet",
  ipv6: "IPv6 broken",
  "path-mtu": "path MTU",
  "web-filtered": "web filtered",
  "http-blocked": "web blocked, ping works",
  "web-target": "one web target",
  destination: "one destination",
  bufferbloat: "bufferbloat",
  clock: "clock skew",
  machine: "this machine",
  "vpn-caveat": "VPN caveat",
};
const STATUS = { healthy: "healthy", problems: "problems", down: "down", insufficient: "not enough data" };
const mark = (ok) => (ok ? `<span class="ok">✓</span>` : `<span class="bad">✗</span>`);
const checkList = (checks) =>
  Object.entries(checks ?? {})
    .map(([k, ok]) => `${mark(ok)} ${esc(k.replace(/_/g, " "))}`)
    .join(" · ");

const ran = run.clients.filter((c) => c.status !== "skipped");
const phases = ran.flatMap((c) => (c.phases ?? []).map((p) => ({ ...p, client: c.name })));
const checks = phases.flatMap((p) => Object.entries(p.checks ?? {}));
const failed =
  checks.filter(([, ok]) => !ok).length + phases.filter((p) => !p.device && !p.skipped).length;
const shortName = (name) => CLIENTS[name]?.split(" (")[0] ?? name;
const list = (items) => items.map(esc).join(", ");

// What this run checked, in areas, each gated on the record so that the page
// never claims a check that did not run. The check names are the ones run.sh
// writes: name, label, key, bypassed, clean_log and a phase's own asserts.
function areas() {
  const withCheck = (k) => [...new Set(phases.filter((p) => k in (p.checks ?? {})).map((p) => p.client))];
  const out = [];
  const named = withCheck("name");
  if (named.length) {
    const seen = [...new Set(phases.filter((p) => p.recognised_as).map((p) => p.recognised_as))];
    const resolvers = checks.some(([k]) => /resolver/.test(k));
    out.push([
      "Tunnel naming",
      `what octomon calls each tunnel, from its device type, address blocks${resolvers ? ", the running client and the resolvers it configures" : " and the running client"}: ${list(seen)}.`,
    ]);
  }
  if (withCheck("label").length) {
    out.push([
      "Location labels",
      "the label a location gets under each tunnel, and whether it carries the tunnel address (WireGuard) or not (clients that hand out a new address per connection).",
    ]);
  }
  const keyed = phases.filter((p) => p.client !== "faults" && "key" in (p.checks ?? {}) && p.key !== "first");
  if (keyed.length) {
    const n = (k) => keyed.filter((p) => p.key === k).length;
    out.push([
      "Location identity",
      `that a tunnel keeps one learned location across reconnects, other servers, new leases and new device registrations (${n("same")} phases), gets a new one only where that is by design (${n("different")}), and that the network underneath comes back as itself when the tunnel drops (${n("restored")}).`,
    ]);
  }
  const bystanders = withCheck("bypassed");
  if (bystanders.length) {
    out.push([
      "Resident mesh clients",
      `a mesh client with only its own routes (${list(bystanders.map(shortName))}) is listed as a bypassed tunnel, does not become the location, and does not lend its name to a VPN brought up beside it.`,
    ]);
  }
  const crowded = phases.filter((p) => p.client === "crowded" && p.device);
  if (crowded.length) {
    const seen = [...new Set(crowded.filter((p) => p.recognised_as).map((p) => p.recognised_as))];
    out.push([
      "Several clients at once",
      `one machine with NordVPN, WARP, Tailscale, wg-quick and OpenVPN installed and their daemons all resident while one tunnel at a time, or two, is connected: each tunnel is named as itself (${list(seen)}) and no resident client lends its name to another's tunnel.`,
    ]);
  }
  const faults = phases.filter((p) => p.client === "faults" && p.device);
  if (faults.length) {
    out.push([
      "Analysis under faults",
      `a container with no VPN breaks its own network one way per phase, and the analysis has to notice, name the right cause, keep the same location throughout and never call a usable network down:<ul>${faults
        .map((p) => `<li>${esc(p.name)}</li>`)
        .join("")}</ul>`,
    ]);
  }
  if (withCheck("clean_log").length) {
    out.push(["Stability", "no panic and no collector restart in any phase, read from octomon's own error log."]);
  }
  return out;
}

const notRun = (p, cols) =>
  `<tr><td>${esc(p.name)}</td><td colspan="${cols - 1}" class="muted">${esc(p.reason ?? "not run")}</td></tr>`;

function phaseRow(p, cols) {
  if (p.skipped) return notRun(p, cols);
  if (!p.device) {
    return `<tr><td>${esc(p.name)}</td><td colspan="${cols - 1}">${mark(false)} ${esc(p.reason ?? "did not complete")}</td></tr>`;
  }
  return `<tr>
            <td>${esc(p.name)}</td>
            <td><code>${esc(p.device)}</code></td>
            <td>${
              p.recognised_as
                ? `${esc(p.recognised_as)}${p.label_has_address ? " <span class=\"muted\">(label carries the tunnel address)</span>" : ""}`
                : `<span class="muted">no tunnel: the LAN itself</span>`
            }</td>
            <td>${esc(KEY[p.key] ?? p.key)}</td>
            <td class="checks">${checkList(p.checks)}</td>
          </tr>`;
}

// The fault client has no tunnel to describe; what matters is what the
// analysis concluded: octomon's status and the causes it named.
function faultRow(p) {
  if (p.skipped) return notRun(p, 3);
  if (!p.device) {
    return `<tr><td>${esc(p.name)}</td><td colspan="2">${mark(false)} ${esc(p.reason ?? "did not complete")}</td></tr>`;
  }
  const causes = (p.causes ?? []).map((c) => CAUSES[c] ?? c);
  const said = `${esc(STATUS[p.status] ?? p.status)}${
    causes.length ? `: ${esc(causes.join(", "))}` : ""
  }${p.exit_code != null ? ` <span class="muted">(exit ${esc(String(p.exit_code))})</span>` : ""}`;
  return `<tr>
            <td>${esc(p.name)}</td>
            <td>${said}</td>
            <td class="checks">${checkList(p.checks)}</td>
          </tr>`;
}

function clientCard(c) {
  const title = CLIENTS[c.name] ?? c.name;
  if (c.status === "skipped") {
    return `      <div class="card">
        <h3>${esc(title)} <span class="tag skip">not run</span></h3>
        <p>${esc(c.reason ?? "skipped")}.</p>
      </div>`;
  }
  const faults = c.name === "faults";
  const rows = (c.phases ?? []).map((p) => (faults ? faultRow(p) : phaseRow(p, 5))).join("\n");
  const head = faults
    ? "<th>what was broken</th><th>what octomon said</th><th>checks</th>"
    : "<th>phase</th><th>device</th><th>recognised as</th><th>location key</th><th>checks</th>";
  return `      <div class="card">
        <h3>${esc(title)} <span class="tag ${c.status === "pass" ? "pass" : "fail"}">${c.status === "pass" ? "passed" : "failed"}</span></h3>${
          c.reason ? `\n        <p>${esc(c.reason)}.</p>` : ""
        }
        <table>
          <thead><tr>${head}</tr></thead>
          <tbody>
${rows}
          </tbody>
        </table>
      </div>`;
}

const verdict = failed
  ? `<span class="bad">${failed} ${failed === 1 ? "check" : "checks"} failed</span>`
  : `<span class="ok">every check held</span>`;
const skipped = run.clients.filter((c) => c.status === "skipped");

const body = `<main id="top">
  <div class="pagehead">
    <div class="wrap">
      <h1>Tested against real VPN clients</h1>
      <p class="lede">Before each release, octomon is run inside Linux containers next to
      real VPN clients to check what it says about each tunnel. This page is the record for the current release.</p>
    </div>
  </div>

  <section id="v${esc(run.octomon)}">
    <div class="wrap">
      <h2>octomon ${esc(run.octomon)} <span class="muted">· tested ${esc(humanDate(run.date))}</span></h2>
      <p class="runmeta">${ran.length} clients · ${phases.length} phases · ${checks.length} checks · ${verdict} · ${esc(run.host)} · built from <a href="${REPO}/commit/${esc(run.commit)}"><code>${esc(run.commit)}</code></a>${
        run.dirty ? " with uncommitted changes" : ""
      }</p>
      <div class="post">
        <h3>What this release was checked for</h3>
        <dl class="areas">
${areas()
  .map(([title, text]) => `          <dt>${esc(title)}</dt><dd>${text}</dd>`)
  .join("\n")}
        </dl>
        <p>Clients: ${list(ran.map((c) => CLIENTS[c.name] ?? c.name))}.${
          skipped.length ? ` Not run this time: ${list(skipped.map((c) => CLIENTS[c.name] ?? c.name))}.` : ""
        }</p>
      </div>
    </div>
  </section>

  <section>
    <div class="wrap">
      <h2>The detail</h2>
${run.clients.map(clientCard).join("\n")}
    </div>
  </section>

  <section>
    <div class="wrap">
      <div class="post">
        <p>The rig is in the repository under
        <a href="${REPO}/tree/main/testing/vpn-rig"><code>testing/vpn-rig/</code></a> and has one
        container per client with the rig's own WireGuard, OpenVPN and GRE servers for the
        self-contained cases and real accounts for the others. One client has no VPN at
        all and breaks its own network on purpose, to check what the analysis says. It is run by hand and not
        part of the automated test suite. What is published is the outcome only: the client, the
        device shape octomon saw, the name it gave the tunnel, and whether each check
        held. Only the latest run is kept; a run against a new release replaces this page.</p>
      </div>
    </div>
  </section>
</main>`;

const extraCss = `
  .runmeta { font-family: var(--octo-mono); font-size: 0.8rem; color: var(--octo-muted); margin: -6px 0 14px; }
  .muted { color: var(--octo-muted); font-weight: 400; font-size: 0.85em; }
  .post h3 { margin: 0 0 8px; font-size: 1.05rem; }
  dl.areas { margin: 0 0 12px; display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; }
  dl.areas dt { font-family: var(--octo-mono); font-weight: 700; color: var(--octo-green); font-size: 0.8rem; padding-top: 2px; }
  dl.areas dd { margin: 0; font-size: 0.92rem; }
  dl.areas dd ul { margin: 4px 0 0; padding-left: 1.2em; }
  dl.areas dd li { margin: 1px 0; }
  .card { padding: 12px 16px; margin: 0 0 10px; }
  .card h3 { margin: 0 0 4px; font-size: 1rem; }
  .card p { margin: 4px 0; font-size: 0.9rem; }
  .tag { font-family: var(--octo-mono); font-size: 0.68rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.04em; padding: 1px 7px; border-radius: var(--octo-radius-chip); vertical-align: middle; margin-left: 8px; }
  .tag.pass { background: rgba(63, 207, 92, 0.15); color: var(--octo-green); }
  .tag.fail { background: rgba(224, 82, 77, 0.15); color: var(--octo-red); }
  .tag.skip { background: rgba(138, 150, 164, 0.15); color: var(--octo-muted); }
  .card table { width: 100%; border-collapse: collapse; margin: 2px 0 0; font-size: 0.84rem; }
  .card th, .card td { text-align: left; padding: 4px 8px; border-bottom: 1px solid var(--octo-line); vertical-align: top; }
  .card th { font-family: var(--octo-mono); font-weight: 700; color: var(--octo-green); font-size: 0.74rem; }
  .card tr:last-child td { border-bottom: 0; }
  .card td:nth-child(3) { white-space: nowrap; }
  .card td.checks { font-family: var(--octo-mono); font-size: 0.78rem; white-space: nowrap; }
  .ok { color: var(--octo-green); } .bad { color: var(--octo-red); }
  @media (max-width: 700px) {
    dl.areas { display: block; }
    dl.areas dd { margin: 0 0 8px; }
    .card table, .card thead, .card tbody, .card tr, .card td { display: block; }
    .card thead { display: none; }
    .card td { border-bottom: 0; padding: 2px 0; }
    .card tr { border-bottom: 1px solid var(--octo-line); padding: 6px 0; }
    .card tr:last-child { border-bottom: 0; }
    .card td.checks, .card td:nth-child(3) { white-space: normal; }
  }`;

const html = page({
  title: "octomon: tested against real VPN clients",
  description: `What octomon ${run.octomon} was checked for before release: ${list(ran.map((c) => shortName(c.name)))}, ${phases.length} phases, ${checks.length} checks.`,
  url: URL_PATH,
  ogType: "website",
  ogTitle: "octomon: tested against real VPN clients",
  ogDescription: `Real VPN clients in containers, checked against octomon ${run.octomon}: naming, labels, location identity across reconnects, and the analysis under injected faults.`,
  ogImage: DEFAULT_OG,
  body,
  extraCss,
  jsonLd: {
    "@context": "https://schema.org",
    "@type": "WebPage",
    "@id": URL_PATH,
    url: URL_PATH,
    name: "octomon: tested against real VPN clients",
    dateModified: run.date,
    publisher: PUBLISHER,
  },
});

writeFileSync(join(SITE, "testing.html"), html);
console.log(`tools/testing.mjs: /testing (octomon ${run.octomon}, ${ran.length} clients, ${checks.length} checks)`);
