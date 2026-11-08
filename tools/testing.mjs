// Renders website/testing.html from website/testing/vpn-rig.json: the record
// of the VPN rig's runs (testing/vpn-rig/), one per octomon release, newest
// first. The JSON is written by testing/vpn-rig/publish.sh from an allow-list
// (no addresses, keys, hostnames or logs), so this page shows only what that
// file holds. Run by `npm run site`, and by publish.sh itself.
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
const { runs } = JSON.parse(readFileSync(DATA, "utf8"));
if (!runs?.length) {
  console.log("tools/testing.mjs: no runs recorded, nothing to render");
  process.exit(0);
}

// Plain words for the record's field values.
const CLIENTS = {
  wireguard: "WireGuard (wg-quick, kernel device)",
  openvpn: "OpenVPN (tun)",
  l2tp: "L2TP/IPsec (ppp)",
  nordvpn: "NordVPN app (NordLynx)",
  tailscale: "Tailscale",
  warp: "Cloudflare WARP",
  proton: "Proton VPN",
};
const KEY = {
  first: "first connection",
  same: "same location after reconnecting",
  different: "a new location, as designed",
};
const mark = (ok) => (ok ? `<span class="ok">✓</span>` : `<span class="bad">✗</span>`);

function phaseRow(p) {
  if (!p.device) {
    return `<tr><td>${esc(p.name)}</td><td colspan="4">${mark(false)} ${esc(p.reason ?? "did not complete")}</td></tr>`;
  }
  const checks = [
    ["named", p.checks.name],
    ["label", p.checks.label],
    ["key", p.checks.key],
    ["clean log", p.checks.clean_log],
  ]
    .map(([k, ok]) => `${mark(ok)} ${k}`)
    .join(" · ");
  return `<tr>
            <td>${esc(p.name)}</td>
            <td><code>${esc(p.device)}</code></td>
            <td>${esc(p.recognised_as)}${p.label_has_address ? " <span class=\"muted\">(label carries the tunnel address)</span>" : ""}</td>
            <td>${esc(KEY[p.key] ?? p.key)}</td>
            <td class="checks">${checks}</td>
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
  const rows = (c.phases ?? []).map(phaseRow).join("\n");
  return `      <div class="card">
        <h3>${esc(title)} <span class="tag ${c.status === "pass" ? "pass" : "fail"}">${c.status === "pass" ? "passed" : "failed"}</span></h3>${
          c.reason ? `\n        <p>${esc(c.reason)}.</p>` : ""
        }
        <table>
          <thead><tr><th>phase</th><th>device</th><th>recognised as</th><th>location key</th><th>checks</th></tr></thead>
          <tbody>
${rows}
          </tbody>
        </table>
      </div>`;
}

function runTitle(r) {
  const n = r.clients.filter((c) => c.status !== "skipped").length;
  const passed = r.clients.filter((c) => c.status === "pass").length;
  return `octomon ${esc(r.octomon)} <span class="muted">· ${esc(humanDate(r.date))} · ${passed}/${n} clients passed</span>`;
}

function runMeta(r) {
  return `<p class="runmeta">${esc(r.host)} · built from <a href="${REPO}/commit/${esc(r.commit)}"><code>${esc(r.commit)}</code></a>${
    r.dirty ? " with uncommitted changes" : ""
  }</p>`;
}

function runSection(r) {
  return `  <section id="v${esc(r.octomon)}">
    <div class="wrap">
      <h2>${runTitle(r)}</h2>
      ${runMeta(r)}
${r.clients.map(clientCard).join("\n")}
    </div>
  </section>`;
}

// An earlier run shows only its title until opened; a link to its anchor
// opens it (the script at the end of the page).
function runFolded(r) {
  return `      <details class="run" id="v${esc(r.octomon)}">
        <summary>${runTitle(r)}</summary>
        ${runMeta(r)}
${r.clients.map(clientCard).join("\n")}
      </details>`;
}

const [latest, ...earlier] = runs;
const body = `<main id="top">
  <div class="pagehead">
    <div class="wrap">
      <h1>Tested against real VPN clients</h1>
      <p class="lede">Before each release, octomon is run inside Linux containers next to
      real VPN clients, and what it says about each tunnel is checked: that it names the
      client, that the location label has the right shape, and that the location it files
      the network under stays the same when the tunnel reconnects, lands on another server
      or gets a new address. These are the results.</p>
    </div>
  </div>

  <section>
    <div class="wrap">
      <div class="post">
        <p>The rig is in the repository under
        <a href="${REPO}/tree/main/testing/vpn-rig"><code>testing/vpn-rig/</code></a>: one
        container per client, the rig's own WireGuard and OpenVPN servers for the
        self-contained cases, a real account for the rest. It is run by hand; it is not
        part of the automated test suite, which is why the result is published here
        rather than in a badge. What is published is the outcome only: the client, the
        device shape octomon saw, the name it gave the tunnel, and whether each check
        held. Addresses, keys and logs from the runs stay on the machine that ran them.</p>
        <p>What it cannot tell you: anything about macOS or Windows (the rig is Linux by
        construction), Wi-Fi, a real home or office network underneath the tunnel, or
        corporate clients such as Zscaler and GlobalProtect.</p>
      </div>
    </div>
  </section>

${runSection(latest)}
${earlier.length ? `
  <section>
    <div class="wrap">
      <h2>Earlier runs</h2>
${earlier.map(runFolded).join("\n")}
    </div>
  </section>
<script>
  // A link to an earlier run (#v0.12.0) opens it.
  const open = () => { const d = location.hash && document.querySelector(\`details[id="\${CSS.escape(location.hash.slice(1))}"]\`); if (d) { d.open = true; d.scrollIntoView(); } };
  addEventListener("hashchange", open); open();
</script>` : ""}
</main>`;

const extraCss = `
  .runmeta { font-family: var(--octo-mono); font-size: 0.8rem; color: var(--octo-muted); margin: -6px 0 10px; }
  .muted { color: var(--octo-muted); font-weight: 400; font-size: 0.85em; }
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
  details.run { border-top: 1px solid var(--octo-line); padding: 10px 0 4px; }
  details.run:last-of-type { border-bottom: 1px solid var(--octo-line); }
  details.run summary { cursor: pointer; font-weight: 700; font-size: 1.05rem; list-style: none; padding: 2px 0; }
  details.run summary::-webkit-details-marker { display: none; }
  details.run summary::before { content: "▸"; display: inline-block; width: 1.1em; color: var(--octo-muted); }
  details.run[open] summary::before { content: "▾"; }
  details.run[open] summary { margin-bottom: 10px; }
  details.run .runmeta { margin: 0 0 10px 1.1em; }
  details.run .card { margin-left: 1.1em; }
  @media (max-width: 700px) {
    .card table, .card thead, .card tbody, .card tr, .card td { display: block; }
    .card thead { display: none; }
    .card td { border-bottom: 0; padding: 2px 0; }
    .card tr { border-bottom: 1px solid var(--octo-line); padding: 6px 0; }
    .card tr:last-child { border-bottom: 0; }
    .card td.checks, .card td:nth-child(3) { white-space: normal; }
    details.run .runmeta, details.run .card { margin-left: 0; }
  }`;

const html = page({
  title: "octomon: tested against real VPN clients",
  description: `What octomon says about real VPN clients, checked before each release: ${latest.clients
    .filter((c) => c.status !== "skipped")
    .map((c) => CLIENTS[c.name]?.split(" (")[0] ?? c.name)
    .join(", ")} against octomon ${latest.octomon}.`,
  url: URL_PATH,
  ogType: "website",
  ogTitle: "octomon: tested against real VPN clients",
  ogDescription: `Real VPN clients in containers, checked against octomon ${latest.octomon}: naming, labels and location identity across reconnects.`,
  ogImage: DEFAULT_OG,
  body,
  extraCss,
  jsonLd: {
    "@context": "https://schema.org",
    "@type": "WebPage",
    "@id": URL_PATH,
    url: URL_PATH,
    name: "octomon: tested against real VPN clients",
    dateModified: latest.date,
    publisher: PUBLISHER,
  },
});

writeFileSync(join(SITE, "testing.html"), html);
console.log(`tools/testing.mjs: /testing (${runs.length} run${runs.length === 1 ? "" : "s"}, latest octomon ${latest.octomon})`);
