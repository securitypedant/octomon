#!/usr/bin/env node
// Renders website/changelog.md to website/changelog.html, writes the release
// RSS feed at website/changelog.xml, and updates the changelog block of
// sitemap.xml.
//
//   npm run changelog
//
// The source is one Markdown file: frontmatter, an intro, then one `## <ver> ·
// <date>` section per release. The first paragraph of a section is its
// summary, which becomes the feed's description and the lede on the page; the
// rest is the section's body. Output is deterministic, so re-running with no
// source change is a no-op.

import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { marked } from "marked";
import {
  DEFAULT_OG,
  ORIGIN,
  PERSON,
  PUBLISHER,
  REPO,
  esc,
  humanDate,
  page,
  parseFrontmatter,
  replaceBlock,
  rssDate,
} from "./page.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SITE = join(ROOT, "website");
const SOURCE = join(SITE, "changelog.md");
const URL_PATH = `${ORIGIN}/changelog`;

// `## 0.10.1 · 2026-08-30` — the middle dot rather than a dash so the version
// and the date can never be confused for a range.
const HEADING = /^## +([0-9][0-9A-Za-z.\-+]*) +· +(\d{4}-\d{2}-\d{2}) *$/;

// ----------------------------------------------------------------- the source

function loadReleases() {
  const raw = readFileSync(SOURCE, "utf8");
  const { meta, body } = parseFrontmatter(raw, "website/changelog.md");
  for (const key of ["title", "description"]) {
    if (!meta[key]) throw new Error(`website/changelog.md: missing "${key}" in frontmatter`);
  }

  const lines = body.split("\n");
  const releases = [];
  const intro = [];
  let current = null;
  for (const line of lines) {
    const m = HEADING.exec(line);
    if (m) {
      current = { version: m[1], date: m[2], human: humanDate(m[2]), lines: [] };
      releases.push(current);
      continue;
    }
    // A stray `## Anything Else` would silently vanish into the previous
    // release's body, so refuse it rather than swallow it.
    if (/^## /.test(line)) {
      throw new Error(`website/changelog.md: heading is not "## <version> · <YYYY-MM-DD>": ${line}`);
    }
    (current ? current.lines : intro).push(line);
  }
  if (!releases.length) throw new Error("website/changelog.md: no release sections found");

  const seen = new Set();
  for (const r of releases) {
    if (seen.has(r.version)) throw new Error(`website/changelog.md: version ${r.version} appears twice`);
    seen.add(r.version);

    // The summary is the first paragraph; the body is everything after it.
    const text = r.lines.join("\n").trim();
    const split = text.indexOf("\n\n");
    r.summary = (split === -1 ? text : text.slice(0, split)).trim();
    r.body = split === -1 ? "" : text.slice(split).trim();
    if (!r.summary) throw new Error(`website/changelog.md: ${r.version} has no summary paragraph`);
  }

  // Newest first is how the file is written; a version out of date order is a
  // typo, not an intention.
  for (let i = 1; i < releases.length; i++) {
    if (releases[i].date > releases[i - 1].date) {
      throw new Error(
        `website/changelog.md: ${releases[i].version} (${releases[i].date}) is newer than ` +
          `${releases[i - 1].version} (${releases[i - 1].date}) above it`,
      );
    }
  }
  return { meta, intro: intro.join("\n").trim(), releases };
}

// Inline markdown only: a summary is one paragraph, and <p> wrappers would
// fight the lede styling and the feed's description.
function inline(md) {
  return marked.parseInline(md, { gfm: true }).trim();
}

function indent(html, pad) {
  return html
    .trimEnd()
    .split("\n")
    .map((l) => (l ? `${pad}${l}` : l))
    .join("\n");
}

// -------------------------------------------------------------------- the CSS

// Only the rules the release list needs; everything else is the base sheet
// every page carries.
const EXTRA_CSS = `
  /* the page head puts the feed link on the lede's line, hard right */
  .headrow {
    display: flex; flex-wrap: wrap; align-items: baseline;
    justify-content: space-between; gap: 6px 28px;
  }
  .headrow .lede { margin-bottom: 0; }
  .feedlink {
    font-family: var(--octo-mono); font-size: 0.85rem;
    margin: 0; white-space: nowrap;
  }

  /* the intro runs the full wrap rather than the body's reading measure, so
     the one sentence stays on one line */
  .chintro { max-width: none; margin-top: 0; }

  /* the jump list: one row per minor version, its releases as chips beside
     the series label. 39 chips in one ragged block is unreadable. */
  .versions {
    display: flex; flex-wrap: wrap; gap: 8px 26px;
    margin: 0; padding: 0; list-style: none;
    font-family: var(--octo-mono); font-size: 0.85rem;
  }
  .vgroup { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; }
  .vlabel { color: var(--octo-muted); }
  .versions a {
    display: block;
    padding: 3px 9px;
    border: 1px solid var(--octo-line);
    border-radius: var(--octo-radius-chip);
    background: var(--octo-deep);
  }
  .versions a:hover { text-decoration: none; border-color: var(--octo-green); }

  /* one release: a rule above it, the version in mono, the date beside it */
  .release { border-top: 1px solid var(--octo-line); padding-top: 34px; margin-top: 34px; }
  .release:first-child { border-top: 0; padding-top: 0; margin-top: 0; }
  /* the anchor target must clear nothing, but a little air reads better when
     a jump lands on it */
  .release { scroll-margin-top: 18px; }
  .release h2 {
    margin: 0 0 6px;
    font-family: var(--octo-mono); font-weight: 700;
    font-size: 1.4rem; text-transform: none; letter-spacing: 0;
    line-height: 1.2;
  }
  .release h2 a { color: var(--octo-white); }
  .release h2 a:hover { color: var(--octo-green); text-decoration: none; }
  .relmeta {
    font-family: var(--octo-mono); font-size: 0.82rem;
    color: var(--octo-muted); margin: 0 0 0.9em;
  }
  .relsummary { color: var(--octo-white); margin: 0 0 0.2em; }
  .release ul { margin-top: 0.8em; }`;

// ------------------------------------------------------------------- the page

function renderPage({ meta, intro, releases }) {
  // Grouped by minor series, in the order the releases already come in, so
  // 0.10 leads and 0.1 closes without a numeric sort of string parts.
  const series = new Map();
  for (const r of releases) {
    const key = r.version.split(".").slice(0, 2).join(".");
    if (!series.has(key)) series.set(key, []);
    series.get(key).push(r);
  }
  const chips = [...series]
    .map(
      ([key, rs]) => `        <li class="vgroup"><span class="vlabel">${esc(key)}</span>${rs
        .map((r) => `<a href="#v${esc(r.version)}">${esc(r.version)}</a>`)
        .join("")}</li>`,
    )
    .join("\n");

  const list = releases
    .map((r) => {
      const bullets = r.body ? `\n${indent(marked.parse(r.body, { gfm: true }), "          ")}` : "";
      return `        <article class="release" id="v${esc(r.version)}">
          <h2><a href="#v${esc(r.version)}">${esc(r.version)}</a></h2>
          <p class="relmeta"><time datetime="${r.date}">${esc(r.human)}</time> · <a href="${REPO}/releases/tag/v${esc(r.version)}">release on GitHub</a></p>
          <p class="relsummary">${inline(r.summary)}</p>${bullets}
        </article>`;
    })
    .join("\n\n");

  const body = `<main>
  <div class="pagehead">
    <div class="wrap">
      <h1>${esc(meta.title)}</h1>
      <div class="headrow">
        <p class="lede">${esc(meta.description)}</p>
        <p class="feedlink"><a href="/changelog.xml">subscribe to releases (RSS)</a></p>
      </div>
    </div>
  </div>

  <section>
    <div class="wrap">
      <div class="post chintro">
${indent(marked.parse(intro, { gfm: true }), "        ")}
      </div>
      <ul class="versions">
${chips}
      </ul>
    </div>
  </section>

  <section>
    <div class="wrap">
      <div class="post">

${list}

      </div>
    </div>
  </section>
</main>`;

  return page({
    title: `octomon: ${meta.title.toLowerCase()}`,
    description: meta.description,
    url: URL_PATH,
    ogType: "website",
    ogTitle: `octomon: ${meta.title.toLowerCase()}`,
    ogDescription: meta.description,
    ogImage: DEFAULT_OG,
    body,
    extraCss: EXTRA_CSS,
    // Each release is a SoftwareApplication release note, so a crawler gets
    // the version list without parsing the prose.
    jsonLd: {
      "@context": "https://schema.org",
      "@type": "CollectionPage",
      "@id": URL_PATH,
      url: URL_PATH,
      name: `octomon ${meta.title.toLowerCase()}`,
      description: meta.description,
      inLanguage: "en-GB",
      author: PERSON,
      publisher: PUBLISHER,
      dateModified: releases[0].date,
      hasPart: releases.map((r) => ({
        "@type": "SoftwareApplication",
        name: "octomon",
        applicationCategory: "DeveloperApplication",
        operatingSystem: "macOS, Linux, Windows",
        softwareVersion: r.version,
        datePublished: r.date,
        releaseNotes: `${URL_PATH}#v${r.version}`,
        url: `${REPO}/releases/tag/v${r.version}`,
      })),
    },
  });
}

// ------------------------------------------------------------------- the feed

function renderFeed({ meta, releases }) {
  const items = releases
    .map((r) => {
      // The whole entry, not just the summary: a release feed that makes you
      // click through to learn what changed is a notification, not a feed.
      const html = `<p>${inline(r.summary)}</p>` + (r.body ? `\n${marked.parse(r.body, { gfm: true }).trim()}` : "");
      return `  <item>
    <title>octomon ${esc(r.version)}</title>
    <link>${URL_PATH}#v${esc(r.version)}</link>
    <guid isPermaLink="false">${ORIGIN}/changelog/v${esc(r.version)}</guid>
    <pubDate>${rssDate(r.date)}</pubDate>
    <description>${esc(r.summary)}</description>
    <content:encoded><![CDATA[${html}]]></content:encoded>
  </item>`;
    })
    .join("\n");

  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom" xmlns:content="http://purl.org/rss/1.0/modules/content/">
<channel>
  <title>octomon releases</title>
  <link>${URL_PATH}</link>
  <atom:link href="${ORIGIN}/changelog.xml" rel="self" type="application/rss+xml"/>
  <description>${esc(meta.description)}</description>
  <language>en</language>
${items}
</channel>
</rss>
`;
}

// Only the changelog block; tools/blog.mjs owns the blog block above it.
function updateSitemap(releases) {
  const file = join(SITE, "sitemap.xml");
  const xml = readFileSync(file, "utf8");
  const entry = `  <url>\n    <loc>${URL_PATH}</loc>\n    <lastmod>${releases[0].date}</lastmod>\n  </url>`;
  writeFileSync(
    file,
    replaceBlock(xml, "<!-- changelog:start -->", "<!-- changelog:end -->", entry, "sitemap.xml"),
  );
}

// ------------------------------------------------------------------------ run

const doc = loadReleases();
writeFileSync(join(SITE, "changelog.html"), renderPage(doc));
writeFileSync(join(SITE, "changelog.xml"), renderFeed(doc));
updateSitemap(doc.releases);
console.log(
  `  /changelog, /changelog.xml, sitemap.xml  (${doc.releases.length} releases, ` +
    `${doc.releases[doc.releases.length - 1].version} to ${doc.releases[0].version})`,
);
