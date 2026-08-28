#!/usr/bin/env node
// Renders website/blog/<slug>/index.md to a sibling index.html, then writes the
// blog index, the RSS feed, and the blog block of sitemap.xml.
//
//   npm run blog
//
// The site is otherwise pure static assets: this is the only build step, and
// its output is committed, so `wrangler deploy` stays the whole deploy story.
// Output is deterministic, so re-running with no source change is a no-op.

import { spawn } from "node:child_process";
import { existsSync, readdirSync, readFileSync, rmSync, statSync, watch, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { marked } from "marked";
import { buildCards, CARD_FILE } from "./ogcard.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SITE = join(ROOT, "website");
const BLOG = join(SITE, "blog");
const ORIGIN = "https://octomon.dev";
const DEFAULT_OG = `${ORIGIN}/images/octomon-og-card.png`;
const WORDS_PER_MINUTE = 220;
const AUTHOR = "Simon Thorpe";

// Shared by every JSON-LD block, so search engines and AI crawlers see one
// consistent author and publisher across the blog rather than three variants.
const PERSON = {
  "@type": "Person",
  name: AUTHOR,
  url: "https://github.com/securitypedant",
};
const PUBLISHER = {
  "@type": "Organization",
  name: "octomon",
  url: `${ORIGIN}/`,
  logo: { "@type": "ImageObject", url: `${ORIGIN}/images/octomon-icon-tile.png` },
};

// ---------------------------------------------------------------- frontmatter

// A deliberately small YAML subset: `key: value` lines, optional quotes, no
// nesting and no lists. Anything richer belongs in the post body.
function parseFrontmatter(raw, where) {
  if (!raw.startsWith("---\n")) {
    throw new Error(`${where}: no frontmatter block (file must start with ---)`);
  }
  const end = raw.indexOf("\n---", 3);
  if (end === -1) throw new Error(`${where}: frontmatter block is never closed`);

  const meta = {};
  for (const line of raw.slice(4, end).split("\n")) {
    if (!line.trim() || line.trimStart().startsWith("#")) continue;
    const colon = line.indexOf(":");
    if (colon === -1) throw new Error(`${where}: cannot parse frontmatter line: ${line}`);
    const key = line.slice(0, colon).trim();
    let value = line.slice(colon + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    meta[key] = value;
  }
  const body = raw.slice(raw.indexOf("\n", end + 1) + 1);
  return { meta, body };
}

// ---------------------------------------------------------------- small parts

function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

const MONTHS = [
  "January", "February", "March", "April", "May", "June",
  "July", "August", "September", "October", "November", "December",
];

// 2026-08-28 -> 28 August 2026
function humanDate(iso) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso);
  if (!m) throw new Error(`date must be YYYY-MM-DD, got: ${iso}`);
  return `${Number(m[3])} ${MONTHS[Number(m[2]) - 1]} ${m[1]}`;
}

// RFC 822, fixed at midnight UTC so the feed does not churn between builds.
function rssDate(iso) {
  return new Date(`${iso}T00:00:00Z`).toUTCString();
}

function countWords(markdown) {
  return markdown
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/<!--[\s\S]*?-->/g, " ")
    .split(/\s+/)
    .filter(Boolean).length;
}

function readingMinutes(words) {
  return Math.max(1, Math.round(words / WORDS_PER_MINUTE));
}

// --------------------------------------------------------------- the template

// Lifted from website/understand.html so blog pages are the same page furniture
// as the rest of the site. The nav list is duplicated there by hand; if it
// changes, change it in index.html, understand.html, privacy.html and here.
const NAV = `<header>
  <div class="wrap nav">
    <a class="mark" href="/" aria-label="octomon home">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" role="img" aria-hidden="true">
        <g fill="var(--octo-green)">
          <g transform="rotate(-14 22 64)"><rect x="18" y="60" width="8" height="44" rx="4"/></g>
          <g transform="rotate(-7 34 64)"><rect x="30" y="60" width="8" height="58" rx="4"/></g>
          <rect x="42" y="60" width="8" height="40" rx="4"/>
          <rect x="54" y="60" width="8" height="54" rx="4"/>
          <rect x="66" y="60" width="8" height="42" rx="4"/>
          <rect x="78" y="60" width="8" height="58" rx="4" fill="var(--octo-amber)"/>
          <g transform="rotate(7 94 64)"><rect x="90" y="60" width="8" height="46" rx="4"/></g>
          <g transform="rotate(14 106 64)"><rect x="102" y="60" width="8" height="60" rx="4"/></g>
        </g>
        <path d="M22 70 C22 42 38 18 64 18 C90 18 106 42 106 70 Z" fill="var(--octo-green)"/>
        <rect x="44" y="38" width="11" height="18" rx="1.5" fill="var(--octo-red)"/>
        <rect x="73" y="38" width="11" height="18" rx="1.5" fill="var(--octo-red)"/>
      </svg>
      <span class="wordmark">octomon</span>
    </a>
    <input type="checkbox" id="menu" class="menu-toggle" hidden>
    <label for="menu" class="menu-btn" aria-label="menu">&#9776;</label>
    <nav class="links" aria-label="site">
      <a href="/#install">install</a>
      <a href="/#features">features</a>
      <a href="/#video">video</a>
      <a href="/blog/">blog</a>
      <a href="/understand">faq</a>
      <a href="/understand#glossary">glossary</a>
      <a href="/privacy">privacy</a>
      <a href="https://github.com/securitypedant/octomon">github</a>
    </nav>
  </div>
</header>`;

const FOOTER = `<footer>
  <div class="wrap">
    <span>© 2025–2026 Simon Thorpe · MIT or Apache-2.0</span>
    <a href="/blog/">blog</a>
    <a href="/privacy">privacy</a>
    <a href="https://github.com/securitypedant/octomon">github.com/securitypedant/octomon</a>
    <a href="https://crates.io/crates/octomon">crates.io/crates/octomon</a>
    <a href="https://www.youtube.com/watch?v=sHPd2LeYvaw">intro video</a>
  </div>
</footer>`;

// Lifted from website/index.html. Every image in a post body opens full
// screen; only posts that actually carry an image get this appended.
const LIGHTBOX = `<div class="lightbox" id="lightbox" role="dialog" aria-modal="true" aria-label="image, full size, click anywhere to close" hidden>
  <img alt="">
</div>

<script>
  // Lightbox: any image in the post opens full-screen; any click (or Esc)
  // closes. currentSrc reuses whichever rendition the browser already fetched.
  const lb = document.getElementById("lightbox");
  const lbImg = lb.querySelector("img");
  const openLb = (img) => {
    lbImg.src = img.currentSrc || img.src;
    lbImg.alt = img.alt;
    lb.hidden = false;
    document.body.style.overflow = "hidden";
  };
  const closeLb = () => {
    lb.hidden = true;
    lbImg.removeAttribute("src");
    document.body.style.overflow = "";
  };
  for (const img of document.querySelectorAll(".post img")) {
    img.tabIndex = 0;
    img.setAttribute("role", "button");
    img.addEventListener("click", () => openLb(img));
    img.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openLb(img); }
    });
  }
  lb.addEventListener("click", closeLb);
  addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !lb.hidden) closeLb();
  });
</script>`;

const ANALYTICS = `<!-- Cloudflare Web Analytics -->
<script type='module' src='https://static.cloudflareinsights.com/beacon.min.js' data-cf-beacon='{"token": "0ebdfd53d18b49d39f76f9d08b3499c9"}'></script>`;

// The base and chrome rules are the same block every other page carries; the
// .post and .postlist rules below them are the only thing new here.
const CSS = `  /* Every colour on this page is a token from tokens.css, no hex here. */
  * { box-sizing: border-box; }
  html { scroll-behavior: smooth; }
  @media (prefers-reduced-motion: reduce) {
    html { scroll-behavior: auto; }
    *, *::before, *::after { transition: none !important; animation: none !important; }
  }
  body {
    margin: 0;
    background: var(--octo-ink);
    color: var(--octo-white);
    font-family: var(--octo-body);
    font-size: 17px;
    line-height: 1.6;
    /* wide content must scroll inside its own container, never the page */
    overflow-x: clip;
  }
  a { color: var(--octo-green); text-decoration: none; }
  a:hover { text-decoration: underline; }
  :focus-visible {
    outline: 2px solid var(--octo-green);
    outline-offset: 2px;
    border-radius: 4px;
  }
  h1, h2 {
    font-family: var(--octo-display);
    text-transform: uppercase;
    letter-spacing: -0.01em;
    font-weight: 400;
    line-height: 1.05;
    margin: 0 0 0.4em;
  }
  kbd {
    font-family: var(--octo-mono);
    font-size: 0.85em;
    background: var(--octo-deep);
    border: 1px solid var(--octo-line);
    border-bottom-width: 2px;
    border-radius: 5px;
    padding: 0.1em 0.45em;
  }
  .wrap { max-width: 1120px; margin: 0 auto; padding: 0 24px; }

  header {
    border-bottom: 1px solid var(--octo-line);
    background: var(--octo-ink);
  }
  .nav {
    display: flex; flex-wrap: wrap; align-items: center; gap: 8px 12px;
    padding: 14px 0;
  }
  .mark { display: flex; align-items: center; gap: 12px; color: var(--octo-white); }
  .mark:hover { text-decoration: none; }
  .mark svg { width: 34px; height: 34px; display: block; }
  .wordmark {
    font-family: var(--octo-mono);
    font-weight: 800;
    font-size: 1.35rem;
    letter-spacing: 0.023em;
  }
  nav.links { margin-left: auto; display: flex; flex-wrap: wrap; gap: 8px 22px; font-family: var(--octo-mono); font-size: 0.95rem; }
  /* mobile hamburger: pure CSS (checkbox), desktop never sees it */
  .menu-btn { display: none; }

  section { padding: 64px 0; }
  section + section { border-top: 1px solid var(--octo-line); }
  /* the body follows the page head directly, so it needs far less air above
     it than a section that follows another section does */
  main > section { padding-top: 36px; }
  h1 { font-size: clamp(2rem, 4.5vw, 3.4rem); }
  h2 { font-size: clamp(1.6rem, 3vw, 2.4rem); }
  .lede { color: var(--octo-muted); max-width: 56em; margin-top: 0; }

  /* the page head: no hero art, just the title over a magenta rule */
  .pagehead { padding: 44px 0 26px; border-bottom: 2px solid var(--octo-magenta); }
  /* the head's lede runs the full wrap: a one-line description should stay
     on one line rather than wrap early into a narrow column */
  .pagehead .lede { max-width: none; }
  /* byline under a post title: date and reading time, never a name */
  .postmeta {
    font-family: var(--octo-mono);
    font-size: 0.85rem;
    color: var(--octo-muted);
    margin: 0 0 0.9em;
  }

  /* the index: one card per post, newest first, same card as /privacy */
  .postlist { margin-top: 0; }
  .postlist .card:first-child { margin-top: 0; }
  .card {
    background: var(--octo-deep);
    border: 1px solid var(--octo-line);
    border-radius: var(--octo-radius-card);
    padding: 22px 24px;
    margin-top: 24px;
  }
  .card h2 {
    margin: 0 0 10px;
    font-family: var(--octo-mono); font-weight: 700; font-size: 1.15rem;
    text-transform: none; letter-spacing: 0; line-height: 1.35;
  }
  .card h2 a { color: var(--octo-green); }
  .card p { margin: 0 0 0.7em; color: var(--octo-muted); }
  .card p:last-child { margin-bottom: 0; }
  .card .more { font-family: var(--octo-mono); font-size: 0.85rem; }

  /* the post body: one column at a readable measure, not the full 1120 */
  .post { max-width: 36em; }
  .post p, .post li { color: var(--octo-white); }
  .post > p:first-child { margin-top: 0; }
  .post h2 {
    /* smaller than a section head: a subhead should not shout */
    font-size: clamp(1.3rem, 2.2vw, 1.7rem);
    margin: 1.9em 0 0.5em;
  }
  .post h3 {
    margin: 1.6em 0 0.4em;
    font-family: var(--octo-mono); font-weight: 700; font-size: 1.05rem;
    color: var(--octo-green);
  }
  .post ul, .post ol { padding-left: 1.3em; margin: 1em 0; }
  .post li { margin: 0.5em 0; }
  .post li::marker { color: var(--octo-magenta); }
  .post code {
    font-family: var(--octo-mono); font-size: 0.9em;
    color: var(--octo-green);
    background: var(--octo-deep);
    border: 1px solid var(--octo-line);
    border-radius: 5px;
    padding: 0.08em 0.35em;
    /* a run that wraps gets its padding and border on both halves */
    -webkit-box-decoration-break: clone;
    box-decoration-break: clone;
  }
  .post pre {
    background: var(--octo-deep);
    border: 1px solid var(--octo-line);
    border-radius: var(--octo-radius-chip);
    padding: 16px 18px;
    /* the block scrolls, the page never does */
    overflow-x: auto;
  }
  .post pre code {
    background: none; border: 0; padding: 0;
    color: var(--octo-white); font-size: 0.88rem; line-height: 1.5;
  }
  .post blockquote {
    margin: 1.4em 0;
    padding: 2px 0 2px 18px;
    border-left: 3px solid var(--octo-magenta);
    color: var(--octo-muted);
  }
  .post blockquote p:last-child { margin-bottom: 0; }
  .post img {
    max-width: 100%; height: auto; display: block;
    border: 1px solid var(--octo-line);
    border-radius: var(--octo-radius-card);
    cursor: zoom-in;
  }

  /* lightbox: any click (or Esc) closes. Same as the homepage's. */
  .lightbox {
    position: fixed; inset: 0; z-index: 50;
    display: flex; align-items: center; justify-content: center;
    padding: 3vmin;
    background: color-mix(in srgb, var(--octo-deep) 94%, transparent);
    cursor: zoom-out;
  }
  .lightbox[hidden] { display: none; }
  .lightbox img {
    max-width: 100%; max-height: 100%; width: auto; height: auto;
    border: 1px solid var(--octo-line);
    border-radius: var(--octo-radius-card);
  }
  .post figure { margin: 1.8em 0; }
  .post figcaption {
    font-family: var(--octo-mono); font-size: 0.82rem;
    color: var(--octo-muted); margin-top: 10px;
  }
  .post hr { border: 0; border-top: 1px solid var(--octo-line); margin: 2.4em 0; }
  .post strong { color: var(--octo-white); }
  .post table { width: 100%; border-collapse: collapse; margin: 1.4em 0; font-size: 0.94rem; }
  .post th, .post td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--octo-line); }
  .post th { font-family: var(--octo-mono); font-weight: 700; color: var(--octo-green); }

  .backlink { font-family: var(--octo-mono); font-size: 0.9rem; margin-top: 48px; }

  footer {
    border-top: 2px solid var(--octo-magenta); /* decorative rule */
    padding: 28px 0 40px;
    color: var(--octo-muted);
    font-size: 0.9rem;
  }
  footer .wrap { display: flex; flex-wrap: wrap; gap: 8px 24px; align-items: center; }

  /* phones */
  @media (max-width: 600px) {
    .wrap { padding: 0 16px; }
    /* hamburger: the mark keeps the left edge; links drop into a column
       only when the burger is checked */
    .menu-btn {
      display: block; margin-left: auto; cursor: pointer;
      font-size: 1.5rem; line-height: 1; color: var(--octo-white);
      padding: 4px 8px; border: 1px solid var(--octo-line);
      border-radius: var(--octo-radius-chip);
    }
    nav.links { display: none; }
    /* air between the mark/burger row and the rule beneath it */
    .nav { padding-bottom: 24px; }
    .menu-toggle:checked ~ nav.links {
      display: flex; flex-basis: 100%; flex-direction: column;
      gap: 12px; padding: 8px 2px 12px; font-size: 1rem;
    }
    section { padding: 44px 0; }
    .pagehead { padding: 32px 0 22px; }
    main > section { padding-top: 28px; }
    .card { padding: 16px; }
    .post pre { padding: 12px 14px; }
    footer .wrap { flex-direction: column; align-items: flex-start; gap: 6px; }
  }
  @media (max-width: 480px) {
    .wordmark { font-size: 1.15rem; }
  }`;

function page({
  title,
  description,
  url,
  ogType,
  ogTitle,
  ogDescription,
  ogImage,
  body,
  extraMeta = "",
  jsonLd = null,
  tail = "",
}) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(description)}">
<meta name="author" content="${esc(AUTHOR)}">
<link rel="canonical" href="${esc(url)}">
<link rel="alternate" type="application/rss+xml" title="octomon blog" href="/blog/feed.xml">
<link rel="icon" type="image/png" sizes="32x32" href="/images/octomon-logo-32.png">
<link rel="icon" type="image/png" sizes="512x512" href="/images/octomon-icon-tile.png">
<link rel="apple-touch-icon" sizes="180x180" href="/images/octomon-icon-tile.png">
<meta property="og:site_name" content="octomon">
<meta property="og:locale" content="en_GB">
<meta property="og:type" content="${esc(ogType)}">
<meta property="og:url" content="${esc(url)}">
<meta property="og:title" content="${esc(ogTitle)}">
<meta property="og:description" content="${esc(ogDescription)}">
<meta property="og:image" content="${esc(ogImage)}">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="${esc(ogTitle)}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${esc(ogTitle)}">
<meta name="twitter:description" content="${esc(ogDescription)}">
<meta name="twitter:image" content="${esc(ogImage)}">
${extraMeta}<link rel="stylesheet" href="/tokens.css">
<style>
${CSS}
</style>
${jsonLd ? `<script type="application/ld+json">\n${JSON.stringify(jsonLd, null, 2)}\n</script>\n` : ""}${ANALYTICS}
</head>
<body>

${NAV}

${body}

${FOOTER}
${tail ? `\n${tail}\n` : ""}
</body>
</html>
`;
}

// ------------------------------------------------------------------ the posts

function loadPosts() {
  const dirs = readdirSync(BLOG)
    .filter((name) => statSync(join(BLOG, name)).isDirectory())
    .sort();

  const posts = [];
  const drafts = [];
  for (const slug of dirs) {
    const file = join(BLOG, slug, "index.md");
    let raw;
    try {
      raw = readFileSync(file, "utf8");
    } catch {
      console.warn(`  skipped blog/${slug}: no index.md`);
      continue;
    }
    const { meta, body } = parseFrontmatter(raw, `blog/${slug}/index.md`);
    for (const key of ["title", "description", "date"]) {
      if (!meta[key]) throw new Error(`blog/${slug}/index.md: missing "${key}" in frontmatter`);
    }
    if (meta.draft === "true") {
      // Unpublishing has to remove the page, not merely stop writing it: a
      // stale index.html from an earlier build would otherwise stay live at
      // its own URL, unlisted but perfectly readable.
      const stale = join(BLOG, slug, "index.html");
      if (existsSync(stale)) {
        rmSync(stale);
        console.log(`  draft, unpublished (removed its page): blog/${slug}`);
      } else {
        console.log(`  draft, not published: blog/${slug}`);
      }
      drafts.push(slug);
      continue;
    }
    posts.push({
      slug,
      title: meta.title,
      description: meta.description,
      date: meta.date,
      human: humanDate(meta.date),
      words: countWords(body),
      minutes: readingMinutes(countWords(body)),
      // frontmatter wins; otherwise the generated card, set once it exists
      ogImage: meta.og_image
        ? new URL(meta.og_image, `${ORIGIN}/blog/${slug}/`).href
        : DEFAULT_OG,
      pinnedOg: Boolean(meta.og_image),
      body,
    });
  }
  // newest first, slug breaking ties so two posts on one day stay stable
  posts.sort((a, b) => (a.date === b.date ? a.slug.localeCompare(b.slug) : b.date.localeCompare(a.date)));
  posts.drafts = drafts;
  return posts;
}

function renderPost(post) {
  const url = `${ORIGIN}/blog/${post.slug}/`;
  const html = marked.parse(post.body, { gfm: true });
  const hasImage = /<img\b/i.test(html);
  const body = `<main>
  <div class="pagehead">
    <div class="wrap">
      <h1>${esc(post.title)}</h1>
      <p class="postmeta"><time datetime="${post.date}">${esc(post.human)}</time> · ${post.minutes} min read</p>
      <p class="lede">${esc(post.description)}</p>
    </div>
  </div>

  <section>
    <div class="wrap">
      <article class="post">
${html.trimEnd().split("\n").map((l) => (l ? `        ${l}` : l)).join("\n")}
      </article>
      <p class="backlink"><a href="/blog/">← all posts</a></p>
    </div>
  </section>
</main>`;

  return page({
    title: `octomon: ${post.title}`,
    description: post.description,
    url,
    ogType: "article",
    ogTitle: post.title,
    ogDescription: post.description,
    ogImage: post.ogImage,
    body,
    tail: hasImage ? LIGHTBOX : "",
    extraMeta:
      `<meta property="article:published_time" content="${post.date}">\n` +
      `<meta property="article:author" content="${esc(AUTHOR)}">\n`,
    // BlogPosting is what search engines and AI crawlers read to get the
    // headline, date and author without having to infer them from the markup.
    jsonLd: {
      "@context": "https://schema.org",
      "@type": "BlogPosting",
      "@id": url,
      mainEntityOfPage: { "@type": "WebPage", "@id": url },
      url,
      headline: post.title,
      description: post.description,
      datePublished: post.date,
      dateModified: post.date,
      author: PERSON,
      publisher: PUBLISHER,
      image: post.ogImage,
      wordCount: post.words,
      inLanguage: "en-GB",
      isPartOf: { "@type": "Blog", "@id": `${ORIGIN}/blog/`, name: "octomon blog" },
    },
  });
}

function renderIndex(posts) {
  const cards = posts
    .map(
      (p) => `      <article class="card">
        <p class="postmeta"><time datetime="${p.date}">${esc(p.human)}</time> · ${p.minutes} min read</p>
        <h2><a href="/blog/${p.slug}/">${esc(p.title)}</a></h2>
        <p>${esc(p.description)}</p>
        <p class="more"><a href="/blog/${p.slug}/">read →</a></p>
      </article>`,
    )
    .join("\n\n");

  const body = `<main>
  <div class="pagehead">
    <div class="wrap">
      <h1>Blog</h1>
      <p class="lede">Notes on building octomon: why it works the way it does,
      what shipped, and what turned out to be wrong. Occasional, not scheduled.</p>
    </div>
  </div>

  <section>
    <div class="wrap">
      <div class="postlist">

${cards}

      </div>
    </div>
  </section>
</main>`;

  return page({
    title: "octomon: blog",
    description:
      "Notes on building octomon, a terminal dashboard that tells you whether it's your Wi-Fi, your ISP or the Internet.",
    url: `${ORIGIN}/blog/`,
    ogType: "website",
    ogTitle: "octomon: blog",
    ogDescription: "Notes on building octomon: why it works the way it does, and what shipped.",
    ogImage: DEFAULT_OG,
    body,
    // the Blog node plus every post on it, so a crawler gets the whole index
    // from one page without walking the links
    jsonLd: {
      "@context": "https://schema.org",
      "@type": "Blog",
      "@id": `${ORIGIN}/blog/`,
      url: `${ORIGIN}/blog/`,
      name: "octomon blog",
      description: "Notes on building octomon: why it works the way it does, and what shipped.",
      inLanguage: "en-GB",
      author: PERSON,
      publisher: PUBLISHER,
      blogPost: posts.map((p) => ({
        "@type": "BlogPosting",
        "@id": `${ORIGIN}/blog/${p.slug}/`,
        url: `${ORIGIN}/blog/${p.slug}/`,
        headline: p.title,
        description: p.description,
        datePublished: p.date,
        author: PERSON,
        image: p.ogImage,
      })),
    },
  });
}

// The site's 404. Generated here rather than hand-written because this is the
// only place that already owns the nav, footer and base CSS, so it cannot drift
// away from the other pages the way a fourth hand-maintained file would.
function render404() {
  const body = `<main>
  <div class="pagehead">
    <div class="wrap">
      <h1>404</h1>
      <p class="postmeta"><span style="color: var(--octo-red)">\u25cf destination unreachable</span> \u00b7 this end, not yours</p>
      <p class="lede">The address resolved, the server answered, and there is
      nothing at this path. Your connection is fine, which is the one diagnosis
      octomon cannot help you with.</p>
    </div>
  </div>

  <section>
    <div class="wrap">
      <article class="post">
        <p>Somewhere to go instead:</p>
        <ul>
          <li><a href="/">what octomon is, and what the dashboard shows</a></li>
          <li><a href="/blog/">the blog</a></li>
          <li><a href="/understand">the FAQ and the glossary</a></li>
          <li><a href="/privacy">what octomon keeps, and what it does not</a></li>
          <li><a href="https://github.com/securitypedant/octomon">the source on GitHub</a></li>
        </ul>
      </article>
    </div>
  </section>
</main>`;

  return page({
    title: "octomon: not found",
    description: "That page does not exist on octomon.dev.",
    url: `${ORIGIN}/404`,
    ogType: "website",
    ogTitle: "octomon: not found",
    ogDescription: "That page does not exist on octomon.dev.",
    ogImage: DEFAULT_OG,
    body,
    // a 404 has no business in an index
    extraMeta: '<meta name="robots" content="noindex">\n',
  });
}

function renderFeed(posts) {
  const items = posts
    .map(
      (p) => `  <item>
    <title>${esc(p.title)}</title>
    <link>${ORIGIN}/blog/${p.slug}/</link>
    <guid isPermaLink="true">${ORIGIN}/blog/${p.slug}/</guid>
    <pubDate>${rssDate(p.date)}</pubDate>
    <description>${esc(p.description)}</description>
  </item>`,
    )
    .join("\n");

  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
  <title>octomon blog</title>
  <link>${ORIGIN}/blog/</link>
  <atom:link href="${ORIGIN}/blog/feed.xml" rel="self" type="application/rss+xml"/>
  <description>Notes on building octomon.</description>
  <language>en</language>
${items}
</channel>
</rss>
`;
}

// Keeps the draft block of website/.assetsignore in step with the frontmatter,
// so a `draft: true` post's images and any other files in its folder are never
// uploaded either. Without this the page and its Markdown are gone but a
// screenshot is still fetchable by guessing its name.
function updateAssetsIgnore(draftSlugs) {
  const file = join(SITE, ".assetsignore");
  const text = readFileSync(file, "utf8");
  const start = "# drafts:start";
  const end = "# drafts:end";
  const a = text.indexOf(start);
  const b = text.indexOf(end);
  if (a === -1 || b === -1) throw new Error(`.assetsignore: missing ${start} / ${end} markers`);

  const lines = draftSlugs.map((s) => `blog/${s}/`).join("\n");
  const next = `${text.slice(0, a + start.length)}\n${lines}${lines ? "\n" : ""}${text.slice(b)}`;
  writeFileSync(file, next);
}

// Rewrites only what sits between the markers, so the hand-maintained core
// entries above them are never touched.
function updateSitemap(posts) {
  const file = join(SITE, "sitemap.xml");
  const xml = readFileSync(file, "utf8");
  const start = "<!-- blog:start -->";
  const end = "<!-- blog:end -->";
  const a = xml.indexOf(start);
  const b = xml.indexOf(end);
  if (a === -1 || b === -1) {
    throw new Error(`sitemap.xml: missing ${start} / ${end} markers`);
  }
  const newest = posts.length ? posts[0].date : null;
  const entries = [
    ...(newest ? [{ loc: `${ORIGIN}/blog/`, mod: newest }] : []),
    ...posts.map((p) => ({ loc: `${ORIGIN}/blog/${p.slug}/`, mod: p.date })),
  ]
    .map((e) => `  <url>\n    <loc>${e.loc}</loc>\n    <lastmod>${e.mod}</lastmod>\n  </url>`)
    .join("\n");

  const next = `${xml.slice(0, a + start.length)}\n${entries}\n  ${xml.slice(b)}`;
  writeFileSync(file, next);
}

// ------------------------------------------------------------------------ run

function build({ force = false } = {}) {
  const posts = loadPosts();

  // Social cards first: a post's og:image points at its own card once drawn.
  const withCard = buildCards(BLOG, posts, {
    force,
    tokensCss: readFileSync(join(SITE, "tokens.css"), "utf8"),
  });
  for (const post of posts) {
    if (!post.pinnedOg && withCard.has(post.slug)) {
      post.ogImage = `${ORIGIN}/blog/${post.slug}/${CARD_FILE}`;
    }
  }

  for (const post of posts) {
    writeFileSync(join(BLOG, post.slug, "index.html"), renderPost(post));
    console.log(`  /blog/${post.slug}  (${post.minutes} min)`);
  }
  writeFileSync(join(BLOG, "index.html"), renderIndex(posts));
  writeFileSync(join(BLOG, "feed.xml"), renderFeed(posts));
  writeFileSync(join(SITE, "404.html"), render404());
  updateSitemap(posts);
  updateAssetsIgnore(posts.drafts);
  console.log(`  /blog, /blog/feed.xml, /404.html, sitemap.xml  (${posts.length} posts)`);
}

const force = process.argv.includes("--cards");
build({ force });

// --watch: rebuild whenever a post's markdown changes, so `wrangler dev` picks
// the new HTML straight up. A bad frontmatter block reports itself and waits
// for the next save rather than killing the watcher.
if (process.argv.includes("--watch")) {
  let pending = null;
  const rebuild = (what) => {
    clearTimeout(pending);
    pending = setTimeout(() => {
      console.log(`\n  ${what} changed`);
      try {
        build({ force });
      } catch (err) {
        console.error(`  ${err.message}`);
      }
    }, 120);
  };

  watch(BLOG, { recursive: true }, (_event, name) => {
    if (name?.endsWith(".md")) rebuild(name);
  });

  // The renderer itself is held in memory, so editing it would otherwise let a
  // long-running watcher keep emitting the old HTML and quietly overwrite a
  // fresh `npm run blog`. Restart the process instead.
  const TOOLS = dirname(fileURLToPath(import.meta.url));
  watch(TOOLS, (_event, name) => {
    if (!name?.endsWith(".mjs")) return;
    console.log(`\n  tools/${name} changed, restarting the watcher`);
    const child = spawn(process.execPath, process.argv.slice(1), {
      stdio: "inherit",
      detached: false,
    });
    child.on("spawn", () => process.exit(0));
  });

  console.log("\n  watching website/blog for markdown changes, ctrl-c to stop");
}
