// The furniture every generated page on octomon.dev shares: the nav, the
// footer, the base stylesheet, the <head> block and the small date/escaping
// helpers. Imported by tools/blog.mjs and tools/changelog.mjs so the two
// generators cannot drift apart the way two copies would.

export const ORIGIN = "https://octomon.dev";
export const REPO = "https://github.com/securitypedant/octomon";
export const DEFAULT_OG = `${ORIGIN}/images/octomon-og-card.png`;
export const AUTHOR = "Simon Thorpe";

// Shared by every JSON-LD block, so search engines and AI crawlers see one
// consistent author and publisher across the site rather than three variants.
export const PERSON = {
  "@type": "Person",
  name: AUTHOR,
  url: "https://github.com/securitypedant",
};
export const PUBLISHER = {
  "@type": "Organization",
  name: "octomon",
  url: `${ORIGIN}/`,
  logo: { "@type": "ImageObject", url: `${ORIGIN}/images/octomon-icon-tile.png` },
};

// ---------------------------------------------------------------- frontmatter

// A deliberately small YAML subset: `key: value` lines, optional quotes, no
// nesting and no lists. Anything richer belongs in the document body.
export function parseFrontmatter(raw, where) {
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

export function esc(s) {
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
export function humanDate(iso) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso);
  if (!m) throw new Error(`date must be YYYY-MM-DD, got: ${iso}`);
  return `${Number(m[3])} ${MONTHS[Number(m[2]) - 1]} ${m[1]}`;
}

// RFC 822, fixed at midnight UTC so a feed does not churn between builds.
export function rssDate(iso) {
  return new Date(`${iso}T00:00:00Z`).toUTCString();
}

// Rewrites only what sits between a pair of markers, so hand-maintained
// entries outside them are never touched. Used for sitemap.xml blocks and
// the draft list in .assetsignore.
export function replaceBlock(text, startMark, endMark, inner, where) {
  const a = text.indexOf(startMark);
  const b = text.indexOf(endMark);
  if (a === -1 || b === -1) {
    throw new Error(`${where}: missing ${startMark} / ${endMark} markers`);
  }
  return `${text.slice(0, a + startMark.length)}\n${inner}\n  ${text.slice(b)}`;
}

// --------------------------------------------------------------- the template

// Lifted from website/understand.html so generated pages carry the same page
// furniture as the rest of the site. The nav list is duplicated there by hand;
// if it changes, change it in index.html, understand.html, privacy.html and
// here.
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
      <a href="/howto">how to</a>
      <a href="/#features">features</a>
      <a href="/#video">video</a>
      <a href="/blog/">blog</a>
      <a href="/changelog">changelog</a>
      <a href="/understand">faq</a>
      <a href="/understand#glossary">glossary</a>
      <a href="/privacy">privacy</a>
      <a href="${REPO}">github</a>
    </nav>
  </div>
</header>`;

const FOOTER = `<footer>
  <div class="wrap">
    <span>© 2025–2026 Simon Thorpe · MIT or Apache-2.0</span>
    <a href="/blog/">blog</a>
    <a href="/changelog">changelog</a>
    <a href="/privacy">privacy</a>
    <a href="${REPO}">github.com/securitypedant/octomon</a>
    <a href="https://crates.io/crates/octomon">crates.io/crates/octomon</a>
    <a href="https://www.youtube.com/watch?v=sHPd2LeYvaw">intro video</a>
  </div>
</footer>`;

const ANALYTICS = `<!-- Cloudflare Web Analytics -->
<script type='module' src='https://static.cloudflareinsights.com/beacon.min.js' data-cf-beacon='{"token": "0ebdfd53d18b49d39f76f9d08b3499c9"}'></script>`;

// The base and chrome rules are the same block every other page carries; the
// .post and .postlist rules below them cover long-form body copy. A page that
// needs more passes it as `extraCss`.
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
    /* the closed nav is one row: the mark left, the burger right, both
       centred in a band with equal air above and below. The open menu gets
       its bottom air from the checked links rule below instead. */
    .nav { padding: 12px 0; }
    /* the open menu lines up with the mark above it, which the tablet rule
       has already nudged 12px in from the wrap's edge; without this the links
       sit further left than the logo they hang under */
    .menu-toggle:checked ~ nav.links {
      display: flex; flex-basis: 100%; flex-direction: column;
      gap: 12px; padding: 8px 2px 12px 12px; font-size: 1rem;
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

export function page({
  title,
  description,
  url,
  ogType,
  ogTitle,
  ogDescription,
  ogImage,
  body,
  extraMeta = "",
  extraCss = "",
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
<link rel="alternate" type="application/rss+xml" title="octomon releases" href="/changelog.xml">
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
${CSS}${extraCss ? `\n${extraCss}` : ""}
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
