// Generates the social card (og:image) for a blog post: 1200x630 PNG, drawn
// from the same brand tokens as the site and rendered by headless Chrome, the
// same SVG-to-PNG route the rest of the brand assets use.
//
// Cards are cached. A card is redrawn only when the title, the date or the
// layout itself changes, so an ordinary `npm run blog` needs neither Chrome nor
// a network connection. `npm run blog -- --cards` forces a redraw of all of
// them.

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

// Bump when the layout below changes, so every card is redrawn on the next run.
const LAYOUT_VERSION = 1;

const CARD_FILE = "card.png";
// Build state, so it lives beside the tool and not inside the served site.
const CACHE_FILE = join(dirname(fileURLToPath(import.meta.url)), "cards.cache.json");

// Where Chrome tends to be. CHROME_PATH wins if it is set.
const CHROME_CANDIDATES = [
  process.env.CHROME_PATH,
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
].filter(Boolean);

function findChrome() {
  return CHROME_CANDIDATES.find((p) => existsSync(p)) ?? null;
}

function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// Anton is condensed, so a long title still fits; step the size down rather
// than let a four-line title collide with the footer row.
function titleSize(title) {
  if (title.length <= 26) return 104;
  if (title.length <= 40) return 86;
  if (title.length <= 58) return 72;
  return 60;
}

// The card is one HTML page rather than a bare SVG, because webfonts load
// reliably in a document and not always in a standalone SVG.
function cardHtml({ title, human }, tokensCss) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<!-- website/tokens.css inlined: only the Google Fonts @import inside it needs
     the network, and its @import has to lead its own stylesheet. -->
<style>
${tokensCss}
</style>
<style>
  /* Every colour here is a token from tokens.css, no hex. */
  * { box-sizing: border-box; margin: 0; }
  html, body { width: 1200px; height: 630px; }
  body {
    background-color: var(--octo-ink);
    background-image:
      radial-gradient(900px 560px at 4% -10%, color-mix(in srgb, var(--octo-green) 16%, transparent), transparent 70%),
      radial-gradient(900px 620px at 100% 110%, color-mix(in srgb, var(--octo-magenta) 22%, transparent), transparent 70%);
    color: var(--octo-white);
    font-family: var(--octo-body);
    padding: 64px 72px 0;
    display: flex; flex-direction: column;
    /* the magenta rule the site puts under every page head */
    border-bottom: 10px solid var(--octo-magenta);
  }
  .mark { display: flex; align-items: center; gap: 18px; }
  .mark svg { width: 62px; height: 62px; display: block; }
  .wordmark {
    font-family: var(--octo-mono); font-weight: 800;
    font-size: 2.1rem; letter-spacing: 0.023em;
  }
  h1 {
    font-family: var(--octo-display);
    text-transform: uppercase;
    font-weight: 400;
    letter-spacing: -0.01em;
    line-height: 1.02;
    font-size: ${titleSize(title)}px;
    margin: auto 0;
    max-width: 15ch;
  }
  .foot {
    display: flex; justify-content: space-between; align-items: baseline;
    font-family: var(--octo-mono); font-size: 1.35rem;
    padding-bottom: 56px;
  }
  .foot .date { color: var(--octo-muted); }
  .foot .site { color: var(--octo-green); }
</style>
</head>
<body>
  <div class="mark">
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
  </div>

  <h1>${esc(title)}</h1>

  <div class="foot">
    <span class="date">${esc(human)}</span>
    <span class="site">octomon.dev</span>
  </div>
</body>
</html>
`;
}

function shoot(chrome, html, outPng) {
  const work = mkdtempSync(join(tmpdir(), "octomon-card-"));
  try {
    const page = join(work, "card.html");
    writeFileSync(page, html);
    execFileSync(
      chrome,
      [
        "--headless",
        "--disable-gpu",
        "--hide-scrollbars",
        "--force-device-scale-factor=1",
        "--window-size=1200,630",
        // let the webfonts arrive before the shutter
        "--virtual-time-budget=8000",
        `--screenshot=${outPng}`,
        `file://${page}`,
      ],
      { stdio: "ignore" },
    );
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

// Draws any card that is missing or stale. Returns the set of slugs that now
// have a card on disk, so the caller can point og:image at it.
export function buildCards(blogDir, posts, { force = false, tokensCss = "" } = {}) {
  const cacheFile = CACHE_FILE;
  let cache = {};
  try {
    cache = JSON.parse(readFileSync(cacheFile, "utf8"));
  } catch {
    // no cache yet, or it is unreadable: draw everything
  }

  const wanted = posts.filter((p) => {
    const png = join(blogDir, p.slug, CARD_FILE);
    const key = createHash("sha256")
      .update(`${LAYOUT_VERSION}\n${p.title}\n${p.human}`)
      .digest("hex")
      .slice(0, 16);
    p.cardKey = key;
    return force || !existsSync(png) || cache[p.slug] !== key;
  });

  const have = new Set(
    posts.filter((p) => existsSync(join(blogDir, p.slug, CARD_FILE))).map((p) => p.slug),
  );

  if (wanted.length === 0) return have;

  const chrome = findChrome();
  if (!chrome) {
    console.warn(
      `  no Chrome found, so ${wanted.length} social card(s) were not drawn.\n` +
        "  Set CHROME_PATH, or install Chrome, then re-run. Those posts fall back\n" +
        "  to the site's default og card.",
    );
    return have;
  }

  for (const p of wanted) {
    const png = join(blogDir, p.slug, CARD_FILE);
    shoot(chrome, cardHtml(p, tokensCss), png);
    if (!existsSync(png)) throw new Error(`card render produced nothing for blog/${p.slug}`);
    cache[p.slug] = p.cardKey;
    have.add(p.slug);
    console.log(`  drew  /blog/${p.slug}/${CARD_FILE}`);
  }

  // drop cache entries for posts that no longer exist
  const live = new Set(posts.map((p) => p.slug));
  for (const slug of Object.keys(cache)) if (!live.has(slug)) delete cache[slug];

  const ordered = Object.fromEntries(Object.keys(cache).sort().map((k) => [k, cache[k]]));
  writeFileSync(cacheFile, `${JSON.stringify(ordered, null, 2)}\n`);
  return have;
}

export { CARD_FILE };
