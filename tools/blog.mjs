#!/usr/bin/env node
// Renders website/blog/<slug>/index.md to a sibling index.html, then writes the
// blog index, the RSS feed, the 404 page, and the blog block of sitemap.xml.
//
//   npm run blog
//
// The site is otherwise pure static assets: this and tools/changelog.mjs are
// the only build steps, and their output is committed, so `wrangler deploy`
// stays the whole deploy story. Output is deterministic, so re-running with no
// source change is a no-op.

import { spawn } from "node:child_process";
import { existsSync, readdirSync, readFileSync, rmSync, statSync, watch, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { marked } from "marked";
import { buildCards, CARD_FILE } from "./ogcard.mjs";
import {
  AUTHOR,
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
const BLOG = join(SITE, "blog");
const WORDS_PER_MINUTE = 220;

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
      <p class="postmeta"><span style="color: var(--octo-red)">● destination unreachable</span> · this end, not yours</p>
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
          <li><a href="/changelog">every release, and what changed</a></li>
          <li><a href="/understand">the FAQ and the glossary</a></li>
          <li><a href="/privacy">what octomon keeps, and what it does not</a></li>
          <li><a href="${REPO}">the source on GitHub</a></li>
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

// Rewrites only the blog block, so the hand-maintained core entries and the
// changelog block (tools/changelog.mjs owns that one) are never touched.
function updateSitemap(posts) {
  const file = join(SITE, "sitemap.xml");
  const xml = readFileSync(file, "utf8");
  const newest = posts.length ? posts[0].date : null;
  const entries = [
    ...(newest ? [{ loc: `${ORIGIN}/blog/`, mod: newest }] : []),
    ...posts.map((p) => ({ loc: `${ORIGIN}/blog/${p.slug}/`, mod: p.date })),
  ]
    .map((e) => `  <url>\n    <loc>${e.loc}</loc>\n    <lastmod>${e.mod}</lastmod>\n  </url>`)
    .join("\n");

  writeFileSync(
    file,
    replaceBlock(xml, "<!-- blog:start -->", "<!-- blog:end -->", entries, "sitemap.xml"),
  );
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
