#!/usr/bin/env node
// A preview server for website/, for editing the Markdown sources and seeing
// the result immediately.
//
//   npm run dev            # http://localhost:8788
//   npm run dev -- --port 9000
//
// It does three things wrangler dev would otherwise be needed for:
//
//   - resolves paths the way Cloudflare's assets pipeline does, so /changelog,
//     /privacy and /blog/ work rather than only their .html files;
//   - reruns tools/changelog.mjs or tools/blog.mjs when their sources change;
//   - reloads the open tab when a rebuild finishes, via an SSE snippet that is
//     injected into responses here and never written into the committed HTML.
//
// It serves only what is in website/, has no worker behind it, so /edge and
// /apt/* are not available here.

import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, readFileSync, statSync, watch } from "node:fs";
import { extname, join, normalize, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SITE = join(ROOT, "website");
const TOOLS = join(ROOT, "tools");

const portArg = process.argv.indexOf("--port");
const PORT = portArg === -1 ? 8788 : Number(process.argv[portArg + 1]);

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".xml": "application/xml; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".gif": "image/gif",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".mp4": "video/mp4",
};

// ------------------------------------------------------------------- reloading

const clients = new Set();

function announceReload() {
  for (const res of clients) res.write("data: reload\n\n");
}

// Injected into every HTML response this server sends, and only here: the
// committed pages must stay exactly what `wrangler deploy` uploads.
const RELOAD_SNIPPET = `<script>
  // dev server only, injected by tools/serve.mjs
  new EventSource("/__reload").onmessage = () => location.reload();
</script>
`;

// ------------------------------------------------------------------- building

// Each generator runs as its own process, so a syntax error in one of them
// reports itself and leaves the server up rather than taking it down.
let queued = null;
let running = false;

function runBuild(script, what) {
  if (running) {
    queued = [script, what];
    return;
  }
  running = true;
  console.log(`\n  ${what} changed, running tools/${script}`);
  const child = spawn(process.execPath, [join(TOOLS, script)], { stdio: "inherit" });
  child.on("exit", (code) => {
    running = false;
    if (code === 0) announceReload();
    else console.error(`  tools/${script} failed (exit ${code}); the last good output is still being served`);
    if (queued) {
      const [s, w] = queued;
      queued = null;
      runBuild(s, w);
    }
  });
}

let debounce = null;
function scheduleBuild(script, what) {
  clearTimeout(debounce);
  debounce = setTimeout(() => runBuild(script, what), 120);
}

// -------------------------------------------------------------------- serving

// Cloudflare's assets pipeline, as far as this site uses it: an exact file
// wins, then <path>.html, then <path>/index.html. That is what makes
// /changelog and /privacy resolve without their extensions.
function resolve(pathname) {
  const rel = normalize(decodeURIComponent(pathname)).replace(/^(\.\.[/\\])+/, "");
  const base = join(SITE, rel);
  if (!base.startsWith(SITE)) return null;

  const candidates = [];
  if (!base.endsWith("/")) candidates.push(base, `${base}.html`);
  candidates.push(join(base, "index.html"));
  for (const file of candidates) {
    if (existsSync(file) && statSync(file).isFile()) return file;
  }
  return null;
}

const server = createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  if (url.pathname === "/__reload") {
    res.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache",
      connection: "keep-alive",
    });
    res.write("retry: 500\n\n");
    clients.add(res);
    req.on("close", () => clients.delete(res));
    return;
  }

  const file = resolve(url.pathname);
  if (!file) {
    // The site's own 404, so the page under test is the one people will see.
    const notFound = join(SITE, "404.html");
    const body = existsSync(notFound)
      ? readFileSync(notFound, "utf8").replace("</body>", `${RELOAD_SNIPPET}</body>`)
      : "not found\n";
    res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
    res.end(body);
    return;
  }

  const type = TYPES[extname(file).toLowerCase()] ?? "application/octet-stream";
  // Nothing is cached: the whole point here is seeing the last save.
  const headers = { "content-type": type, "cache-control": "no-store" };
  if (type.startsWith("text/html")) {
    const html = readFileSync(file, "utf8").replace("</body>", `${RELOAD_SNIPPET}</body>`);
    res.writeHead(200, headers);
    res.end(html);
  } else {
    res.writeHead(200, headers);
    res.end(readFileSync(file));
  }
});

// ------------------------------------------------------------------------ run

// Build once at startup, so a source edited while the server was down is on
// screen from the first request.
runBuild("changelog.mjs", "startup");
runBuild("blog.mjs", "startup");

watch(SITE, { recursive: true }, (_event, name) => {
  if (!name?.endsWith(".md")) return;
  if (name === "changelog.md") scheduleBuild("changelog.mjs", "website/changelog.md");
  else if (name.startsWith("blog/")) scheduleBuild("blog.mjs", `website/${name}`);
});

// The generators are read fresh on every rebuild, but this file is not: edit
// it and the running server would keep the old behaviour. Restart instead.
watch(TOOLS, (_event, name) => {
  if (!name?.endsWith(".mjs")) return;
  if (name === "serve.mjs") {
    console.log("\n  tools/serve.mjs changed, restarting");
    const child = spawn(process.execPath, process.argv.slice(1), { stdio: "inherit" });
    child.on("spawn", () => process.exit(0));
    return;
  }
  if (name === "blog.mjs" || name === "ogcard.mjs") scheduleBuild("blog.mjs", `tools/${name}`);
  else if (name === "changelog.mjs") scheduleBuild("changelog.mjs", `tools/${name}`);
  else if (name === "page.mjs") {
    // Shared furniture: both generators emit it, so both have to rerun.
    scheduleBuild("changelog.mjs", "tools/page.mjs");
    runBuild("blog.mjs", "tools/page.mjs");
  }
});

server.listen(PORT, () => {
  console.log(`\n  octomon.dev preview on http://localhost:${PORT}`);
  console.log(`    changelog   http://localhost:${PORT}/changelog`);
  console.log(`    feed        http://localhost:${PORT}/changelog.xml`);
  console.log(`    blog        http://localhost:${PORT}/blog/`);
  console.log("\n  editing website/changelog.md rebuilds and reloads the tab. ctrl-c to stop.");
});
