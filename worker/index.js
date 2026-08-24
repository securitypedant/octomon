// octomon.dev: static site from ./website (served by the assets pipeline
// before this worker runs), plus /apt/* read from the octomon-apt R2 bucket —
// the Debian repository CI publishes into (.github/workflows/deb.yml).

const TYPES = {
  ".deb": "application/vnd.debian.binary-package",
  ".gz": "application/gzip",
  ".gpg": "application/pgp-keys",
  ".asc": "application/pgp-signature",
};

function contentType(key) {
  const dot = key.lastIndexOf(".");
  const ext = dot >= 0 ? key.slice(dot) : "";
  // Release/InRelease/Packages and anything unrecognised: plain text is what
  // apt expects to fetch, and octet-stream would still work.
  return TYPES[ext] ?? "text/plain; charset=utf-8";
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/apt/")) {
      // Non-asset paths that reach the worker have no answer of their own.
      return new Response("not found\n", { status: 404 });
    }
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("method not allowed\n", {
        status: 405,
        headers: { allow: "GET, HEAD" },
      });
    }
    const key = decodeURIComponent(url.pathname.slice("/apt/".length));
    if (!key) {
      return new Response("octomon apt repository\n", {
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }
    const object = await env.APT.get(`apt/${key}`);
    if (!object) {
      return new Response("not found\n", { status: 404 });
    }
    const headers = {
      "content-type": contentType(key),
      "content-length": String(object.size),
      etag: object.httpEtag,
      // Indexes change on release; short TTL keeps `apt update` honest while
      // still absorbing fleets that update in lockstep. Pool files are
      // versioned by name and could cache longer, but one rule is simpler.
      "cache-control": "public, max-age=300",
    };
    if (request.method === "HEAD") {
      return new Response(null, { headers });
    }
    return new Response(object.body, { headers });
  },
};
