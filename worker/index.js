// octomon.dev: static site from ./website (served by the assets pipeline
// before this worker runs), /apt/* read from the octomon-apt R2 bucket —
// the Debian repository CI publishes into (.github/workflows/deb.yml) —
// and /edge, the one endpoint the octomon client itself calls.
//
// /edge privacy contract (see the site's /privacy page, which is the public
// face of this promise): the handler is pure request→response. It reads
// request.cf — facts Cloudflare computed before this code ran — and returns
// them TO THE CALLER. It stores nothing about the caller: no logging of
// request data, no KV/R2 writes, and the single Analytics Engine datapoint
// (when the EDGE_STATS binding exists) carries only octomon's own version
// string and a count — no IP, no location, no user agent echo. Workers Logs
// stay disabled for this worker.

/// The octomon version family ("0.8") out of our own client's User-Agent
/// ("octomon/0.8.0 (…)"), "other" for anything else — browsers poking the
/// endpoint out of curiosity get counted without being fingerprinted.
function versionFamily(ua) {
  const m = /^octomon\/(\d+\.\d+)/.exec(ua ?? "");
  return m ? m[1] : "other";
}

function edgeAnswer(request, env, ctx) {
  const cf = request.cf ?? {};
  const body = {
    ip: request.headers.get("cf-connecting-ip") ?? "",
    asn: cf.asn ?? 0,
    isp: cf.asOrganization ?? "",
    colo: cf.colo ?? "",
    city: cf.city ?? "",
    country: cf.country ?? "",
    tcp_rtt_ms: cf.clientTcpRtt ?? null,
    http: cf.httpProtocol ?? "",
    tls: cf.tlsVersion ?? "",
    ts: Math.floor(Date.now() / 1000),
  };
  if (env.EDGE_STATS) {
    // The whole record: one version family, one count. This is the entire
    // input to the graph on /privacy.
    ctx.waitUntil(
      Promise.resolve(
        env.EDGE_STATS.writeDataPoint({
          blobs: [versionFamily(request.headers.get("user-agent"))],
          doubles: [1],
        }),
      ).catch(() => {}),
    );
  }
  return new Response(JSON.stringify(body) + "\n", {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

// The public aggregate behind the /privacy graph: daily request counts per
// octomon version family for the last 30 days, queried from Analytics
// Engine and cached for an hour. Deliberately coarse — day buckets and
// version *families* — so even a fleet of one cannot be traced through it.
async function edgeStats(env) {
  if (!env.AE_QUERY_TOKEN || !env.CF_ACCOUNT_ID) {
    return new Response(JSON.stringify({ series: [] }) + "\n", {
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  }
  const sql = `
    SELECT toStartOfInterval(timestamp, INTERVAL '1' DAY) AS day,
           blob1 AS version,
           sum(_sample_interval * double1) AS calls
    FROM octomon_edge
    WHERE timestamp > now() - INTERVAL '30' DAY
    GROUP BY day, version
    ORDER BY day, version`;
  const resp = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/analytics_engine/sql`,
    {
      method: "POST",
      headers: { authorization: `Bearer ${env.AE_QUERY_TOKEN}` },
      body: sql,
    },
  );
  if (!resp.ok) {
    return new Response(JSON.stringify({ series: [] }) + "\n", {
      status: 200,
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  }
  const data = await resp.json();
  const series = (data.data ?? []).map((r) => ({
    day: r.day,
    version: r.version,
    calls: Math.round(Number(r.calls) || 0),
  }));
  return new Response(JSON.stringify({ series }) + "\n", {
    headers: {
      "content-type": "application/json; charset=utf-8",
      // One aggregate an hour is plenty; the cache also shields the API
      // token path from being hammered through the public page.
      "cache-control": "public, max-age=3600",
    },
  });
}

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
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/edge") {
      return edgeAnswer(request, env, ctx);
    }
    if (url.pathname === "/edge/stats") {
      return edgeStats(env);
    }
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
