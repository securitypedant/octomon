// /edge/stats memo, run with `node --test worker/`. The worker is imported
// fresh per test (its memo is module state), with fetch and the clock
// stubbed, so nothing here reaches Cloudflare.
import { test } from "node:test";
import assert from "node:assert/strict";

let loads = 0;
async function freshWorker() {
  loads += 1;
  return (await import(`./index.js?case=${loads}`)).default;
}

const env = { AE_QUERY_TOKEN: "t", CF_ACCOUNT_ID: "a" };
const row = { day: "2026-11-01", version: "0.11.9", why: "refresh", calls: 4 };

function harness(t) {
  const waited = [];
  const ctx = { waitUntil: (p) => waited.push(p) };
  let now = 1_000_000;
  t.mock.method(Date, "now", () => now);
  t.mock.method(console, "error", () => {});
  return {
    ctx,
    waited,
    advance: (ms) => (now += ms),
    stats: (w) => w.fetch(new Request("https://octomon.dev/edge/stats"), env, ctx),
  };
}

function answer(body, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

test("a good answer is served from the memo for the hour", async (t) => {
  const h = harness(t);
  const fetch = t.mock.method(globalThis, "fetch", async () => answer({ data: [row] }));
  const w = await freshWorker();
  const first = await h.stats(w);
  assert.equal(first.headers.get("cache-control"), "public, max-age=3600");
  const body = await first.json();
  assert.equal(body.series.length, 1);
  assert.equal(body.stale, undefined, "a fresh answer isn't marked");
  assert.ok(fetch.mock.calls[0].arguments[1].signal instanceof AbortSignal, "the query is bounded");
  h.advance(59 * 60 * 1000);
  await h.stats(w);
  assert.equal(fetch.mock.callCount(), 1);
  h.advance(2 * 60 * 1000);
  await h.stats(w);
  assert.equal(fetch.mock.callCount(), 2);
  assert.equal(h.waited.length, 2, "every refresh is kept alive with waitUntil");
});

test("a miss during a running refresh serves the memo instead of awaiting it", async (t) => {
  const h = harness(t);
  let release;
  const fetch = t.mock.method(
    globalThis,
    "fetch",
    () => new Promise((r) => (release = () => r(answer({ data: [row] })))),
  );
  const w = await freshWorker();
  const a = h.stats(w);
  const b = await h.stats(w);
  assert.equal(fetch.mock.callCount(), 1);
  assert.deepEqual((await b.json()).series, []);
  assert.equal(b.headers.get("cache-control"), "no-store");
  release();
  assert.equal((await (await a).json()).series.length, 1);
});

test("a refresh that never reports back only delays the next one", async (t) => {
  const h = harness(t);
  const fetch = t.mock.method(globalThis, "fetch", () => new Promise(() => {}));
  const w = await freshWorker();
  h.stats(w);
  h.advance(5 * 1000);
  await h.stats(w);
  assert.equal(fetch.mock.callCount(), 1);
  h.advance(6 * 1000);
  h.stats(w);
  assert.equal(fetch.mock.callCount(), 2);
});

test("a failure keeps the last good series, uncached, and retries after a minute", async (t) => {
  const h = harness(t);
  let reply = answer({ data: [row] });
  const fetch = t.mock.method(globalThis, "fetch", async () => reply);
  const w = await freshWorker();
  await h.stats(w);
  h.advance(61 * 60 * 1000);
  for (const bad of [
    () => answer({ errors: ["quota"] }, 429),
    () => answer({ meta: [] }),
    () => new Response("not json"),
  ]) {
    reply = bad();
    const r = await h.stats(w);
    assert.equal(r.headers.get("cache-control"), "no-store");
    const body = await r.json();
    assert.equal(body.series.length, 1, "last good series kept");
    assert.equal(body.stale, true, "and marked as such");
    const calls = fetch.mock.callCount();
    h.advance(30 * 1000);
    await h.stats(w);
    assert.equal(fetch.mock.callCount(), calls, "no retry inside the minute");
    h.advance(31 * 1000);
  }
  reply = answer({ data: [row, row] });
  const back = await h.stats(w);
  assert.equal((await back.json()).series.length, 2);
  assert.equal(back.headers.get("cache-control"), "public, max-age=3600");
});

test("a thrown fetch is a failure, not a 500", async (t) => {
  const h = harness(t);
  t.mock.method(globalThis, "fetch", async () => {
    throw new TypeError("network down");
  });
  const r = await h.stats(await freshWorker());
  assert.equal(r.status, 200);
  assert.deepEqual(await r.json(), { series: [], stale: true });
});

test("a slow refresh that settles after a newer one doesn't overwrite it", async (t) => {
  const h = harness(t);
  const pending = [];
  t.mock.method(globalThis, "fetch", () => new Promise((r) => pending.push(r)));
  const w = await freshWorker();
  const slow = h.stats(w);
  h.advance(11 * 1000);
  const fast = h.stats(w);
  pending[1](answer({ data: [row, row] }));
  await fast;
  pending[0](new Response("not json"));
  await slow;
  const r = await h.stats(w);
  assert.equal((await r.json()).series.length, 2);
  assert.equal(r.headers.get("cache-control"), "public, max-age=3600");
});
