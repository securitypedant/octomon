// /apt/* and /rpm/* served from the one R2 bucket, run with `node --test
// worker/`. The bucket is a stub keyed like the real one (apt/…, rpm/…).
import { test } from "node:test";
import assert from "node:assert/strict";

const worker = (await import("./index.js?case=repos")).default;

function bucket(keys) {
  return {
    get: async (key) =>
      key in keys
        ? { body: keys[key], size: keys[key].length, httpEtag: `"${key}"` }
        : null,
  };
}

const env = {
  APT: bucket({
    "apt/dists/stable/InRelease": "-----BEGIN PGP SIGNED MESSAGE-----",
    "apt/pool/main/o/octomon/octomon_0.12.1-1_amd64.deb": "deb",
    "rpm/octomon.repo": "[octomon]",
    "rpm/repodata/repomd.xml": "<repomd/>",
    "rpm/repodata/repomd.xml.asc": "-----BEGIN PGP SIGNATURE-----",
    "rpm/octomon-0.12.1-1.x86_64.rpm": "rpm",
  }),
  ASSETS: { fetch: async () => new Response("<h1>404</h1>", { status: 200 }) },
};
const get = (path) => worker.fetch(new Request(`https://octomon.dev${path}`), env, {});

test("each repository maps onto its own bucket prefix", async () => {
  const deb = await get("/apt/pool/main/o/octomon/octomon_0.12.1-1_amd64.deb");
  assert.equal(deb.status, 200);
  assert.equal(deb.headers.get("content-type"), "application/vnd.debian.binary-package");
  const rpm = await get("/rpm/octomon-0.12.1-1.x86_64.rpm");
  assert.equal(rpm.status, 200);
  assert.equal(rpm.headers.get("content-type"), "application/x-rpm");
  assert.equal(await rpm.text(), "rpm");
});

test("repository indexes carry the types their clients expect", async () => {
  assert.equal(
    (await get("/apt/dists/stable/InRelease")).headers.get("content-type"),
    "text/plain; charset=utf-8",
  );
  assert.equal((await get("/rpm/octomon.repo")).headers.get("content-type"), "text/plain; charset=utf-8");
  assert.equal((await get("/rpm/repodata/repomd.xml")).headers.get("content-type"), "application/xml");
  assert.equal(
    (await get("/rpm/repodata/repomd.xml.asc")).headers.get("content-type"),
    "application/pgp-signature",
  );
});

test("one repository's keys are not reachable through the other's prefix", async () => {
  assert.equal((await get("/apt/octomon.repo")).status, 404);
  assert.equal((await get("/rpm/dists/stable/InRelease")).status, 404);
});

test("the bare prefix names the repository; anything else is the site's 404", async () => {
  assert.equal(await (await get("/rpm/")).text(), "octomon rpm repository\n");
  assert.equal(await (await get("/apt/")).text(), "octomon apt repository\n");
  const other = await get("/yum/octomon.repo");
  assert.equal(other.status, 404);
  assert.equal(other.headers.get("content-type"), "text/html; charset=utf-8");
});
