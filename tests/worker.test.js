import { test } from "node:test";
import assert from "node:assert/strict";
import worker, { handleRequest, safeEqual, checkAccess } from "../src/worker.js";

const env = { ASSETS: { fetch: async () => new Response("asset") }, AI_MODEL: "m" };
// Any network attempt in these tests fails loudly instead of reaching the internet.
const noNetwork = async (url) => { throw new Error(`unexpected network call: ${url}`); };
const call = (path, init, e = env) => handleRequest(new Request("https://x.test" + path, init), e, {}, { fetchImpl: noNetwork });
const post = (body, headers = {}, e = env) =>
  call("/api/research", { method: "POST", headers: { "content-type": "application/json", ...headers }, body: typeof body === "string" ? body : JSON.stringify(body) }, e);

test("health reports configuration without leaking secrets", async () => {
  const r = await call("/api/health", {}, { ...env, ACCESS_TOKEN: "s3cret" });
  const j = await r.json();
  assert.equal(r.status, 200);
  assert.equal(j.accessTokenRequired, true);
  assert.equal(JSON.stringify(j).includes("s3cret"), false);
});

test("default export handles errors and routes", async () => {
  const r = await worker.fetch(new Request("https://x.test/api/health"), env, {});
  assert.equal(r.status, 200);
});

test("non-api paths go to static assets", async () => {
  assert.equal(await (await call("/")).text(), "asset");
});

test("unknown api path is 404 json", async () => {
  const r = await call("/api/nope");
  assert.equal(r.status, 404);
  assert.equal((await r.json()).ok, false);
});

test("research requires POST", async () => {
  assert.equal((await call("/api/research")).status, 405);
});

test("research rejects bad content-type, bad json, oversize body and invalid input", async () => {
  assert.equal((await call("/api/research", { method: "POST", headers: { "content-type": "text/plain" }, body: "x" })).status, 400);
  assert.equal((await post("{not json")).status, 400);
  assert.equal((await post({ name: "x", question: "q".repeat(20000) })).status, 400);
  const r = await post({ name: "x", url: "https://127.0.0.1" });
  const j = await r.json();
  assert.equal(r.status, 400);
  assert.equal(j.error.field, "url");
});

test("access token is enforced when configured", async () => {
  const e = { ...env, ACCESS_TOKEN: "tok" };
  assert.equal((await post({ name: "x" }, {}, e)).status, 401);
  assert.equal((await post({ name: "x" }, { authorization: "Bearer wrong" }, e)).status, 401);
  assert.notEqual((await post({ name: "x" }, { authorization: "Bearer tok" }, e)).status, 401);
});

test("safeEqual / checkAccess", () => {
  assert.equal(safeEqual("a", "a"), true);
  assert.equal(safeEqual("a", "b"), false);
  assert.equal(safeEqual("a", "ab"), false);
  assert.equal(checkAccess(new Request("https://x.test"), {}), true);
});

test("fail closed: REQUIRE_ACCESS_TOKEN without a configured token disables research and says so", async () => {
  const e = { ...env, REQUIRE_ACCESS_TOKEN: "true" };
  const r = await post({ name: "x" }, {}, e);
  assert.equal(r.status, 503);
  assert.equal((await r.json()).error.code, "token_not_configured");
  const h = await (await call("/api/health", {}, e)).json();
  assert.equal(h.accessTokenRequired, true);
  assert.equal(h.tokenConfigured, false);
});

test("fail closed: once the token exists, requests need it (401 without, no 503)", async () => {
  const e = { ...env, REQUIRE_ACCESS_TOKEN: "true", ACCESS_TOKEN: "tok" };
  assert.equal((await post({ name: "x" }, {}, e)).status, 401);
  const h = await (await call("/api/health", {}, e)).json();
  assert.equal(h.tokenConfigured, true);
});

test("without REQUIRE_ACCESS_TOKEN and without a token the API stays open (local tests only)", async () => {
  const h = await (await call("/api/health")).json();
  assert.equal(h.accessTokenRequired, false);
});
