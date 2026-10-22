import { test } from "node:test";
import assert from "node:assert/strict";
import { safeFetch } from "../src/safe-fetch.js";
import { mockFetch, html } from "./helpers.js";

test("rejects non-public or non-https URLs without calling fetch", async () => {
  const log = [];
  const fetchImpl = mockFetch({}, log);
  for (const u of ["http://example.com", "https://127.0.0.1", "https://localhost", "https://169.254.169.254/x"]) {
    const r = await safeFetch(u, { fetchImpl });
    assert.equal(r.ok, false);
    assert.equal(r.error.code, "invalid_url");
  }
  assert.equal(log.length, 0);
});

test("returns text for a normal page", async () => {
  const r = await safeFetch("https://a.example.org/", { fetchImpl: mockFetch({ "https://a.example.org/": html("<p>hi</p>") }) });
  assert.equal(r.ok, true);
  assert.equal(r.text, "<p>hi</p>");
  assert.equal(r.truncated, false);
});

test("follows safe redirects and re-validates each hop", async () => {
  const fetchImpl = mockFetch({
    "https://a.example.org/": { status: 301, headers: { location: "https://b.example.org/x" } },
    "https://b.example.org/x": html("ok"),
  });
  const r = await safeFetch("https://a.example.org/", { fetchImpl });
  assert.equal(r.ok, true);
  assert.equal(r.finalUrl, "https://b.example.org/x");
  assert.equal(r.redirects, 1);
});

test("blocks redirects to internal or non-https targets", async () => {
  for (const location of ["https://169.254.169.254/latest/meta-data", "http://b.example.org/", "https://localhost/admin", "https://[::1]/"]) {
    const fetchImpl = mockFetch({ "https://a.example.org/": { status: 302, headers: { location } } });
    const r = await safeFetch("https://a.example.org/", { fetchImpl });
    assert.equal(r.ok, false, location);
    assert.equal(r.error.code, "blocked_redirect", location);
  }
});

test("caps redirect chains", async () => {
  const fetchImpl = mockFetch({ "https://a.example.org/": { status: 302, headers: { location: "https://a.example.org/" } } });
  const r = await safeFetch("https://a.example.org/", { fetchImpl, maxRedirects: 3 });
  assert.equal(r.error.code, "too_many_redirects");
});

test("truncates oversized bodies", async () => {
  const fetchImpl = mockFetch({ "https://a.example.org/": html("x".repeat(5000)) });
  const r = await safeFetch("https://a.example.org/", { fetchImpl, maxBytes: 1000 });
  assert.equal(r.ok, true);
  assert.equal(r.text.length, 1000);
  assert.equal(r.truncated, true);
});

test("maps timeouts, network errors, 429, 404 and bad content types to codes", async () => {
  const t = Object.assign(new Error("t"), { name: "TimeoutError" });
  const cases = [
    [{ throws: t }, "timeout"],
    [{ throws: new Error("boom") }, "network_error"],
    [{ status: 429, headers: { "retry-after": "30" } }, "rate_limited"],
    [{ status: 404 }, "http_error"],
    [{ headers: { "content-type": "application/octet-stream" }, body: "bin" }, "unsupported_content_type"],
  ];
  for (const [route, code] of cases) {
    const r = await safeFetch("https://a.example.org/", { fetchImpl: mockFetch({ "https://a.example.org/": route }) });
    assert.equal(r.ok, false);
    assert.equal(r.error.code, code);
  }
});

test("manual redirect mode and user-agent are sent", async () => {
  const log = [];
  await safeFetch("https://a.example.org/", { fetchImpl: mockFetch({ "https://a.example.org/": html("x") }, log) });
  assert.equal(log[0].init.redirect, "manual");
  assert.match(log[0].init.headers["user-agent"], /CryptoHunterAI/);
});
