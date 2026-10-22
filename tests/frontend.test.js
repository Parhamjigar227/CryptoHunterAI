import { test } from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFileSync } from "node:fs";

// Loads the browser scripts into a bare VM context (no DOM) to test their pure functions.
const ctx = vm.createContext({ console, URL, TextDecoder });
for (const f of ["utils", "markdown", "research"]) {
  vm.runInContext(readFileSync(new URL(`../public/js/${f}.js`, import.meta.url), "utf8"), ctx, { filename: f + ".js" });
}
const run = (expr) => vm.runInContext(expr, ctx);
const renderMarkdown = (md) => run("renderMarkdown")(md);

test("markdown: headings, lists, bold, code, italic, hr", () => {
  const h = renderMarkdown("# T\n\n## S\n- a\n- **b** `c` _d_\n\n---");
  assert.match(h, /<h1>T<\/h1>/);
  assert.match(h, /<h2>S<\/h2>/);
  assert.match(h, /<ul><li>a<\/li><li><strong>b<\/strong> <code class="ltr">c<\/code> <em>d<\/em><\/li><\/ul>/);
  assert.match(h, /<hr>/);
});

test("markdown: tables render with header and rows", () => {
  const h = renderMarkdown("| a | b |\n|---|---|\n| 1 | [x](https://e.org/p) |\n\nafter");
  assert.match(h, /<th>a<\/th><th>b<\/th>/);
  assert.match(h, /<td>1<\/td><td><a href="https:\/\/e\.org\/p"/);
  assert.match(h, /<p>after<\/p>/);
});

test("markdown: XSS payloads are escaped or dropped", () => {
  const payloads = [
    "<script>alert(1)</script>",
    '<img src=x onerror="alert(1)">',
    "[click](javascript:alert(1))",
    "[click](data:text/html;base64,AAAA)",
    '[x](https://e.org/" onmouseover="alert(1))',
    "**<b onclick=1>x</b>**",
    "`<svg onload=alert(1)>`",
    "| <i>h</i> |\n|---|\n| <u>c</u> |",
  ];
  for (const p of payloads) {
    const h = renderMarkdown(p);
    assert.equal(/<(script|img|svg|b|i|u)\b/i.test(h.replace(/<\/?(strong|code|table|thead|tbody|tr|th|td|div|p|a|em|ul|li|h\d|hr|br)\b[^>]*>/g, "")), false, "raw tag survived: " + p + " => " + h);
    assert.equal(/href="(javascript|data):/i.test(h), false, p);
    assert.equal(/<[^>]+\son\w+\s*=/i.test(h), false, "event handler attribute: " + p);
  }
});

test("markdown: only https/http links become anchors, with noopener", () => {
  const h = renderMarkdown("[a](https://e.org/x) [b](ftp://e.org/x)");
  assert.match(h, /<a href="https:\/\/e\.org\/x" target="_blank" rel="noopener noreferrer">a<\/a>/);
  assert.equal(h.includes('href="ftp'), false);
});

test("splitNdjson keeps partial lines and skips corrupt ones", () => {
  const split = run("splitNdjson");
  const r = split('{"type":"stage"}\n{bad}\n{"type":"sou');
  assert.deepEqual(JSON.parse(JSON.stringify(r.events)), [{ type: "stage" }]);
  assert.equal(r.rest, '{"type":"sou');
  assert.deepEqual(JSON.parse(JSON.stringify(split(r.rest + 'rce"}\n').events)), [{ type: "source" }]);
});

test("buildReportHtml is a standalone rtl document with escaped title", () => {
  const html = run("buildReportHtml")("# x", "<b>t</b>");
  assert.match(html, /^<!doctype html><html lang="fa" dir="rtl">/);
  assert.equal(html.includes("<b>t</b>"), false);
  assert.match(html, /<h1>x<\/h1>/);
});
