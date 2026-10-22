import { test } from "node:test";
import assert from "node:assert/strict";
import { computeRisk, computeConfidence, splitSections, assembleReport, SECTION_ORDER } from "../src/report.js";

const NOW = Date.parse("2026-10-23T00:00:00Z");
const src = (id, ok, data = null, extra = {}) => ({ id, title: id + " title", url: `https://${id}.example.org/`, fetchedAt: "2026-10-23T00:00:00.000Z", ok, data, error: ok ? null : { code: "http_error", message: "boom" }, limitations: ["lim " + id], ...extra });
const research = (sources, input = {}) => ({ input: { name: "Foo", chain: "other", contract: null, url: null, question: "", ...input }, sources, notes: [], limited: false, usable: true });

test("risk: no signals with data => explicit not-a-safety-claim level", () => {
  const r = computeRisk(research([src("website", true, { riskMentions: [] })]), NOW);
  assert.equal(r.score, 0);
  assert.match(r.level, /به معنی امن بودن نیست/);
});

test("risk: weights and levels", () => {
  const site = src("website", true, { riskMentions: [{ id: "guaranteed_returns" }, { id: "seed_phrase" }] });
  const cg = src("coingecko", true, { contractMatch: false });
  const r = computeRisk(research([site, cg]), NOW);
  assert.equal(r.score, 3 + 1 + 4);
  assert.equal(r.level, "زیاد");
  assert.deepEqual(r.signals.map((s) => s.id).sort(), ["contract_mismatch", "guaranteed_returns", "seed_phrase_mention"]);
});

test("risk: github signals use dates relative to now", () => {
  const gh = src("github", true, { archived: true, isFork: true, createdAt: "2026-10-10T00:00:00Z", pushedAt: "2024-01-01T00:00:00Z" });
  const r = computeRisk(research([gh]), NOW);
  assert.deepEqual(r.signals.map((s) => s.id).sort(), ["repo_archived", "repo_fork", "repo_new", "repo_stale"]);
  assert.equal(r.score, 4);
  assert.equal(r.level, "متوسط");
});

test("risk: unknown when nothing succeeded; not_listed counts as a signal", () => {
  const cg = src("coingecko", false); cg.error = { code: "not_found", message: "x" };
  assert.equal(computeRisk(research([cg]), NOW).level, "نامشخص");
  assert.equal(computeRisk(research([cg, src("website", true, { riskMentions: [] })]), NOW).score, 1);
});

test("confidence never reaches high and drops with failures", () => {
  assert.equal(computeConfidence(research([src("a", false)])).level, "ندارد");
  assert.equal(computeConfidence(research([src("a", true), src("b", false)])).level, "کم");
  const c = computeConfidence(research([src("a", true), src("b", true), src("c", true)]));
  assert.equal(c.level, "متوسط");
  assert.notEqual(c.level, "بالا");
});

test("splitSections maps known headings only", () => {
  const s = splitSections("intro\n## خلاصه\nA\nB\n## نامربوط\nzzz\n## یافته‌های تأییدشده:\nC");
  assert.equal(s["خلاصه"], "A\nB");
  assert.equal(s["یافته‌های تأییدشده"], "C");
  assert.equal(Object.keys(s).length, 2);
});

test("assembleReport: all headings in the specified order, sources with links, placeholders for missing sections", () => {
  const rs = research([src("website", true, { riskMentions: [] }), src("coingecko", false)], { name: "Foo", question: "ایردراپ؟" });
  const md = assembleReport({
    research: rs, sections: { "خلاصه": "SUMMARY-TEXT" }, aiError: null, risk: computeRisk(rs, NOW), confidence: computeConfidence(rs),
    model: "m1", now: new Date("2026-10-23T01:00:00Z"),
  });
  assert.match(md, /^# گزارش تحقیق: Foo/);
  assert.match(md, /2026-10-23T01:00:00.000Z/);
  assert.match(md, /SUMMARY-TEXT/);
  assert.match(md, /\[website title\]\(https:\/\/website\.example\.org\/\)/);
  assert.match(md, /ناموفق \(boom\)/);
  assert.match(md, /مدل این بخش را تولید نکرد/);
  assert.match(md, /ایردراپ؟/);
  assert.match(md, /روش محاسبه/);
  assert.match(md, /مشاوره مالی/);
  let last = -1;
  for (const h of ["خلاصه", "منابع بررسی‌شده", "یافته‌های تأییدشده", "ادعاهای تأییدنشده", "تناقض‌ها و هشدارهای امنیتی", "وضعیت توکن و ایردراپ", "ریسک‌های فنی و اقتصادی", "علائم هشدار و سطح ریسک", "میزان اطمینان", "اطلاعات نامعلوم", "پیشنهاد برای بررسی بعدی"]) {
    const i = md.indexOf(`## ${h}`);
    assert.ok(i > last, `heading out of order or missing: ${h}`);
    last = i;
  }
  assert.equal(SECTION_ORDER.length, 8);
});

test("assembleReport without AI states it clearly and keeps deterministic parts", () => {
  const rs = research([src("website", true, { riskMentions: [{ id: "guaranteed_returns" }] })]);
  const md = assembleReport({ research: rs, sections: {}, aiError: { code: "quota_exhausted", message: "سهمیه تمام شد" }, risk: computeRisk(rs, NOW), confidence: computeConfidence(rs), model: null });
  assert.match(md, /تحلیل هوش مصنوعی انجام نشد: سهمیه تمام شد/);
  assert.match(md, /تحلیل هوش مصنوعی در دسترس نبود/);
  assert.match(md, /\(\+3\)/);
});
