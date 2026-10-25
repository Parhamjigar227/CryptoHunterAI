import { LIMITS, ValidationError, parseResearchInput } from "./validate.js";
import { runResearch } from "./research.js";
import { analyzeResearch } from "./analyze.js";
import { assembleReport, computeConfidence, computePositives, computeRisk, splitSections } from "./report.js";

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };

export function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

export function errorResponse(status, code, message, field) {
  return jsonResponse({ ok: false, error: { code, message, ...(field ? { field } : {}) } }, status);
}

// Constant-time string comparison for the optional access token.
export function safeEqual(a, b) {
  const enc = new TextEncoder();
  const x = enc.encode(String(a));
  const y = enc.encode(String(b));
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  }
  return diff === 0;
}

// If the ACCESS_TOKEN secret is set, every /api/research call must send it.
// This protects the free Workers AI quota from anonymous callers.
export function checkAccess(request, env) {
  if (!env.ACCESS_TOKEN) return true;
  const header = request.headers.get("authorization") || "";
  const match = /^Bearer (.+)$/.exec(header);
  return Boolean(match) && safeEqual(match[1], env.ACCESS_TOKEN);
}

async function readJsonBody(request) {
  const type = request.headers.get("content-type") || "";
  if (!type.toLowerCase().includes("application/json")) {
    throw new ValidationError("body", "Content-Type باید application/json باشد.");
  }
  const declared = Number(request.headers.get("content-length") || 0);
  if (declared > LIMITS.bodyBytes) {
    throw new ValidationError("body", "بدنهٔ درخواست بیش از حد بزرگ است.");
  }
  const text = await request.text();
  if (new TextEncoder().encode(text).length > LIMITS.bodyBytes) {
    throw new ValidationError("body", "بدنهٔ درخواست بیش از حد بزرگ است.");
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new ValidationError("body", "بدنهٔ درخواست JSON معتبر نیست.");
  }
}

// Runs research -> analysis -> report and streams newline-delimited JSON events:
// stage | source | result | error. The client renders them as they arrive.
export function streamResearch(input, env, ctx, deps = {}) {
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const encoder = new TextEncoder();
  const send = (event) => writer.write(encoder.encode(JSON.stringify(event) + "\n")).catch(() => {});

  const job = (async () => {
    try {
      const research = await runResearch(input, { fetchImpl: deps.fetchImpl, githubToken: env.GITHUB_TOKEN, coingeckoKey: env.COINGECKO_API_KEY, onProgress: send });
      if (!research.usable) {
        await send({ type: "error", error: { code: "no_evidence", message: "هیچ منبعی دریافت نشد؛ بدون شواهد، تحلیل انجام نمی‌شود." }, sources: research.sources, notes: research.notes });
        return;
      }
      await send({ type: "stage", stage: "analysis", message: "در حال تحلیل شواهد با هوش مصنوعی…" });
      const ai = await analyzeResearch(research, env, deps);
      const risk = computeRisk(research);
      const confidence = computeConfidence(research);
      const positives = computePositives(research);
      const generatedAt = new Date();
      const markdown = assembleReport({
        research, sections: ai.ok ? splitSections(ai.text) : {}, aiError: ai.ok ? null : ai.error,
        risk, confidence, positives, model: ai.ok ? ai.model : null, now: generatedAt,
      });
      await send({
        type: "result",
        report: {
          markdown, risk, confidence, positives, generatedAt: generatedAt.toISOString(),
          model: ai.ok ? ai.model : null, aiError: ai.ok ? null : ai.error, usage: ai.ok ? ai.usage : null,
          sources: research.sources.map(({ id, title, url, fetchedAt, ok, error, limitations }) => ({ id, title, url, fetchedAt, ok, error, limitations })),
          input,
        },
      });
    } catch (err) {
      console.error("pipeline error", err && err.stack ? err.stack : String(err));
      await send({ type: "error", error: { code: "internal_error", message: "خطای داخلی هنگام تحقیق." } });
    } finally {
      await writer.close().catch(() => {});
    }
  })();
  ctx?.waitUntil?.(job);
  return new Response(readable, { headers: { "content-type": "application/x-ndjson; charset=utf-8", "cache-control": "no-store" } });
}

// REQUIRE_ACCESS_TOKEN="true" (set in wrangler.jsonc) makes the API fail closed:
// until the ACCESS_TOKEN secret exists, research is disabled instead of public.
const tokenRequired = (env) => Boolean(env.ACCESS_TOKEN) || env.REQUIRE_ACCESS_TOKEN === "true";

export async function handleRequest(request, env, ctx, deps = {}) {
  const url = new URL(request.url);

  if (url.pathname === "/api/health") {
    if (request.method !== "GET") return errorResponse(405, "method_not_allowed", "فقط GET مجاز است.");
    return jsonResponse({
      ok: true,
      aiBinding: Boolean(env.AI),
      model: env.AI_MODEL || null,
      accessTokenRequired: tokenRequired(env),
      tokenConfigured: Boolean(env.ACCESS_TOKEN),
    });
  }

  if (url.pathname === "/api/research") {
    if (request.method !== "POST") return errorResponse(405, "method_not_allowed", "فقط POST مجاز است.");
    if (tokenRequired(env) && !env.ACCESS_TOKEN) {
      return errorResponse(503, "token_not_configured", "رمز دسترسی (ACCESS_TOKEN) روی این سرور تنظیم نشده؛ برای جلوگیری از مصرف سهمیه، تحقیق غیرفعال است. راهنما: HANDOFF.md");
    }
    if (!checkAccess(request, env)) return errorResponse(401, "unauthorized", "توکن دسترسی نامعتبر یا ارسال‌نشده است.");
    let input;
    try {
      input = parseResearchInput(await readJsonBody(request));
    } catch (err) {
      if (err instanceof ValidationError) return errorResponse(400, "invalid_input", err.message, err.field);
      throw err;
    }
    return streamResearch(input, env, ctx, deps);
  }

  if (url.pathname.startsWith("/api/")) return errorResponse(404, "not_found", "مسیر API وجود ندارد.");
  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (err) {
      console.error("unhandled", err && err.stack ? err.stack : String(err));
      return errorResponse(500, "internal_error", "خطای داخلی سرور.");
    }
  },
};
