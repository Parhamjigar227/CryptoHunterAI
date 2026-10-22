import { LIMITS, ValidationError, parseResearchInput } from "./validate.js";

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

export async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);

  if (url.pathname === "/api/health") {
    if (request.method !== "GET") return errorResponse(405, "method_not_allowed", "فقط GET مجاز است.");
    return jsonResponse({
      ok: true,
      aiBinding: Boolean(env.AI),
      model: env.AI_MODEL || null,
      accessTokenRequired: Boolean(env.ACCESS_TOKEN),
    });
  }

  if (url.pathname === "/api/research") {
    if (request.method !== "POST") return errorResponse(405, "method_not_allowed", "فقط POST مجاز است.");
    if (!checkAccess(request, env)) return errorResponse(401, "unauthorized", "توکن دسترسی نامعتبر یا ارسال‌نشده است.");
    let input;
    try {
      input = parseResearchInput(await readJsonBody(request));
    } catch (err) {
      if (err instanceof ValidationError) return errorResponse(400, "invalid_input", err.message, err.field);
      throw err;
    }
    // The research pipeline is wired in parts 2-3 (see STATUS.md); until then
    // valid requests get an honest 501 rather than fake data.
    console.log("research request accepted", { chain: input.chain, hasUrl: Boolean(input.url) });
    return errorResponse(501, "not_implemented", "موتور تحقیق هنوز متصل نشده است.");
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
