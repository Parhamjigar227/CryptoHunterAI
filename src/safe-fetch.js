import { parsePublicHttpsUrl } from "./validate.js";

const DEFAULTS = {
  timeoutMs: 8000,
  maxBytes: 500_000,
  maxRedirects: 3,
  accept: ["text/html", "text/plain", "application/json", "application/xhtml+xml"],
  userAgent: "CryptoHunterAI-research/0.2 (+https://github.com/Parhamjigar227/CryptoHunterAI)",
};

// Fetches a public https URL with a timeout, a body-size cap, a content-type
// allowlist and manual redirect handling (every hop is re-validated).
// Never throws: returns { ok:true, ... } or { ok:false, error:{code,message} }.
export async function safeFetch(rawUrl, options = {}) {
  const opts = { ...DEFAULTS, ...options };
  const fetchImpl = opts.fetchImpl || globalThis.fetch;

  let url = parsePublicHttpsUrl(rawUrl);
  if (!url) return fail("invalid_url", "آدرس معتبر یا عمومی نیست.");

  const chain = [];
  for (let hop = 0; hop <= opts.maxRedirects; hop++) {
    chain.push(url.toString());
    let response;
    try {
      response = await fetchImpl(url.toString(), {
        method: "GET",
        redirect: "manual",
        headers: { "user-agent": opts.userAgent, accept: opts.accept.join(", "), ...(opts.headers || {}) },
        signal: AbortSignal.timeout(opts.timeoutMs),
      });
    } catch (err) {
      if (err && (err.name === "TimeoutError" || err.name === "AbortError")) {
        return fail("timeout", `پاسخ در ${opts.timeoutMs / 1000} ثانیه نرسید.`, chain);
      }
      return fail("network_error", "اتصال به منبع ناموفق بود.", chain);
    }

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      const next = location ? safeResolve(location, url) : null;
      const valid = next && parsePublicHttpsUrl(next.toString());
      if (!valid) return fail("blocked_redirect", "ریدایرکت به مقصد نامعتبر یا غیرعمومی مسدود شد.", chain);
      url = valid;
      continue;
    }

    const contentType = (response.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
    const base = {
      status: response.status,
      finalUrl: url.toString(),
      redirects: chain.length - 1,
      contentType,
      retryAfter: response.headers.get("retry-after") || null,
    };

    if (response.status === 429) return { ok: false, ...base, error: { code: "rate_limited", message: "منبع محدودیت نرخ درخواست اعمال کرد." } };
    if (!response.ok) return { ok: false, ...base, error: { code: "http_error", message: `منبع با کد ${response.status} پاسخ داد.` } };
    if (!opts.accept.includes(contentType)) {
      return { ok: false, ...base, error: { code: "unsupported_content_type", message: `نوع محتوا پشتیبانی نمی‌شود: ${contentType || "نامشخص"}` } };
    }

    try {
      const { text, truncated } = await readLimited(response, opts.maxBytes);
      return { ok: true, ...base, text, truncated };
    } catch {
      return { ok: false, ...base, error: { code: "read_error", message: "خواندن پاسخ ناموفق بود." } };
    }
  }
  return fail("too_many_redirects", `بیش از ${opts.maxRedirects} ریدایرکت.`, chain);
}

function fail(code, message, chain = []) {
  return { ok: false, status: null, finalUrl: chain[chain.length - 1] || null, error: { code, message } };
}

function safeResolve(location, base) {
  try {
    return new URL(location, base);
  } catch {
    return null;
  }
}

async function readLimited(response, maxBytes) {
  if (!response.body) return { text: "", truncated: false };
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (total + value.length > maxBytes) {
      chunks.push(value.slice(0, maxBytes - total));
      total = maxBytes;
      truncated = true;
      await reader.cancel();
      break;
    }
    chunks.push(value);
    total += value.length;
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    bytes.set(c, offset);
    offset += c.length;
  }
  return { text: new TextDecoder("utf-8", { fatal: false }).decode(bytes), truncated };
}
