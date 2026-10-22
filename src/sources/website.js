import { safeFetch } from "../safe-fetch.js";

// Phrases that matter for scam screening. A match is a *mention*, not proof:
// legitimate sites also warn "never share your seed phrase". The analysis
// step receives the surrounding context and must judge it.
export const RISK_PATTERNS = [
  { id: "seed_phrase", label: "عبارت بازیابی/سید", re: /seed phrase|recovery phrase|secret recovery|mnemonic|عبارت بازیابی|کلمات بازیابی|سید فریز/gi },
  { id: "private_key", label: "کلید خصوصی", re: /private key|کلید خصوصی/gi },
  { id: "guaranteed_returns", label: "سود تضمینی", re: /guaranteed (?:returns?|profits?|income)|risk[- ]free|double your|سود تضمینی|بدون ریسک/gi },
  { id: "wallet_validation", label: "اعتبارسنجی/همگام‌سازی کیف پول", re: /validate your wallet|sync (?:your )?wallet|wallet validation|rectif(?:y|ication)|اعتبارسنجی کیف پول/gi },
];

const SOCIAL_HOSTS = {
  "x.com": "x", "twitter.com": "x", "t.me": "telegram", "discord.gg": "discord",
  "discord.com": "discord", "github.com": "github", "medium.com": "blog",
};

export function stripHtml(html) {
  return decodeEntities(
    html
      .replace(/<!--[\s\S]*?-->/g, " ")
      .replace(/<(script|style|noscript|svg)\b[\s\S]*?<\/\1>/gi, " ")
      .replace(/<[^>]+>/g, " "),
  ).replace(/\s+/g, " ").trim();
}

function decodeEntities(s) {
  return s
    .replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Math.min(Number(n), 0x10ffff)));
}

export function extractMeta(html) {
  const title = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html);
  let description = null;
  for (const tag of html.match(/<meta\b[^>]*>/gi) || []) {
    const name = /(?:name|property)=["'](description|og:description)["']/i.exec(tag);
    const content = /content=["']([^"']*)["']/i.exec(tag);
    if (name && content) {
      description = decodeEntities(content[1]).trim();
      break;
    }
  }
  return { title: title ? stripHtml(title[1]).slice(0, 200) : null, description: description ? description.slice(0, 500) : null };
}

export function extractLinks(html, baseUrl) {
  const found = {};
  for (const m of html.matchAll(/href=["']([^"'#][^"']*)["']/gi)) {
    let u;
    try {
      u = new URL(decodeEntities(m[1]), baseUrl);
    } catch {
      continue;
    }
    if (u.protocol !== "https:") continue;
    const host = u.hostname.replace(/^www\./, "");
    const kind = SOCIAL_HOSTS[host] || (/^docs?\./.test(host) ? "docs" : null);
    if (!kind) continue;
    if (kind === "github" && u.pathname.split("/").filter(Boolean).length < 1) continue;
    (found[kind] ||= new Set()).add(u.origin + u.pathname.replace(/\/$/, ""));
  }
  return Object.fromEntries(Object.entries(found).map(([k, v]) => [k, [...v].slice(0, 5)]));
}

export function scanRisk(text) {
  const hits = [];
  for (const { id, label, re } of RISK_PATTERNS) {
    re.lastIndex = 0;
    const contexts = [];
    for (const m of text.matchAll(re)) {
      const start = Math.max(0, m.index - 80);
      contexts.push(text.slice(start, m.index + m[0].length + 80));
      if (contexts.length >= 2) break;
    }
    if (contexts.length) hits.push({ id, label, contexts });
  }
  return hits;
}

export async function fetchWebsite(rawUrl, deps = {}) {
  const fetchedAt = new Date().toISOString();
  const result = await safeFetch(rawUrl, { fetchImpl: deps.fetchImpl, timeoutMs: 8000, maxBytes: 500_000 });
  const base = { id: "website", title: "وب‌سایت رسمی (واردشده توسط کاربر)", url: rawUrl, fetchedAt };

  if (!result.ok) {
    return { ...base, ok: false, data: null, error: result.error, limitations: ["صفحه دریافت نشد؛ هیچ ادعایی دربارهٔ محتوای سایت قابل تأیید نیست."] };
  }

  const html = result.text;
  const text = stripHtml(html);
  const limitations = [
    "این آدرس را کاربر داده است و رسمی‌بودن آن مستقل تأیید نشده، مگر اینکه منبع دیگری (مثلاً CoinGecko) همان را گزارش کند.",
    "فقط صفحهٔ اصلی بررسی شده، نه کل سایت. محتوای ساخته‌شده با جاوااسکریپت دیده نمی‌شود.",
  ];
  if (result.truncated) limitations.push("حجم صفحه بیش از حد مجاز بود و بخشی از آن خوانده شد.");
  if (text.length < 200) limitations.push("متن قابل خواندن بسیار کم است (احتمالاً صفحهٔ جاوااسکریپتی).");

  return {
    ...base,
    url: result.finalUrl,
    ok: true,
    error: null,
    data: {
      finalUrl: result.finalUrl,
      redirected: result.redirects > 0,
      ...extractMeta(html),
      textExcerpt: text.slice(0, 3000),
      links: extractLinks(html, result.finalUrl),
      riskMentions: scanRisk(text),
    },
    limitations,
  };
}
