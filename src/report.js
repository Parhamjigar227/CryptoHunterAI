// Deterministic parts of the report. The model never produces these, so it
// cannot invent scores, sources or timestamps.

export const SECTION_ORDER = [
  "خلاصه",
  "یافته‌های تأییدشده",
  "ادعاهای تأییدنشده",
  "تناقض‌ها و هشدارهای امنیتی",
  "وضعیت توکن و ایردراپ",
  "ریسک‌های فنی و اقتصادی",
  "اطلاعات نامعلوم",
  "پیشنهاد برای بررسی بعدی",
];

const DAY = 86_400_000;

// Each signal has a documented weight. This is a count of observed warning
// signs, not a probability of fraud and not a safety guarantee.
export function computeRisk(research, now = Date.now()) {
  const signals = [];
  const add = (id, weight, text, source) => signals.push({ id, weight, text, source });
  const byId = Object.fromEntries(research.sources.map((s) => [s.id, s]));

  const site = byId.website;
  if (site?.ok) {
    const mentions = Object.fromEntries(site.data.riskMentions.map((m) => [m.id, m]));
    if (mentions.guaranteed_returns) add("guaranteed_returns", 3, "وب‌سایت عبارت‌هایی مثل «سود تضمینی/بدون ریسک» دارد.", "website");
    if (mentions.wallet_validation) add("wallet_validation", 3, "وب‌سایت به «اعتبارسنجی/همگام‌سازی کیف پول» اشاره می‌کند (الگوی رایج کلاهبرداری).", "website");
    if (mentions.seed_phrase) add("seed_phrase_mention", 1, "وب‌سایت به عبارت بازیابی اشاره دارد (ممکن است فقط هشدار امنیتی باشد؛ زمینهٔ متن را بخوانید).", "website");
    if (mentions.private_key) add("private_key_mention", 1, "وب‌سایت به کلید خصوصی اشاره دارد (ممکن است فقط هشدار امنیتی باشد؛ زمینهٔ متن را بخوانید).", "website");
  }

  const cg = byId.coingecko;
  if (cg?.ok && cg.data.contractMatch === false) {
    add("contract_mismatch", 4, "آدرس قراردادِ واردشده در فهرست قراردادهای این توکن در CoinGecko نیست.", "coingecko");
  }
  if (cg && !cg.ok && cg.error?.code === "not_found") {
    add("not_listed", 1, "پروژه/قرارداد در CoinGecko پیدا نشد (تأیید مستقل وجود ندارد).", "coingecko");
  }

  const gh = byId.github;
  if (gh?.ok) {
    const d = gh.data;
    if (d.archived) add("repo_archived", 1, "مخزن GitHub آرشیو شده است.", "github");
    if (d.isFork) add("repo_fork", 1, "مخزن GitHub فورک است.", "github");
    if (d.createdAt && now - Date.parse(d.createdAt) < 30 * DAY) add("repo_new", 1, "مخزن GitHub کمتر از ۳۰ روز پیش ساخته شده است.", "github");
    if (d.pushedAt && now - Date.parse(d.pushedAt) > 365 * DAY) add("repo_stale", 1, "آخرین فعالیت مخزن بیش از یک سال پیش بوده است.", "github");
  }

  const score = signals.reduce((n, s) => n + s.weight, 0);
  const evaluated = research.sources.filter((s) => s.ok).length;
  let level;
  if (evaluated === 0) level = "نامشخص";
  else if (score === 0) level = "هیچ علامت هشداری در منابع بررسی‌شده دیده نشد (به معنی امن بودن نیست)";
  else if (score <= 2) level = "کم";
  else if (score <= 5) level = "متوسط";
  else level = "زیاد";

  return {
    score,
    level,
    signals,
    method: "جمع وزن‌دار علائم هشدار مشاهده‌شده: «سود تضمینی/اعتبارسنجی کیف پول» ۳، «عدم تطابق قرارداد» ۴، سایر علائم ۱ امتیاز. ≤۲ کم، ۳ تا ۵ متوسط، ≥۶ زیاد. این عدد احتمال کلاهبرداری نیست و فقط به منابع بررسی‌شده محدود است.",
  };
}

export function computeConfidence(research) {
  const ok = research.sources.filter((s) => s.ok).length;
  if (ok === 0) return { level: "ندارد", reason: "هیچ منبعی با موفقیت دریافت نشد." };
  const base = ok === 1 ? "کم" : "متوسط";
  return {
    level: base,
    reason: `${ok} منبع از ${research.sources.length} منبع دریافت شد. اطمینان «بالا» در این نسخه ممکن نیست چون جست‌وجوی مستقل وب، کاوشگر بلاکچین و حسابرسی امنیتی انجام نمی‌شود.`,
  };
}

// Normalises Persian text for heading comparison: ZWNJ -> space, Arabic ي/ك -> ی/ک.
const norm = (t) => t.replace(/[\u200c\u200f]/g, " ").replace(/ي/g, "ی").replace(/ك/g, "ک").replace(/\s+/g, " ").trim();

// Real models wrap output in code fences and style headings differently
// ("### x", "**x**", "1. x", trailing colon). Returns the bare heading text or null.
function headingText(line) {
  const m = /^\s{0,3}(?:#{1,6}\s*|\*\*|\d+[.)]\s*)(.+?)\s*$/.exec(line);
  if (!m) return null;
  return norm(m[1].replace(/\*+/g, "").replace(/[:：]+\s*$/, ""));
}

// Splits model markdown into { heading: body } for the expected headings. If no
// expected heading is found at all, the whole text is kept under "خلاصه".
export function splitSections(markdown) {
  const text = String(markdown || "").replace(/^\s*```[a-z]*\s*\n/i, "").replace(/\n\s*```\s*$/, "").trim();
  const expected = SECTION_ORDER.map((h) => [h, norm(h)]);
  const out = {};
  let current = null;
  for (const line of text.split("\n")) {
    const heading = headingText(line);
    const hit = heading && expected.find(([, n]) => heading === n || heading.startsWith(n + " ") || heading.startsWith(n + "("));
    if (hit) {
      current = hit[0];
      if (!(current in out)) out[current] = [];
      continue;
    }
    // An unknown "#" heading ends the current section so its text cannot leak into another one.
    if (/^\s{0,3}#{1,6}\s/.test(line)) { current = null; continue; }
    if (current) out[current].push(line);
  }
  const result = Object.fromEntries(Object.entries(out).map(([k, v]) => [k, v.join("\n").trim()]));
  if (!Object.keys(result).length && text) return { "خلاصه": text };
  return result;
}

const MISSING = "_مدل این بخش را تولید نکرد؛ اطلاعات نامعلوم است._";
const NO_AI = "_تحلیل هوش مصنوعی در دسترس نبود و این بخش تولید نشد. جدول منابع و علائم هشدار خودکار در همین گزارش همچنان معتبرند._";

function sourcesTable(sources) {
  const rows = sources.map((s) => {
    const status = s.ok ? "دریافت شد" : `ناموفق (${s.error?.message || "نامشخص"})`;
    return `| \`${s.id}\` | [${s.title}](${s.url}) | ${s.fetchedAt} | ${status} |`;
  });
  const limits = sources.flatMap((s) => s.limitations.map((l) => `- **${s.id}:** ${l}`));
  return [
    "| شناسه | منبع | زمان دریافت (UTC) | وضعیت |",
    "|---|---|---|---|",
    ...rows,
    "",
    "**محدودیت‌های هر منبع:**",
    ...limits,
  ].join("\n");
}

export function assembleReport({ research, sections, aiError, risk, confidence, model, now = new Date() }) {
  const inp = research.input;
  const get = (h) => (aiError ? NO_AI : sections[h] || MISSING);

  const head = [
    `# گزارش تحقیق: ${inp.name || inp.url || inp.contract}`,
    "",
    `- **تاریخ و زمان بررسی (UTC):** ${now.toISOString()}`,
    inp.url ? `- **وب‌سایت واردشده:** ${inp.url}` : null,
    inp.contract ? `- **قرارداد واردشده:** \`${inp.contract}\` (شبکه: ${inp.chain})` : null,
    inp.question ? `- **سؤال کاربر:** ${inp.question}` : null,
    research.limited ? "- **توجه:** تحقیق محدود بوده است (برخی منابع در دسترس نبودند یا کمتر از دو منبع دریافت شد)." : null,
    aiError ? `- **توجه:** تحلیل هوش مصنوعی انجام نشد: ${aiError.message}` : null,
    model ? `- **مدل تحلیل:** \`${model}\`` : null,
  ].filter(Boolean);

  const signals = risk.signals.length
    ? risk.signals.map((s) => `- (+${s.weight}) ${s.text} [${s.source}]`).join("\n")
    : "- هیچ علامتی ثبت نشد.";

  const notes = research.notes.length ? research.notes.map((n) => `- ${n}`).join("\n") : "";

  return [
    head.join("\n"),
    "## خلاصه\n\n" + get("خلاصه"),
    "## منابع بررسی‌شده\n\n" + sourcesTable(research.sources) + (notes ? "\n\n" + notes : ""),
    "## یافته‌های تأییدشده\n\n" + get("یافته‌های تأییدشده"),
    "## ادعاهای تأییدنشده\n\n" + get("ادعاهای تأییدنشده"),
    "## تناقض‌ها و هشدارهای امنیتی\n\n" + get("تناقض‌ها و هشدارهای امنیتی"),
    "## وضعیت توکن و ایردراپ\n\n" + get("وضعیت توکن و ایردراپ"),
    "## ریسک‌های فنی و اقتصادی\n\n" + get("ریسک‌های فنی و اقتصادی"),
    `## علائم هشدار و سطح ریسک\n\n**سطح علائم هشدار:** ${risk.level} (مجموع وزن: ${risk.score})\n\n${signals}\n\n**روش محاسبه:** ${risk.method}`,
    `## میزان اطمینان\n\n**${confidence.level}** — ${confidence.reason}`,
    "## اطلاعات نامعلوم\n\n" + get("اطلاعات نامعلوم"),
    "## پیشنهاد برای بررسی بعدی\n\n" + get("پیشنهاد برای بررسی بعدی"),
    "---\n_این گزارش ابزار کمکی تحقیق است، نه مشاوره مالی. هیچ سود یا امنیتی تضمین نمی‌شود و هیچ تراکنشی انجام نشده است._",
  ].join("\n\n");
}
