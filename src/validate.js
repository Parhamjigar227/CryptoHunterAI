// Input validation for POST /api/research.
// Everything here is pure (no network, no env) so it can be unit-tested directly.

export const LIMITS = {
  name: 100,
  question: 500,
  url: 2048,
  bodyBytes: 8 * 1024,
};

export const CHAINS = [
  "ethereum", "bsc", "polygon", "arbitrum", "optimism", "base", "avalanche", "solana", "other",
];

const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const BASE58_ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

export class ValidationError extends Error {
  constructor(field, message) {
    super(message);
    this.name = "ValidationError";
    this.field = field;
  }
}

// Strips control characters (incl. newlines) so user text cannot smuggle
// extra lines into prompts or logs, then trims and collapses whitespace.
export function cleanText(value) {
  return String(value ?? "")
    .replace(/[\u0000-\u001f\u007f​-‏‪-‮⁦-⁩]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

export function parseResearchInput(raw) {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new ValidationError("body", "بدنهٔ درخواست باید یک شیء JSON باشد.");
  }

  const name = cleanText(raw.name);
  const question = cleanText(raw.question);
  const urlText = cleanText(raw.url);
  const contract = cleanText(raw.contract);
  const chain = cleanText(raw.chain).toLowerCase() || "other";

  if (name.length > LIMITS.name) {
    throw new ValidationError("name", `نام پروژه نباید بیش از ${LIMITS.name} نویسه باشد.`);
  }
  if (question.length > LIMITS.question) {
    throw new ValidationError("question", `سؤال نباید بیش از ${LIMITS.question} نویسه باشد.`);
  }
  if (!name && !urlText && !contract) {
    throw new ValidationError("name", "حداقل یکی از نام پروژه، آدرس وب‌سایت یا آدرس قرارداد لازم است.");
  }
  if (!CHAINS.includes(chain)) {
    throw new ValidationError("chain", "شبکه نامعتبر است.");
  }

  let url = null;
  if (urlText) {
    if (urlText.length > LIMITS.url) {
      throw new ValidationError("url", "آدرس وب‌سایت بیش از حد طولانی است.");
    }
    url = parsePublicHttpsUrl(urlText);
    if (!url) {
      throw new ValidationError("url", "آدرس وب‌سایت باید یک URL معتبر با https و دامنهٔ عمومی باشد.");
    }
  }

  if (contract) {
    const ok = chain === "solana"
      ? BASE58_ADDRESS.test(contract)
      : EVM_ADDRESS.test(contract) || (chain === "other" && BASE58_ADDRESS.test(contract));
    if (!ok) {
      throw new ValidationError("contract", "قالب آدرس قرارداد با شبکهٔ انتخاب‌شده سازگار نیست.");
    }
  }

  return { name, question, url: url ? url.toString() : null, contract: contract || null, chain };
}

// Returns a URL object only for https URLs that point at a public-looking
// hostname. Hostname-level check only: DNS answers are not inspected here
// (Workers cannot resolve DNS ahead of fetch). See docs/reviews/part-01.md.
export function parsePublicHttpsUrl(text) {
  let url;
  try {
    url = new URL(text);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  if (url.username || url.password) return null;
  if (url.port && url.port !== "443") return null;
  if (!isPublicHostname(url.hostname)) return null;
  url.hash = "";
  return url;
}

export function isPublicHostname(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (!host || host.length > 253) return false;
  if (host.includes(":")) return false; // IPv6 literal
  if (/^[0-9.]+$/.test(host)) return false; // IPv4 literal (any form)
  if (/^0x[0-9a-f]+$/i.test(host)) return false; // hex IP
  if (!host.includes(".")) return false; // single-label names (localhost, intranet)
  const blockedSuffixes = [
    ".localhost", ".local", ".internal", ".lan", ".home", ".corp", ".intranet",
    ".private", ".test", ".invalid", ".example", ".onion", ".arpa",
  ];
  if (blockedSuffixes.some((s) => host.endsWith(s))) return false;
  const labels = host.split(".");
  if (labels.some((l) => l.length === 0 || l.length > 63 || !/^[a-z0-9-]+$/.test(l))) {
    return false;
  }
  // Numeric-only TLD would be an IP in disguise.
  if (/^[0-9]+$/.test(labels[labels.length - 1])) return false;
  return true;
}
