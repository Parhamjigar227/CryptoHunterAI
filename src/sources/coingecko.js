import { safeFetch } from "../safe-fetch.js";

const API = "https://api.coingecko.com/api/v3";
const PLATFORM_IDS = {
  ethereum: "ethereum", bsc: "binance-smart-chain", polygon: "polygon-pos", arbitrum: "arbitrum-one",
  optimism: "optimistic-ethereum", base: "base", avalanche: "avalanche", solana: "solana",
};
const COIN_QUERY = "localization=false&tickers=false&community_data=false&developer_data=false&sparkline=false";

async function getJson(path, deps) {
  const r = await safeFetch(`${API}${path}`, { fetchImpl: deps.fetchImpl, accept: ["application/json"], timeoutMs: 8000 });
  if (!r.ok) return { ok: false, error: r.error, status: r.status };
  try {
    return { ok: true, json: JSON.parse(r.text) };
  } catch {
    return { ok: false, error: { code: "invalid_json", message: "پاسخ CoinGecko JSON معتبر نبود." } };
  }
}

const sameAddress = (a, b) => typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase();

export function summarizeCoin(c, contract) {
  const md = c.market_data || {};
  const platforms = c.platforms || {};
  return {
    id: c.id ?? null,
    name: c.name ?? null,
    symbol: c.symbol ?? null,
    marketCapRank: c.market_cap_rank ?? null,
    categories: (c.categories || []).slice(0, 8),
    genesisDate: c.genesis_date ?? null,
    homepage: (c.links?.homepage || []).filter(Boolean).slice(0, 3),
    githubRepos: (c.links?.repos_url?.github || []).filter(Boolean).slice(0, 3),
    contracts: Object.fromEntries(Object.entries(platforms).filter(([, v]) => v).slice(0, 10)),
    contractMatch: contract ? Object.values(platforms).some((v) => sameAddress(v, contract)) : null,
    supply: {
      circulating: md.circulating_supply ?? null,
      total: md.total_supply ?? null,
      max: md.max_supply ?? null,
    },
    priceUsd: md.current_price?.usd ?? null,
    marketCapUsd: md.market_cap?.usd ?? null,
  };
}

export async function fetchCoinGecko({ name, chain, contract }, deps = {}) {
  const fetchedAt = new Date().toISOString();
  const base = { id: "coingecko", title: "CoinGecko (داده‌های بازار و قرارداد)", url: "https://www.coingecko.com", fetchedAt };
  const failed = (error, limitations = []) => ({
    ...base, ok: false, data: null, error,
    limitations: ["اطلاعات بازار دریافت نشد.", ...limitations],
  });

  let coinJson = null;
  let matchedBy = null;
  let candidates = [];
  const platform = PLATFORM_IDS[chain];

  if (contract && platform) {
    const addr = chain === "solana" ? contract : contract.toLowerCase();
    const r = await getJson(`/coins/${platform}/contract/${addr}`, deps);
    if (r.ok) {
      coinJson = r.json;
      matchedBy = "contract";
    } else if (r.status === 404) {
      if (!name) return failed({ code: "not_found", message: "این آدرس قرارداد در CoinGecko یافت نشد." }, ["نبود در CoinGecko به معنی نامعتبر بودن یا کلاهبرداری نیست؛ فقط یعنی تأیید مستقل نشده."]);
    } else if (!name) {
      return failed(r.error);
    }
  }

  if (!coinJson && name) {
    const s = await getJson(`/search?query=${encodeURIComponent(name)}`, deps);
    if (!s.ok) return failed(s.error);
    candidates = (s.json.coins || []).slice(0, 5).map((c) => ({ id: c.id, name: c.name, symbol: c.symbol, marketCapRank: c.market_cap_rank ?? null }));
    if (!candidates.length) return failed({ code: "not_found", message: "پروژه‌ای با این نام در CoinGecko پیدا نشد." }, ["نبود در CoinGecko به معنی نامعتبر بودن نیست؛ ممکن است پروژه هنوز توکن منتشرنشده داشته باشد."]);
    const lower = name.toLowerCase();
    const exact = candidates.find((c) => c.name?.toLowerCase() === lower || c.symbol?.toLowerCase() === lower);
    matchedBy = exact ? "search-exact" : "search-top-unverified";
    const pick = exact || candidates[0];
    const c = await getJson(`/coins/${encodeURIComponent(pick.id)}?${COIN_QUERY}`, deps);
    if (!c.ok) return failed(c.error);
    coinJson = c.json;
  }

  if (!coinJson) return failed({ code: "no_query", message: "نام یا آدرس قراردادِ قابل جست‌وجو داده نشده است." });

  const data = { ...summarizeCoin(coinJson, contract), matchedBy, candidates };
  const limitations = [
    "قیمت و ارزش بازار لحظه‌ای و وابسته به تجمیع CoinGecko است و برای سنجش اعتبار پروژه کافی نیست.",
    "جدول آنلاک/وستینگ توکن در این منبع بررسی نشده است.",
  ];
  if (matchedBy === "search-top-unverified") limitations.push("تطبیق فقط با جست‌وجوی نام و بدون تطابق دقیق انجام شد؛ ممکن است توکن دیگری با نام مشابه باشد.");
  if (matchedBy === "search-exact") limitations.push("تطبیق بر اساس نام یا نماد است؛ نام‌های تکراری در بازار رایج است و این تطابق هویت را اثبات نمی‌کند.");
  if (contract && data.contractMatch === false) limitations.push("آدرس قراردادِ واردشده در فهرست قراردادهای این توکن در CoinGecko نیست؛ هشدار: ممکن است توکن جعلی یا اشتباه باشد.");

  return { ...base, url: data.id ? `https://www.coingecko.com/en/coins/${data.id}` : base.url, ok: true, error: null, data, limitations };
}
