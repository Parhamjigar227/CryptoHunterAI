import { fetchWebsite } from "./sources/website.js";
import { fetchGithubRepo, parseGithubRepo } from "./sources/github.js";
import { fetchCoinGecko } from "./sources/coingecko.js";

// Collects evidence from real sources. Returns plain data only; nothing here
// is trusted as instructions downstream (see src/analyze.js).
// deps: { fetchImpl?, githubToken?, coingeckoKey?, onProgress?(event) }
export async function runResearch(input, deps = {}) {
  const emit = deps.onProgress || (() => {});
  const startedAt = new Date().toISOString();
  const sources = [];
  const notes = [];

  emit({ type: "stage", stage: "sources", message: "در حال دریافت منابع…" });

  const [site, coin] = await Promise.all([
    input.url ? fetchWebsite(input.url, deps).then((s) => (emit({ type: "source", id: s.id, ok: s.ok }), s)) : null,
    input.name || input.contract ? fetchCoinGecko(input, { fetchImpl: deps.fetchImpl, apiKey: deps.coingeckoKey }).then((s) => (emit({ type: "source", id: s.id, ok: s.ok }), s)) : null,
  ]);
  if (site) sources.push(site);
  if (coin) sources.push(coin);

  // GitHub repo: prefer one linked from the official site, then CoinGecko.
  const candidates = [
    ...(site?.ok ? site.data.links.github || [] : []),
    ...(coin?.ok ? coin.data.githubRepos : []),
  ];
  const repo = candidates.map(parseGithubRepo).find(Boolean);
  if (repo) {
    const gh = await fetchGithubRepo(repo, { fetchImpl: deps.fetchImpl, token: deps.githubToken });
    emit({ type: "source", id: gh.id, ok: gh.ok });
    sources.push(gh);
  } else {
    notes.push("لینک مخزن GitHub در منابع بررسی‌شده پیدا نشد.");
  }

  if (!input.url) notes.push("آدرس وب‌سایت داده نشد؛ بررسی سایت رسمی انجام نشد.");
  const okCount = sources.filter((s) => s.ok).length;
  if (okCount === 0) notes.push("هیچ منبعی با موفقیت دریافت نشد؛ تحلیل ممکن نیست.");

  return {
    input,
    startedAt,
    finishedAt: new Date().toISOString(),
    sources,
    notes,
    limited: okCount < 2 || sources.some((s) => !s.ok),
    usable: okCount > 0,
  };
}
