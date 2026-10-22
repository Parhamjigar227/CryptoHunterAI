import { safeFetch } from "../safe-fetch.js";

const RESERVED_OWNERS = new Set([
  "orgs", "sponsors", "features", "topics", "marketplace", "settings", "about", "pricing",
  "login", "join", "explore", "collections", "enterprise", "apps", "events", "readme", "security",
]);
const NAME_RE = /^[A-Za-z0-9_.-]{1,100}$/;

// Accepts a github.com URL and returns { owner, repo } or null.
export function parseGithubRepo(text) {
  let u;
  try {
    u = new URL(text);
  } catch {
    return null;
  }
  if (u.protocol !== "https:" || !["github.com", "www.github.com"].includes(u.hostname)) return null;
  const [owner, rawRepo] = u.pathname.split("/").filter(Boolean);
  if (!owner || !rawRepo || RESERVED_OWNERS.has(owner.toLowerCase())) return null;
  const repo = rawRepo.replace(/\.git$/, "");
  return NAME_RE.test(owner) && NAME_RE.test(repo) ? { owner, repo } : null;
}

export async function fetchGithubRepo({ owner, repo }, deps = {}) {
  const fetchedAt = new Date().toISOString();
  const pageUrl = `https://github.com/${owner}/${repo}`;
  const base = { id: "github", title: `مخزن GitHub: ${owner}/${repo}`, url: pageUrl, fetchedAt };

  const headers = { accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28" };
  if (deps.token) headers.authorization = `Bearer ${deps.token}`;

  const r = await safeFetch(`https://api.github.com/repos/${owner}/${repo}`, {
    fetchImpl: deps.fetchImpl, accept: ["application/json"], headers, timeoutMs: 8000,
  });

  if (!r.ok) {
    const limitations = ["اطلاعات مخزن دریافت نشد."];
    if (r.error.code === "rate_limited" || r.status === 403) {
      limitations.push("محدودیت نرخ GitHub برای درخواست بدون توکن؛ برای رفع، Secret به نام GITHUB_TOKEN (فقط خواندن اطلاعات عمومی) تنظیم شود.");
    }
    if (r.status === 404) limitations.push("مخزن وجود ندارد یا خصوصی است.");
    return { ...base, ok: false, data: null, error: r.error, limitations };
  }

  let j;
  try {
    j = JSON.parse(r.text);
  } catch {
    return { ...base, ok: false, data: null, error: { code: "invalid_json", message: "پاسخ GitHub JSON معتبر نبود." }, limitations: ["اطلاعات مخزن خوانده نشد."] };
  }

  return {
    ...base,
    ok: true,
    error: null,
    data: {
      fullName: j.full_name ?? `${owner}/${repo}`,
      description: j.description ?? null,
      ownerType: j.owner?.type ?? null,
      createdAt: j.created_at ?? null,
      pushedAt: j.pushed_at ?? null,
      stars: j.stargazers_count ?? null,
      forks: j.forks_count ?? null,
      openIssues: j.open_issues_count ?? null,
      archived: Boolean(j.archived),
      isFork: Boolean(j.fork),
      license: j.license?.spdx_id ?? null,
      defaultBranch: j.default_branch ?? null,
      homepage: j.homepage || null,
    },
    limitations: [
      "ستاره و فورک را می‌توان ساختگی کرد و به‌تنهایی نشانهٔ اعتبار نیست.",
      "بررسی کیفیت کد، حسابرسی امنیتی و مالکیت واقعی مخزن انجام نشده است.",
      ...(j.fork ? ["این مخزن فورک است؛ ممکن است کپی پروژهٔ دیگری باشد."] : []),
    ],
  };
}
