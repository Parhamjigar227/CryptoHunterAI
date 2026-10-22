// Test double for fetch. routes: { [url]: {status?, headers?, body?, throws?} | fn(url, init) }.
// Unlisted URLs fail the test loudly so we never silently hit the network.
export function mockFetch(routes, log = []) {
  return async (url, init) => {
    log.push({ url: String(url), init });
    const route = routes[String(url)];
    if (!route) throw new Error(`mockFetch: unexpected request to ${url}`);
    const r = typeof route === "function" ? route(url, init) : route;
    if (r.throws) throw r.throws;
    const body = typeof r.body === "string" || r.body === undefined ? r.body ?? "" : JSON.stringify(r.body);
    return new Response(body, {
      status: r.status ?? 200,
      headers: { "content-type": "application/json", ...(r.headers || {}) },
    });
  };
}

export const html = (body, extra = {}) => ({ headers: { "content-type": "text/html; charset=utf-8" }, body, ...extra });

// Reads an NDJSON streaming Response into an array of events.
export async function readEvents(response) {
  const text = await response.text();
  return text.split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

// Fake Workers AI binding for tests only (production uses the real binding).
export const fakeAi = (impl) => ({ calls: [], async run(model, input) { this.calls.push({ model, input }); return impl(model, input); } });
