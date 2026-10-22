// Test-only HTTP adapter: runs the real Worker handler in Node and serves public/ as assets.
// External sources (website/CoinGecko/GitHub) and the AI binding are fakes; see ui.e2e.mjs.
import http from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { handleRequest } from "../../src/worker.js";

const PUBLIC = new URL("../../public/", import.meta.url).pathname;
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css" };

async function serveAsset(request) {
  let path = new URL(request.url).pathname;
  if (path === "/") path = "/index.html";
  const file = normalize(join(PUBLIC, path));
  if (!file.startsWith(PUBLIC)) return new Response("forbidden", { status: 403 });
  try {
    return new Response(await readFile(file), { headers: { "content-type": TYPES[extname(file)] || "application/octet-stream" } });
  } catch {
    return new Response("not found", { status: 404 });
  }
}

export function startServer({ env = {}, fetchImpl }) {
  const fullEnv = { ASSETS: { fetch: serveAsset }, ...env };
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const hasBody = !["GET", "HEAD"].includes(req.method);
    const request = new Request(`http://${req.headers.host}${req.url}`, {
      method: req.method, headers: req.headers, body: hasBody ? Buffer.concat(chunks) : undefined,
    });
    const response = await handleRequest(request, fullEnv, { waitUntil() {} }, { fetchImpl });
    res.writeHead(response.status, Object.fromEntries(response.headers));
    if (response.body) for await (const chunk of response.body) res.write(chunk);
    res.end();
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => {
    resolve({ url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) });
  }));
}
