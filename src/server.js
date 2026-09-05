import { createServer } from "node:http";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, normalize } from "node:path";
import { handleProxyRequest } from "./proxy.js";
import * as api from "./api.js";

const PORT = process.env.PORT ?? 8787;
const ROOT = dirname(fileURLToPath(import.meta.url));
const GUI_DIR = join(ROOT, "gui");
const NODE_MODULES_DIR = join(ROOT, "..", "node_modules");

const ROUTES = {
  "POST /api/users": (b) => api.createUser(b),
  "GET /api/users": () => api.listUsers(),
  "POST /api/upstreams": (b) => api.createUpstream(b),
  "GET /api/upstreams": () => api.listUpstreams(),
  "POST /api/keys": (b) => api.createApiKey(b),
  "GET /api/keys": (b, q) => api.listApiKeys(q.get("userId")),
  "POST /api/grants": (b) => api.grantAccess(b),
  "DELETE /api/grants": (b) => api.revokeAccess(b),
  "POST /api/secrets": (b) => api.addUpstreamSecret(b),
  "DELETE /api/secrets": (b) => api.removeUpstreamSecret(b),
  "GET /api/keyring/status": () => api.keyringStatus(),
  "GET /api/health": () => ({ ok: true, uptimeSeconds: Math.floor(process.uptime()) }),
};

const STATIC_MIME = { ".js": "text/javascript", ".css": "text/css", ".html": "text/html", ".json": "application/json" };

async function serveStatic(res, baseDir, relPath) {
  const filePath = normalize(join(baseDir, relPath));
  if (!filePath.startsWith(normalize(baseDir))) {
    res.writeHead(403);
    res.end();
    return true;
  }
  try {
    const data = await readFile(filePath);
    const ext = filePath.slice(filePath.lastIndexOf("."));
    res.writeHead(200, { "content-type": STATIC_MIME[ext] ?? "application/octet-stream" });
    res.end(data);
    return true;
  } catch {
    return false;
  }
}

async function toWebRequest(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const body = Buffer.concat(chunks);
  const url = `http://localhost:${PORT}${req.url}`;
  return new Request(url, {
    method: req.method,
    headers: req.headers,
    body: ["GET", "HEAD"].includes(req.method) ? undefined : body,
  });
}

const server = createServer((req, res) => {
  handleRequest(req, res).catch((err) => {
    console.error("okeydokey request failed:", err);
    if (res.headersSent) res.destroy();
    else {
      res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: String(err?.message ?? err) }));
    }
  });
});

async function handleRequest(req, res) {
  const [pathname, search] = req.url.split("?");
  const query = new URLSearchParams(search ?? "");

  if (pathname.startsWith("/proxy/")) {
    const webReq = await toWebRequest(req);
    const webRes = await handleProxyRequest(webReq);
    res.writeHead(webRes.status, Object.fromEntries(webRes.headers));
    // Piped rather than buffered: a server-sent-event upstream never closes
    // until the whole completion is produced, so awaiting its full body would
    // deliver a token-by-token response all at once at the end.
    if (webRes.body) await pipeline(Readable.fromWeb(webRes.body), res);
    else res.end();
    return;
  }

  const key = `${req.method} ${pathname}`;
  const handler = ROUTES[key];
  if (handler) {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {};
    try {
      const result = await handler(body, query);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(result));
    } catch (err) {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: String(err.message ?? err) }));
    }
    return;
  }

  if (pathname.startsWith("/node_modules/")) {
    if (await serveStatic(res, NODE_MODULES_DIR, pathname.replace("/node_modules/", ""))) return;
  }
  const guiPath = pathname === "/" ? "/index.html" : pathname;
  if (await serveStatic(res, GUI_DIR, guiPath)) return;

  res.writeHead(404, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: "not found" }));
}

server.listen(PORT, () => console.log(`okeydokey listening on :${PORT}`));
