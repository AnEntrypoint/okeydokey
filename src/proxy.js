import { hashKey } from "./crypto.js";
import { decrypt, encrypt } from "./crypto.js";
import { resolveUpstreamToken, injectCredential } from "./auth/engine.js";
import * as repo from "./db/repo.js";

// Fully generic: the only thing that varies per upstream is data (upstreams.auth_descriptor,
// upstreams.base_url) pulled from the DB at request time. No branch here names a provider.
export async function handleProxyRequest(req) {
  const start = Date.now();
  const url = new URL(req.url);
  const [, , upstreamName, ...rest] = url.pathname.split("/"); // /proxy/:name/*
  const upstreamPath = "/" + rest.join("/");

  const authHeader = req.headers.get("authorization") ?? "";
  const callerToken = authHeader.replace(/^Bearer\s+/i, "");
  if (!callerToken) return json(401, { error: "missing bearer token" });

  const apiKey = await repo.findApiKeyByHash(hashKey(callerToken));
  if (!apiKey) return json(401, { error: "invalid or revoked api key" });

  const upstream = await repo.findUpstreamByName(upstreamName);
  if (!upstream) return json(404, { error: `unknown upstream: ${upstreamName}` });

  const grant = await repo.findGrant(apiKey.id, upstream.id);
  if (!grant) return json(403, { error: "api key not granted access to this upstream" });
  if (!upstreamPath.startsWith(grant.path_prefix)) return json(403, { error: "path outside granted prefix" });

  const descriptor = JSON.parse(upstream.auth_descriptor);
  const credentials = descriptor.kind === "bearer_passthrough" ? {} : await repo.findCredentials(upstream.id);

  const { token } = await resolveUpstreamToken({
    descriptor,
    credentials: credentials ?? {},
    callerToken,
    decrypt,
    encrypt,
    saveCredentials: (fields) => repo.saveCredentials(upstream.id, fields),
  });

  const targetUrl = new URL(upstream.base_url.replace(/\/$/, "") + upstreamPath + url.search);
  const outHeaders = new Headers(req.headers);
  outHeaders.delete("authorization");
  outHeaders.delete("host");
  injectCredential({ descriptor, token, headers: outHeaders, url: targetUrl });

  const upstreamRes = await fetch(targetUrl, {
    method: req.method,
    headers: outHeaders,
    body: ["GET", "HEAD"].includes(req.method) ? undefined : req.body,
    duplex: "half",
  });

  await repo.touchApiKey(apiKey.id);
  await repo.logRequest({
    apiKeyId: apiKey.id,
    upstreamId: upstream.id,
    method: req.method,
    path: upstreamPath,
    status: upstreamRes.status,
    durationMs: Date.now() - start,
  });

  return upstreamRes;
}

function json(status, body) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}
