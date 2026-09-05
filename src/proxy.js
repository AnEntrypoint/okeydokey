import { decrypt, encrypt, hashKey } from "./crypto.js";
import { resolveUpstreamToken, injectCredential } from "./auth/engine.js";
import { createUpstreamKeyring } from "./keyring/upstream.js";
import { rotateCredentials } from "./keyring/rotate.js";
import * as repo from "./db/repo.js";

// Headers that describe the byte framing of ONE hop. `fetch` has already
// decoded the upstream body by the time we see it, so forwarding the
// upstream's content-encoding hands the caller a decompressed body labelled
// compressed, and its content-length counts bytes that no longer exist.
const PER_HOP_HEADERS = ["content-encoding", "content-length", "transfer-encoding", "connection", "keep-alive", "upgrade"];

// A caller's own bearer key is an okeydokey credential, never an upstream one:
// forwarding it would leak the gateway's issued key to every upstream. `host`
// belongs to this server, not the target.
const CALLER_ONLY_HEADERS = ["authorization", "host", "content-length", "connection", "keep-alive", "upgrade"];

export const upstreamKeyring = createUpstreamKeyring({
  loadSecrets: async (upstreamId) => {
    const rows = await repo.listSecrets(upstreamId);
    return rows.map((row) => decrypt(row.secret_ciphertext));
  },
});

// Rotation only applies where a second credential could plausibly answer
// differently. A token-derived kind resolves through a refresh flow whose
// output is one token, so a rejected token means "refresh failed", not "try
// the next key".
const ROTATABLE_KINDS = new Set(["static"]);

export async function handleProxyRequest(req) {
  const start = Date.now();
  const url = new URL(req.url);
  const [, , upstreamName, ...rest] = url.pathname.split("/"); // /proxy/:name/*
  const upstreamPath = "/" + rest.join("/");

  const callerToken = (req.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!callerToken) return json(401, { error: "missing bearer token" });

  const apiKey = await repo.findApiKeyByHash(hashKey(callerToken));
  if (!apiKey) return json(401, { error: "invalid or revoked api key" });

  const upstream = await repo.findUpstreamByName(upstreamName);
  if (!upstream) return json(404, { error: `unknown upstream: ${upstreamName}` });

  const grant = await repo.findGrant(apiKey.id, upstream.id);
  if (!grant) return json(403, { error: "api key not granted access to this upstream" });
  if (!upstreamPath.startsWith(grant.path_prefix)) return json(403, { error: "path outside granted prefix" });

  const descriptor = JSON.parse(upstream.auth_descriptor);
  const targetUrl = new URL(upstream.base_url.replace(/\/$/, "") + upstreamPath + url.search);

  // The body is read once here rather than streamed straight through: a
  // rotation retry needs to send the same bytes again, and a consumed
  // ReadableStream cannot be replayed.
  const body = ["GET", "HEAD"].includes(req.method) ? undefined : Buffer.from(await req.arrayBuffer());

  const send = async (token) => {
    const outHeaders = new Headers(req.headers);
    for (const name of CALLER_ONLY_HEADERS) outHeaders.delete(name);
    const attemptUrl = new URL(targetUrl);
    injectCredential({ descriptor, token, headers: outHeaders, url: attemptUrl });
    return fetch(attemptUrl, { method: req.method, headers: outHeaders, body });
  };

  let upstreamRes;
  let rotations = 0;

  if (ROTATABLE_KINDS.has(descriptor.kind)) {
    await upstreamKeyring.load(upstream.id);
    const rotated = await rotateCredentials(upstreamKeyring, upstream.id, send);
    if (rotated.exhausted) return json(500, { error: `upstream ${upstreamName} has no credential on file` });
    upstreamRes = rotated.result;
    rotations = rotated.rotations;
  } else {
    const credentials = descriptor.kind === "bearer_passthrough" ? {} : await repo.findCredentials(upstream.id);
    const { token } = await resolveUpstreamToken({
      descriptor,
      credentials: credentials ?? {},
      callerToken,
      decrypt,
      encrypt,
      saveCredentials: (fields) => repo.saveCredentials(upstream.id, fields),
    });
    upstreamRes = await send(token);
  }

  await repo.touchApiKey(apiKey.id);
  await repo.logRequest({
    apiKeyId: apiKey.id,
    upstreamId: upstream.id,
    method: req.method,
    path: upstreamPath,
    status: upstreamRes.status,
    durationMs: Date.now() - start,
  });

  const responseHeaders = new Headers(upstreamRes.headers);
  for (const name of PER_HOP_HEADERS) responseHeaders.delete(name);
  if (rotations > 0) responseHeaders.set("x-okeydokey-credential-rotations", String(rotations));

  // The body is handed back as the live stream it is. Buffering it here would
  // hold a server-sent-event response until the upstream closed it, which for
  // a token-by-token API means the caller waits out the whole completion and
  // then receives it at once.
  return new Response(upstreamRes.body, { status: upstreamRes.status, headers: responseHeaders });
}

function json(status, body) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}
