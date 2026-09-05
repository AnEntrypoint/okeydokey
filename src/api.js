import { randomUUID } from "node:crypto";
import { db } from "./db/client.js";
import * as repo from "./db/repo.js";
import { encrypt, generateApiKey } from "./crypto.js";
import { upstreamKeyring } from "./proxy.js";

// Generic management API. Every write here operates on data shaped by the
// UpstreamAuthDescriptor schema; nothing branches on a provider name.

export async function createUser({ email }) {
  const id = randomUUID();
  await db.execute({ sql: `INSERT INTO users (id, email) VALUES (?, ?)`, args: [id, email ?? null] });
  return { id, email };
}

export async function listUsers() {
  const res = await db.execute(`SELECT id, email, created_at FROM users ORDER BY created_at DESC`);
  return res.rows;
}

// `secrets` is the rotatable pool; `secret` remains accepted as the
// single-credential spelling of the same thing. The first entry is also
// written to upstream_credentials, which is where the OAuth kinds read their
// client secret from.
export async function createUpstream({ name, baseUrl, authDescriptor, secret, secrets }) {
  const id = randomUUID();
  const pool = (secrets ?? [secret ?? ""]).map((value) => String(value ?? "")).filter((value, index) => value !== "" || index === 0);
  await db.execute({
    sql: `INSERT INTO upstreams (id, name, base_url, auth_descriptor) VALUES (?, ?, ?, ?)`,
    args: [id, name, baseUrl, JSON.stringify(authDescriptor)],
  });
  await db.execute({
    sql: `INSERT INTO upstream_credentials (upstream_id, secret_ciphertext) VALUES (?, ?)`,
    args: [id, encrypt(pool[0])],
  });
  for (const value of pool) await repo.addSecret(id, encrypt(value));
  await upstreamKeyring.load(id);
  return { id, name, baseUrl, authDescriptor, secretCount: pool.length };
}

export async function addUpstreamSecret({ upstreamId, secret }) {
  const position = await repo.addSecret(upstreamId, encrypt(String(secret ?? "")));
  await upstreamKeyring.load(upstreamId);
  return { upstreamId, position };
}

export async function removeUpstreamSecret({ upstreamId, position }) {
  await repo.deleteSecret(upstreamId, Number(position));
  await upstreamKeyring.load(upstreamId);
  return { upstreamId, position: Number(position) };
}

// Per-credential health for every upstream that holds a rotatable pool.
// Credentials come back masked; nothing here can return material to
// authenticate with.
export async function keyringStatus() {
  const res = await db.execute(`SELECT id, name FROM upstreams ORDER BY name ASC`);
  const upstreams = [];
  for (const row of res.rows) {
    await upstreamKeyring.load(row.id);
    upstreams.push({ upstream: row.name, upstreamId: row.id, credentials: upstreamKeyring.status(row.id) });
  }
  return { upstreams };
}

export async function listUpstreams() {
  const res = await db.execute(`SELECT id, name, base_url, auth_descriptor, created_at FROM upstreams ORDER BY created_at DESC`);
  return res.rows.map((r) => ({ ...r, auth_descriptor: JSON.parse(r.auth_descriptor) }));
}

export async function createApiKey({ userId, name }) {
  const id = randomUUID();
  const { raw, hash, prefix } = generateApiKey();
  await db.execute({
    sql: `INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix) VALUES (?, ?, ?, ?, ?)`,
    args: [id, userId, name, hash, prefix],
  });
  return { id, name, rawKey: raw }; // rawKey is shown exactly once
}

export async function listApiKeys(userId) {
  const res = await db.execute({
    sql: `SELECT id, name, key_prefix, revoked_at, created_at, last_used_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC`,
    args: [userId],
  });
  return res.rows;
}

export async function revokeApiKey(id) {
  await db.execute({ sql: `UPDATE api_keys SET revoked_at = unixepoch() WHERE id = ?`, args: [id] });
}

export async function grantAccess({ apiKeyId, upstreamId, pathPrefix = "/", rateLimitPerMin }) {
  await db.execute({
    sql: `INSERT OR REPLACE INTO key_grants (api_key_id, upstream_id, path_prefix, rate_limit_per_min) VALUES (?, ?, ?, ?)`,
    args: [apiKeyId, upstreamId, pathPrefix, rateLimitPerMin ?? null],
  });
}

export async function revokeAccess({ apiKeyId, upstreamId }) {
  await db.execute({
    sql: `DELETE FROM key_grants WHERE api_key_id = ? AND upstream_id = ?`,
    args: [apiKeyId, upstreamId],
  });
}
