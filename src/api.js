import { randomUUID } from "node:crypto";
import { db } from "./db/client.js";
import { encrypt, generateApiKey } from "./crypto.js";

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

export async function createUpstream({ name, baseUrl, authDescriptor, secret }) {
  const id = randomUUID();
  await db.execute({
    sql: `INSERT INTO upstreams (id, name, base_url, auth_descriptor) VALUES (?, ?, ?, ?)`,
    args: [id, name, baseUrl, JSON.stringify(authDescriptor)],
  });
  await db.execute({
    sql: `INSERT INTO upstream_credentials (upstream_id, secret_ciphertext) VALUES (?, ?)`,
    args: [id, encrypt(secret ?? "")],
  });
  return { id, name, baseUrl, authDescriptor };
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
