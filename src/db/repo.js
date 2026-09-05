import { db } from "./client.js";

export async function findApiKeyByHash(hash) {
  const res = await db.execute({
    sql: `SELECT * FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL`,
    args: [hash],
  });
  return res.rows[0] ?? null;
}

export async function findGrant(apiKeyId, upstreamId) {
  const res = await db.execute({
    sql: `SELECT * FROM key_grants WHERE api_key_id = ? AND upstream_id = ?`,
    args: [apiKeyId, upstreamId],
  });
  return res.rows[0] ?? null;
}

export async function findUpstreamByName(name) {
  const res = await db.execute({
    sql: `SELECT * FROM upstreams WHERE name = ?`,
    args: [name],
  });
  return res.rows[0] ?? null;
}

export async function findCredentials(upstreamId) {
  const res = await db.execute({
    sql: `SELECT * FROM upstream_credentials WHERE upstream_id = ?`,
    args: [upstreamId],
  });
  return res.rows[0] ?? null;
}

export async function saveCredentials(upstreamId, fields) {
  const keys = Object.keys(fields);
  if (keys.length === 0) return;
  const sets = keys.map((k) => `${k} = ?`).join(", ");
  await db.execute({
    sql: `UPDATE upstream_credentials SET ${sets}, updated_at = unixepoch() WHERE upstream_id = ?`,
    args: [...keys.map((k) => fields[k]), upstreamId],
  });
}

export async function touchApiKey(id) {
  await db.execute({ sql: `UPDATE api_keys SET last_used_at = unixepoch() WHERE id = ?`, args: [id] });
}

export async function logRequest({ apiKeyId, upstreamId, method, path, status, durationMs }) {
  await db.execute({
    sql: `INSERT INTO request_log (api_key_id, upstream_id, method, path, status, duration_ms) VALUES (?, ?, ?, ?, ?, ?)`,
    args: [apiKeyId, upstreamId, method, path, status, durationMs],
  });
}
