-- Generalized bearer-key gateway schema.
-- No table encodes a specific provider; providers are rows of data (upstreams.auth_descriptor).

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- One upstream = one target API surface, described entirely by auth_descriptor (JSON).
-- auth_descriptor.kind selects the auth strategy at runtime: "static" | "oauth2" | "device" | "bearer_passthrough".
-- Every field the strategy needs (token_url, device_url, scopes, header shape, refresh policy) lives inside the JSON,
-- so adding a new provider is a new row, never a new code path.
CREATE TABLE IF NOT EXISTS upstreams (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  base_url TEXT NOT NULL,
  auth_descriptor TEXT NOT NULL, -- JSON, see src/auth/descriptor.schema.json
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- The upstream credential material itself (client secret, static key, refresh token, device grant state).
-- Encrypted at rest (see src/crypto.js). Never returned to callers.
CREATE TABLE IF NOT EXISTS upstream_credentials (
  upstream_id TEXT PRIMARY KEY REFERENCES upstreams(id) ON DELETE CASCADE,
  secret_ciphertext TEXT NOT NULL,
  access_token_ciphertext TEXT,
  refresh_token_ciphertext TEXT,
  expires_at INTEGER,
  -- Set when a refresh token has been rejected as permanently invalid, so the
  -- gateway stops paying for an exchange that cannot succeed on every request.
  refresh_dead INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- A bearer key issued to a caller. Scoped to zero or more upstreams via key_grants.
-- The rotatable credential pool for an upstream whose auth kind is a plain
-- stored secret. Rate-limited APIs are commonly fronted by several keys for
-- one account; holding exactly one made an exhausted key a hard outage.
-- Position is declaration order, which is also the order they are tried.
CREATE TABLE IF NOT EXISTS upstream_secrets (
  upstream_id TEXT NOT NULL REFERENCES upstreams(id) ON DELETE CASCADE,
  position INTEGER NOT NULL,
  secret_ciphertext TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY (upstream_id, position)
);

CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE, -- sha256 of the bearer token; raw token never stored
  key_prefix TEXT NOT NULL,      -- first 8 chars, for display/lookup only
  revoked_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  last_used_at INTEGER
);

CREATE TABLE IF NOT EXISTS key_grants (
  api_key_id TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
  upstream_id TEXT NOT NULL REFERENCES upstreams(id) ON DELETE CASCADE,
  path_prefix TEXT NOT NULL DEFAULT '/', -- restricts which upstream paths this key may reach
  rate_limit_per_min INTEGER,
  PRIMARY KEY (api_key_id, upstream_id)
);

CREATE TABLE IF NOT EXISTS request_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  api_key_id TEXT REFERENCES api_keys(id) ON DELETE SET NULL,
  upstream_id TEXT REFERENCES upstreams(id) ON DELETE SET NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  status INTEGER,
  duration_ms INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_key_grants_upstream ON key_grants(upstream_id);
CREATE INDEX IF NOT EXISTS idx_request_log_key ON request_log(api_key_id, created_at);
