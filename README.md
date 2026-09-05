# okeydokey

Generalized bearer-key gateway. Callers get an `okeydokey`-issued bearer key;
upstream credentials (GitHub, Copilot, GCloud, Anthropic, OpenAI, Gemini, AWS,
or any other API) never leave the server.

## Why generalized

There is exactly one code path per **auth mechanism** (`src/auth/strategies/`),
never per provider:

- `static` — a fixed secret/API key, injected verbatim.
- `bearer_passthrough` — no upstream secret held; the caller's own token is forwarded (routing/audit only).
- `oauth2_client_credentials` — RFC 6749 §4.4.
- `oauth2_authcode` — RFC 6749 §4.1, refresh-token renewal.
- `device_code` — RFC 8628, refresh-token renewal (initial device grant done once via the GUI).

Every provider is a **row of data** in the `upstreams` table: a `base_url` and
an `auth_descriptor` JSON blob (`src/auth/descriptor.schema.json`) selecting
one of the mechanisms above plus its parameters (token URL, client id,
header/query injection shape). Adding GitHub, OpenAI, or any future API is a
GUI form submission, never a code change.

## Run

```sh
npm install
npm run migrate
OKEYDOKEY_MASTER_KEY=<32+ char secret> npm start
```

GUI at `http://localhost:8787/`. Proxy calls: `Authorization: Bearer <key>` to
`http://localhost:8787/proxy/<upstream-name>/<path>`.

## Storage

libsql (`@libsql/client`), local file by default (`OKEYDOKEY_DB_URL`,
`OKEYDOKEY_DB_TOKEN` for Turso/remote). Schema: `src/db/schema.sql`.

## GUI

Built with `@anentrypoint/design` (webjsx), served statically from `src/gui`.
