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

## Credential rotation

An upstream whose auth kind is a stored secret holds a *pool* of them, tried in
declaration order:

```sh
curl -X POST localhost:8787/api/upstreams -d '{"name":"groq","baseUrl":"https://api.groq.com/openai/v1",
  "authDescriptor":{"kind":"static","inject":{"location":"header","name":"Authorization","template":"Bearer {token}"}},
  "secrets":["key-a","key-b","key-c"]}'
```

The proxy advances to the next credential on 401/403/429 -- the failures a
different key could plausibly answer -- and stops on anything else, since a 5xx
is the upstream's answer rather than the key's. A rejected credential enters an
escalating cooldown (30s, 1m, 2m, 4m, 8m) and is skipped until it expires, so a
revoked key costs one request rather than every request. Hops are reported in
`x-okeydokey-credential-rotations`. `POST`/`DELETE /api/secrets` manage the pool
and `GET /api/keyring/status` shows per-credential health with the credentials
masked.

## Embedding just the credential ring

`okeydokey/keyring` is the same ring the gateway uses, with no third-party
import in its module graph, so a host can hold its own credentials without
running the gateway or installing a database:

```js
const { createEnvKeyring, rotateCredentials } = require("okeydokey/keyring");

const ring = createEnvKeyring({
  indexedSuffixMax: 99,               // GROQ_API_KEY_1 .. GROQ_API_KEY_99
  bagPrefix: "MYAPP_KEYS_",           // MYAPP_KEYS_GROQ_API_KEY=["k1","k2"]
  aliases: { GEMINI_API_KEY: ["GOOGLE_API_KEY"] },
});

const { result, rotations } = await rotateCredentials(ring, "GROQ_API_KEY",
  (key) => fetch(url, { headers: { Authorization: `Bearer ${key}` } }));
```

CommonJS hosts need Node >= 20.19 for `require()` of an ES module.

## Storage

libsql (`@libsql/client`), local file by default (`OKEYDOKEY_DB_URL`,
`OKEYDOKEY_DB_TOKEN` for Turso/remote). Schema: `src/db/schema.sql`.

`@libsql/client` and `@anentrypoint/design` are *optional peer* dependencies:
the gateway needs both, the embeddable ring imports neither, so a host using
only `okeydokey/keyring` is not made to install a SQL driver and a browser
design system. A clone gets them from `devDependencies` on a plain
`npm install`; installing okeydokey as a dependency elsewhere to run the
gateway needs them added explicitly.

## GUI

Built with `@anentrypoint/design` (webjsx), served statically from `src/gui`.
