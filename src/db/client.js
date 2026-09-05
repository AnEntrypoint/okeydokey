import { createRequire } from "node:module";

// The gateway's storage driver is an optional peer: `okeydokey/keyring`, the
// half a host embeds, never opens a database, so a consumer of the core is not
// made to install one. Resolved lazily with a message that names the fix,
// rather than an unresolved-import stack trace.
const require = createRequire(import.meta.url);

let createClient;
try {
  ({ createClient } = require("@libsql/client"));
} catch {
  throw new Error(
    "okeydokey's gateway needs the @libsql/client peer dependency: run `npm install @libsql/client`. " +
      "Embedding only the credential ring (`okeydokey/keyring`) does not require it.",
  );
}

export const db = createClient({
  url: process.env.OKEYDOKEY_DB_URL ?? "file:okeydokey.db",
  authToken: process.env.OKEYDOKEY_DB_TOKEN,
});
