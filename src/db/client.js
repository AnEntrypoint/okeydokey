import { createClient } from "@libsql/client";

export const db = createClient({
  url: process.env.OKEYDOKEY_DB_URL ?? "file:okeydokey.db",
  authToken: process.env.OKEYDOKEY_DB_TOKEN,
});
