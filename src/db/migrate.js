import { readFileSync, existsSync, unlinkSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { db } from "./client.js";

const dir = dirname(fileURLToPath(import.meta.url));
const sql = readFileSync(join(dir, "schema.sql"), "utf8");

function splitStatements(source) {
  const withoutComments = source.replace(/--.*$/gm, "");
  return withoutComments.split(";").map((s) => s.trim()).filter(Boolean);
}

async function migrate() {
  const statements = splitStatements(sql);
  for (const stmt of statements) {
    try {
      await db.execute(stmt);
    } catch (err) {
      console.error(`FAILED on statement:\n${stmt}\n`);
      throw err;
    }
  }
  console.log(`migrated: ${statements.length} statements applied`);
}

migrate();
