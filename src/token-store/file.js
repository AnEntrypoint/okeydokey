import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

// A token record on local disk, for hosts that hold their own credentials
// rather than going through the gateway's database.
export function createFileTokenStore({ path, onCorrupt } = {}) {
  const resolvePath = typeof path === "function" ? path : () => path;
  let warnedCorrupt = false;

  return {
    get path() {
      return resolvePath();
    },

    // An absent file means "never authorized", which is a state, not a
    // failure. A file that exists but does not parse is a different state
    // entirely -- a truncated or half-written token record -- and collapsing
    // the two leaves an operator with no way to tell a fresh install from a
    // corrupted one. It is reported once per process, since this is read on
    // every request.
    read() {
      const file = resolvePath();
      let raw;
      try {
        raw = readFileSync(file, "utf8");
      } catch {
        return null;
      }
      try {
        return JSON.parse(raw);
      } catch (err) {
        if (!warnedCorrupt) {
          warnedCorrupt = true;
          onCorrupt?.({ path: file, error: err });
        }
        return null;
      }
    },

    // Written to a sibling temp file and renamed, so a crash mid-write leaves
    // the previous record intact rather than the truncated file the read path
    // above has to warn about.
    write(record) {
      const file = resolvePath();
      mkdirSync(dirname(file), { recursive: true });
      const tmp = file + ".tmp";
      writeFileSync(tmp, JSON.stringify(record, null, 2), { mode: 0o600 });
      renameSync(tmp, file);
      return record;
    },

    update(mutate) {
      const current = this.read();
      if (!current) return null;
      const next = mutate(current) ?? current;
      return this.write(next);
    },
  };
}
