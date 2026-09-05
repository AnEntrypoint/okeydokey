// A credential source answers one question: which raw credential values exist
// for this ref, in the order they should be tried. A ref is whatever names a
// credential set to the host -- an env-var name, an upstream id, a provider
// slug. Sources never know about backoff, rotation or masking.

const trimmedOrNull = (value) => {
  if (value === undefined || value === null) return null;
  const trimmed = String(value).trim();
  return trimmed === "" ? null : trimmed;
};

// Reads env vars under three conventions, in this order per resolved name:
//   NAME                      the primary credential
//   NAME_1 .. NAME_<max>      additional credentials, declared order
//   <bagPrefix>NAME           a JSON array of credentials, escape hatch
// `resolveNames` maps a ref to the env-var names it expands to, so the same
// implementation serves both the canonical name and same-credential aliases.
export function createEnvSource({
  env = process.env,
  indexedSuffixMax = 0,
  bagPrefix = null,
  resolveNames = (ref) => [ref],
} = {}) {
  return {
    list(ref) {
      const out = [];
      for (const name of resolveNames(ref)) {
        if (!name) continue;
        const primary = trimmedOrNull(env[name]);
        if (primary) out.push(primary);
        for (let i = 1; i <= indexedSuffixMax; i++) {
          const indexed = trimmedOrNull(env[`${name}_${i}`]);
          if (indexed) out.push(indexed);
        }
        if (bagPrefix) {
          const bag = env[bagPrefix + name];
          if (bag) {
            let parsed;
            try {
              parsed = JSON.parse(bag);
            } catch {
              parsed = null;
            }
            if (Array.isArray(parsed)) {
              for (const entry of parsed) {
                const value = trimmedOrNull(entry);
                if (value) out.push(value);
              }
            }
          }
        }
      }
      return out;
    },
  };
}

// Env-var names that hold the SAME real credential under a different spelling.
// Google issues one Gemini key its own docs call GEMINI_API_KEY or
// GOOGLE_API_KEY interchangeably; a host that only ever reads one name is
// blind to a working credential configured under the other.
export function createAliasSource({ aliases = {}, ...envOptions } = {}) {
  return createEnvSource({ ...envOptions, resolveNames: (ref) => aliases[ref] ?? [] });
}

// Credentials registered at runtime by the host (a config file, a discovered
// provider) rather than read from the environment.
export function createMemorySource() {
  const byRef = new Map();
  return {
    list(ref) {
      return byRef.get(ref) ?? [];
    },
    register(ref, value) {
      const trimmed = trimmedOrNull(value);
      if (!ref || !trimmed) return false;
      if (!byRef.has(ref)) byRef.set(ref, []);
      const values = byRef.get(ref);
      if (values.includes(trimmed)) return false;
      values.push(trimmed);
      return true;
    },
    clear(ref) {
      if (ref === undefined) byRef.clear();
      else byRef.delete(ref);
    },
  };
}

// Credentials supplied by an async store (okeydokey's own upstream_credentials
// rows). Sync `list` serves whatever the last refresh loaded, so the hot path
// never awaits; `refresh` is called by the store's own write path.
export function createCachedSource({ load } = {}) {
  const byRef = new Map();
  return {
    list(ref) {
      return byRef.get(ref) ?? [];
    },
    async refresh(ref) {
      const values = (await load(ref)) ?? [];
      byRef.set(ref, values.map(trimmedOrNull).filter(Boolean));
      return byRef.get(ref);
    },
    clear(ref) {
      if (ref === undefined) byRef.clear();
      else byRef.delete(ref);
    },
  };
}
