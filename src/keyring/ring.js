import { createHash } from "node:crypto";
import {
  DEFAULT_BACKOFF_STEPS_MS,
  createBackoffState,
  isCoolingDown,
  recordFailure,
  recordSuccess,
} from "./backoff.js";
import { classifyStatus, isBackoffWorthy } from "./classify.js";
import { maskCredential } from "./mask.js";

// Backoff state is keyed by a digest of the credential, never the credential
// itself: a Map key survives into heap dumps, `util.inspect` output and error
// traces, and a ring that has done its job holds the only in-process copy of
// several live secrets.
const stateKey = (ref, credential) =>
  ref + "|" + createHash("sha256").update(credential).digest("hex").slice(0, 16);

// One credential set per ref, tried in source order, each with its own
// escalating backoff so an exhausted or revoked credential does not take the
// rest of its set down with it.
export function createKeyring({ sources = [], backoffSteps = DEFAULT_BACKOFF_STEPS_MS, clock = Date.now } = {}) {
  const states = new Map();

  const stateFor = (ref, credential) => {
    const id = stateKey(ref, credential);
    if (!states.has(id)) states.set(id, createBackoffState());
    return states.get(id);
  };

  const list = (ref) => {
    if (!ref) return [];
    const seen = new Set();
    const out = [];
    for (const source of sources) {
      for (const value of source.list(ref)) {
        if (seen.has(value)) continue;
        seen.add(value);
        out.push(value);
      }
    }
    return out;
  };

  const usable = (ref) => {
    const now = clock();
    return list(ref).filter((credential) => !isCoolingDown(stateFor(ref, credential), now));
  };

  return {
    list,
    usable,
    has: (ref) => list(ref).length > 0,

    // The credential to try now. When every credential is cooling down this
    // still returns one -- the closest to expiring -- so the caller attempts
    // and learns something rather than failing on stale local state.
    select(ref) {
      const credentials = list(ref);
      if (credentials.length === 0) return null;
      const now = clock();
      for (const credential of credentials) {
        if (!isCoolingDown(stateFor(ref, credential), now)) return credential;
      }
      let soonest = credentials[0];
      let soonestAt = stateFor(ref, soonest).nextCheck;
      for (const credential of credentials) {
        const at = stateFor(ref, credential).nextCheck;
        if (at < soonestAt) {
          soonest = credential;
          soonestAt = at;
        }
      }
      return soonest;
    },

    markFailed(ref, credential, reason) {
      if (!ref || !credential) return;
      recordFailure(stateFor(ref, credential), reason, backoffSteps, clock());
    },

    markOk(ref, credential) {
      if (!ref || !credential) return;
      recordSuccess(stateFor(ref, credential));
    },

    // Forget learned health. No argument clears the whole ring; a ref clears
    // that set; a ref plus credential clears one entry.
    reset(ref, credential) {
      if (ref === undefined) {
        states.clear();
        return;
      }
      if (credential !== undefined) {
        states.delete(stateKey(ref, credential));
        return;
      }
      const prefix = ref + "|";
      for (const id of [...states.keys()]) if (id.startsWith(prefix)) states.delete(id);
    },

    status(ref) {
      const now = clock();
      return list(ref).map((credential, index) => {
        const state = stateFor(ref, credential);
        const inBackoff = isCoolingDown(state, now);
        return {
          index,
          credential: maskCredential(credential),
          ok: state.ok,
          failCount: state.failCount,
          lastFailedAt: state.lastFailedAt,
          lastReason: state.lastReason,
          inBackoff,
          nextRetryInMs: inBackoff ? state.nextCheck - now : 0,
        };
      });
    },

    classify: (status) => classifyStatus(status),
    isBackoffWorthy,
    backoffSteps,
  };
}
