// Escalating per-credential backoff. Pure state, no I/O, no clock ownership:
// `now` is passed in so callers can drive it deterministically.

export const DEFAULT_BACKOFF_STEPS_MS = [30000, 60000, 120000, 240000, 480000];

export function createBackoffState() {
  return { ok: null, failCount: 0, nextCheck: 0, lastFailedAt: null, lastReason: null };
}

export function recordFailure(state, reason, steps, now) {
  state.ok = false;
  state.failCount += 1;
  state.lastFailedAt = now;
  state.lastReason = reason || "error";
  state.nextCheck = now + steps[Math.min(state.failCount - 1, steps.length - 1)];
  return state;
}

export function recordSuccess(state) {
  state.ok = true;
  state.failCount = 0;
  state.nextCheck = 0;
  state.lastReason = null;
  state.lastFailedAt = null;
  return state;
}

export function isCoolingDown(state, now) {
  return state.nextCheck > now;
}
