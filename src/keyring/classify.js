// HTTP status -> backoff reason. A 5xx is the upstream's fault rather than the
// credential's, so it is classified but deliberately not backoff-worthy: see
// BACKOFF_WORTHY_REASONS, which callers consult before calling markFailed.

export const DEFAULT_STATUS_REASONS = [
  { match: (s) => s === 401 || s === 403, reason: "auth" },
  { match: (s) => s === 429, reason: "rate_limit" },
  { match: (s) => s >= 500, reason: "upstream_5xx" },
];

export const BACKOFF_WORTHY_REASONS = new Set(["auth", "rate_limit"]);

export function classifyStatus(status, rules = DEFAULT_STATUS_REASONS) {
  for (const rule of rules) if (rule.match(status)) return rule.reason;
  return null;
}

export function isBackoffWorthy(reason) {
  return BACKOFF_WORTHY_REASONS.has(reason);
}
