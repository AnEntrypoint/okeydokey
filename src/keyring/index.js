export { createKeyring } from "./ring.js";
export { rotateCredentials } from "./rotate.js";
export { createEnvSource, createAliasSource, createMemorySource, createCachedSource } from "./sources.js";
export { classifyStatus, isBackoffWorthy, BACKOFF_WORTHY_REASONS, DEFAULT_STATUS_REASONS } from "./classify.js";
export { DEFAULT_BACKOFF_STEPS_MS } from "./backoff.js";
export { maskCredential } from "./mask.js";

import { createKeyring } from "./ring.js";
import { createEnvSource, createAliasSource, createMemorySource } from "./sources.js";

// The environment-backed composition: env vars first so an explicitly
// configured credential always outranks a discovered one, then whatever the
// host registered at runtime, then same-credential aliases last so the
// canonical spelling wins when both are set.
export function createEnvKeyring({
  env = process.env,
  indexedSuffixMax = 99,
  bagPrefix = null,
  aliases = {},
  backoffSteps,
  clock,
} = {}) {
  const memory = createMemorySource();
  const ring = createKeyring({
    sources: [
      createEnvSource({ env, indexedSuffixMax, bagPrefix }),
      memory,
      createAliasSource({ env, indexedSuffixMax, bagPrefix, aliases }),
    ],
    backoffSteps,
    clock,
  });
  return Object.assign(ring, {
    register: (ref, value) => memory.register(ref, value),
    clearRegistered: (ref) => memory.clear(ref),
  });
}
