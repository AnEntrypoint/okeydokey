import { createKeyring } from "./ring.js";
import { createCachedSource } from "./sources.js";

// The gateway's own credential ring. A ref here is an upstream id, and the
// credentials behind it are the decrypted rows of that upstream's secret pool,
// loaded once per upstream and refreshed when the pool is written.
export function createUpstreamKeyring({ loadSecrets, backoffSteps, clock } = {}) {
  const source = createCachedSource({ load: loadSecrets });
  const ring = createKeyring({ sources: [source], backoffSteps, clock });
  return Object.assign(ring, {
    load: (upstreamId) => source.refresh(upstreamId),
    invalidate: (upstreamId) => source.clear(upstreamId),
  });
}
