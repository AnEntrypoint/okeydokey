// bearer_passthrough: no upstream credential is held at all; the caller's own bearer
// key IS the upstream token (rare, but keeps the engine generic for upstreams that
// want the gateway purely for routing/auditing rather than credential hiding).
export async function resolve({ callerToken }) {
  return { token: callerToken, expiresAt: null };
}
