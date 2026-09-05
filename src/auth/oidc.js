// OIDC discovery and token inspection, shared by every strategy that resolves
// endpoints at runtime rather than from a fixed descriptor.

// A discovered endpoint is attacker-influenced input until proven otherwise:
// discovery hands back URLs that the client will then post credentials to, so
// substituting one is enough to harvest a device grant. Every discovered URL
// is checked against the issuer's own registrable domain before use.
export function assertAllowedOrigin(url, allowedHosts, field = "endpoint") {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`${field} is not a valid URL: ${url}`);
  }
  if (parsed.protocol !== "https:") throw new Error(`${field} must be https: ${url}`);
  const host = (parsed.hostname || "").toLowerCase();
  const allowed = allowedHosts.some((candidate) => {
    const suffix = String(candidate).toLowerCase();
    return host === suffix || host.endsWith("." + suffix);
  });
  if (!allowed) {
    throw new Error(`${field} host '${host}' is outside the allowed origins (${allowedHosts.join(", ")}): ${url}`);
  }
  return url;
}

export async function discoverOidc({ issuer, discoveryUrl, allowedHosts, timeoutMs = 15000, fetchImpl = fetch }) {
  const url = discoveryUrl ?? `${String(issuer).replace(/\/$/, "")}/.well-known/openid-configuration`;
  const hosts = allowedHosts ?? [new URL(url).hostname];
  const res = await fetchImpl(url, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) throw new Error(`OIDC discovery failed (HTTP ${res.status})`);
  const payload = await res.json();
  const authorizationEndpoint = String(payload.authorization_endpoint ?? "").trim();
  const tokenEndpoint = String(payload.token_endpoint ?? "").trim();
  if (!tokenEndpoint) throw new Error("OIDC discovery response has no token_endpoint");
  assertAllowedOrigin(tokenEndpoint, hosts, "token_endpoint");
  if (authorizationEndpoint) assertAllowedOrigin(authorizationEndpoint, hosts, "authorization_endpoint");
  const deviceAuthorizationEndpoint = String(payload.device_authorization_endpoint ?? "").trim();
  if (deviceAuthorizationEndpoint) assertAllowedOrigin(deviceAuthorizationEndpoint, hosts, "device_authorization_endpoint");
  return {
    authorization_endpoint: authorizationEndpoint,
    token_endpoint: tokenEndpoint,
    ...(deviceAuthorizationEndpoint ? { device_authorization_endpoint: deviceAuthorizationEndpoint } : {}),
  };
}

// True when a JWT access token's `exp` is within `skewSeconds` of now. A token
// that is not a JWT reports false: an opaque token carries no expiry to read,
// and guessing one would refresh working credentials on every call.
export function isJwtExpiring(accessToken, skewSeconds = 0) {
  if (typeof accessToken !== "string") return false;
  const parts = accessToken.split(".");
  if (parts.length < 2) return false;
  try {
    const segment = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = segment.padEnd(segment.length + ((4 - (segment.length % 4)) % 4), "=");
    const claims = JSON.parse(Buffer.from(padded, "base64").toString("utf8"));
    if (typeof claims.exp !== "number") return false;
    return claims.exp <= Date.now() / 1000 + Math.max(0, skewSeconds);
  } catch {
    return false;
  }
}
