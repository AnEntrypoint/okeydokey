import { assertAllowedOrigin } from "./oidc.js";

// RFC 8628 device authorization grant, and the refresh-token exchange that
// keeps its result alive. Provider-agnostic: every endpoint, client id and
// scope is an argument.

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const form = (fields) => new URLSearchParams(Object.entries(fields).filter(([, v]) => v !== undefined && v !== null));

const POST_FORM = { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" };

// RFC 8628 section 3.1/3.2. The response carries the code the user types and
// the URL they type it into; both are surfaced to the caller to display.
export async function requestDeviceAuthorization({
  deviceAuthorizationUrl,
  clientId,
  scope,
  extraParams,
  allowedHosts,
  timeoutMs = 15000,
  fetchImpl = fetch,
}) {
  if (allowedHosts) assertAllowedOrigin(deviceAuthorizationUrl, allowedHosts, "device_authorization_endpoint");
  const res = await fetchImpl(deviceAuthorizationUrl, {
    method: "POST",
    headers: POST_FORM,
    body: form({ client_id: clientId, scope, ...extraParams }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(`device authorization request failed (HTTP ${res.status})${detail ? `: ${detail}` : ""}`);
  }
  const payload = await res.json();
  for (const field of ["device_code", "user_code", "verification_uri"]) {
    if (!(field in payload)) throw new Error(`device authorization response is missing ${field}`);
  }
  return {
    ...payload,
    // RFC 8628 section 3.2: both are optional with these defaults, so a
    // provider that omits them still yields a usable polling plan.
    expires_in: Number(payload.expires_in ?? 1800),
    interval: Number(payload.interval ?? 5),
    verification_uri_complete: payload.verification_uri_complete ?? payload.verification_uri,
  };
}

// RFC 8628 section 3.4/3.5. `authorization_pending` and `slow_down` are the
// normal answers while the user is still approving, not failures;
// `slow_down` additionally requires backing the interval off.
export async function pollDeviceToken({
  tokenUrl,
  clientId,
  deviceCode,
  expiresInSeconds,
  intervalSeconds = 5,
  clientSecret,
  extraParams,
  allowedHosts,
  fetchImpl = fetch,
  onPoll,
  signal,
}) {
  if (allowedHosts) assertAllowedOrigin(tokenUrl, allowedHosts, "token_endpoint");
  const deadline = Date.now() + Math.max(1, expiresInSeconds) * 1000;
  let interval = Math.max(1, intervalSeconds);

  while (Date.now() < deadline) {
    if (signal?.aborted) throw new Error("device authorization polling was cancelled");
    const res = await fetchImpl(tokenUrl, {
      method: "POST",
      headers: POST_FORM,
      body: form({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        client_id: clientId,
        client_secret: clientSecret,
        device_code: deviceCode,
        ...extraParams,
      }),
    });

    if (res.ok) {
      const payload = await res.json();
      if (!payload.access_token) throw new Error("device token response is missing access_token");
      return payload;
    }

    let error;
    try {
      error = await res.json();
    } catch {
      throw new Error(`device token polling returned a non-JSON error (HTTP ${res.status})`);
    }
    const code = String(error.error ?? "");
    if (code === "authorization_pending" || code === "slow_down") {
      if (code === "slow_down") interval = Math.min(interval + 5, 30);
      onPoll?.({ status: code, intervalSeconds: interval });
      await sleep(interval * 1000);
      continue;
    }
    throw new Error(`device token polling failed: ${error.error_description ?? code ?? `HTTP ${res.status}`}`);
  }
  throw new Error("timed out waiting for device authorization");
}

// A refresh token rejected as `invalid_grant` is expired, revoked or already
// consumed, and will never succeed on retry -- unlike a 429 or a 5xx. The
// distinction is returned rather than thrown-and-guessed so a caller can stop
// re-attempting a doomed exchange on every request.
export class RefreshRejectedError extends Error {
  constructor(message, { permanent = false, status } = {}) {
    super(message);
    this.name = "RefreshRejectedError";
    this.permanent = permanent;
    this.status = status;
  }
}

export async function refreshAccessToken({
  tokenUrl,
  clientId,
  clientSecret,
  refreshToken,
  scope,
  extraParams,
  allowedHosts,
  timeoutMs = 20000,
  fetchImpl = fetch,
}) {
  if (!refreshToken) throw new RefreshRejectedError("no refresh_token on file", { permanent: true });
  if (allowedHosts) assertAllowedOrigin(tokenUrl, allowedHosts, "token_endpoint");
  const res = await fetchImpl(tokenUrl, {
    method: "POST",
    headers: POST_FORM,
    body: form({ grant_type: "refresh_token", client_id: clientId, client_secret: clientSecret, refresh_token: refreshToken, scope, ...extraParams }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    const permanent = res.status === 400 && /invalid_grant/i.test(detail);
    throw new RefreshRejectedError(`token refresh failed (HTTP ${res.status})${detail ? `: ${detail}` : ""}`, {
      permanent,
      status: res.status,
    });
  }
  const payload = await res.json();
  const accessToken = String(payload.access_token ?? "").trim();
  if (!accessToken) throw new RefreshRejectedError("token refresh response is missing access_token", { status: res.status });
  return {
    access_token: accessToken,
    // Not every provider rotates the refresh token; keeping the old one when
    // none comes back is what lets the next refresh work at all.
    refresh_token: String(payload.refresh_token ?? refreshToken).trim(),
    id_token: String(payload.id_token ?? ""),
    expires_in: payload.expires_in,
    token_type: String(payload.token_type ?? "Bearer"),
    refreshed_at: new Date().toISOString(),
  };
}
