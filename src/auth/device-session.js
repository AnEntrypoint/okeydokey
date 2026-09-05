import { discoverOidc, isJwtExpiring } from "./oidc.js";
import { pollDeviceToken, refreshAccessToken, requestDeviceAuthorization, RefreshRejectedError } from "./device-flow.js";

// A complete device-code credential lifecycle over a token store: initial
// grant, proactive refresh before expiry, reactive refresh on a rejection, and
// a durable record that the refresh token is permanently dead. Every provider
// detail arrives as configuration.
export function createDeviceCodeSession({
  store,
  clientId,
  clientSecret,
  scope,
  issuer,
  discoveryUrl,
  deviceAuthorizationUrl,
  tokenUrl,
  allowedHosts,
  refreshSkewSeconds = 3600,
  extraParams,
  fetchImpl = fetch,
  onAuthorized,
}) {
  const resolveEndpoints = async (cached) => {
    if (cached?.token_endpoint && (deviceAuthorizationUrl || cached.device_authorization_endpoint)) return cached;
    if (tokenUrl && deviceAuthorizationUrl) {
      return { token_endpoint: tokenUrl, device_authorization_endpoint: deviceAuthorizationUrl };
    }
    const discovered = await discoverOidc({ issuer, discoveryUrl, allowedHosts, fetchImpl });
    return {
      ...discovered,
      token_endpoint: tokenUrl ?? discovered.token_endpoint,
      device_authorization_endpoint: deviceAuthorizationUrl ?? discovered.device_authorization_endpoint,
    };
  };

  const session = {
    hasCredentials() {
      const record = store.read();
      return Boolean(record?.tokens?.access_token);
    },

    // A refresh token rejected as invalid_grant stays rejected until the user
    // authorizes again. Recording that on disk is what lets a caller drop the
    // provider entirely rather than spending a request, and a request's
    // latency budget, on a doomed exchange every single time.
    isRefreshDead() {
      return Boolean(store.read()?.refresh_dead);
    },

    markRefreshDead(reason) {
      store.update((record) => ({
        ...record,
        refresh_dead: true,
        refresh_dead_reason: reason,
        refresh_dead_at: new Date().toISOString(),
      }));
    },

    // Runs the user-facing half of the grant. `onPrompt` receives the
    // verification URL and user code as soon as they exist, before polling
    // starts, since the user cannot approve what they have not been shown.
    async authorize({ onPrompt, onPoll, signal, extra } = {}) {
      const endpoints = await resolveEndpoints(null);
      const grant = await requestDeviceAuthorization({
        deviceAuthorizationUrl: endpoints.device_authorization_endpoint,
        clientId,
        scope,
        extraParams,
        allowedHosts,
        fetchImpl,
      });
      onPrompt?.({
        verificationUri: grant.verification_uri,
        verificationUriComplete: grant.verification_uri_complete,
        userCode: grant.user_code,
        intervalSeconds: grant.interval,
        expiresInSeconds: grant.expires_in,
      });
      const tokens = await pollDeviceToken({
        tokenUrl: endpoints.token_endpoint,
        clientId,
        clientSecret,
        deviceCode: grant.device_code,
        expiresInSeconds: grant.expires_in,
        intervalSeconds: grant.interval,
        extraParams,
        allowedHosts,
        fetchImpl,
        onPoll,
        signal,
      });
      const record = store.write({
        tokens: {
          access_token: String(tokens.access_token),
          refresh_token: String(tokens.refresh_token ?? ""),
          id_token: String(tokens.id_token ?? ""),
          expires_in: tokens.expires_in,
          token_type: String(tokens.token_type ?? "Bearer"),
          refreshed_at: new Date().toISOString(),
        },
        endpoints,
        authorized_at: new Date().toISOString(),
        refresh_dead: false,
        ...extra,
      });
      onAuthorized?.(record);
      return record;
    },

    // The access token to use now, refreshed first if it is close enough to
    // expiry that a request would race it.
    async accessToken() {
      const record = store.read();
      if (!record?.tokens?.access_token) throw new Error("no device-code credentials on file; authorize first");
      if (!isJwtExpiring(record.tokens.access_token, refreshSkewSeconds)) return record.tokens.access_token;
      return (await session.refresh()).tokens.access_token;
    },

    // Unconditional refresh, for the reactive case where the upstream has
    // already rejected a token this side still believed was valid.
    async refresh() {
      const record = store.read();
      if (!record?.tokens?.refresh_token) throw new Error("no refresh_token on file; authorize again");
      const endpoints = await resolveEndpoints(record.endpoints);
      try {
        const tokens = await refreshAccessToken({
          tokenUrl: endpoints.token_endpoint,
          clientId,
          clientSecret,
          refreshToken: record.tokens.refresh_token,
          extraParams,
          allowedHosts,
          fetchImpl,
        });
        return store.write({ ...record, tokens: { ...record.tokens, ...tokens }, endpoints });
      } catch (err) {
        if (err instanceof RefreshRejectedError && err.permanent) session.markRefreshDead(err.message.slice(0, 300));
        throw err;
      }
    },

    read: () => store.read(),
  };

  return session;
}
