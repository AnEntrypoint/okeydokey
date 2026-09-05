import { refreshAccessToken, RefreshRejectedError } from "../device-flow.js";

// device_code: RFC 8628. The initial device grant is a user-interactive step
// that happens once (via `createDeviceCodeSession().authorize()`, or the admin
// GUI); what a proxied request needs is the ongoing refresh, which this
// resolves. It is not the authcode strategy: a device grant's refresh token can
// be rejected as permanently invalid, and recording that is what stops every
// later request from re-attempting an exchange that cannot succeed.
export async function resolve({ descriptor, credentials, decrypt, encrypt, saveCredentials }) {
  const now = Math.floor(Date.now() / 1000);
  const skew = descriptor.device?.refresh_skew_seconds ?? descriptor.oauth2?.refresh_skew_seconds ?? 60;

  if (credentials.refresh_dead) {
    throw new Error("device_code: the refresh token was permanently rejected; re-run the device authorization");
  }
  if (credentials.access_token_ciphertext && credentials.expires_at && credentials.expires_at - skew > now) {
    return { token: decrypt(credentials.access_token_ciphertext), expiresAt: credentials.expires_at };
  }
  if (!credentials.refresh_token_ciphertext) {
    throw new Error("device_code: no refresh_token on file; complete the device authorization grant first");
  }

  const config = descriptor.device ?? descriptor.oauth2 ?? {};
  try {
    const tokens = await refreshAccessToken({
      tokenUrl: config.token_url,
      clientId: config.client_id,
      refreshToken: decrypt(credentials.refresh_token_ciphertext),
      extraParams: config.extra_params,
    });
    const expiresAt = now + (tokens.expires_in ?? 3600);
    await saveCredentials({
      access_token_ciphertext: encrypt(tokens.access_token),
      refresh_token_ciphertext: encrypt(tokens.refresh_token),
      expires_at: expiresAt,
    });
    return { token: tokens.access_token, expiresAt };
  } catch (err) {
    if (err instanceof RefreshRejectedError && err.permanent) {
      await saveCredentials({ refresh_dead: 1 });
    }
    throw err;
  }
}
