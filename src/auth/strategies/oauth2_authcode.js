// oauth2_authcode: RFC 6749 §4.1. The initial authorize+exchange happens once, out of
// band, via the admin GUI (src/gui); this strategy only handles ongoing refresh, which
// is generic across every provider using this grant (refresh_token -> access_token).
export async function resolve({ descriptor, credentials, decrypt, encrypt, saveCredentials }) {
  const now = Math.floor(Date.now() / 1000);
  const skew = descriptor.oauth2?.refresh_skew_seconds ?? 60;

  if (credentials.access_token_ciphertext && credentials.expires_at && credentials.expires_at - skew > now) {
    return { token: decrypt(credentials.access_token_ciphertext), expiresAt: credentials.expires_at };
  }
  if (!credentials.refresh_token_ciphertext) {
    throw new Error("oauth2_authcode: no refresh_token on file; complete the authorize-code flow via the GUI first");
  }

  const refreshToken = decrypt(credentials.refresh_token_ciphertext);
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: descriptor.oauth2.client_id,
    ...(descriptor.oauth2.extra_params ?? {}),
  });

  const res = await fetch(descriptor.oauth2.token_url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!res.ok) throw new Error(`oauth2_authcode refresh failed: ${res.status} ${await res.text()}`);
  const json = await res.json();
  const expiresAt = now + (json.expires_in ?? 3600);

  await saveCredentials({
    access_token_ciphertext: encrypt(json.access_token),
    refresh_token_ciphertext: json.refresh_token ? encrypt(json.refresh_token) : undefined,
    expires_at: expiresAt,
  });

  return { token: json.access_token, expiresAt };
}
