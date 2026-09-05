// oauth2_client_credentials: RFC 6749 §4.4. Generic across every provider using this
// grant type — the token_url/client_id/scope come entirely from the descriptor.
export async function resolve({ descriptor, credentials, decrypt, encrypt, saveCredentials }) {
  const now = Math.floor(Date.now() / 1000);
  const skew = descriptor.oauth2?.refresh_skew_seconds ?? 60;

  if (credentials.access_token_ciphertext && credentials.expires_at && credentials.expires_at - skew > now) {
    return { token: decrypt(credentials.access_token_ciphertext), expiresAt: credentials.expires_at };
  }

  const clientSecret = decrypt(credentials.secret_ciphertext);
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: descriptor.oauth2.client_id,
    client_secret: clientSecret,
    ...(descriptor.oauth2.scope ? { scope: descriptor.oauth2.scope } : {}),
    ...(descriptor.oauth2.extra_params ?? {}),
  });

  const res = await fetch(descriptor.oauth2.token_url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!res.ok) throw new Error(`oauth2_client_credentials token fetch failed: ${res.status} ${await res.text()}`);
  const json = await res.json();
  const expiresAt = now + (json.expires_in ?? 3600);

  await saveCredentials({
    access_token_ciphertext: encrypt(json.access_token),
    expires_at: expiresAt,
  });

  return { token: json.access_token, expiresAt };
}
