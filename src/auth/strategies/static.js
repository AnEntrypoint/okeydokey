// static: the stored secret is the credential, used as-is. No refresh.
export async function resolve({ credentials, decrypt }) {
  return { token: decrypt(credentials.secret_ciphertext), expiresAt: null };
}
