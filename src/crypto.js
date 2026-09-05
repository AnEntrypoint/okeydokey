import { createCipheriv, createDecipheriv, randomBytes, createHash, scryptSync } from "node:crypto";

const key = scryptSync(process.env.OKEYDOKEY_MASTER_KEY ?? "", "okeydokey-salt", 32);

export function encrypt(plaintext) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64");
}

export function decrypt(ciphertext) {
  const buf = Buffer.from(ciphertext, "base64");
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const enc = buf.subarray(28);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8");
}

export function hashKey(rawToken) {
  return createHash("sha256").update(rawToken).digest("hex");
}

export function generateApiKey() {
  const raw = "ok_" + randomBytes(24).toString("base64url");
  return { raw, hash: hashKey(raw), prefix: raw.slice(0, 11) };
}
