// Credential display form. Never returns enough material to authenticate with.

export function maskCredential(value) {
  if (!value) return null;
  if (value.length <= 8) return "***" + value.slice(-2);
  return value.slice(0, 4) + "..." + value.slice(-4);
}
