/** Ed25519 helpers on Web Crypto (available in Workers and Node). */

export function decodeBase64(value: string): Uint8Array | null {
  const normalised = value.trim().replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalised)) return null;
  const padded = normalised + '='.repeat((4 - (normalised.length % 4)) % 4);
  try {
    const binary = atob(padded);
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

export function encodeBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

const hex = (bytes: Uint8Array) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
const ff = 'ff'.repeat(30);

/**
 * Encodings of small-order Ed25519 points (and their non-canonical variants), as blocklisted by
 * libsodium. Such keys are degenerate: with some verifiers a signature can verify for any message.
 */
const SMALL_ORDER_KEYS = new Set([
  `01${'00'.repeat(31)}`,
  `ec${ff}ff7f`,
  '00'.repeat(32),
  `${'00'.repeat(31)}80`,
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
  `ec${ff}ffff`,
  `ed${ff}ff7f`,
  `ed${ff}ffff`,
  `ee${ff}ff7f`,
  `ee${ff}ffff`,
]);

/** Canonical form of a public key: standard base64 of the raw 32 bytes, or null if invalid. */
export async function canonicalPublicKey(value: string): Promise<string | null> {
  const raw = decodeBase64(value);
  if (!raw || raw.length !== 32) return null;
  if (SMALL_ORDER_KEYS.has(hex(raw))) return null;
  try {
    await crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
  } catch {
    return null;
  }
  return encodeBase64(raw);
}

/** Short SHA-256 fingerprint of a public key, for display. */
export async function keyFingerprint(publicKeyBase64: string): Promise<string> {
  const raw = decodeBase64(publicKeyBase64) ?? new Uint8Array();
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', raw));
  return [...digest.slice(0, 8)].map((b) => b.toString(16).padStart(2, '0')).join(':');
}

export async function verifyEd25519(
  publicKeyBase64: string,
  signatureBase64: string,
  message: string,
): Promise<boolean> {
  const raw = decodeBase64(publicKeyBase64);
  const signature = decodeBase64(signatureBase64);
  if (!raw || raw.length !== 32 || !signature || signature.length !== 64) return false;
  if (SMALL_ORDER_KEYS.has(hex(raw))) return false;
  try {
    const key = await crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify('Ed25519', key, signature, new TextEncoder().encode(message));
  } catch {
    return false;
  }
}

export async function sha256HexBytes(data: string): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data)),
  );
  return [...digest].map((b) => b.toString(16).padStart(2, '0')).join('');
}
