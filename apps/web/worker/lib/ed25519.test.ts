// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { generateWorkerKey } from '../testing/harness.ts';
import {
  canonicalPublicKey,
  decodeBase64,
  encodeBase64,
  keyFingerprint,
  verifyEd25519,
} from './ed25519.ts';

const b64 = (hex: string) =>
  encodeBase64(Uint8Array.from(hex.match(/../g)!.map((h) => parseInt(h, 16))));

describe('ed25519 helpers', () => {
  it('canonicalises standard and URL-safe base64 keys', async () => {
    const { publicKey } = await generateWorkerKey();
    const urlSafe = publicKey.replace(/\+/g, '-').replace(/\//g, '_').replace(/=$/, '');
    expect(await canonicalPublicKey(urlSafe)).toBe(publicKey);
    expect(await canonicalPublicKey('not base64!')).toBeNull();
    expect(await canonicalPublicKey(encodeBase64(new Uint8Array(31)))).toBeNull();
  });

  it.each([
    '00'.repeat(32),
    `01${'00'.repeat(31)}`,
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
    `ec${'ff'.repeat(30)}ff7f`,
  ])('rejects small-order key %s', async (hex) => {
    expect(await canonicalPublicKey(b64(hex))).toBeNull();
    expect(await verifyEd25519(b64(hex), encodeBase64(new Uint8Array(64)), 'message')).toBe(false);
  });

  it('verifies only the exact signed message', async () => {
    const key = await generateWorkerKey();
    const sig = encodeBase64(
      new Uint8Array(
        await crypto.subtle.sign('Ed25519', key.privateKey, new TextEncoder().encode('hello')),
      ),
    );
    expect(await verifyEd25519(key.publicKey, sig, 'hello')).toBe(true);
    expect(await verifyEd25519(key.publicKey, sig, 'hellO')).toBe(false);
    expect(await verifyEd25519(key.publicKey, 'AAAA', 'hello')).toBe(false);
  });

  it('fingerprints keys and round-trips base64', async () => {
    const { publicKey } = await generateWorkerKey();
    expect(await keyFingerprint(publicKey)).toMatch(/^([0-9a-f]{2}:){7}[0-9a-f]{2}$/);
    expect(encodeBase64(decodeBase64(publicKey)!)).toBe(publicKey);
  });
});
