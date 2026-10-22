// @vitest-environment node
import { workerSigningString } from '@exdomainvault/shared';
import { describe, expect, it } from 'vitest';
import { generateWorkerKey } from '../testing/harness.ts';
import {
  canonicalPublicKey,
  decodeBase64,
  encodeBase64,
  keyFingerprint,
  sha256HexBytes,
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

describe('cross-language signing vector (docs/worker-protocol.md)', () => {
  const vector = {
    publicKeyB64: '11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=',
    body: '{"profiles":["passive"]}',
    bodySha256: 'def6b531b6f37f9c565098a3ac8c254408e4ed44786231270b37aa796805b174',
    signatureB64:
      'ZezimbXKZPd6JLSnkaX3KsoP2/w/b/UCe2jDS3DGdsbswJ3XZ5nzjH//t/NgiZ2N15xQyUS/JW0704Lw+gTMBw==',
  };

  it('produces the documented signing string and verifies the documented signature', async () => {
    expect(await sha256HexBytes(vector.body)).toBe(vector.bodySha256);
    const message = workerSigningString(
      'post',
      '/api/v1/internal/worker/claim',
      '1792656000',
      'vector-nonce-0123456789abcdef',
      vector.bodySha256,
    );
    expect(await verifyEd25519(vector.publicKeyB64, vector.signatureB64, message)).toBe(true);
  });
});
