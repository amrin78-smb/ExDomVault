// @vitest-environment node
/**
 * Hardening: Cloudflare Access JWT attacks not covered by cloudflare-access.test.ts (which covers
 * wrong aud/iss, expired, unknown signing key, no email, alg=none and a tampered payload).
 * Here: HS256 key confusion, other algorithms, embedded/remote key headers, missing or unknown
 * kid, missing required claims, not-yet-valid tokens, clock tolerance bounds, malformed tokens and
 * credential-source confusion, plus the end-to-end path through the app.
 */
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import { schema } from '@exdomainvault/database';
import {
  SignJWT,
  createLocalJWKSet,
  exportJWK,
  exportSPKI,
  generateKeyPair,
  importJWK,
  type JWK,
  type JWTPayload,
} from 'jose';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp } from '../app.ts';
import { cloudflareAccessProvider } from './cloudflare-access.ts';

const ISSUER = 'https://team.cloudflareaccess.com';
const AUDIENCE = 'aud-tag-123';

let privateKey: CryptoKey;
let publicJwk: JWK;
let publicPem: string;
let jwks: ReturnType<typeof createLocalJWKSet>;
let attackerRsa: CryptoKeyPair;
let attackerEc: CryptoKeyPair;

beforeAll(async () => {
  const pair = await generateKeyPair('RS256', { extractable: true });
  privateKey = pair.privateKey;
  publicJwk = { ...(await exportJWK(pair.publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
  publicPem = await exportSPKI(pair.publicKey);
  // Two keys like Cloudflare's real JWKS (current + next), so kid selection matters.
  const second = await generateKeyPair('RS256', { extractable: true });
  const secondJwk = { ...(await exportJWK(second.publicKey)), kid: 'k2', alg: 'RS256' };
  jwks = createLocalJWKSet({ keys: [publicJwk, secondJwk] });
  attackerRsa = await generateKeyPair('RS256', { extractable: true });
  attackerEc = await generateKeyPair('ES256', { extractable: true });
});

const now = () => Math.floor(Date.now() / 1000);
const baseClaims = (): JWTPayload => ({
  iss: ISSUER,
  aud: AUDIENCE,
  sub: 'sub-1',
  email: 'analyst@example.com',
  type: 'app',
  iat: now(),
  exp: now() + 300,
});

const enc = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');

async function sign(
  claims: JWTPayload = baseClaims(),
  header: Record<string, unknown> = { alg: 'RS256', kid: 'k1' },
  key: CryptoKey | Uint8Array = privateKey,
) {
  return new SignJWT(claims).setProtectedHeader(header as { alg: string }).sign(key);
}

const provider = () =>
  cloudflareAccessProvider({ issuer: ISSUER, audience: AUDIENCE, getKey: jwks });
const authWith = (headers: Record<string, string>) =>
  provider().authenticate(new Request('https://app.example/api/v1/me', { headers }));
const authToken = (token: string) => authWith({ 'Cf-Access-Jwt-Assertion': token });

async function expectRejected(token: string) {
  const result = await authToken(token);
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.reason).toBe('invalid_credentials');
}

describe('Access JWT: algorithm attacks', () => {
  it('accepts the legitimate token (positive control)', async () => {
    expect((await authToken(await sign())).ok).toBe(true);
  });

  it('rejects HS256 signed with the RSA public key as the HMAC secret (key confusion)', async () => {
    for (const secret of [
      new TextEncoder().encode(publicPem),
      new TextEncoder().encode(JSON.stringify(publicJwk)),
      Buffer.from(publicJwk.n!, 'base64url'),
    ]) {
      await expectRejected(await sign(baseClaims(), { alg: 'HS256', kid: 'k1' }, secret));
    }
  });

  it('rejects other asymmetric algorithms, even with a valid kid', async () => {
    // The legitimate private key material, re-imported for RS512 and PS256.
    const jwk = await exportJWK(privateKey);
    for (const alg of ['RS512', 'PS256']) {
      const key = (await importJWK({ ...jwk, alg }, alg)) as CryptoKey;
      await expectRejected(await sign(baseClaims(), { alg, kid: 'k1' }, key));
    }
    await expectRejected(
      await sign(baseClaims(), { alg: 'ES256', kid: 'k1' }, attackerEc.privateKey),
    );
  });

  it('rejects alg=none in every spelling, with or without a signature part', async () => {
    for (const alg of ['none', 'None', 'NONE', 'nOnE', '']) {
      const unsigned = `${enc({ alg, kid: 'k1' })}.${enc(baseClaims())}`;
      await expectRejected(`${unsigned}.`);
      await expectRejected(unsigned);
      await expectRejected(`${unsigned}.${Buffer.from('sig').toString('base64url')}`);
    }
  });

  it('ignores embedded and remote key headers (jwk / jku / x5u / x5c)', async () => {
    const attackerJwk = await exportJWK(attackerRsa.publicKey);
    for (const extra of [
      { jwk: attackerJwk },
      { jku: 'https://evil.example/jwks.json' },
      { x5u: 'https://evil.example/cert.pem' },
      { x5c: ['MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA'] },
    ]) {
      await expectRejected(
        await sign(baseClaims(), { alg: 'RS256', kid: 'k1', ...extra }, attackerRsa.privateKey),
      );
    }
  });
});

describe('Access JWT: key selection', () => {
  it('rejects a token signed by an unknown key with no kid', async () => {
    await expectRejected(await sign(baseClaims(), { alg: 'RS256' }, attackerRsa.privateKey));
  });

  it('rejects an unknown kid', async () => {
    await expectRejected(await sign(baseClaims(), { alg: 'RS256', kid: 'nope' }));
    await expectRejected(await sign(baseClaims(), { alg: 'RS256', kid: '../k1' }));
  });

  it('rejects a legitimate signature presented under the other key id', async () => {
    await expectRejected(await sign(baseClaims(), { alg: 'RS256', kid: 'k2' }));
  });
});

describe('Access JWT: claims', () => {
  it.each(['sub', 'exp', 'iat', 'iss', 'aud'] as const)('rejects a token without %s', async (c) => {
    const { [c]: _omitted, ...claims } = baseClaims();
    await expectRejected(await sign(claims));
  });

  it('rejects a non-string or empty email', async () => {
    for (const email of [42, ['admin@example.com'], { v: 'a@example.com' }, '', null]) {
      await expectRejected(await sign({ ...baseClaims(), email } as JWTPayload));
    }
  });

  it('rejects an empty subject', async () => {
    await expectRejected(await sign({ ...baseClaims(), sub: '' }));
  });

  it('rejects a token that is not yet valid (nbf beyond the tolerance)', async () => {
    await expectRejected(await sign({ ...baseClaims(), nbf: now() + 120 }));
  });

  it('honours the 10 s clock tolerance and no more', async () => {
    expect((await authToken(await sign({ ...baseClaims(), exp: now() - 5 }))).ok).toBe(true);
    await expectRejected(await sign({ ...baseClaims(), exp: now() - 30 }));
  });

  it('rejects issuer and audience look-alikes', async () => {
    for (const iss of [
      `${ISSUER}/`,
      'https://team.cloudflareaccess.com.evil.example',
      'http://team.cloudflareaccess.com',
      'https://TEAM.cloudflareaccess.com',
    ]) {
      await expectRejected(await sign({ ...baseClaims(), iss }));
    }
    for (const aud of [`${AUDIENCE} `, AUDIENCE.toUpperCase(), [], ['other']]) {
      await expectRejected(await sign({ ...baseClaims(), aud }));
    }
  });
});

describe('Access JWT: token transport', () => {
  it('rejects malformed tokens without throwing', async () => {
    for (const bad of [
      'a.b.c',
      '...',
      'not-a-jwt',
      'x'.repeat(100_000),
      `${enc({ alg: 'RS256', kid: 'k1' })}.%%%.sig`,
      'Bearer ' + 'a.b.c',
    ]) {
      await expectRejected(bad);
    }
  });

  it('a bad header token is not rescued by a good cookie (no credential fallback)', async () => {
    const result = await authWith({
      'Cf-Access-Jwt-Assertion': 'a.b.c',
      Cookie: `CF_Authorization=${await sign()}`,
    });
    expect(result.ok).toBe(false);
  });

  it('only the exact cookie name is read', async () => {
    const token = await sign();
    for (const cookie of [
      `XCF_Authorization=${token}`,
      `CF_Authorization_x=${token}`,
      `cf_authorization=${token}`,
    ]) {
      const result = await authWith({ Cookie: cookie });
      expect(result, cookie.slice(0, 20)).toEqual({ ok: false, reason: 'missing_credentials' });
    }
  });

  it('a token sent as an Authorization bearer header is not accepted', async () => {
    const result = await authWith({ Authorization: `Bearer ${await sign()}` });
    expect(result.ok).toBe(false);
  });
});

describe('Access JWT end to end through the app', () => {
  let t: TestDatabase;
  const env = {
    APP_ENV: 'production',
    APP_VERSION: 'test',
    AUTH_PROVIDER: 'cloudflare_access',
    ACCESS_TEAM_DOMAIN: 'team.cloudflareaccess.com',
    ACCESS_AUD: AUDIENCE,
    HYPERDRIVE: { connectionString: 'postgres://u:p@db.example.invalid/app' },
  };
  const app = () =>
    createApp({
      connect: async () => ({ db: t.db, close: async () => {} }),
      auth: { accessGetKey: jwks },
    });
  const me = async (token: string) =>
    app().request(
      '/api/v1/me',
      { headers: { 'Cf-Access-Jwt-Assertion': token } },
      env as unknown as Env,
    );

  beforeAll(async () => {
    t = await createTestDatabase();
    await t.db.insert(schema.users).values({
      email: 'analyst@example.com',
      role: 'analyst',
      authProvider: 'cloudflare_access',
      authProviderSubject: 'sub-1',
    });
  }, 30_000);
  afterAll(async () => {
    await t?.close();
  });
  beforeEach(() => {
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'warn').mockImplementation(() => {});
  });
  afterEach(() => vi.restoreAllMocks());

  it('a valid token for a provisioned user is accepted (positive control)', async () => {
    expect((await me(await sign())).status).toBe(200);
  });

  it('the same email under a different Access subject is refused (identity conflict)', async () => {
    const res = await me(await sign({ ...baseClaims(), sub: 'attacker-sub' }));
    expect(res.status).toBe(403);
  });

  it('a validly signed token for an unprovisioned email is refused', async () => {
    const res = await me(await sign({ ...baseClaims(), sub: 'x', email: 'stranger@example.com' }));
    expect(res.status).toBe(403);
    expect(await t.db.select().from(schema.users)).toHaveLength(1);
  });

  it('HS256 confusion and wrong audience are 401 through the app', async () => {
    const hs = await sign(
      baseClaims(),
      { alg: 'HS256', kid: 'k1' },
      new TextEncoder().encode(publicPem),
    );
    expect((await me(hs)).status).toBe(401);
    expect((await me(await sign({ ...baseClaims(), aud: 'other-app' }))).status).toBe(401);
  });
});
