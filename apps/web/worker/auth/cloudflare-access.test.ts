// @vitest-environment node
import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair, type JWK } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { cloudflareAccessProvider } from './cloudflare-access.ts';

const ISSUER = 'https://team.cloudflareaccess.com';
const AUDIENCE = 'aud-tag-123';

let privateKey: CryptoKey;
let otherKey: CryptoKey;
let jwks: ReturnType<typeof createLocalJWKSet>;

beforeAll(async () => {
  const pair = await generateKeyPair('RS256');
  privateKey = pair.privateKey;
  otherKey = (await generateKeyPair('RS256')).privateKey;
  const jwk: JWK = { ...(await exportJWK(pair.publicKey)), kid: 'k1', alg: 'RS256' };
  jwks = createLocalJWKSet({ keys: [jwk] });
});

function token(claims: Record<string, unknown> = {}, opts: { key?: CryptoKey; exp?: string } = {}) {
  const { iss = ISSUER, aud = AUDIENCE, ...rest } = claims;
  return new SignJWT({ email: 'Analyst@Example.com', type: 'app', ...rest })
    .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
    .setIssuer(iss as string)
    .setAudience(aud as string)
    .setSubject('sub-1')
    .setIssuedAt()
    .setExpirationTime(opts.exp ?? '5m')
    .sign(opts.key ?? privateKey);
}

const provider = () => cloudflareAccessProvider({ issuer: ISSUER, audience: AUDIENCE, getKey: jwks });
const req = (headers: Record<string, string>) => new Request('https://app.example/api/v1/me', { headers });

describe('Cloudflare Access provider', () => {
  it('accepts a valid token from the Access header and normalises the email', async () => {
    const result = await provider().authenticate(req({ 'Cf-Access-Jwt-Assertion': await token() }));
    expect(result).toEqual({
      ok: true,
      identity: { provider: 'cloudflare_access', subject: 'sub-1', email: 'analyst@example.com', name: null },
    });
  });

  it('accepts a valid token from the CF_Authorization cookie', async () => {
    const result = await provider().authenticate(
      req({ Cookie: `theme=dark; CF_Authorization=${await token()}` }),
    );
    expect(result.ok).toBe(true);
  });

  it('reports missing credentials', async () => {
    expect(await provider().authenticate(req({}))).toEqual({
      ok: false,
      reason: 'missing_credentials',
    });
  });

  it('ignores plain identity headers', async () => {
    const result = await provider().authenticate(
      req({ 'Cf-Access-Authenticated-User-Email': 'admin@example.com' }),
    );
    expect(result.ok).toBe(false);
  });

  it.each([
    ['wrong audience', () => token({ aud: 'other-app' })],
    ['wrong issuer', () => token({ iss: 'https://evil.cloudflareaccess.com' })],
    ['expired', () => token({}, { exp: '-5m' })],
    ['signed by an unknown key', () => token({}, { key: otherKey })],
    ['service token without email', () => token({ email: undefined })],
  ])('rejects a token that is %s', async (_label, make) => {
    const result = await provider().authenticate(req({ 'Cf-Access-Jwt-Assertion': await make() }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('invalid_credentials');
  });

  it('rejects an unsigned (alg=none) token', async () => {
    const enc = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    const unsigned = `${enc({ alg: 'none' })}.${enc({ iss: ISSUER, aud: AUDIENCE, sub: 's', email: 'a@example.com', iat: now, exp: now + 300 })}.`;
    const result = await provider().authenticate(req({ 'Cf-Access-Jwt-Assertion': unsigned }));
    expect(result.ok).toBe(false);
  });

  it('rejects a tampered payload', async () => {
    const [h, , s] = (await token()).split('.');
    const forged = Buffer.from(
      JSON.stringify({ iss: ISSUER, aud: AUDIENCE, sub: 'sub-1', email: 'admin@example.com' }),
    ).toString('base64url');
    const result = await provider().authenticate(
      req({ 'Cf-Access-Jwt-Assertion': `${h}.${forged}.${s}` }),
    );
    expect(result.ok).toBe(false);
  });
});
