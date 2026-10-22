// @vitest-environment node
import { describe, expect, it } from 'vitest';
import {
  challengeRecordName,
  digestsEqual,
  generateToken,
  matchesChallenge,
  sha256Hex,
} from './domain-verification.ts';

describe('challenge helpers', () => {
  it('generates distinct 256-bit URL-safe tokens', () => {
    const tokens = new Set(Array.from({ length: 50 }, generateToken));
    expect(tokens.size).toBe(50);
    for (const t of tokens) expect(t).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('hashes with SHA-256 (hex)', async () => {
    expect(await sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('compares digests exactly', () => {
    expect(digestsEqual('ab12', 'ab12')).toBe(true);
    expect(digestsEqual('ab12', 'ab13')).toBe(false);
    expect(digestsEqual('ab12', 'ab1')).toBe(false);
  });

  it('matches only the exact prefixed token', async () => {
    const token = generateToken();
    const hash = await sha256Hex(token);
    expect(await matchesChallenge([`exdomainvault-verification=${token}`], hash)).toBe(true);
    expect(await matchesChallenge([`  exdomainvault-verification=${token} `], hash)).toBe(true);
    expect(await matchesChallenge([token], hash)).toBe(false);
    expect(await matchesChallenge([`exdomainvault-verification=${token}x`], hash)).toBe(false);
    expect(await matchesChallenge([`other-verification=${token}`], hash)).toBe(false);
    expect(await matchesChallenge([], hash)).toBe(false);
  });

  it('places the record under the domain being verified', () => {
    expect(challengeRecordName('example.co.uk')).toBe('_exdomainvault-challenge.example.co.uk');
  });
});
