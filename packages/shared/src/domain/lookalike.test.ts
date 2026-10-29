import { describe, expect, it } from 'vitest';
import { LOOKALIKE_TECHNIQUES } from '../api/observations.ts';
import { isValidHostname } from '../hostname/labels.ts';
import {
  LOOKALIKE_TLDS,
  MAX_LOOKALIKE_CANDIDATES,
  generateLookalikes,
  type LookalikeCandidate,
} from './lookalike.ts';

const thaiunion = generateLookalikes('thaiunion.com', { suffix: 'com' });
const byName = new Map(thaiunion.map((c) => [c.candidate, c.technique]));

describe('generateLookalikes (thaiunion.com)', () => {
  it.each([
    ['thaiunlon.com', 'homoglyph'],
    ['thaiuinon.com', 'transposition'],
    ['thai-union.com', 'hyphenation'],
    ['thaiunion.co', 'tld_swap'],
    ['thaiunion.co.th', 'tld_swap'],
    ['rhaiunion.com', 'replacement'],
    ['haiunion.com', 'omission'],
    ['thaiuniion.com', 'repetition'],
    ['thaiuniont.com', undefined], // not a QWERTY neighbour of n: never generated
    ['thalunion.com', 'homoglyph'],
    ['thaiuni0n.com', 'replacement'], // 0 is next to o on the keyboard: replacement wins
    ['thaiunien.com', 'vowel_swap'],
    ['thai.union.com', 'subdomain_dot'],
    ['thaiunion.net', 'tld_swap'],
  ])('%s → %s', (name, technique) => {
    expect(byName.get(name)).toBe(technique);
  });

  it('is deterministic and deduplicated', () => {
    expect(generateLookalikes('thaiunion.com', { suffix: 'com' })).toEqual(thaiunion);
    expect(new Set(thaiunion.map((c) => c.candidate)).size).toBe(thaiunion.length);
  });

  it('never emits the domain itself, and only valid hostnames', () => {
    expect(byName.has('thaiunion.com')).toBe(false);
    for (const c of thaiunion) expect(isValidHostname(c.candidate), c.candidate).toBe(true);
  });

  it('emits techniques in the enum order', () => {
    const order = thaiunion.map((c) => LOOKALIKE_TECHNIQUES.indexOf(c.technique));
    expect([...order].sort((a, b) => a - b)).toEqual(order);
  });

  it('covers every technique and stays well under the cap', () => {
    expect(new Set(thaiunion.map((c) => c.technique))).toEqual(new Set(LOOKALIKE_TECHNIQUES));
    expect(thaiunion.length).toBeGreaterThan(200);
    expect(thaiunion.length).toBeLessThan(MAX_LOOKALIKE_CANDIDATES);
  });

  it('swaps to every curated TLD except its own', () => {
    const swaps = thaiunion.filter((c) => c.technique === 'tld_swap').map((c) => c.candidate);
    expect(swaps).toEqual(LOOKALIKE_TLDS.filter((t) => t !== 'com').map((t) => `thaiunion.${t}`));
  });

  it('bitsquatting stays within LDH characters', () => {
    const bits = thaiunion.filter((c) => c.technique === 'bitsquatting');
    expect(bits.length).toBeGreaterThan(0);
    for (const c of bits) expect(c.candidate).toMatch(/^[a-z0-9-]+\.com$/);
  });

  it('subdomain_dot keeps a registrable label of at least two characters', () => {
    const splits = thaiunion.filter((c) => c.technique === 'subdomain_dot').map((c) => c.candidate);
    expect(splits).toEqual([
      't.haiunion.com',
      'th.aiunion.com',
      'tha.iunion.com',
      'thai.union.com',
      'thaiu.nion.com',
      'thaiun.ion.com',
      'thaiuni.on.com',
    ]);
  });
});

describe('generateLookalikes options', () => {
  it('drops excluded (own) domains and names beneath them', () => {
    const own = ['thaiunion.co.th', 'union.com', 'thai-union.com'];
    const out = generateLookalikes('thaiunion.com', { suffix: 'com', exclude: own });
    const names = new Set(out.map((c) => c.candidate));
    expect(names.has('thaiunion.co.th')).toBe(false);
    expect(names.has('thai-union.com')).toBe(false);
    expect(names.has('thai.union.com')).toBe(false); // beneath union.com
    expect(names.has('thaiunion.net')).toBe(true);
  });

  it('uses the public suffix for multi-label suffixes', () => {
    const out = generateLookalikes('example.co.th', { suffix: 'co.th' });
    const names = new Set(out.map((c) => c.candidate));
    expect(names.has('exampel.co.th')).toBe(true);
    expect(names.has('example.com')).toBe(true);
    expect(names.has('example.co.th')).toBe(false);
    // Without the suffix the default would treat `th` alone as the suffix base: still valid names.
    for (const c of generateLookalikes('example.co.th')) {
      expect(isValidHostname(c.candidate)).toBe(true);
    }
  });

  it('caps the output deterministically', () => {
    const out = generateLookalikes('thaiunion.com', { suffix: 'com', max: 10 });
    expect(out).toEqual(thaiunion.slice(0, 10));
    const long = generateLookalikes(`${'abcdefghij'.repeat(6)}.com`, { max: 99_999 });
    expect(long.length).toBeLessThanOrEqual(MAX_LOOKALIKE_CANDIDATES);
  });

  it('returns nothing for invalid input', () => {
    expect(generateLookalikes('not a domain')).toEqual([]);
    expect(generateLookalikes('com')).toEqual([]);
    expect(generateLookalikes('example.com', { suffix: 'org' })).toEqual([]);
  });

  it('never produces leading/trailing hyphens or empty labels', () => {
    const out: LookalikeCandidate[] = generateLookalikes('a-b.com');
    for (const c of out) expect(isValidHostname(c.candidate), c.candidate).toBe(true);
  });
});
