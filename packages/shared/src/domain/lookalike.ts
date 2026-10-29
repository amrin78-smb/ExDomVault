import type { LookalikeTechnique } from '../api/observations.ts';
import { isValidHostname, LDH_LABEL_RE } from '../hostname/labels.ts';

/**
 * Lookalike-domain generator (Milestone 15, brand monitoring). Pure and deterministic: the same
 * input always yields the same candidates in the same order, so a job's candidate list (captured in
 * its immutable scope snapshot) can be reproduced and compared run to run.
 *
 * Works on the registrable label only (`thaiunion` in `thaiunion.com`); the public suffix is kept
 * except for `tld_swap` (other popular TLDs/ccTLDs) and `subdomain_dot` (`thai.union.com`, whose
 * registrable domain `union.com` is somebody else's name). Every candidate is a valid lowercase
 * LDH hostname. Internationalised (punycode) homoglyphs are deliberately not generated: ASCII
 * look-alikes only (documented limitation).
 *
 * Bump `LOOKALIKE_GENERATOR_VERSION` on any change to the output.
 */
export const LOOKALIKE_GENERATOR_VERSION = 1;

/** Upper bound on candidates per domain (keeps a weekly run within the profile's time budget). */
export const MAX_LOOKALIKE_CANDIDATES = 1500;

export interface LookalikeCandidate {
  candidate: string;
  technique: LookalikeTechnique;
}

export interface GenerateLookalikesOptions {
  /**
   * The domain's public suffix (`com`, `co.th`, …), from the Public Suffix List on the server.
   * Defaults to everything after the first label.
   */
  suffix?: string;
  /**
   * Names never to emit: our own monitored domains. A candidate equal to one of them, or beneath
   * one on a label boundary, is dropped.
   */
  exclude?: readonly string[];
  /** Cap (default and maximum `MAX_LOOKALIKE_CANDIDATES`). */
  max?: number;
}

/**
 * Popular generic TLDs and ccTLDs (incl. the second-level registries used in South-East Asia and
 * by large brands). Order is fixed: it is the order `tld_swap` candidates are emitted in.
 */
export const LOOKALIKE_TLDS: readonly string[] = [
  'com',
  'net',
  'org',
  'co',
  'io',
  'info',
  'biz',
  'asia',
  'co.th',
  'in.th',
  'th',
  'com.my',
  'sg',
  'com.sg',
  'com.au',
  'co.uk',
  'de',
  'fr',
  'es',
  'it',
  'nl',
  'us',
  'ca',
  'cn',
  'com.cn',
  'jp',
  'kr',
  'vn',
  'com.vn',
  'id',
  'co.id',
  'ph',
  'com.ph',
  'xyz',
  'online',
  'site',
  'shop',
  'store',
  'app',
  'dev',
  'cloud',
];

/** QWERTY neighbours (incl. the digit row), as commonly used for typo generation. */
const QWERTY: Readonly<Record<string, string>> = {
  '1': '2q',
  '2': '3wq1',
  '3': '4ew2',
  '4': '5re3',
  '5': '6tr4',
  '6': '7yt5',
  '7': '8uy6',
  '8': '9iu7',
  '9': '0oi8',
  '0': 'po9',
  q: '12wa',
  w: '3esaq2',
  e: '4rdsw3',
  r: '5tfde4',
  t: '6ygfr5',
  y: '7uhgt6',
  u: '8ijhy7',
  i: '9okju8',
  o: '0plki9',
  p: 'lo0',
  a: 'qwsz',
  s: 'edxzaw',
  d: 'rfcxse',
  f: 'tgvcdr',
  g: 'yhbvft',
  h: 'ujnbgy',
  j: 'ikmnhu',
  k: 'olmji',
  l: 'kop',
  z: 'asx',
  x: 'zsdc',
  c: 'xdfv',
  v: 'cfgb',
  b: 'vghn',
  n: 'bhjm',
  m: 'njk',
};

/** ASCII look-alikes of single characters (visually confusable in common fonts). */
const HOMOGLYPHS: Readonly<Record<string, readonly string[]>> = {
  '0': ['o'],
  '1': ['l', 'i'],
  '3': ['8'],
  '5': ['s'],
  '6': ['b'],
  '8': ['3'],
  b: ['d', '6'],
  c: ['e'],
  d: ['b', 'cl'],
  e: ['c'],
  g: ['q', '9'],
  i: ['1', 'l'],
  l: ['1', 'i'],
  m: ['rn', 'nn'],
  n: ['m'],
  o: ['0'],
  q: ['g'],
  s: ['5'],
  u: ['v'],
  v: ['u'],
  w: ['vv'],
  z: ['2'],
};

/** Multi-character look-alikes collapsed to one character (`rn` → `m`). */
const HOMOGLYPH_SEQUENCES: readonly (readonly [string, string])[] = [
  ['rn', 'm'],
  ['nn', 'm'],
  ['vv', 'w'],
  ['cl', 'd'],
];

const VOWELS = 'aeiou';
const LDH_CHAR = /^[a-z0-9-]$/;

function* omission(label: string) {
  for (let i = 0; i < label.length; i++) yield label.slice(0, i) + label.slice(i + 1);
}

function* repetition(label: string) {
  for (let i = 0; i < label.length; i++) {
    yield label.slice(0, i + 1) + (label[i] as string) + label.slice(i + 1);
  }
}

function* transposition(label: string) {
  for (let i = 0; i < label.length - 1; i++) {
    const a = label[i] as string;
    const b = label[i + 1] as string;
    if (a !== b) yield label.slice(0, i) + b + a + label.slice(i + 2);
  }
}

function* replacement(label: string) {
  for (let i = 0; i < label.length; i++) {
    for (const c of QWERTY[label[i] as string] ?? '') {
      yield label.slice(0, i) + c + label.slice(i + 1);
    }
  }
}

function* insertion(label: string) {
  for (let i = 0; i < label.length; i++) {
    const ch = label[i] as string;
    for (const c of QWERTY[ch] ?? '') {
      yield label.slice(0, i) + c + ch + label.slice(i + 1);
      yield label.slice(0, i) + ch + c + label.slice(i + 1);
    }
  }
}

function* homoglyph(label: string) {
  for (let i = 0; i < label.length; i++) {
    for (const g of HOMOGLYPHS[label[i] as string] ?? []) {
      yield label.slice(0, i) + g + label.slice(i + 1);
    }
  }
  for (const [seq, g] of HOMOGLYPH_SEQUENCES) {
    for (let i = label.indexOf(seq); i !== -1; i = label.indexOf(seq, i + 1)) {
      yield label.slice(0, i) + g + label.slice(i + seq.length);
    }
  }
}

function* hyphenation(label: string) {
  for (let i = 1; i < label.length; i++) {
    if (label[i - 1] !== '-' && label[i] !== '-') yield `${label.slice(0, i)}-${label.slice(i)}`;
  }
}

function* bitsquatting(label: string) {
  for (let i = 0; i < label.length; i++) {
    const code = label.charCodeAt(i);
    for (let bit = 0; bit < 8; bit++) {
      const c = String.fromCharCode(code ^ (1 << bit));
      if (LDH_CHAR.test(c)) yield label.slice(0, i) + c + label.slice(i + 1);
    }
  }
}

function* vowelSwap(label: string) {
  for (let i = 0; i < label.length; i++) {
    if (!VOWELS.includes(label[i] as string)) continue;
    for (const v of VOWELS) {
      if (v !== label[i]) yield label.slice(0, i) + v + label.slice(i + 1);
    }
  }
}

const LABEL_TECHNIQUES: readonly (readonly [
  LookalikeTechnique,
  (label: string) => Iterable<string>,
])[] = [
  ['omission', omission],
  ['repetition', repetition],
  ['transposition', transposition],
  ['replacement', replacement],
  ['insertion', insertion],
  ['homoglyph', homoglyph],
  ['hyphenation', hyphenation],
  ['bitsquatting', bitsquatting],
  ['vowel_swap', vowelSwap],
];

const within = (name: string, domain: string) => name === domain || name.endsWith(`.${domain}`);

/**
 * Lookalike candidates of a registrable domain, deduplicated (first technique wins, in the order of
 * `LOOKALIKE_TECHNIQUES`), never the domain itself or any excluded domain, every one a valid
 * hostname, at most `max`. Returns `[]` for input that is not a valid hostname.
 */
export function generateLookalikes(
  fqdn: string,
  opts: GenerateLookalikesOptions = {},
): LookalikeCandidate[] {
  const domain = fqdn.toLowerCase();
  if (!isValidHostname(domain)) return [];
  const suffix = (opts.suffix ?? domain.slice(domain.indexOf('.') + 1)).toLowerCase();
  if (!domain.endsWith(`.${suffix}`)) return [];
  const registrable = domain.slice(0, -suffix.length - 1);
  // Only the label directly left of the suffix is varied (domains are registrable names).
  const label = registrable.slice(registrable.lastIndexOf('.') + 1);
  if (!LDH_LABEL_RE.test(label)) return [];

  const max = Math.min(opts.max ?? MAX_LOOKALIKE_CANDIDATES, MAX_LOOKALIKE_CANDIDATES);
  const excluded = [domain, ...(opts.exclude ?? []).map((d) => d.toLowerCase())];
  const seen = new Set<string>();
  const out: LookalikeCandidate[] = [];
  const add = (candidate: string, technique: LookalikeTechnique) => {
    if (out.length >= max || seen.has(candidate)) return;
    seen.add(candidate);
    if (!isValidHostname(candidate)) return;
    if (excluded.some((d) => within(candidate, d))) return;
    out.push({ candidate, technique });
  };

  for (const [technique, gen] of LABEL_TECHNIQUES) {
    for (const variant of gen(label)) {
      if (variant.length > 0 && variant !== label) add(`${variant}.${suffix}`, technique);
    }
  }
  for (const tld of LOOKALIKE_TLDS) {
    if (tld !== suffix) add(`${label}.${tld}`, 'tld_swap');
  }
  // `thai.union.com`: someone who owns `union.com` can create it. Split points must leave two
  // valid labels, the right one (the other party's registrable label) at least two characters.
  for (let i = 1; i < label.length - 1; i++) {
    const left = label.slice(0, i);
    const right = label.slice(i);
    if (LDH_LABEL_RE.test(left) && LDH_LABEL_RE.test(right)) {
      add(`${left}.${right}.${suffix}`, 'subdomain_dot');
    }
  }
  return out;
}
