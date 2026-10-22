// eslint-disable-next-line @typescript-eslint/triple-slash-reference -- ambient types for an untyped package file, needed by every consuming tsconfig
/// <reference path="./punycode.d.ts" />
// The explicit ES-module file selects the npm package (not Node's deprecated built-in) and loads
// under plain Node ESM as well as bundlers.
import punycode from 'punycode/punycode.es6.js';
import { parse } from 'tldts';
import { hasEmptyLabel, LDH_LABEL_RE } from './labels.ts';

export {
  hasEmptyLabel,
  isValidHostname,
  LDH_LABEL_RE,
  type HostnameSyntaxOptions,
} from './labels.ts';

/**
 * Domain-name normalisation and boundary checks shared by the API (and, later, scope validation).
 *
 * The canonical form is lowercase ASCII (IDN labels as A-labels, `xn--…`), with no trailing dot.
 * IDNA (UTS #46) mapping is done by the platform WHATWG URL parser; the registrable-domain boundary
 * comes from the Public Suffix List bundled with `tldts`. Server-side only: `tldts` carries the PSL.
 */

export type DomainRejection =
  | 'empty'
  | 'too_long'
  | 'invalid_characters'
  | 'wildcard'
  | 'ip_address'
  | 'invalid_label'
  | 'invalid_idn'
  | 'single_label'
  | 'unknown_suffix'
  | 'public_suffix'
  | 'private_suffix'
  | 'reserved_suffix'
  | 'not_registrable';

export type DomainWarning =
  /** Contains non-ASCII characters: compare the A-label, not how the name looks. */
  | 'idn'
  /** A label mixes scripts (e.g. Latin and Cyrillic) — a common homograph technique. */
  | 'mixed_script';

export type NormalisedDomain =
  | {
      ok: true;
      /** Canonical lowercase A-label form, no trailing dot. */
      fqdn: string;
      /** Unicode form for display alongside `fqdn` (equal to `fqdn` for ASCII names). */
      unicode: string;
      publicSuffix: string;
      warnings: DomainWarning[];
    }
  | {
      ok: false;
      reason: DomainRejection;
      message: string;
      /** For subdomains: the registrable domain that could be registered instead. */
      suggestion?: string;
    };

// The WHATWG URL parser exists in every runtime this package targets (Workers, browsers, Node);
// declared here because the package compiles without DOM or Node typings.
declare const URL: new (input: string) => { hostname: string };

const MAX_INPUT_LENGTH = 1024;
const MAX_NAME_LENGTH = 253;
const LDH_LABEL = LDH_LABEL_RE;
/** ASCII is restricted to letters, digits, hyphen and dot before the URL parser sees the input, so
 * percent-encoding, numeric IP shorthands (`0x7f.1`), userinfo, ports and paths never reach it. */
const ALLOWED_ASCII = /^[a-z0-9.-]$/i;
/** Top-level domains that are in the PSL's ICANN section but are never organisation domains. */
const RESERVED_TLDS = new Set(['arpa']);

const reject = (
  reason: DomainRejection,
  message: string,
  suggestion?: string,
): NormalisedDomain => ({ ok: false, reason, message, ...(suggestion ? { suggestion } : {}) });

/** Validates and canonicalises a registrable domain (e.g. `example.co.uk`) entered by a user. */
export function normaliseDomain(input: string): NormalisedDomain {
  const trimmed = input.trim();
  if (trimmed === '') return reject('empty', 'Enter a domain name.');
  if (trimmed.length > MAX_INPUT_LENGTH) return reject('too_long', 'The domain name is too long.');
  if (trimmed.includes('*')) {
    return reject('wildcard', 'Wildcards are not allowed; enter the registered domain itself.');
  }

  let hasNonAscii = false;
  for (const ch of trimmed) {
    if (ch.charCodeAt(0) > 0x7f) {
      hasNonAscii = true;
    } else if (!ALLOWED_ASCII.test(ch)) {
      return reject(
        'invalid_characters',
        'Enter only a domain name (letters, digits, hyphens and dots) — no scheme, path, port, spaces or underscores.',
      );
    }
  }

  let host: string;
  try {
    host = new URL(`http://${trimmed}`).hostname;
  } catch {
    return reject('invalid_idn', 'The domain name is not valid.');
  }
  if (host.endsWith('.')) host = host.slice(0, -1);

  if (/^\d+(\.\d+){3}$/.test(host) || host.startsWith('[')) {
    return reject('ip_address', 'IP addresses cannot be registered; enter a domain name.');
  }
  if (host.length === 0 || host.length > MAX_NAME_LENGTH) {
    return reject('too_long', 'A domain name can be at most 253 characters.');
  }

  const labels = host.split('.');
  for (const label of labels) {
    if (!LDH_LABEL.test(label)) {
      return reject(
        'invalid_label',
        'Each part of the name must be 1–63 letters, digits or hyphens and must not start or end with a hyphen.',
      );
    }
    if (label.slice(2, 4) === '--' && !label.startsWith('xn--')) {
      return reject('invalid_label', 'Labels with "--" in positions 3–4 are reserved.');
    }
    if (label.startsWith('xn--') && !isValidALabel(label)) {
      return reject('invalid_idn', 'The internationalised domain name is not valid.');
    }
  }
  if (labels.length < 2)
    return reject('single_label', 'Enter a full domain name such as example.com.');

  const parsed = parse(host, { allowPrivateDomains: true });
  const suffix = parsed.publicSuffix ?? '';
  if (parsed.isIp)
    return reject('ip_address', 'IP addresses cannot be registered; enter a domain name.');
  if (parsed.isPrivate) {
    return reject(
      'private_suffix',
      `Names under ${suffix} belong to a shared hosting platform and cannot be registered here.`,
    );
  }
  if (!parsed.isIcann) {
    return reject('unknown_suffix', `".${suffix}" is not a public top-level domain.`);
  }
  if (RESERVED_TLDS.has(labels.at(-1) ?? '')) {
    return reject('reserved_suffix', 'Infrastructure domains (.arpa) cannot be registered.');
  }
  if (!parsed.domain) {
    return reject('public_suffix', `${host} is a public suffix, not a registrable domain.`);
  }
  if (parsed.domain !== host) {
    return reject(
      'not_registrable',
      `${host} is a subdomain. Register the domain ${parsed.domain} instead; subdomains are tracked as assets.`,
      parsed.domain,
    );
  }

  const unicode = labels.map((l) => (l.startsWith('xn--') ? punycode.toUnicode(l) : l)).join('.');
  const warnings: DomainWarning[] = [];
  if (hasNonAscii || unicode !== host) warnings.push('idn');
  if (unicode.split('.').some(hasMixedScripts)) warnings.push('mixed_script');

  return { ok: true, fqdn: host, unicode, publicSuffix: suffix, warnings };
}

/** True when an `xn--` label decodes and re-encodes to itself (rejects malformed punycode). */
function isValidALabel(label: string): boolean {
  try {
    const decoded = punycode.toUnicode(label);
    if (decoded === label) return false;
    return new URL(`http://${decoded}`).hostname === label;
  } catch {
    return false;
  }
}

const SCRIPTS = [
  ['Latin', /\p{Script=Latin}/u],
  ['Cyrillic', /\p{Script=Cyrillic}/u],
  ['Greek', /\p{Script=Greek}/u],
  ['Armenian', /\p{Script=Armenian}/u],
  ['Hebrew', /\p{Script=Hebrew}/u],
  ['Arabic', /\p{Script=Arabic}/u],
  ['Han', /\p{Script=Han}/u],
  ['Hiragana', /\p{Script=Hiragana}/u],
  ['Katakana', /\p{Script=Katakana}/u],
  ['Hangul', /\p{Script=Hangul}/u],
] as const;

/** Scripts conventionally written together (Japanese, Korean); ASCII digits/hyphens are neutral. */
const COMPATIBLE = [
  new Set(['Han', 'Hiragana', 'Katakana', 'Latin']),
  new Set(['Han', 'Hangul', 'Latin']),
];

function hasMixedScripts(label: string): boolean {
  const seen = new Set<string>();
  for (const ch of label) {
    for (const [name, re] of SCRIPTS) {
      if (re.test(ch)) seen.add(name);
    }
  }
  if (seen.size <= 1) return false;
  return !COMPATIBLE.some((set) => [...seen].every((s) => set.has(s)));
}

/**
 * Exact DNS label-boundary check: is `hostname` the domain itself or a name beneath it?
 * Both arguments must already be canonical (lowercase A-labels, no trailing dot).
 * `evil-example.com` and `example.com.evil.net` are NOT within `example.com`.
 */
export function isWithinDomain(hostname: string, domain: string): boolean {
  if (hostname === '' || domain === '') return false;
  // Malformed names (`.example.com`, `www..example.com`) are never inside anything.
  if (hasEmptyLabel(hostname) || hasEmptyLabel(domain)) return false;
  return hostname === domain || hostname.endsWith(`.${domain}`);
}
