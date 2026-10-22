import { describe, expect, it } from 'vitest';
import { isWithinDomain, normaliseDomain, type DomainRejection } from './normalise.ts';

function accepted(input: string) {
  const r = normaliseDomain(input);
  if (!r.ok) throw new Error(`expected ${input} to be accepted, got ${r.reason}: ${r.message}`);
  return r;
}

function rejected(input: string): DomainRejection {
  const r = normaliseDomain(input);
  if (r.ok) throw new Error(`expected ${input} to be rejected, got ${r.fqdn}`);
  return r.reason;
}

describe('normaliseDomain', () => {
  it.each([
    ['example.com', 'example.com'],
    ['Example.COM', 'example.com'],
    ['  example.com  ', 'example.com'],
    ['example.com.', 'example.com'],
    ['EXAMPLE.co.uk.', 'example.co.uk'],
    ['my-company.io', 'my-company.io'],
    ['123example.com', '123example.com'],
    ['xn--mnchen-3ya.de', 'xn--mnchen-3ya.de'],
    ['münchen.de', 'xn--mnchen-3ya.de'],
    ['MÜNCHEN.DE', 'xn--mnchen-3ya.de'],
    ['пример.рф', 'xn--e1afmkfd.xn--p1ai'],
    ['ｅｘａｍｐｌｅ。com', 'example.com'], // full-width forms are mapped by IDNA (UTS #46)
  ])('normalises %s → %s', (input, fqdn) => {
    expect(accepted(input).fqdn).toBe(fqdn);
  });

  it('returns the Unicode form for display and flags IDNs', () => {
    const r = accepted('xn--mnchen-3ya.de');
    expect(r.unicode).toBe('münchen.de');
    expect(r.warnings).toEqual(['idn']);
    expect(accepted('example.com')).toMatchObject({ unicode: 'example.com', warnings: [] });
  });

  it('flags homographs that mix Latin and Cyrillic, and keeps them distinct from the real name', () => {
    // "е" below is U+0435 CYRILLIC SMALL LETTER IE.
    const spoof = accepted('еxample.com');
    expect(spoof.fqdn).not.toBe('example.com');
    expect(spoof.fqdn.startsWith('xn--')).toBe(true);
    expect(spoof.warnings).toEqual(['idn', 'mixed_script']);
    // Same-looking name entered as its A-label is still flagged.
    expect(accepted(spoof.fqdn).warnings).toContain('mixed_script');
  });

  it('does not flag single-script or conventional Japanese IDNs as mixed', () => {
    expect(accepted('пример.рф').warnings).toEqual(['idn']);
    expect(accepted('ドメイン名例.jp').warnings).toEqual(['idn']);
    expect(accepted('日本語ドメイン.jp').warnings).toEqual(['idn']);
  });

  it.each<[string, DomainRejection]>([
    ['', 'empty'],
    ['   ', 'empty'],
    ['*.example.com', 'wildcard'],
    ['https://example.com', 'invalid_characters'],
    ['example.com/path', 'invalid_characters'],
    ['example.com:443', 'invalid_characters'],
    ['user@example.com', 'invalid_characters'],
    ['exa%6dple.com', 'invalid_characters'],
    ['exa mple.com', 'invalid_characters'],
    ['_dmarc.example.com', 'invalid_characters'],
    ['exam\tple.com', 'invalid_characters'],
    ['[::1]', 'invalid_characters'],
    ['192.0.2.1', 'ip_address'],
    ['0x7f.1', 'ip_address'],
    ['-example.com', 'invalid_label'],
    ['example-.com', 'invalid_label'],
    ['ex--ample.com', 'invalid_label'],
    ['a..com', 'invalid_label'],
    [`${'a'.repeat(64)}.com`, 'invalid_label'],
    ['xn--zz.com', 'invalid_idn'],
    ['localhost', 'single_label'],
    ['com', 'single_label'],
    ['co.uk', 'public_suffix'],
    ['foo.local', 'unknown_suffix'],
    ['foo.internal', 'unknown_suffix'],
    ['foo.test', 'unknown_suffix'],
    ['foo.github.io', 'private_suffix'],
    ['tenant.workers.dev', 'private_suffix'],
    ['1.2.0.192.in-addr.arpa', 'reserved_suffix'],
    ['www.example.com', 'not_registrable'],
  ])('rejects %j (%s)', (input, reason) => {
    expect(rejected(input)).toBe(reason);
  });

  it('rejects names longer than 253 characters', () => {
    const long = `${Array.from({ length: 5 }, () => 'a'.repeat(63)).join('.')}.com`;
    expect(rejected(long)).toBe('too_long');
  });

  it('suggests the registrable domain for subdomains', () => {
    const r = normaliseDomain('Mail.Example.co.uk');
    expect(r).toMatchObject({ ok: false, reason: 'not_registrable', suggestion: 'example.co.uk' });
  });

  it('is idempotent', () => {
    for (const input of ['Example.COM.', 'münchen.de', 'еxample.com']) {
      const once = accepted(input).fqdn;
      expect(accepted(once).fqdn).toBe(once);
    }
  });
});

describe('isWithinDomain', () => {
  it.each([
    ['example.com', 'example.com', true],
    ['www.example.com', 'example.com', true],
    ['a.b.example.com', 'example.com', true],
    ['evil-example.com', 'example.com', false],
    ['notexample.com', 'example.com', false],
    ['example.com.evil.net', 'example.com', false],
    ['example.co', 'example.com', false],
    ['xn--xample-2of.com', 'example.com', false],
    ['', 'example.com', false],
    ['example.com', '', false],
  ])('%s within %s → %s', (host, domain, expected) => {
    expect(isWithinDomain(host, domain)).toBe(expected);
  });
});
