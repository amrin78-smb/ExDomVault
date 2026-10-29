import { describe, expect, it } from 'vitest';
import { dnsObservationSchema, tlsObservationSchema } from '../api/observations.ts';
import { hasEmptyLabel, isValidHostname } from './labels.ts';

describe('isValidHostname', () => {
  it.each(['example.com', 'www.example.com', 'a-b.example.com', `${'a'.repeat(63)}.example.com`])(
    'accepts %s',
    (name) => expect(isValidHostname(name)).toBe(true),
  );

  it.each([
    ['empty', ''],
    ['single label', 'localhost'],
    ['empty leading label', '.example.com'],
    ['empty inner label', 'www..example.com'],
    ['trailing dot', 'www.example.com.'],
    ['hyphen-only label', '-.example.com'],
    ['leading hyphen', '-www.example.com'],
    ['trailing hyphen', 'www-.example.com'],
    ['64-char label', `${'a'.repeat(64)}.example.com`],
    ['uppercase', 'WWW.example.com'],
    ['underscore', '_dmarc.example.com'],
    ['inner underscore', 'a_b.example.com'],
    ['too long', `${'a.'.repeat(127)}com`],
  ])('rejects %s', (_label, name) => expect(isValidHostname(name)).toBe(false));

  it('allows leading service labels only when asked', () => {
    expect(isValidHostname('_dmarc.example.com', { allowServiceLabels: true })).toBe(true);
    expect(isValidHostname('_25._tcp.mx.example.com', { allowServiceLabels: true })).toBe(true);
    // Not leading, a bare underscore, or the service label as the domain itself.
    expect(isValidHostname('www._dmarc.example.com', { allowServiceLabels: true })).toBe(false);
    // DKIM / BIMI selector names (Milestone 15).
    expect(isValidHostname('selector1._domainkey.example.com', { allowServiceLabels: true })).toBe(
      true,
    );
    expect(isValidHostname('default._bimi.example.com', { allowServiceLabels: true })).toBe(true);
    expect(isValidHostname('selector1._domainkey.example.com')).toBe(false);
    expect(isValidHostname('a.b._domainkey.example.com', { allowServiceLabels: true })).toBe(false);
    expect(isValidHostname('s1._domainkey.com', { allowServiceLabels: true })).toBe(false);
    expect(isValidHostname('-x._domainkey.example.com', { allowServiceLabels: true })).toBe(false);
    expect(isValidHostname('_.example.com', { allowServiceLabels: true })).toBe(false);
    expect(isValidHostname('_dmarc.com', { allowServiceLabels: true })).toBe(false);
    expect(isValidHostname('_-x.example.com', { allowServiceLabels: true })).toBe(false);
  });

  it('hasEmptyLabel', () => {
    expect(hasEmptyLabel('a..b')).toBe(true);
    expect(hasEmptyLabel('.a.b')).toBe(true);
    expect(hasEmptyLabel('a.b')).toBe(false);
  });
});

describe('observation hostname schemas', () => {
  const base = {
    targetId: '00000000-0000-4000-8000-000000000000',
    observedAt: '2026-10-22T10:00:00.000Z',
    checkerVersion: '1',
    resultStatus: 'success',
  };
  it('dns observations accept _dmarc names; tls observations do not', () => {
    const dns = { kind: 'dns', ...base, recordType: 'TXT', ttl: 300, values: [] };
    expect(dnsObservationSchema.safeParse({ ...dns, hostname: '_dmarc.example.com' }).success).toBe(
      true,
    );
    expect(dnsObservationSchema.safeParse({ ...dns, hostname: 'www..example.com' }).success).toBe(
      false,
    );
    const tls = {
      kind: 'tls',
      ...base,
      ipAddress: '8.8.8.8',
      port: 443,
      protocolVersion: null,
      notBefore: null,
      notAfter: null,
      issuer: null,
      subject: null,
      subjectAltNames: [],
      fingerprintSha256: null,
      hostnameMatches: null,
    };
    expect(tlsObservationSchema.safeParse({ ...tls, hostname: '_dmarc.example.com' }).success).toBe(
      false,
    );
    const ok = tlsObservationSchema.parse({ ...tls, hostname: 'www.example.com' });
    expect(ok.check).toBe('tls_certificate');
  });
});
