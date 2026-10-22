/**
 * Synthetic TLS fixtures (test-only). Documentation addresses (RFC 5737 / RFC 3849) and
 * reserved example names only; no live systems.
 */
import type { TlsObservation } from '../types.ts';
import { NOW, tls } from './builders.ts';

export const WWW = 'www.example.com';
export const IPV4 = '203.0.113.10';
export const IPV4_B = '198.51.100.20';
export const IPV6 = '2001:db8::10';

const DAY_MS = 86_400_000;

/** ISO time `days` (may be fractional/negative) after the fixture NOW. */
export function daysFromNow(days: number): string {
  return new Date(Date.parse(NOW) + days * DAY_MS).toISOString();
}

/** A healthy, trusted certificate valid for 60 more days on the given address. */
export function goodCert(ip = IPV4, fields: Partial<TlsObservation> = {}): TlsObservation {
  return tls(
    { ipAddress: ip, notBefore: daysFromNow(-30), notAfter: daysFromNow(60), ...fields },
    { evidence: { trusted: true } },
  );
}

/** A successful observation with custom evidence (e.g. untrusted chain). */
export function certWith(
  ip: string,
  fields: Partial<TlsObservation>,
  evidence: Record<string, unknown>,
): TlsObservation {
  return tls(
    { ipAddress: ip, notBefore: daysFromNow(-30), notAfter: daysFromNow(60), ...fields },
    { evidence },
  );
}

/** A failed handshake (connect error or timeout): certificate fields null. */
export function failedTls(ip = IPV4, status: 'error' | 'timeout' = 'error'): TlsObservation {
  return tls(
    {
      ipAddress: ip,
      protocolVersion: null,
      notBefore: null,
      notAfter: null,
      issuer: null,
      subject: null,
      subjectAltNames: [],
      fingerprintSha256: null,
      hostnameMatches: null,
    },
    {
      status,
      evidence: {
        trusted: false,
        error: status === 'timeout' ? 'timeout' : 'ConnectionRefusedError',
      },
    },
  );
}

export const VERIFY = {
  hostname: "Hostname mismatch, certificate is not valid for 'www.example.com'.",
  expired: 'certificate has expired',
  selfSigned: 'self-signed certificate',
  unknownCa: 'unable to get local issuer certificate',
  odd: 'some unusual verification failure',
} as const;
