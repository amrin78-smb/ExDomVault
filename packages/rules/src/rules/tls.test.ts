import { describe, expect, it } from 'vitest';
import { evaluate, fingerprint } from '../evaluator.ts';
import { input } from '../fixtures/builders.ts';
import {
  certWith,
  daysFromNow,
  failedTls,
  goodCert,
  IPV4,
  IPV4_B,
  IPV6,
  VERIFY,
  WWW,
} from '../fixtures/tls-fixtures.ts';
import type { TlsObservation } from '../types.ts';
import {
  classifyVerifyError,
  expirySeverity,
  tls001,
  tls002,
  tls003,
  tls004,
  tls005,
  tlsRules,
} from './tls.ts';

const run = (rule: typeof tls001, tls: TlsObservation[]) =>
  rule.evaluate(input({ tls }, {}, { checks: ['tls_certificate'] }));

const checked443 = [{ hostname: WWW, component: '443' }];

describe('TLS-001 expired / not-yet-valid certificate', () => {
  it('raises high for an expired certificate, one finding per hostname:port listing the IPs', () => {
    const out = run(tls001, [
      goodCert(IPV4, { notAfter: daysFromNow(-1) }),
      goodCert(IPV6, { notAfter: daysFromNow(-1) }),
    ]);
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({
      hostname: WWW,
      component: '443',
      severity: 'high',
      confidence: 'high',
      exposure: 'web',
      evidence: { condition: 'expired', affectedAddresses: [IPV4, IPV6] },
    });
    expect(out.findings[0]!.title).toMatch(/Expired/);
    expect(out.checked).toEqual([]);
  });

  it('raises when only one of several IPs serves an expired certificate', () => {
    const out = run(tls001, [goodCert(IPV4), goodCert(IPV6, { notAfter: daysFromNow(-0.5) })]);
    expect(out.findings[0]?.evidence['affectedAddresses']).toEqual([IPV6]);
  });

  it('raises with not-yet-valid wording when notBefore is in the future', () => {
    const out = run(tls001, [goodCert(IPV4, { notBefore: daysFromNow(2) })]);
    expect(out.findings[0]).toMatchObject({
      severity: 'high',
      evidence: { condition: 'not_yet_valid' },
    });
    expect(out.findings[0]!.title).toMatch(/not yet valid/);
  });

  it('treats notAfter exactly at evaluation time as still valid (X.509 notAfter is inclusive)', () => {
    const out = run(tls001, [goodCert(IPV4, { notAfter: daysFromNow(0) })]);
    expect(out.findings).toEqual([]);
    expect(out.checked).toEqual(checked443);
  });

  it('resolves (checked) when every address succeeded with a valid certificate', () => {
    const out = run(tls001, [goodCert(IPV4), goodCert(IPV6)]);
    expect(out).toEqual({ findings: [], checked: checked443 });
  });

  it('does not resolve when one address failed (insufficient evidence)', () => {
    const out = run(tls001, [goodCert(IPV4), failedTls(IPV6, 'timeout')]);
    expect(out).toEqual({ findings: [], checked: [] });
  });

  it('neither raises nor resolves from failed handshakes alone', () => {
    expect(run(tls001, [failedTls(IPV4), failedTls(IPV6, 'timeout')])).toEqual({
      findings: [],
      checked: [],
    });
  });

  it('keeps hostnames and ports separate', () => {
    const out = run(tls001, [
      goodCert(IPV4, { notAfter: daysFromNow(-3) }),
      goodCert(IPV4, { hostname: 'example.com' }),
    ]);
    expect(out.findings.map((f) => f.hostname)).toEqual([WWW]);
    expect(out.checked).toEqual([{ hostname: 'example.com', component: '443' }]);
  });
});

describe('TLS-002 hostname mismatch', () => {
  it('raises medium on a mismatch (hostname-only verify error)', () => {
    const out = run(tls002, [
      certWith(IPV4, { hostnameMatches: false }, { trusted: false, verifyError: VERIFY.hostname }),
    ]);
    expect(out.findings[0]).toMatchObject({
      component: '443',
      severity: 'medium',
      evidence: { alsoUntrusted: false, affectedAddresses: [IPV4] },
    });
  });

  it('raises high when the chain is also untrusted', () => {
    const out = run(tls002, [
      certWith(
        IPV4,
        { hostnameMatches: false },
        { trusted: false, verifyError: VERIFY.selfSigned },
      ),
    ]);
    expect(out.findings[0]).toMatchObject({ severity: 'high', evidence: { alsoUntrusted: true } });
  });

  it('dedupes across IPv4 and IPv6 addresses', () => {
    const out = run(tls002, [
      certWith(IPV4, { hostnameMatches: false }, { trusted: false, verifyError: VERIFY.hostname }),
      certWith(IPV6, { hostnameMatches: false }, { trusted: false, verifyError: VERIFY.hostname }),
    ]);
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]!.evidence['affectedAddresses']).toEqual([IPV4, IPV6]);
  });

  it('resolves when all certificates match', () => {
    expect(run(tls002, [goodCert(IPV4), goodCert(IPV6)])).toEqual({
      findings: [],
      checked: checked443,
    });
  });

  it('does not resolve with a failed address or unknown match status', () => {
    expect(run(tls002, [goodCert(IPV4), failedTls(IPV6)]).checked).toEqual([]);
    expect(run(tls002, [goodCert(IPV4, { hostnameMatches: null })])).toEqual({
      findings: [],
      checked: [],
    });
  });
});

describe('TLS-003 expiry within 14 days', () => {
  it.each([
    [14, 'medium'],
    [13.5, 'medium'],
    [4, 'medium'],
    [3, 'high'],
    [0.2, 'high'],
    [0, 'high'],
  ] as const)('%s days remaining → %s', (days, severity) => {
    const out = run(tls003, [goodCert(IPV4, { notAfter: daysFromNow(days) })]);
    expect(out.findings[0]).toMatchObject({ component: '443', severity });
    expect(out.checked).toEqual([]);
  });

  it('does not raise beyond 14 days, and resolves', () => {
    const out = run(tls003, [goodCert(IPV4, { notAfter: daysFromNow(14.01) })]);
    expect(out).toEqual({ findings: [], checked: checked443 });
  });

  it('leaves already-expired certificates to TLS-001', () => {
    const out = run(tls003, [goodCert(IPV4, { notAfter: daysFromNow(-1) })]);
    expect(out).toEqual({ findings: [], checked: checked443 });
  });

  it('uses the soonest expiry across addresses (IPv6 included) and lists them', () => {
    const out = run(tls003, [
      goodCert(IPV4, { notAfter: daysFromNow(10) }),
      goodCert(IPV6, { notAfter: daysFromNow(2) }),
    ]);
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({
      severity: 'high',
      evidence: { daysRemaining: 2, affectedAddresses: [IPV6, IPV4] },
    });
  });

  it('insufficient evidence: no finding, not checked', () => {
    expect(run(tls003, [failedTls(IPV4, 'timeout')])).toEqual({ findings: [], checked: [] });
  });

  it('expirySeverity boundaries', () => {
    expect(expirySeverity(-0.001)).toBeNull();
    expect(expirySeverity(14.001)).toBeNull();
    expect(expirySeverity(3)).toBe('high');
    expect(expirySeverity(3.01)).toBe('medium');
  });
});

describe('TLS-004 weak TLS version', () => {
  it.each(['TLSv1', 'TLSv1.1', 'SSLv3'])('raises medium/medium-confidence for %s', (v) => {
    const out = run(tls004, [goodCert(IPV4, { protocolVersion: v })]);
    expect(out.findings[0]).toMatchObject({
      severity: 'medium',
      confidence: 'medium',
      evidence: { negotiatedVersions: [v], method: 'negotiated_version_only' },
    });
  });

  it('resolves for TLS 1.2 / 1.3 on every address', () => {
    expect(
      run(tls004, [
        goodCert(IPV4, { protocolVersion: 'TLSv1.2' }),
        goodCert(IPV6, { protocolVersion: 'TLSv1.3' }),
      ]),
    ).toEqual({ findings: [], checked: checked443 });
  });

  it('does not resolve on an unknown version string or a failed address', () => {
    expect(run(tls004, [goodCert(IPV4, { protocolVersion: 'QUIC?' })]).checked).toEqual([]);
    expect(run(tls004, [goodCert(IPV4), failedTls(IPV6)]).checked).toEqual([]);
  });
});

describe('TLS-005 untrusted chain', () => {
  it.each([VERIFY.selfSigned, VERIFY.unknownCa])('raises medium/high-confidence for "%s"', (e) => {
    const out = run(tls005, [certWith(IPV4, {}, { trusted: false, verifyError: e })]);
    expect(out.findings[0]).toMatchObject({
      severity: 'medium',
      confidence: 'high',
      evidence: { verifyErrors: [e] },
    });
  });

  it('medium confidence for an unrecognised verification message', () => {
    const out = run(tls005, [certWith(IPV4, {}, { trusted: false, verifyError: VERIFY.odd })]);
    expect(out.findings[0]?.confidence).toBe('medium');
  });

  it('does not raise for hostname-only or expiry-only verification failures', () => {
    const out = run(tls005, [
      certWith(IPV4, { hostnameMatches: false }, { trusted: false, verifyError: VERIFY.hostname }),
      certWith(IPV6, {}, { trusted: false, verifyError: VERIFY.expired }),
    ]);
    expect(out).toEqual({ findings: [], checked: checked443 });
  });

  it('insufficient: untrusted without a message, or a failed address', () => {
    expect(run(tls005, [certWith(IPV4, {}, { trusted: false })]).checked).toEqual([]);
    expect(run(tls005, [goodCert(IPV4), failedTls(IPV4_B)]).checked).toEqual([]);
  });

  it('classifies OpenSSL messages', () => {
    expect(classifyVerifyError(VERIFY.hostname)).toBe('hostname');
    expect(
      classifyVerifyError("IP address mismatch, certificate is not valid for '203.0.113.10'."),
    ).toBe('hostname');
    expect(classifyVerifyError(VERIFY.expired)).toBe('expired');
    expect(classifyVerifyError('certificate is not yet valid')).toBe('not_yet_valid');
    expect(classifyVerifyError('handshake_failed: WRONG_VERSION_NUMBER')).toBe('handshake');
    expect(classifyVerifyError(VERIFY.selfSigned)).toBe('chain');
  });
});

describe('TLS rules metadata', () => {
  it('declare the contract fields and references', () => {
    for (const r of tlsRules) {
      expect(r).toMatchObject({ version: 1, category: 'tls', requires: ['tls'] });
      expect(r.requiresChecks).toEqual(['tls_certificate', 'tls_configuration']);
      expect(r.detection.length).toBeGreaterThan(20);
      expect(r.resolution.length).toBeGreaterThan(20);
    }
    expect(tlsRules.map((r) => r.id)).toEqual([
      'TLS-001',
      'TLS-002',
      'TLS-003',
      'TLS-004',
      'TLS-005',
    ]);
  });

  it('advisories carry actions and references and never claim compromise', () => {
    const f = run(tls001, [goodCert(IPV4, { notAfter: daysFromNow(-1) })]).findings[0]!;
    for (const r of tlsRules) {
      const a = r.advisory(f, input().context);
      expect(a.recommendedActions.length).toBeGreaterThan(0);
      expect(a.references.length).toBeGreaterThan(0);
      expect(`${a.summary} ${a.businessImpact}`).not.toMatch(/compromised|was exploited|breach/i);
    }
  });
});

describe('TLS rules through the evaluator', () => {
  it('produces fingerprinted upserts and resolutions; skips without a TLS check or success', () => {
    const current = {
      tls: [
        goodCert(IPV4, { notAfter: daysFromNow(5) }),
        goodCert(IPV6, { notAfter: daysFromNow(5) }),
        goodCert(IPV4, { hostname: 'api.example.com', notAfter: daysFromNow(-2) }),
      ],
    };
    const res = evaluate(input(current, {}, { checks: ['tls_certificate'] }), tlsRules);
    expect(res.errors).toEqual([]);
    expect(res.upserts.map((u) => `${u.ruleId}:${u.hostname}`).sort()).toEqual([
      'TLS-001:api.example.com',
      'TLS-003:www.example.com',
    ]);
    const tls003Up = res.upserts.find((u) => u.ruleId === 'TLS-003')!;
    expect(tls003Up.fingerprint).toBe(fingerprint('TLS-003', 'domain-1', WWW, '443'));
    expect(tls003Up.riskInputs).toMatchObject({ severity: 'medium', exposure: 'web' });
    expect(res.resolutions.map((r) => `${r.ruleId}:${r.hostname}`)).toContain(
      'TLS-001:www.example.com',
    );

    expect(evaluate(input(current, {}, { checks: ['dns'] }), tlsRules).skipped).toHaveLength(5);
    const failed = evaluate(
      input({ tls: [failedTls(IPV4)] }, {}, { checks: ['tls_certificate'] }),
      tlsRules,
    );
    expect(failed).toMatchObject({ upserts: [], resolutions: [] });
    expect(failed.skipped).toHaveLength(5);
  });
});
