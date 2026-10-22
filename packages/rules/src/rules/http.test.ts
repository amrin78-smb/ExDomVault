import { describe, expect, it } from 'vitest';
import { evaluate, fingerprint } from '../evaluator.ts';
import { input } from '../fixtures/builders.ts';
import {
  ALL_HEADERS,
  HOST,
  httpsFailed,
  httpsOk,
  NO_HEADERS,
  plainOk,
  plainRedirectOutOfScope,
  plainRedirectToHttps,
} from '../fixtures/http-fixtures.ts';
import type { HttpObservation, Rule } from '../types.ts';
import {
  disclosesVersion,
  http001,
  http002,
  http003,
  http004,
  http005,
  httpRules,
  missingSecurityHeaders,
  parseUrl,
} from './http.ts';

const run = (rule: Rule, http: HttpObservation[]) =>
  rule.evaluate(input({ http }, {}, { checks: ['http_availability', 'http_headers'] }));

describe('parseUrl', () => {
  it('extracts scheme and lowercase host', () => {
    expect(parseUrl('https://WWW.Example.com/path')).toEqual({
      scheme: 'https',
      host: 'www.example.com',
    });
    expect(parseUrl('http://example.com:8080')).toEqual({ scheme: 'http', host: 'example.com' });
    expect(parseUrl('ftp://example.com/')).toBeNull();
    expect(parseUrl(null)).toBeNull();
  });
});

describe('HTTP-001 HTTPS not available', () => {
  it('raises medium/high when HTTPS times out and plain HTTP answers', () => {
    const out = run(http001, [httpsFailed(HOST, 'timeout'), plainOk()]);
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({
      hostname: HOST,
      component: 'https',
      severity: 'medium',
      confidence: 'high',
      exposure: 'web',
    });
    expect(out.checked).toEqual([]);
  });

  it('still raises when plain HTTP redirects out of scope (parked domain, partial observation)', () => {
    const out = run(http001, [
      httpsFailed('example.com', 'error'),
      plainRedirectOutOfScope('example.com'),
    ]);
    expect(out.findings[0]).toMatchObject({ hostname: 'example.com', component: 'https' });
  });

  it('no finding when neither scheme answered (not a web host)', () => {
    const plainFailed = { ...httpsFailed(), url: `http://${HOST}/`, finalUrl: `http://${HOST}/` };
    expect(run(http001, [httpsFailed(), plainFailed])).toEqual({ findings: [], checked: [] });
  });

  it('resolves when HTTPS answers (also when a later redirect was refused)', () => {
    expect(run(http001, [httpsOk()])).toEqual({
      findings: [],
      checked: [{ hostname: HOST, component: 'https' }],
    });
    const refused = httpsOk(HOST, { statusCode: 301 });
    expect(run(http001, [{ ...refused, resultStatus: 'partial' }]).checked).toHaveLength(1);
  });

  it('insufficient evidence: HTTPS failed and no plain-HTTP observation', () => {
    expect(run(http001, [httpsFailed()])).toEqual({ findings: [], checked: [] });
  });
});

describe('HTTP-002 HTTP does not redirect to HTTPS', () => {
  it('raises low when plain HTTP serves 200', () => {
    const out = run(http002, [httpsFailed(), plainOk()]);
    expect(out.findings[0]).toMatchObject({
      component: 'http-redirect',
      severity: 'low',
      confidence: 'high',
    });
  });

  it('raises when an in-domain redirect chain ends on plain HTTP 200', () => {
    const o = plainRedirectToHttps();
    const chain: HttpObservation = {
      ...o,
      finalUrl: 'http://example.com/home',
      evidence: {
        hops: [
          { url: `http://${HOST}/`, ip: '203.0.113.10', status: 302, decision: 'followed' },
          { url: 'http://example.com/home', ip: '203.0.113.10', status: 200, decision: 'final' },
        ],
      },
    };
    expect(run(http002, [chain]).findings).toHaveLength(1);
  });

  it('does not flag a redirect to HTTPS, and resolves', () => {
    expect(run(http002, [plainRedirectToHttps()])).toEqual({
      findings: [],
      checked: [{ hostname: HOST, component: 'http-redirect' }],
    });
  });

  it('does not flag a redirect to another domain (the host forwards elsewhere)', () => {
    expect(run(http002, [plainRedirectOutOfScope()])).toEqual({
      findings: [],
      checked: [{ hostname: HOST, component: 'http-redirect' }],
    });
  });

  it('insufficient evidence: plain HTTP without a response', () => {
    const failed = { ...httpsFailed(), url: `http://${HOST}/` };
    expect(run(http002, [failed])).toEqual({ findings: [], checked: [] });
  });
});

describe('HTTP-003 HSTS missing', () => {
  it('raises low when the final HTTPS response has no HSTS', () => {
    const out = run(http003, [
      httpsOk(HOST, { hstsEnabled: false }, { securityHeaders: NO_HEADERS }),
    ]);
    expect(out.findings[0]).toMatchObject({
      component: 'hsts',
      severity: 'low',
      evidence: { strictTransportSecurity: null },
    });
  });

  it('resolves when HSTS is enabled', () => {
    expect(run(http003, [httpsOk()])).toEqual({
      findings: [],
      checked: [{ hostname: HOST, component: 'hsts' }],
    });
  });

  it('skips hosts without HTTPS (HTTP-001 covers them) and partial/failed observations', () => {
    expect(run(http003, [httpsFailed(), plainOk()])).toEqual({ findings: [], checked: [] });
    const partial: HttpObservation = {
      ...httpsOk(HOST, { hstsEnabled: false }),
      resultStatus: 'partial',
    };
    expect(run(http003, [partial])).toEqual({ findings: [], checked: [] });
  });
});

describe('HTTP-004 missing security headers', () => {
  it('lists missing headers; low when framing protection is missing', () => {
    const out = run(http004, [httpsOk(HOST, {}, { securityHeaders: NO_HEADERS })]);
    expect(out.findings[0]).toMatchObject({
      component: 'headers',
      severity: 'low',
      evidence: {
        missing: [
          'content-security-policy',
          'x-content-type-options',
          'x-frame-options',
          'referrer-policy',
        ],
      },
    });
  });

  it('informational when only non-framing headers are missing', () => {
    const out = run(http004, [
      httpsOk(HOST, {}, { securityHeaders: { ...ALL_HEADERS, 'referrer-policy': null } }),
    ]);
    expect(out.findings[0]).toMatchObject({
      severity: 'informational',
      evidence: { missing: ['referrer-policy'] },
    });
  });

  it('accepts CSP frame-ancestors instead of X-Frame-Options; requires nosniff', () => {
    expect(
      missingSecurityHeaders({
        ...ALL_HEADERS,
        'x-frame-options': null,
        'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
      }),
    ).toEqual([]);
    expect(missingSecurityHeaders({ ...ALL_HEADERS, 'x-content-type-options': 'sniff' })).toEqual([
      'x-content-type-options',
    ]);
  });

  it('resolves when all headers are present', () => {
    expect(run(http004, [httpsOk(HOST, {}, {})])).toEqual({
      findings: [],
      checked: [{ hostname: HOST, component: 'headers' }],
    });
  });

  it('insufficient: headers not captured, non-200 final status, or failed observation', () => {
    expect(run(http004, [httpsOk()])).toEqual({ findings: [], checked: [] });
    expect(
      run(http004, [httpsOk(HOST, { statusCode: 404 }, { securityHeaders: NO_HEADERS })]),
    ).toEqual({ findings: [], checked: [] });
    expect(run(http004, [httpsFailed()])).toEqual({ findings: [], checked: [] });
  });
});

describe('HTTP-005 software version disclosure', () => {
  it('raises informational with the header values as evidence', () => {
    const out = run(http005, [
      httpsOk(HOST, {}, { server: 'Apache/2.4.41 (Ubuntu)', xPoweredBy: 'PHP/8.1.2' }),
    ]);
    expect(out.findings[0]).toMatchObject({
      component: 'version-disclosure',
      severity: 'informational',
      evidence: {
        responses: [{ server: 'Apache/2.4.41 (Ubuntu)', xPoweredBy: 'PHP/8.1.2' }],
      },
    });
    expect(out.findings[0]!.description).toMatch(/does not confirm that the version is vulnerable/);
  });

  it('raises from a partial observation (real response) but resolves only from success', () => {
    const partial: HttpObservation = {
      ...httpsOk(HOST, { statusCode: 301 }, { server: 'nginx/1.18.0' }),
      resultStatus: 'partial',
    };
    expect(run(http005, [partial]).findings).toHaveLength(1);
    const cleanPartial: HttpObservation = {
      ...httpsOk(HOST, {}, { server: 'nginx' }),
      resultStatus: 'partial',
    };
    expect(run(http005, [cleanPartial])).toEqual({ findings: [], checked: [] });
  });

  it('resolves when headers carry no version', () => {
    expect(
      run(http005, [httpsOk(HOST, {}, { server: 'cloudflare', xPoweredBy: 'ASP.NET' })]),
    ).toEqual({
      findings: [],
      checked: [{ hostname: HOST, component: 'version-disclosure' }],
    });
  });

  it('insufficient when http_headers did not capture the headers', () => {
    expect(run(http005, [httpsOk()])).toEqual({ findings: [], checked: [] });
  });

  it('version pattern', () => {
    expect(disclosesVersion('Microsoft-IIS/10.0')).toBe(true);
    expect(disclosesVersion('nginx')).toBe(false);
    expect(disclosesVersion('gws')).toBe(false);
    expect(disclosesVersion(null)).toBe(false);
  });
});

describe('HTTP rules metadata and advisories', () => {
  it('declare contract fields', () => {
    expect(httpRules.map((r) => r.id)).toEqual([
      'HTTP-001',
      'HTTP-002',
      'HTTP-003',
      'HTTP-004',
      'HTTP-005',
    ]);
    for (const r of httpRules) {
      expect(r).toMatchObject({ version: 1, category: 'http' });
      expect(r.requiresChecks.length).toBeGreaterThan(0);
    }
    expect(http004.requiresChecks).toEqual(['http_headers']);
    expect(http005.requiresChecks).toEqual(['http_headers']);
  });

  it('advisories have actions and references and no compromise claims', () => {
    const f = run(http004, [httpsOk(HOST, {}, { securityHeaders: NO_HEADERS })]).findings[0]!;
    for (const r of httpRules) {
      const a = r.advisory(f, input().context);
      expect(a.recommendedActions.length).toBeGreaterThan(0);
      expect(a.references.length).toBeGreaterThan(0);
      expect(`${a.summary} ${a.businessImpact}`).not.toMatch(/compromised|was exploited|breach/i);
    }
  });
});

describe('HTTP rules through the evaluator', () => {
  it('runs HTTP-001/002 without any successful observation (parked domain case)', () => {
    const res = evaluate(
      input(
        { http: [httpsFailed('example.com'), plainRedirectOutOfScope('example.com')] },
        {},
        { checks: ['http_availability'] },
      ),
      httpRules,
    );
    expect(res.errors).toEqual([]);
    expect(res.upserts.map((u) => u.ruleId)).toEqual(['HTTP-001']);
    expect(res.upserts[0]!.fingerprint).toBe(
      fingerprint('HTTP-001', 'domain-1', 'example.com', 'https'),
    );
    expect(res.resolutions.map((r) => r.ruleId)).toEqual(['HTTP-002']);
    expect(res.skipped).toEqual(['HTTP-003', 'HTTP-004', 'HTTP-005']);
  });

  it('a healthy HTTPS site resolves every rule it checked', () => {
    const res = evaluate(
      input({ http: [httpsOk(HOST, {}, { server: 'nginx' })] }, {}, { checks: ['http_headers'] }),
      httpRules,
    );
    expect(res.upserts).toEqual([]);
    expect(res.resolutions.map((r) => r.ruleId)).toEqual([
      'HTTP-001',
      'HTTP-003',
      'HTTP-004',
      'HTTP-005',
    ]);
  });
});
