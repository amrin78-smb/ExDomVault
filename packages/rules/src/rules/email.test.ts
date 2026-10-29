import { describe, expect, it } from 'vitest';
import { evaluate } from '../evaluator.ts';
import { APEX, dns, dnsFailed, input } from '../fixtures/builders.ts';
import { ruleById } from '../registry.ts';
import type { DnsRecordSetObservation } from '../types.ts';
import {
  analyseMtaSts,
  analyseTlsRpt,
  dkimKeys,
  dkimSelector,
  email001,
  email002,
  email003,
  email004,
  email005,
  rsaModulusBits,
} from './email.ts';

// Synthetic test keys generated for these tests only (never used anywhere).
const RSA_512 =
  'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALdhAEKlgksZ43BLCr9hcUXDPMgBB+cefuGqnKdE8Ykq/SCeHREz57qtDQFVbbWQACrZCk8Nc0EWjIOk3LAhJKUCAwEAAQ==';
const RSA_768_PKCS1 =
  'MGgCYQDBNK2rUlacvBqg9zgsEGWOieuLkaqqmg+kIQOWewAcsTqoe/FCZBZfcZ7Fn59MJssJ3noZXCmSYFF1HZueDHv5vosvnVnec5/6VF/DtoVS47iaq8Kh++J3jsCIJweLAskCAwEAAQ==';
const RSA_1024 =
  'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDK/Ioxhc3j1lX+3YMX9HDy3jk9skziLBcjHbxwpCdgLT+9zPHd0Yw/VgdIfzlljPuvFCrboc30Rz5YMN9jxeLozqQkjMba9wZWq1orwEp8dgcmUsd3al6CtfHcuutqJpinV15UqbFumEcU+W81l/nqoYcQWWr17Uwb9j+t1T72oQIDAQAB';
const RSA_2048 =
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3MihHVQxLIZ4ixkt8Gt4n/qTed4Xmo0jXxmHTP2Ukzr8M0uaqQwBdzLDOdWJh6fZ/aS52nD3Hx+QpEbRgsUIibyZNAGYRG9d5AZYnAXyTIUOaV5fJjb7l73WaLOLWL/1hc+QaO2zbfXMUIX0xyoPZ1drhkyf2mASJGcIphjGSP5BF0s4DRMihV/kXen1EQrDkn9OEoMam7xEEOOaqquR7OkOA0Gf2ni6MJiQbDSKCQ7KaGHm/ViTRl1RihOsO8rOUjwWWylZ+r5p3AnFuIs6gtMZzeVgKkzEH3fk6BaW7kW1BEL3aJQAWkEXPXoo9KrsatHzaWgSTZjUiKb36v7dOQIDAQAB';

const q = (s: string) => `"${s}"`;
/** TXT presentation format split into 255-character strings, as resolvers return long records. */
const txtValue = (s: string) => (s.match(/.{1,255}/g) ?? ['']).map(q).join(' ');
const MX = dns(APEX, 'MX', ['10 mx1.example.com.']);
const NULL_MX = dns(APEX, 'MX', ['0 .']);
const MTA_STS = `_mta-sts.${APEX}`;
const TLS_RPT = `_smtp._tls.${APEX}`;
const dkim = (selector: string, values: string[], opts = {}) =>
  dns(`${selector}._domainkey.${APEX}`, 'TXT', values, opts);
const dkimKey = (p: string, extra = 'v=DKIM1; k=rsa; ') => txtValue(`${extra}p=${p}`);

describe('parsers', () => {
  it('parses MTA-STS records per RFC 8461 §3.1', () => {
    expect(analyseMtaSts([q('v=STSv1; id=20261029T0000')]).problem).toBeNull();
    expect(analyseMtaSts([q('v=STSv1;id=abc;')]).problem).toBeNull();
    expect(analyseMtaSts([]).problem).toBe('missing');
    expect(analyseMtaSts([q('v=spf1 -all')]).problem).toBe('missing');
    expect(analyseMtaSts([q('v=STSv1; id=a'), q('v=STSv1; id=b')]).problem).toBe('multiple');
    expect(analyseMtaSts([q('v=STSv1;')]).problem).toBe('invalid_id');
    expect(analyseMtaSts([q('v=STSv1; id=has-dash')]).problem).toBe('invalid_id');
    expect(analyseMtaSts([q(`v=STSv1; id=${'a'.repeat(33)}`)]).problem).toBe('invalid_id');
  });

  it('parses TLS-RPT records per RFC 8460 §3', () => {
    expect(analyseTlsRpt([q('v=TLSRPTv1; rua=mailto:tls@example.com')]).problem).toBeNull();
    expect(
      analyseTlsRpt([q('v=TLSRPTv1;rua=mailto:a@example.com,https://r.example.net/v1')]).problem,
    ).toBeNull();
    expect(analyseTlsRpt([]).problem).toBe('missing');
    expect(analyseTlsRpt([q('v=TLSRPTv1;')]).problem).toBe('invalid_rua');
    expect(analyseTlsRpt([q('v=TLSRPTv1; rua=ftp://x')]).problem).toBe('invalid_rua');
    expect(
      analyseTlsRpt([q('v=TLSRPTv1; rua=mailto:a@x.test'), q('v=TLSRPTv1; rua=mailto:b@x.test')])
        .problem,
    ).toBe('multiple');
  });

  it('measures RSA modulus sizes (SPKI and PKCS#1)', () => {
    expect(rsaModulusBits(RSA_512)).toBe(512);
    expect(rsaModulusBits(RSA_768_PKCS1)).toBe(768);
    expect(rsaModulusBits(RSA_1024)).toBe(1024);
    expect(rsaModulusBits(RSA_2048)).toBe(2048);
    expect(rsaModulusBits('not base64!')).toBeNull();
    expect(rsaModulusBits('AAAA')).toBeNull();
  });

  it('recognises DKIM key records and selectors', () => {
    expect(dkimKeys([dkimKey(RSA_2048)])).toEqual([{ keyType: 'rsa', revoked: false, bits: 2048 }]);
    expect(dkimKeys([q('v=DKIM1; p=')])).toEqual([{ keyType: 'rsa', revoked: true, bits: null }]);
    expect(
      dkimKeys([q('v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=')]),
    ).toEqual([{ keyType: 'ed25519', revoked: false, bits: null }]);
    expect(dkimKeys([q('v=spf1 -all'), q('google-site-verification=abc')])).toEqual([]);
    expect(dkimSelector(`s1._domainkey.${APEX}`, APEX)).toBe('s1');
    expect(dkimSelector(`a.b._domainkey.${APEX}`, APEX)).toBeNull();
    expect(dkimSelector(`s1._domainkey.other.test`, APEX)).toBeNull();
  });
});

describe('EMAIL-001 no MTA-STS policy', () => {
  it('raises for a mail domain without a v=STSv1 record (NXDOMAIN)', () => {
    const out = email001.evaluate(
      input({ dns: [MX, dns(MTA_STS, 'TXT', [], { evidence: { rcode: 'NXDOMAIN' } })] }),
    );
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({
      hostname: APEX,
      component: 'mta-sts',
      severity: 'low',
      confidence: 'high',
      evidence: { queriedName: MTA_STS, policyFileChecked: false, mail: 'mail' },
    });
  });

  it('resolves when a record is published or the domain has no mail', () => {
    const ok = email001.evaluate(input({ dns: [MX, dns(MTA_STS, 'TXT', [q('v=STSv1; id=1')])] }));
    expect(ok).toEqual({ findings: [], checked: [{ hostname: APEX, component: 'mta-sts' }] });
    const parked = email001.evaluate(input({ dns: [NULL_MX] }));
    expect(parked).toEqual({ findings: [], checked: [{ hostname: APEX, component: 'mta-sts' }] });
    // A malformed record is EMAIL-002's concern, not "missing".
    const bad = email001.evaluate(input({ dns: [MX, dns(MTA_STS, 'TXT', [q('v=STSv1;')])] }));
    expect(bad.findings).toEqual([]);
  });

  it('neither raises nor resolves on failed or missing lookups', () => {
    const none = { findings: [], checked: [] };
    expect(email001.evaluate(input({ dns: [MX, dnsFailed(MTA_STS, 'TXT')] }))).toEqual(none);
    expect(email001.evaluate(input({ dns: [MX] }))).toEqual(none);
    expect(email001.evaluate(input({ dns: [dnsFailed(APEX, 'MX', 'timeout')] }))).toEqual(none);
  });
});

describe('EMAIL-002 malformed MTA-STS record', () => {
  it('raises for duplicate or invalid records', () => {
    const dup = email002.evaluate(
      input({ dns: [MX, dns(MTA_STS, 'TXT', [q('v=STSv1; id=a'), q('v=STSv1; id=b')])] }),
    );
    expect(dup.findings[0]).toMatchObject({ severity: 'low', evidence: { problem: 'multiple' } });
    const noId = email002.evaluate(input({ dns: [MX, dns(MTA_STS, 'TXT', [q('v=STSv1;')])] }));
    expect(noId.findings[0]?.evidence.problem).toBe('invalid_id');
  });

  it('resolves when the record is valid or absent', () => {
    for (const values of [[q('v=STSv1; id=2026')], []]) {
      const out = email002.evaluate(input({ dns: [MX, dns(MTA_STS, 'TXT', values)] }));
      expect(out).toEqual({
        findings: [],
        checked: [{ hostname: APEX, component: 'mta-sts-record' }],
      });
    }
  });
});

describe('EMAIL-003 no TLS-RPT', () => {
  it('raises (informational) for a mail domain without TLS-RPT', () => {
    const out = email003.evaluate(input({ dns: [MX, dns(TLS_RPT, 'TXT', [])] }));
    expect(out.findings[0]).toMatchObject({
      component: 'tls-rpt',
      severity: 'informational',
      evidence: { problem: 'missing' },
    });
  });

  it('resolves with a valid record and skips failed lookups', () => {
    const ok = email003.evaluate(
      input({ dns: [MX, dns(TLS_RPT, 'TXT', [q('v=TLSRPTv1; rua=mailto:tls@example.com')])] }),
    );
    expect(ok.checked).toEqual([{ hostname: APEX, component: 'tls-rpt' }]);
    const failed = email003.evaluate(input({ dns: [MX, dnsFailed(TLS_RPT, 'TXT')] }));
    expect(failed).toEqual({ findings: [], checked: [] });
  });
});

describe('EMAIL-004 no DKIM key at common selectors', () => {
  const empty = ['google', 'selector1', 's1'].map((s) =>
    dkim(s, [], { evidence: { rcode: 'NXDOMAIN' } }),
  );

  it('raises with low confidence when no queried selector has a key', () => {
    const out = email004.evaluate(input({ dns: [MX, ...empty] }));
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({
      component: 'dkim',
      severity: 'informational',
      confidence: 'low',
      evidence: { selectorsQueried: ['google', 's1', 'selector1'] },
    });
    expect(out.findings[0]!.description).toMatch(/cannot be listed/);
  });

  it('counts a key at any selector (including a CNAME-delegated one) and resolves', () => {
    const delegated = dkim('selector1', [dkimKey(RSA_2048)], {
      evidence: { rcode: 'NOERROR', canonicalName: 'selector1-example-com._domainkey.x.test' },
    });
    const out = email004.evaluate(input({ dns: [MX, ...empty.slice(0, 2), delegated] }));
    expect(out).toEqual({ findings: [], checked: [{ hostname: APEX, component: 'dkim' }] });
  });

  it('a revoked key alone does not count as DKIM in use', () => {
    const out = email004.evaluate(input({ dns: [MX, dkim('google', [q('v=DKIM1; p=')])] }));
    expect(out.findings).toHaveLength(1);
  });

  it('never decides on an incomplete selector sweep, and resolves for non-mail domains', () => {
    const partial = email004.evaluate(
      input({ dns: [MX, ...empty, dnsFailed(`k1._domainkey.${APEX}`, 'TXT', 'timeout')] }),
    );
    expect(partial).toEqual({ findings: [], checked: [] });
    expect(email004.evaluate(input({ dns: [MX] }))).toEqual({ findings: [], checked: [] });
    expect(email004.evaluate(input({ dns: [NULL_MX, ...empty] })).checked).toEqual([
      { hostname: APEX, component: 'dkim' },
    ]);
  });
});

describe('EMAIL-005 weak or revoked DKIM key', () => {
  it('raises medium for RSA keys under 1024 bits, one finding per selector', () => {
    const out = email005.evaluate(
      input({
        dns: [
          dkim('s1', [dkimKey(RSA_512)]),
          dkim('k1', [txtValue(`k=rsa; p=${RSA_768_PKCS1}`)]),
          dkim('google', [dkimKey(RSA_2048)]),
          dkim('selector1', [dkimKey(RSA_1024)]),
        ],
      }),
    );
    expect(out.findings.map((f) => [f.component, f.severity, f.evidence.keys])).toEqual([
      ['dkim:k1', 'medium', [{ keyType: 'rsa', revoked: false, bits: 768 }]],
      ['dkim:s1', 'medium', [{ keyType: 'rsa', revoked: false, bits: 512 }]],
    ]);
    expect(out.checked).toEqual([
      { hostname: APEX, component: 'dkim:google' },
      { hostname: APEX, component: 'dkim:selector1' },
    ]);
  });

  it('reports a revoked key as informational and resolves when the record is gone', () => {
    const revoked = email005.evaluate(input({ dns: [dkim('s2', [q('v=DKIM1; p=')])] }));
    expect(revoked.findings[0]).toMatchObject({ component: 'dkim:s2', severity: 'informational' });
    const gone = email005.evaluate(input({ dns: [dkim('s2', [])] }));
    expect(gone).toEqual({ findings: [], checked: [{ hostname: APEX, component: 'dkim:s2' }] });
  });

  it('neither raises nor resolves on failed lookups or unparseable keys', () => {
    const out = email005.evaluate(
      input({ dns: [dnsFailed(`s1._domainkey.${APEX}`, 'TXT'), dkim('s2', [q('p=%%%')])] }),
    );
    expect(out).toEqual({ findings: [], checked: [] });
  });
});

describe('registry and evaluator integration', () => {
  it('registers the e-mail rules with deterministic metadata', () => {
    for (const id of ['EMAIL-001', 'EMAIL-002', 'EMAIL-003', 'EMAIL-004', 'EMAIL-005']) {
      expect(ruleById(id)?.category).toBe('email');
    }
  });

  it('a failed job-level MX lookup never resolves active e-mail findings', () => {
    const dnsObs: DnsRecordSetObservation[] = [
      dnsFailed(APEX, 'MX'),
      dns(APEX, 'A', ['192.0.2.10']),
    ];
    const result = evaluate(input({ dns: dnsObs }), [email001, email003, email004]);
    expect(result.resolutions).toEqual([]);
    expect(result.upserts).toEqual([]);
  });
});
