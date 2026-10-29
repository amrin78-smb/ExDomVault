import { describe, expect, it } from 'vitest';
import { evaluate, fingerprint } from '../evaluator.ts';
import { APEX, asPrevious, context, dns, dnsFailed, http, input } from '../fixtures/builders.ts';
import type { DnsRecordSetObservation } from '../types.ts';
import {
  analyseSpf,
  decodeTxt,
  dns001,
  dns002,
  dns003,
  dns004,
  dns005,
  dns006,
  dns007,
  dns008,
  dnsRules,
  isWithinDomain,
  takeoverProneService,
} from './dns.ts';

const DMARC = `_dmarc.${APEX}`;
const ns = (names: string[]) => dns(APEX, 'NS', names);
const soa = (mname: string) =>
  dns(APEX, 'SOA', [`${mname} hostmaster.${APEX}. 2026102201 7200 3600 1209600 300`]);
const txt = (host: string, values: string[]) => dns(host, 'TXT', values);
const q = (s: string) => `"${s}"`;
const apexMx = (values: string[]) => dns(APEX, 'MX', values);

describe('helpers', () => {
  it('decodes TXT presentation format', () => {
    expect(decodeTxt('"v=spf1 include:_spf.example.net" " -all"')).toBe(
      'v=spf1 include:_spf.example.net -all',
    );
    expect(decodeTxt('"a\\"b\\\\c\\059d"')).toBe('a"b\\c;d');
    expect(decodeTxt('v=DMARC1; p=reject')).toBe('v=DMARC1; p=reject');
    expect(decodeTxt('"caf\\195\\169"')).toBe('café');
    expect(decodeTxt('"bad\\255byte"')).toBe('bad\u00ffbyte');
  });

  it('matches domains on exact label boundaries', () => {
    expect(isWithinDomain('www.example.com.', 'example.com')).toBe(true);
    expect(isWithinDomain('EXAMPLE.COM', 'example.com')).toBe(true);
    expect(isWithinDomain('notexample.com', 'example.com')).toBe(false);
    expect(isWithinDomain('example.com.evil.test', 'example.com')).toBe(false);
  });

  it('recognises takeover-prone services by label suffix only', () => {
    expect(takeoverProneService('old-site.azurewebsites.net.')).toBe('azurewebsites.net');
    expect(takeoverProneService('bucket.s3-website-eu-west-1.amazonaws.com')).toBe(
      'amazonaws.com (S3)',
    );
    expect(takeoverProneService('notgithub.io')).toBeNull();
    expect(takeoverProneService('cdn.example.net')).toBeNull();
  });
});

describe('DNS-001 unexpected authoritative DNS change', () => {
  const prevNs = asPrevious([
    ns(['ns1.provider-a.test.', 'ns2.provider-a.test.']),
    soa('ns1.provider-a.test.'),
  ]);

  it('raises with old and new values when the NS set changes', () => {
    const out = dns001.evaluate(
      input(
        {
          dns: [ns(['ns1.provider-b.test.', 'ns2.provider-b.test.']), soa('ns1.provider-b.test.')],
        },
        { dns: prevNs },
      ),
    );
    expect(out.checked).toEqual([]);
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({
      hostname: APEX,
      component: 'ns',
      severity: 'medium',
      confidence: 'high',
      evidence: {
        ns: {
          previous: ['ns1.provider-a.test', 'ns2.provider-a.test'],
          current: ['ns1.provider-b.test', 'ns2.provider-b.test'],
          changed: true,
        },
        soaPrimary: {
          previous: 'ns1.provider-a.test',
          current: 'ns1.provider-b.test',
          changed: true,
        },
      },
    });
    expect(out.findings[0]!.description).not.toMatch(/compromised|attack/i);
  });

  it('raises when only the SOA primary changes', () => {
    const out = dns001.evaluate(
      input(
        {
          dns: [ns(['ns1.provider-a.test.', 'ns2.provider-a.test.']), soa('ns9.provider-a.test.')],
        },
        { dns: prevNs },
      ),
    );
    expect(out.findings[0]?.evidence).toMatchObject({
      ns: { changed: false },
      soaPrimary: { changed: true },
    });
  });

  it('ignores case, ordering and SOA serial changes', () => {
    const out = dns001.evaluate(
      input(
        {
          dns: [
            ns(['NS2.provider-a.test.', 'ns1.provider-a.test.']),
            dns(APEX, 'SOA', [
              `ns1.provider-a.test. hostmaster.${APEX}. 2026102299 7200 3600 1209600 300`,
            ]),
          ],
        },
        { dns: prevNs },
      ),
    );
    expect(out).toEqual({ findings: [], checked: [] });
  });

  it('needs successful current and previous NS (first scan, failures)', () => {
    const changed = [ns(['ns1.provider-b.test.'])];
    expect(dns001.evaluate(input({ dns: changed })).findings).toEqual([]);
    expect(
      dns001.evaluate(input({ dns: [dnsFailed(APEX, 'NS', 'timeout')] }, { dns: prevNs })),
    ).toEqual({
      findings: [],
      checked: [],
    });
    expect(
      dns001.evaluate(input({ dns: changed }, { dns: asPrevious([dnsFailed(APEX, 'NS')]) })),
    ).toEqual({
      findings: [],
      checked: [],
    });
  });

  it('never auto-resolves (unchanged evidence lists nothing as checked)', () => {
    const same = dns001.evaluate(
      input({ dns: [ns(['ns1.provider-a.test.', 'ns2.provider-a.test.'])] }, { dns: prevNs }),
    );
    expect(same.checked).toEqual([]);
  });
});

describe('DNS-002 potential dangling CNAME', () => {
  const host = `shop.${APEX}`;
  const nx = { rcode: 'NXDOMAIN' };
  const dangling = (target: string, extra: DnsRecordSetObservation[] = []) => [
    dns(host, 'CNAME', [target]),
    dns(host, 'A', [], { evidence: nx }),
    dns(host, 'AAAA', [], { evidence: nx }),
    ...extra,
  ];

  it('raises for a takeover-prone target with no address', () => {
    const out = dns002.evaluate(input({ dns: dangling('old-shop.azurewebsites.net.') }));
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({
      hostname: host,
      component: 'cname',
      severity: 'medium',
      confidence: 'medium',
      exposure: 'web',
      evidence: {
        takeoverProneService: 'azurewebsites.net',
        finalTarget: 'old-shop.azurewebsites.net',
      },
    });
    expect(out.findings[0]!.description).toMatch(/requires validation/);
    expect(out.checked).toEqual([]);
  });

  it('uses low confidence for a generic external target with NODATA', () => {
    const out = dns002.evaluate(
      input({
        dns: [dns(host, 'CNAME', ['shop.vendor.test.']), dns(host, 'A', []), dns(host, 'AAAA', [])],
      }),
    );
    expect(out.findings[0]).toMatchObject({
      confidence: 'low',
      evidence: { takeoverProneService: null },
    });
  });

  it('does not raise when the alias still resolves (resolved condition is checked)', () => {
    const out = dns002.evaluate(
      input({
        dns: [
          dns(host, 'CNAME', ['shop.azurewebsites.net.']),
          dns(host, 'A', ['203.0.113.7']),
          dns(host, 'AAAA', []),
        ],
      }),
    );
    expect(out).toEqual({ findings: [], checked: [{ hostname: host, component: 'cname' }] });
  });

  it('does not raise for in-domain targets', () => {
    const out = dns002.evaluate(input({ dns: dangling(`gone.${APEX}.`) }));
    expect(out).toEqual({ findings: [], checked: [{ hostname: host, component: 'cname' }] });
  });

  it('follows an in-domain CNAME chain to an external target', () => {
    const out = dns002.evaluate(
      input({
        dns: dangling(`edge.${APEX}.`, [dns(`edge.${APEX}`, 'CNAME', ['site.herokuapp.com.'])]),
      }),
    );
    expect(out.findings[0]?.evidence).toMatchObject({
      cnameChain: [`edge.${APEX}`, 'site.herokuapp.com'],
      takeoverProneService: 'herokuapp.com',
    });
  });

  it('survives CNAME loops', () => {
    const out = dns002.evaluate(
      input({
        dns: dangling(`a.${APEX}.`, [
          dns(`a.${APEX}`, 'CNAME', [`b.${APEX}.`]),
          dns(`b.${APEX}`, 'CNAME', [`a.${APEX}.`]),
        ]),
      }),
    );
    expect(out.findings).toEqual([]);
  });

  it('a hostname without CNAME is checked (resolves a removed alias)', () => {
    const out = dns002.evaluate(
      input({ dns: [dns(host, 'CNAME', []), dns(host, 'A', ['203.0.113.7'])] }),
    );
    expect(out.checked).toEqual([{ hostname: host, component: 'cname' }]);
  });

  it('insufficient evidence: failed A/AAAA or failed CNAME neither raise nor resolve', () => {
    const failedA = [
      dns(host, 'CNAME', ['x.github.io.']),
      dnsFailed(host, 'A'),
      dns(host, 'AAAA', []),
    ];
    expect(dns002.evaluate(input({ dns: failedA }))).toEqual({ findings: [], checked: [] });
    const missingAaaa = [dns(host, 'CNAME', ['x.github.io.']), dns(host, 'A', [])];
    expect(dns002.evaluate(input({ dns: missingAaaa }))).toEqual({ findings: [], checked: [] });
    const failedCname = [
      dnsFailed(host, 'CNAME', 'timeout'),
      dns(host, 'A', []),
      dns(host, 'AAAA', []),
    ];
    expect(dns002.evaluate(input({ dns: failedCname }))).toEqual({ findings: [], checked: [] });
  });
});

describe('DNS-003 missing DMARC policy', () => {
  it('raises when no DMARC record exists (NXDOMAIN)', () => {
    const out = dns003.evaluate(
      input({
        dns: [
          dns(DMARC, 'TXT', [], { evidence: { rcode: 'NXDOMAIN' } }),
          apexMx([`10 mx.${APEX}.`]),
        ],
      }),
    );
    expect(out.findings[0]).toMatchObject({
      hostname: APEX,
      component: 'dmarc',
      severity: 'medium',
      confidence: 'high',
      evidence: { problem: 'missing', mail: 'mail' },
    });
    expect(out.findings[0]!.description).toMatch(/not evidence/);
  });

  it('ignores unrelated TXT at _dmarc and flags multiple / policy-less records', () => {
    expect(
      dns003.evaluate(input({ dns: [txt(DMARC, [q('google-site-verification=abc')])] })).findings[0]
        ?.evidence,
    ).toMatchObject({ problem: 'missing' });
    expect(
      dns003.evaluate(
        input({ dns: [txt(DMARC, [q('v=DMARC1; p=reject'), q('v=DMARC1; p=none')])] }),
      ).findings[0]?.evidence,
    ).toMatchObject({ problem: 'multiple' });
    expect(
      dns003.evaluate(input({ dns: [txt(DMARC, [q('v=DMARC1; rua=mailto:d@example.com')])] }))
        .findings[0]?.evidence,
    ).toMatchObject({ problem: 'invalid_policy' });
    expect(
      dns003.evaluate(input({ dns: [txt(DMARC, [q('v=DMARC1; p=block')])] })).findings,
    ).toHaveLength(1);
  });

  it('accepts uppercase, spacing and multi-string records (resolution: checked)', () => {
    for (const value of [
      q('v=DMARC1; p=reject; rua=mailto:d@example.com'),
      q(' V = dmarc1 ;  P = Quarantine '),
      '"v=DMARC1; " "p=reject"',
      'v=DMARC1;p=none',
    ]) {
      expect(dns003.evaluate(input({ dns: [txt(DMARC, [value])] }))).toEqual({
        findings: [],
        checked: [{ hostname: APEX, component: 'dmarc' }],
      });
    }
  });

  it('insufficient evidence: failed or missing _dmarc lookup', () => {
    expect(dns003.evaluate(input({ dns: [dnsFailed(DMARC, 'TXT', 'timeout')] }))).toEqual({
      findings: [],
      checked: [],
    });
    expect(dns003.evaluate(input({ dns: [txt(APEX, [])] }))).toEqual({ findings: [], checked: [] });
  });

  it('tailors the advisory for parked domains (no MX / null MX)', () => {
    for (const mx of [[], ['0 .']]) {
      const out = dns003.evaluate(input({ dns: [txt(DMARC, []), apexMx(mx)] }));
      const finding = out.findings[0]!;
      expect(finding.evidence.mail).toBe('no_mail');
      const advisory = dns003.advisory(finding, context());
      expect(advisory.recommendedActions.join(' ')).toMatch(/p=reject.*null MX.*v=spf1 -all/s);
      expect(advisory.references.some((r) => r.includes('m3aawg'))).toBe(true);
    }
  });
});

describe('DNS-007 monitoring-only DMARC policy', () => {
  it('raises low for p=none', () => {
    const out = dns007.evaluate(
      input({ dns: [txt(DMARC, [q('v=DMARC1; p=none; rua=mailto:d@example.com')])] }),
    );
    expect(out.findings[0]).toMatchObject({
      component: 'dmarc',
      severity: 'low',
      evidence: { policy: 'none', reportingConfigured: true },
    });
  });

  it('is checked for enforced, missing or duplicate policies (DNS-003 covers the latter)', () => {
    for (const values of [
      [q('v=DMARC1; p=reject')],
      [],
      [q('v=DMARC1; p=none'), q('v=DMARC1; p=none')],
    ]) {
      expect(dns007.evaluate(input({ dns: [txt(DMARC, values)] }))).toEqual({
        findings: [],
        checked: [{ hostname: APEX, component: 'dmarc' }],
      });
    }
  });

  it('insufficient evidence: failed lookup', () => {
    expect(dns007.evaluate(input({ dns: [dnsFailed(DMARC, 'TXT')] }))).toEqual({
      findings: [],
      checked: [],
    });
  });
});

describe('DNS-004 SPF configuration', () => {
  const spf = (...values: string[]) => [txt(APEX, values), apexMx([`10 mx.${APEX}.`])];
  const issues = (values: string[]) =>
    (
      dns004.evaluate(input({ dns: spf(...values) })).findings[0]?.evidence.issues as
        { code: string }[] | undefined
    )?.map((i) => i.code) ?? [];

  it('accepts a well-formed record (checked)', () => {
    expect(
      dns004.evaluate(
        input({ dns: spf(q('v=spf1 ip4:192.0.2.0/24 include:_spf.example.net -all')) }),
      ),
    ).toEqual({
      findings: [],
      checked: [{ hostname: APEX, component: 'spf' }],
    });
    expect(issues([q('v=spf1 redirect=_spf.example.net')])).toEqual([]);
    expect(issues(['"v=spf1 ip6:2001:db8::/32 " "mx ~all"'])).toEqual([]);
  });

  it('flags +all as high and ?all / no all as low', () => {
    const plus = dns004.evaluate(input({ dns: spf(q('v=spf1 +all')) })).findings[0];
    expect(plus).toMatchObject({ severity: 'high', component: 'spf' });
    expect(issues([q('v=spf1 all')])).toEqual(['pass_all']);
    expect(issues([q('v=spf1 mx ?all')])).toEqual(['neutral_all']);
    expect(dns004.evaluate(input({ dns: spf(q('v=spf1 mx')) })).findings[0]?.severity).toBe('low');
  });

  it('flags multiple SPF records (permerror)', () => {
    const out = dns004.evaluate(
      input({ dns: spf(q('v=spf1 -all'), q('v=spf1 mx -all'), q('unrelated')) }),
    );
    expect(out.findings[0]).toMatchObject({
      severity: 'medium',
      evidence: { issues: [{ code: 'multiple_records' }] },
    });
  });

  it('flags syntax errors and ptr', () => {
    expect(issues([q('v=spf1 ip4:300.1.1.1 -all')])).toEqual(['syntax_error']);
    expect(issues([q('v=spf1 include -all')])).toEqual(['syntax_error']);
    expect(issues([q('v=spf1 inclde:x.test -all')])).toEqual(['syntax_error']);
    expect(issues([q('v=spf1 ptr -all')])).toEqual(['ptr_mechanism']);
  });

  it('counts top-level DNS-querying terms (limit 10, redirect counts)', () => {
    const includes = Array.from({ length: 10 }, (_, i) => `include:s${i}.example.net`).join(' ');
    expect(issues([q(`v=spf1 ${includes} -all`)])).toEqual([]);
    expect(issues([q(`v=spf1 ${includes} redirect=_spf.example.net`)])).toEqual([
      'too_many_lookups',
    ]);
    expect(analyseSpf(`v=spf1 ${includes} mx a -all`).lookupTerms).toBe(12);
  });

  it('missing SPF is low only when the domain has MX; checked otherwise', () => {
    const withMx = dns004.evaluate(
      input({ dns: [txt(APEX, [q('google-site-verification=x')]), apexMx([`10 mx.${APEX}.`])] }),
    );
    expect(withMx.findings[0]).toMatchObject({
      severity: 'low',
      evidence: { issues: [{ code: 'missing_with_mx' }] },
    });
    const noMx = dns004.evaluate(input({ dns: [txt(APEX, []), apexMx(['0 .'])] }));
    expect(noMx).toEqual({ findings: [], checked: [{ hostname: APEX, component: 'spf' }] });
  });

  it('insufficient evidence: failed TXT, or missing SPF with failed MX', () => {
    expect(
      dns004.evaluate(input({ dns: [dnsFailed(APEX, 'TXT'), apexMx([`10 mx.${APEX}.`])] })),
    ).toEqual({
      findings: [],
      checked: [],
    });
    expect(
      dns004.evaluate(input({ dns: [txt(APEX, []), dnsFailed(APEX, 'MX', 'timeout')] })),
    ).toEqual({
      findings: [],
      checked: [],
    });
    // A partial (truncated) observation is not success either.
    expect(
      dns004.evaluate(
        input({ dns: [dns(APEX, 'TXT', [q('v=spf1 +all')], { status: 'partial' })] }),
      ),
    ).toEqual({
      findings: [],
      checked: [],
    });
  });

  it('advisory lists concrete actions for the issues found', () => {
    const finding = dns004.evaluate(input({ dns: spf(q('v=spf1 +all'), q('v=spf1 -all')) }))
      .findings[0]!;
    const advisory = dns004.advisory(finding, context());
    expect(advisory.recommendedActions[0]).toMatch(/single TXT record/);
    expect(advisory.references).toContain('https://www.rfc-editor.org/rfc/rfc7208');
  });
});

describe('DNS-005 DNSSEC / DNS-006 CAA', () => {
  it('DNS-005 raises when DS is absent and notes signed zones without DS', () => {
    const out = dns005.evaluate(
      input({ dns: [dns(APEX, 'DS', []), dns(APEX, 'DNSKEY', ['257 3 13 AAAA'])] }),
    );
    expect(out.findings[0]).toMatchObject({
      component: 'dnssec',
      severity: 'low',
      evidence: { dnskeyPresent: true },
    });
    expect(dns005.advisory(out.findings[0]!, context()).recommendedActions[0]).toMatch(
      /publish the DS/,
    );
  });

  it('DNS-005 resolves with a DS record and skips failed lookups', () => {
    expect(dns005.evaluate(input({ dns: [dns(APEX, 'DS', ['12345 13 2 ABCDEF'])] }))).toEqual({
      findings: [],
      checked: [{ hostname: APEX, component: 'dnssec' }],
    });
    expect(dns005.evaluate(input({ dns: [dnsFailed(APEX, 'DS')] }))).toEqual({
      findings: [],
      checked: [],
    });
  });

  it('DNS-006 raises (informational) without CAA, resolves with CAA, skips failures', () => {
    expect(dns006.evaluate(input({ dns: [dns(APEX, 'CAA', [])] })).findings[0]).toMatchObject({
      component: 'caa',
      severity: 'informational',
    });
    expect(
      dns006.evaluate(input({ dns: [dns(APEX, 'CAA', ['0 issue "ca.example.net"'])] })).checked,
    ).toEqual([{ hostname: APEX, component: 'caa' }]);
    expect(dns006.evaluate(input({ dns: [dnsFailed(APEX, 'CAA', 'timeout')] }))).toEqual({
      findings: [],
      checked: [],
    });
  });
});

describe('DNS rules through the evaluator', () => {
  const apexRecords = [
    ns(['ns1.provider-a.test.', 'ns2.provider-a.test.']),
    soa('ns1.provider-a.test.'),
    apexMx([`10 mx.${APEX}.`]),
    txt(APEX, [q('v=spf1 mx -all')]),
    dns(APEX, 'CAA', ['0 issue "ca.example.net"']),
    dns(APEX, 'DS', ['12345 13 2 ABCDEF']),
  ];

  it('a well-configured domain raises nothing and resolves every checked component', () => {
    const res = evaluate(
      input({ dns: [...apexRecords, txt(DMARC, [q('v=DMARC1; p=reject')])] }),
      dnsRules,
    );
    expect(res.upserts).toEqual([]);
    expect(res.errors).toEqual([]);
    expect(res.resolutions.map((r) => `${r.ruleId}:${r.component}`).sort()).toEqual([
      'DNS-003:dmarc',
      'DNS-004:spf',
      'DNS-005:dnssec',
      'DNS-006:caa',
      'DNS-007:dmarc',
    ]);
  });

  it('missing DMARC becomes a fingerprinted, risk-scored upsert with an advisory', () => {
    const res = evaluate(input({ dns: [...apexRecords, txt(DMARC, [])] }), dnsRules);
    expect(res.upserts).toHaveLength(1);
    expect(res.upserts[0]).toMatchObject({
      ruleId: 'DNS-003',
      ruleVersion: 1,
      fingerprint: fingerprint('DNS-003', 'domain-1', APEX, 'dmarc'),
      riskScore: 40,
      advisory: { title: `Publish a DMARC policy for ${APEX}` },
    });
  });

  it('all-failed DNS evidence skips every rule', () => {
    const res = evaluate(
      input({ dns: [dnsFailed(APEX, 'NS'), dnsFailed(DMARC, 'TXT')] }),
      dnsRules,
    );
    expect(res.skipped).toEqual(dnsRules.map((r) => r.id));
    expect(res.upserts).toEqual([]);
    expect(res.resolutions).toEqual([]);
  });

  it('rule metadata is complete and ids are unique', () => {
    expect(new Set(dnsRules.map((r) => r.id)).size).toBe(dnsRules.length);
    for (const r of dnsRules) {
      expect(r.version).toBeGreaterThanOrEqual(1);
      expect(r.requiresChecks).toEqual(['dns']);
      expect(r.evidenceRequirements && r.detection && r.resolution).toBeTruthy();
    }
  });
});

describe('DNS-008 subdomain takeover risk confirmed by provider response', () => {
  const host = `shop.${APEX}`;
  const nx = (canonicalName?: string) => ({
    rcode: 'NXDOMAIN',
    ...(canonicalName ? { canonicalName } : {}),
  });
  const aliased = (target: string, a: DnsRecordSetObservation, aaaa: DnsRecordSetObservation) => [
    dns(host, 'CNAME', [`${target}.`]),
    a,
    aaaa,
  ];
  const nxChain = (target: string) =>
    aliased(
      target,
      dns(host, 'A', [], { evidence: nx(target) }),
      dns(host, 'AAAA', [], { evidence: nx(target) }),
    );
  const resolving = (target: string) =>
    aliased(
      target,
      dns(host, 'A', ['192.0.2.50'], { evidence: { rcode: 'NOERROR', canonicalName: target } }),
      dns(host, 'AAAA', [], { evidence: { rcode: 'NOERROR', noData: true } }),
    );
  const signature = (provider: string, h = host, statusCode = 404) =>
    http(
      { url: `https://${h}/`, finalUrl: `https://${h}/`, statusCode },
      { evidence: { hops: [], takeoverSignature: { provider, signature: 'unclaimed' } } },
    );
  const plainHttp = (h = host) => http({ url: `https://${h}/`, finalUrl: `https://${h}/` });
  const checkedTakeover = [{ hostname: host, component: 'takeover' }];

  it('raises (medium confidence) for an NXDOMAIN chain at a provider that releases names', () => {
    const out = dns008.evaluate(input({ dns: nxChain('old-shop.azurewebsites.net') }));
    expect(out.checked).toEqual([]);
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({
      hostname: host,
      component: 'takeover',
      severity: 'high',
      confidence: 'medium',
      exposure: 'web',
      evidence: {
        provider: 'azure',
        evidenceTypes: ['dns_nxdomain'],
        cnameChain: ['old-shop.azurewebsites.net'],
        httpSignature: null,
      },
    });
    expect(out.findings[0]!.description).toMatch(/No takeover was attempted/);
  });

  it('records the chain end from the NXDOMAIN canonical name for multi-hop chains', () => {
    const out = dns008.evaluate(
      input({
        dns: aliased(
          'shop.cdn-partner.test',
          dns(host, 'A', [], { evidence: nx('legacy.cloudapp.net') }),
          dns(host, 'AAAA', [], { evidence: nx('legacy.cloudapp.net') }),
        ),
      }),
    );
    expect(out.findings[0]?.evidence.cnameChain).toEqual([
      'shop.cdn-partner.test',
      'legacy.cloudapp.net',
    ]);
  });

  it('does not raise for NXDOMAIN at providers whose names cannot simply be re-registered', () => {
    const out = dns008.evaluate(input({ dns: nxChain('abc123.herokudns.com') }));
    expect(out.findings).toEqual([]);
  });

  it('resolves when the provider name exists again (DNS-only provider)', () => {
    const out = dns008.evaluate(input({ dns: resolving('shop.azurewebsites.net') }));
    expect(out).toEqual({ findings: [], checked: checkedTakeover });
  });

  it('raises with high confidence on a matching HTTP signature for the CNAME provider', () => {
    const out = dns008.evaluate(
      input(
        { dns: resolving('example-org.github.io'), http: [signature('github_pages')] },
        {},
        { checks: ['dns', 'http_availability'] },
      ),
    );
    expect(out.findings[0]).toMatchObject({
      confidence: 'high',
      severity: 'high',
      evidence: {
        provider: 'github_pages',
        evidenceTypes: ['http_signature'],
        httpSignature: { key: 'github_pages', statusCode: 404 },
      },
    });
  });

  it('ignores a signature from a different provider than the CNAME target', () => {
    const out = dns008.evaluate(
      input({ dns: resolving('my-app.herokuapp.com'), http: [signature('github_pages')] }),
    );
    expect(out).toEqual({ findings: [], checked: checkedTakeover });
  });

  it('accepts a signature without a CNAME only for providers used via A records (medium)', () => {
    const noCname = [dns(host, 'CNAME', []), dns(host, 'A', ['192.0.2.153'])];
    const gh = dns008.evaluate(input({ dns: noCname, http: [signature('github_pages')] }));
    expect(gh.findings[0]).toMatchObject({ confidence: 'medium', evidence: { cnameChain: [] } });
    const heroku = dns008.evaluate(input({ dns: noCname, http: [signature('heroku')] }));
    expect(heroku).toEqual({ findings: [], checked: checkedTakeover });
  });

  it('ignores unknown provider keys and signatures for other hosts', () => {
    const out = dns008.evaluate(
      input({
        dns: [dns(host, 'CNAME', [])],
        http: [signature('made_up'), signature('github_pages', `www.${APEX}`), plainHttp()],
      }),
    );
    expect(out.findings).toEqual([]);
  });

  it('never resolves on incomplete evidence', () => {
    const none = { findings: [], checked: [] };
    // HTTP-confirmable provider, no HTTP response in this job (e.g. a passive scan).
    expect(dns008.evaluate(input({ dns: resolving('example-org.github.io') }))).toEqual(none);
    // A/AAAA failed.
    expect(
      dns008.evaluate(
        input({
          dns: aliased('x.azurewebsites.net', dnsFailed(host, 'A'), dnsFailed(host, 'AAAA')),
        }),
      ),
    ).toEqual(none);
    // CNAME lookup failed.
    expect(
      dns008.evaluate(input({ dns: [dnsFailed(host, 'CNAME')], http: [plainHttp()] })),
    ).toEqual(none);
    // No CNAME, but the HTTP attempt got no response.
    expect(
      dns008.evaluate(
        input({
          dns: [dns(host, 'CNAME', [])],
          http: [http({ url: `https://${host}/`, statusCode: null }, { status: 'error' })],
        }),
      ),
    ).toEqual(none);
  });

  it('a host without CNAME and with a clean HTTP response is checked (resolves)', () => {
    const out = dns008.evaluate(input({ dns: [dns(host, 'CNAME', [])], http: [plainHttp()] }));
    expect(out).toEqual({ findings: [], checked: checkedTakeover });
  });

  it('is registered and keeps DNS-002 as the independent weaker signal', () => {
    expect(dnsRules.map((r) => r.id)).toContain('DNS-008');
    const both = dnsRules
      .filter((r) => r.id === 'DNS-002' || r.id === 'DNS-008')
      .map(
        (r) => r.evaluate(input({ dns: nxChain('old-shop.azurewebsites.net') })).findings.length,
      );
    expect(both).toEqual([1, 1]);
  });
});
