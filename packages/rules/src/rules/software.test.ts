import { describe, expect, it } from 'vitest';
import { evaluate } from '../evaluator.ts';
import { http, input, port } from '../fixtures/builders.ts';
import { ruleById } from '../registry.ts';
import type {
  EvaluationInput,
  HttpObservation,
  PortObservation,
  Rule,
  SoftwareIntel,
} from '../types.ts';
import { soft001, soft002, softwareRules } from './software.ts';

const CHECKS = ['http_availability', 'http_headers', 'tcp_ports', 'service_identification'];

const INTEL: SoftwareIntel = {
  asOf: '2026-10-21T00:00:00.000Z',
  eolCycles: [
    { product: 'php', cycle: '7.4', eolDate: '2022-11-28', eolBoolean: null, latest: '7.4.33' },
    { product: 'php', cycle: '8.3', eolDate: '2027-12-31', eolBoolean: null, latest: '8.3.12' },
    // EOL 2026-03-01: less than a year before NOW (2026-10-22).
    { product: 'php', cycle: '8.1', eolDate: '2026-03-01', eolBoolean: null, latest: '8.1.31' },
    { product: 'nginx', cycle: '1.18', eolDate: null, eolBoolean: true, latest: '1.18.0' },
    { product: 'nodejs', cycle: '18', eolDate: '2025-04-30', eolBoolean: null, latest: '18.20.8' },
    {
      product: 'postgresql',
      cycle: '11',
      eolDate: '2023-11-09',
      eolBoolean: null,
      latest: '11.22',
    },
  ],
  advisories: [
    {
      cveId: 'CVE-2024-4577',
      product: 'php',
      ranges: [
        { startIncluding: '8.1.0', endExcluding: '8.1.29' },
        { startIncluding: '8.3.0', endExcluding: '8.3.8' },
      ],
      cvss: 9.8,
      kev: true,
      kevDateAdded: '2024-06-12',
      ransomware: true,
      title: 'PHP-CGI OS Command Injection',
    },
    {
      cveId: 'CVE-2099-0001',
      product: 'apache_httpd',
      ranges: [{ startIncluding: '2.4.0', endExcluding: '2.4.50' }],
      cvss: 7.5,
      kev: true,
      kevDateAdded: '2021-10-06',
      ransomware: false,
      title: 'Synthetic path traversal',
    },
    {
      cveId: 'CVE-2099-0002',
      product: 'apache_httpd',
      ranges: [{ startIncluding: '2.4.40', endIncluding: '2.4.49' }],
      cvss: null,
      kev: true,
      kevDateAdded: '2021-10-07',
      ransomware: true,
      title: 'Synthetic second advisory',
    },
    {
      cveId: 'CVE-2099-0003',
      product: 'apache_httpd',
      ranges: [],
      cvss: 9.8,
      kev: true,
      kevDateAdded: null,
      ransomware: false,
      title: 'No NVD ranges yet',
    },
  ],
};

const web = (server: string | null, xPoweredBy: string | null = null, host = 'www.example.com') =>
  http(
    { url: `https://${host}/`, finalUrl: `https://${host}/` },
    { evidence: { server, xPoweredBy } },
  );

const svc = (portNumber: number, product: string, version: string | null) =>
  port(
    { port: portNumber, service: 'x' },
    { evidence: { product, ...(version ? { version } : {}) } },
  );

function run(
  rules: readonly Rule[],
  obs: { http?: HttpObservation[]; ports?: PortObservation[] },
  intel: SoftwareIntel | null = INTEL,
) {
  const i: EvaluationInput = input(obs, {}, { checks: CHECKS });
  if (intel) i.context.softwareIntel = intel;
  return evaluate(i, rules);
}

describe('registry', () => {
  it('registers SOFT-001 and SOFT-002 in the software category with manual resolution', () => {
    for (const id of ['SOFT-001', 'SOFT-002']) {
      const rule = ruleById(id);
      expect(rule?.category).toBe('software');
      expect(rule?.manualResolution).toBe(true);
      expect(rule?.requires).toEqual([]);
    }
  });

  it('is skipped when the profile runs no software-relevant check', () => {
    const i = input({ http: [web('PHP/7.4.3')] }, {}, { checks: ['dns'] });
    i.context.softwareIntel = INTEL;
    expect(evaluate(i, softwareRules).skipped).toEqual(['SOFT-001', 'SOFT-002']);
  });
});

describe('SOFT-001 end-of-life software', () => {
  it('raises high for long-EOL core web software, medium confidence, version-free component', () => {
    const r = run([soft001], { http: [web('Apache', 'PHP/7.4.3')] });
    expect(r.upserts).toHaveLength(1);
    const f = r.upserts[0]!;
    expect(f).toMatchObject({
      hostname: 'www.example.com',
      component: 'http_header:www.example.com:php',
      severity: 'high',
      confidence: 'medium',
      exposure: 'web',
    });
    expect(f.evidence).toMatchObject({
      product: 'php',
      version: '7.4.3',
      banner: 'PHP/7.4.3',
      source: 'http_header',
      location: 'www.example.com',
      backportDistribution: null,
      cycle: '7.4',
      eolDate: '2022-11-28',
      intelAsOf: INTEL.asOf,
    });
    expect(f.description).toContain('not proof');
    expect(f.advisory.references).toContain('https://endoflife.date/php');
    expect(r.resolutions).toEqual([]);
  });

  it('is medium when EOL for less than a year, or when the date is unknown', () => {
    expect(run([soft001], { http: [web(null, 'PHP/8.1.2')] }).upserts[0]?.severity).toBe('medium');
    expect(run([soft001], { http: [web('nginx/1.18.0')] }).upserts[0]?.severity).toBe('medium');
  });

  it('is medium for long-EOL software outside the core web stack seen in headers', () => {
    expect(run([soft001], { http: [web(null, 'Node.js/18.19.0')] }).upserts[0]?.severity).toBe(
      'medium',
    );
  });

  it('is high for long-EOL software found by service identification', () => {
    const r = run([soft001], { ports: [svc(5432, 'PostgreSQL DB', '11.2')] });
    expect(r.upserts[0]).toMatchObject({
      hostname: 'example.com',
      component: 'service_identification:203.0.113.10:5432:postgresql',
      severity: 'high',
      exposure: 'network_service',
    });
  });

  it('lowers confidence and points to the distribution when the banner names one', () => {
    const f = run([soft001], { http: [web('Apache/2.4.41 (Ubuntu)', 'PHP/7.4.3-4ubuntu2.19')] })
      .upserts[0]!;
    expect(f.confidence).toBe('low');
    expect(f.evidence['backportDistribution']).toBe('Ubuntu');
    expect(f.evidence['version']).toBe('7.4.3-4ubuntu2.19');
    expect(f.description).toContain('distributions may still patch older versions');
    expect(f.description).toContain("check Ubuntu's support status");
    expect(f.advisory.recommendedActions.join(' ')).toContain('Ubuntu');
  });

  it('refreshes the same fingerprint after an upgrade to another EOL version', () => {
    const a = run([soft001], { http: [web(null, 'PHP/7.4.3')] }).upserts[0]!;
    const b = run([soft001], { http: [web(null, 'PHP/7.4.33')] }).upserts[0]!;
    expect(b.fingerprint).toBe(a.fingerprint);
    expect(b.evidence['version']).toBe('7.4.33');
  });

  it('resolves when the same location reports a supported version', () => {
    const before = run([soft001], { http: [web(null, 'PHP/7.4.3')] }).upserts[0]!;
    const r = run([soft001], { http: [web(null, 'PHP/8.3.1')] });
    expect(r.upserts).toEqual([]);
    expect(r.resolutions.map((x) => x.fingerprint)).toEqual([before.fingerprint]);
  });

  it('does not resolve on a hidden version, missing product, unknown cycle or failed observation', () => {
    for (const obs of [
      { http: [web('Apache', 'PHP')] },
      { http: [web('nginx')] },
      { http: [web(null, 'PHP/8.4.1')] },
      {
        http: [
          http({ statusCode: null }, { status: 'error', evidence: { xPoweredBy: 'PHP/8.3.1' } }),
        ],
      },
      {
        http: [http({}, { status: 'partial', evidence: { xPoweredBy: 'PHP/8.3.1' } })],
      },
    ]) {
      const r = run([soft001], obs);
      expect(r.upserts).toEqual([]);
      expect(r.resolutions).toEqual([]);
    }
  });

  it('produces nothing without software intelligence', () => {
    const r = run(softwareRules, { http: [web(null, 'PHP/7.4.3')] }, null);
    expect(r).toEqual({ upserts: [], resolutions: [], skipped: [], errors: [] });
  });

  it('separates fingerprints per location and source', () => {
    const r = run([soft001], {
      http: [web(null, 'PHP/7.4.3', 'a.example.com'), web(null, 'PHP/7.4.3', 'b.example.com')],
      ports: [svc(80, 'nginx', '1.18.0'), svc(8080, 'nginx', '1.18.0')],
    });
    const fps = r.upserts.map((u) => u.fingerprint);
    expect(fps).toHaveLength(4);
    expect(new Set(fps).size).toBe(4);
  });
});

describe('SOFT-002 known-exploited vulnerability', () => {
  it('raises one finding per CVE with CVE in the component; severity by CVSS / ransomware', () => {
    const r = run([soft002], { http: [web('Apache/2.4.41')] });
    expect(r.upserts.map((u) => [u.component, u.severity])).toEqual([
      ['http_header:www.example.com:apache_httpd:CVE-2099-0001', 'high'],
      ['http_header:www.example.com:apache_httpd:CVE-2099-0002', 'critical'],
    ]);
    const f = r.upserts[0]!;
    expect(f.confidence).toBe('medium');
    expect(f.description).toContain('reports Apache HTTP Server 2.4.41');
    expect(f.description).toContain('falls in the affected range of CVE-2099-0001');
    expect(f.description).toContain('This is not proof — verify');
    expect(f.description).not.toMatch(/\b(is|was) (compromised|exploited)\b/);
    expect(f.evidence).toMatchObject({
      cveId: 'CVE-2099-0001',
      ranges: [{ startIncluding: '2.4.0', endExcluding: '2.4.50' }],
      cvss: 7.5,
      kevDateAdded: '2021-10-06',
      ransomware: false,
      intelAsOf: INTEL.asOf,
    });
    expect(f.advisory.references).toEqual(
      expect.arrayContaining([
        'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
        'https://nvd.nist.gov/vuln/detail/CVE-2099-0001',
      ]),
    );
  });

  it('is critical when CVSS ≥ 9', () => {
    const r = run([soft002], { http: [web(null, 'PHP/8.3.1')] });
    expect(r.upserts.map((u) => [u.evidence['cveId'], u.severity])).toEqual([
      ['CVE-2024-4577', 'critical'],
    ]);
  });

  it('checks CVEs outside the range (resolvable) and raises those inside', () => {
    const r = run([soft002], { http: [web('Apache/2.4.30')] });
    expect(r.upserts.map((u) => u.component)).toEqual([
      'http_header:www.example.com:apache_httpd:CVE-2099-0001',
    ]);
    expect(r.resolutions.map((x) => x.component)).toEqual([
      'http_header:www.example.com:apache_httpd:CVE-2099-0002',
    ]);
  });

  it('resolves after an upgrade out of every range', () => {
    const before = run([soft002], { http: [web('Apache/2.4.41')] }).upserts;
    const r = run([soft002], { http: [web('Apache/2.4.62')] });
    expect(r.upserts).toEqual([]);
    expect(r.resolutions.map((x) => x.fingerprint).sort()).toEqual(
      before.map((u) => u.fingerprint).sort(),
    );
  });

  it('keeps the fingerprint across affected versions', () => {
    const a = run([soft002], { http: [web('Apache/2.4.41')] }).upserts[0]!;
    const b = run([soft002], { http: [web('Apache/2.4.49')] }).upserts[0]!;
    expect(b.fingerprint).toBe(a.fingerprint);
  });

  it('lowers confidence with a backport distribution', () => {
    const r = run([soft002], { http: [web('Apache/2.4.41 (Ubuntu)')] });
    expect(r.upserts.every((u) => u.confidence === 'low')).toBe(true);
    expect(r.upserts[0]?.advisory.references).toContain(
      'https://ubuntu.com/security/CVE-2099-0001',
    );
  });

  it('neither raises nor resolves on hidden or too-coarse versions, failed evidence or no intel', () => {
    for (const obs of [
      { http: [web('Apache')] },
      { http: [web('Apache/2')] },
      {
        http: [
          http({ statusCode: null }, { status: 'timeout', evidence: { server: 'Apache/2.4.62' } }),
        ],
      },
      {
        ports: [
          port({ state: 'filtered' }, { evidence: { product: 'Apache httpd', version: '2.4.62' } }),
        ],
      },
    ]) {
      const r = run([soft002], obs);
      expect(r.upserts).toEqual([]);
      expect(r.resolutions).toEqual([]);
    }
    expect(run([soft002], { http: [web('Apache/2.4.41')] }, null).upserts).toEqual([]);
  });

  it('ignores advisories without ranges', () => {
    const r = run([soft002], { http: [web('Apache/2.4.41')] });
    expect(r.upserts.some((u) => u.evidence['cveId'] === 'CVE-2099-0003')).toBe(false);
    expect(r.resolutions.some((x) => x.component.endsWith('CVE-2099-0003'))).toBe(false);
  });

  it('works on service identification with the domain as hostname', () => {
    const r = run([soft002], { ports: [svc(443, 'Apache httpd', '2.4.41')] });
    expect(r.upserts.map((u) => [u.hostname, u.component, u.exposure])).toEqual([
      [
        'example.com',
        'service_identification:203.0.113.10:443:apache_httpd:CVE-2099-0001',
        'network_service',
      ],
      [
        'example.com',
        'service_identification:203.0.113.10:443:apache_httpd:CVE-2099-0002',
        'network_service',
      ],
    ]);
  });
});

describe('determinism', () => {
  it('produces the same output regardless of observation order', () => {
    const obs = [
      web('Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f PHP/7.4.3', null, 'a.example.com'),
      web('nginx/1.18.0', 'PHP/8.3.1', 'b.example.com'),
    ];
    const ports = [svc(22, 'OpenSSH', '8.2p1'), svc(5432, 'PostgreSQL DB', '11.2')];
    const a = run(softwareRules, { http: obs, ports });
    const b = run(softwareRules, { http: [...obs].reverse(), ports: [...ports].reverse() });
    expect(b).toEqual(a);
    expect(a.upserts.length).toBeGreaterThan(0);
  });
});
