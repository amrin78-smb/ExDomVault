import { describe, expect, it } from 'vitest';
import { http, observations, port } from '../fixtures/builders.ts';
import type { SoftwareIntel } from '../types.ts';
import {
  compareVersions,
  detectDistribution,
  eolStatus,
  extractSoftware,
  matchAdvisories,
  parseHeaderBanner,
  parseServiceBanner,
  softwareApi,
  versionInRange,
} from './index.ts';

describe('parseHeaderBanner', () => {
  const cases: [string, [string, string | null, string | null][]][] = [
    [
      'Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f PHP/7.4.3',
      [
        ['apache_httpd', '2.4.41', 'Ubuntu'],
        ['openssl', '1.1.1f', 'Ubuntu'],
        ['php', '7.4.3', 'Ubuntu'],
      ],
    ],
    ['nginx/1.18.0', [['nginx', '1.18.0', null]]],
    ['nginx/1.18.0 (Ubuntu)', [['nginx', '1.18.0', 'Ubuntu']]],
    ['nginx', [['nginx', null, null]]],
    ['Apache', [['apache_httpd', null, null]]],
    ['Apache/2', [['apache_httpd', '2', null]]],
    ['Microsoft-IIS/10.0', [['microsoft_iis', '10.0', null]]],
    ['Microsoft-IIS/8.5', [['microsoft_iis', '8.5', null]]],
    ['PHP/8.1.2', [['php', '8.1.2', null]]],
    ['PHP/7.4.3-4ubuntu2.19', [['php', '7.4.3-4ubuntu2.19', 'Ubuntu']]],
    ['PHP/7.3.31-1~deb10u1', [['php', '7.3.31-1~deb10u1', 'Debian']]],
    [
      'Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16',
      [
        ['apache_httpd', '2.4.6', 'CentOS'],
        ['openssl', '1.0.2k-fips', 'CentOS'],
        ['php', '5.4.16', 'CentOS'],
      ],
    ],
    [
      'Apache/2.4.37 (Red Hat Enterprise Linux) OpenSSL/1.1.1k',
      [
        ['apache_httpd', '2.4.37', 'Red Hat'],
        ['openssl', '1.1.1k', 'Red Hat'],
      ],
    ],
    ['Apache/2.4.38 (Debian)', [['apache_httpd', '2.4.38', 'Debian']]],
    ['OpenSSL/1.0.2k-fips', [['openssl', '1.0.2k-fips', null]]],
    ['APACHE/2.4.41 (UBUNTU)', [['apache_httpd', '2.4.41', 'Ubuntu']]],
    ['NGINX/1.25.3', [['nginx', '1.25.3', null]]],
    ['Apache-Coyote/1.1', [['apache_tomcat', null, null]]],
    ['lighttpd/1.4.59', [['lighttpd', '1.4.59', null]]],
    ['Express', []],
    ['cloudflare', []],
    ['openresty/1.21.4.1', []],
    ['ASP.NET', []],
    ['PHP/abc', [['php', null, null]]],
    ['', []],
    ['%%%/// ((( garbage )))', []],
    ['nginx/1.18.0 nginx/1.20.0', [['nginx', '1.18.0', null]]],
  ];
  it.each(cases)('%s', (banner, expected) => {
    expect(
      parseHeaderBanner(banner).map((p) => [p.product, p.version, p.backportDistribution]),
    ).toEqual(expected);
  });

  it('only parses the first 200 characters', () => {
    expect(parseHeaderBanner(`${'x'.repeat(200)} PHP/8.1.2`)).toEqual([]);
    expect(parseHeaderBanner(`${'x'.repeat(150)} PHP/8.1.2`)).toHaveLength(1);
  });
});

describe('parseServiceBanner (Nmap)', () => {
  it.each([
    ['Apache httpd', '2.4.41', 'apache_httpd', '2.4.41', null],
    ['OpenSSH', '8.2p1 Ubuntu 4ubuntu0.5', 'openssh', '8.2p1', 'Ubuntu'],
    ['OpenSSH', '7.4', 'openssh', '7.4', null],
    ['nginx', '1.18.0', 'nginx', '1.18.0', null],
    ['Microsoft IIS httpd', '10.0', 'microsoft_iis', '10.0', null],
    ['Apache Tomcat', '9.0.31', 'apache_tomcat', '9.0.31', null],
    ['Apache Tomcat/Coyote JSP engine', '1.1', 'apache_tomcat', null, null],
    ['PostgreSQL DB', '9.6.0 or later', 'postgresql', '9.6.0', null],
    ['MySQL', '5.5.5-10.3.27-MariaDB-0+deb10u1', 'mariadb', '10.3.27', 'Debian'],
    ['MySQL', '8.0.36', 'mysql', '8.0.36', null],
    ['Exim smtpd', '4.92', 'exim', '4.92', null],
    ['Apache httpd', null, 'apache_httpd', null, null],
  ] as const)('%s %s', (product, version, key, v, distro) => {
    expect(parseServiceBanner(product, version)).toEqual({
      product: key,
      version: v,
      backportDistribution: distro,
    });
  });

  it('ignores unknown products', () => {
    expect(parseServiceBanner('Dropbear sshd', '2020.81')).toBeNull();
    expect(parseServiceBanner('Apachefoo', '1.0')).toBeNull();
  });
});

describe('detectDistribution', () => {
  it.each([
    ['2.4.6-97.el7', 'Red Hat'],
    ['1.20.1-1.el8_9', 'Red Hat'],
    ['(CentOS) el7', 'CentOS'],
    ['1.18.0-6+deb11u3', 'Debian'],
    ['(Fedora)', 'Fedora'],
    ['(SUSE)', 'SUSE'],
    ['(Alpine)', 'Alpine'],
    ['1.0.2k-fips', null],
    ['debugger', null],
    ['nginx', null],
  ])('%s → %s', (text, distro) => {
    expect(detectDistribution(text)).toBe(distro);
  });
});

describe('compareVersions', () => {
  it.each([
    ['1.1.1f', '1.1.1w', -1],
    ['8.2p1', '8.9p1', -1],
    ['8.2p1', '8.2p2', -1],
    ['8.2', '8.2p1', -1],
    ['1.1.1', '1.1.1a', -1],
    ['2.4', '2.4.0', 0],
    ['1.18', '1.18.1', -1],
    ['2.4.9', '2.4.10', -1],
    ['10.0', '9.9', 1],
    ['7.4.3-4ubuntu2.19', '7.4.3', 0],
    ['2.4.41-ubuntu', '2.4.41', 0],
    ['1.0.2k-fips', '1.0.2k', 0],
    ['8.2p1 Ubuntu 4ubuntu0.5', '8.2p1', 0],
    ['2.0rc1', '2.0', -1],
    ['2.0-beta2', '2.0-beta10', -1],
    ['v1.2.3', '1.2.3', 0],
    ['abc', '1.0', -1],
    ['abc', 'def', 0],
  ] as const)('%s vs %s → %i', (a, b, expected) => {
    expect(compareVersions(a, b)).toBe(expected);
    expect(compareVersions(b, a)).toBe(-expected || 0);
  });
});

describe('versionInRange', () => {
  it('applies inclusive and exclusive bounds', () => {
    expect(versionInRange('7.4.3', { startIncluding: '7.4.0', endExcluding: '7.4.4' })).toBe(true);
    expect(versionInRange('7.4.4', { startIncluding: '7.4.0', endExcluding: '7.4.4' })).toBe(false);
    expect(versionInRange('7.4.4', { endIncluding: '7.4.4' })).toBe(true);
    expect(versionInRange('7.4.0', { startExcluding: '7.4.0' })).toBe(false);
    expect(versionInRange('7.4.0', { startIncluding: '7.4.0' })).toBe(true);
    expect(versionInRange('7.3.9', { startIncluding: '7.4' })).toBe(false);
    expect(versionInRange('1.1.1f', { startIncluding: '1.1.1', endExcluding: '1.1.1w' })).toBe(
      true,
    );
    expect(versionInRange('2.4.41-4ubuntu', { endExcluding: '2.4.50' })).toBe(true);
  });

  it('never matches an empty range or an unparseable version', () => {
    expect(versionInRange('1.0', {})).toBe(false);
    expect(versionInRange('unknown', { endExcluding: '9.9' })).toBe(false);
  });
});

const CYCLES: SoftwareIntel['eolCycles'] = [
  { product: 'php', cycle: '7.4', eolDate: '2022-11-28', eolBoolean: null, latest: '7.4.33' },
  { product: 'php', cycle: '8.3', eolDate: '2027-12-31', eolBoolean: null, latest: '8.3.12' },
  { product: 'php', cycle: '7', eolDate: '2000-01-01', eolBoolean: null, latest: null },
  { product: 'nginx', cycle: '1.18', eolDate: null, eolBoolean: true, latest: '1.18.0' },
  { product: 'nginx', cycle: '1.27', eolDate: null, eolBoolean: false, latest: '1.27.2' },
  { product: 'nodejs', cycle: '18', eolDate: '2025-04-30', eolBoolean: null, latest: '18.20.8' },
  { product: 'nodejs', cycle: '8.0-lts', eolDate: '2000-01-01', eolBoolean: null, latest: null },
  { product: 'openssl', cycle: '1.1.1', eolDate: '2023-09-11', eolBoolean: null, latest: '1.1.1w' },
];
const NOW = '2026-10-22T00:00:00.000Z';

describe('eolStatus', () => {
  it('uses the longest dotted-prefix cycle', () => {
    expect(eolStatus('php', '7.4.3', CYCLES, NOW)).toEqual({
      cycle: '7.4',
      eolDate: '2022-11-28',
      isEol: true,
      latestInCycle: '7.4.33',
    });
    expect(eolStatus('php', '7.4.3-4ubuntu2.19', CYCLES, NOW)?.cycle).toBe('7.4');
    expect(eolStatus('nginx', '1.18.0', CYCLES, NOW)?.isEol).toBe(true);
    expect(eolStatus('nodejs', '18.19.0', CYCLES, NOW)?.cycle).toBe('18');
    expect(eolStatus('openssl', '1.1.1f', CYCLES, NOW)?.cycle).toBe('1.1.1');
  });

  it('is not EOL before the date or with eol=false', () => {
    expect(eolStatus('php', '8.3.1', CYCLES, NOW)?.isEol).toBe(false);
    expect(eolStatus('nginx', '1.27.0', CYCLES, NOW)?.isEol).toBe(false);
    expect(eolStatus('php', '7.4.3', CYCLES, '2022-11-27T00:00:00.000Z')?.isEol).toBe(false);
    expect(eolStatus('php', '7.4.3', CYCLES, '2022-11-28T00:00:00.000Z')?.isEol).toBe(true);
  });

  it('returns null when no cycle matches', () => {
    expect(eolStatus('php', '8.4.1', CYCLES, NOW)).toBeNull();
    expect(eolStatus('nginx', '1', CYCLES, NOW)).toBeNull();
    expect(eolStatus('microsoft_iis', '10.0', CYCLES, NOW)).toBeNull();
    expect(eolStatus('php', 'hidden', CYCLES, NOW)).toBeNull();
    expect(eolStatus('nodejs', '8.0.0', CYCLES, NOW)).toBeNull();
  });
});

describe('matchAdvisories', () => {
  const adv = (
    cveId: string,
    ranges: SoftwareIntel['advisories'][number]['ranges'],
    kev = true,
  ) => ({
    cveId,
    product: 'php',
    ranges,
    cvss: 9.8,
    kev,
    kevDateAdded: '2024-06-12',
    ransomware: false,
    title: 'Test advisory',
  });
  const ADVISORIES = [
    adv('CVE-2024-0002', [
      { startIncluding: '8.1.0', endExcluding: '8.1.29' },
      { startIncluding: '7.4.0', endExcluding: '7.4.34' },
    ]),
    adv('CVE-2024-0001', [{ endExcluding: '7.0.0' }]),
    adv('CVE-2024-0003', []),
    adv('CVE-2024-0004', [{ endExcluding: '9.0.0' }], false),
  ];

  it('matches if ANY range includes the version, only KEV with ranges, sorted', () => {
    expect(matchAdvisories('php', '7.4.3', ADVISORIES).map((a) => a.cveId)).toEqual([
      'CVE-2024-0002',
    ]);
    expect(matchAdvisories('php', '5.6.40', ADVISORIES).map((a) => a.cveId)).toEqual([
      'CVE-2024-0001',
    ]);
    expect(matchAdvisories('php', '8.3.0', ADVISORIES)).toEqual([]);
    expect(matchAdvisories('nginx', '7.4.3', ADVISORIES)).toEqual([]);
  });
});

describe('extractSoftware', () => {
  it('reads successful http headers and open service identification, deduplicated', () => {
    const set = observations({
      http: [
        http({}, { evidence: { server: 'Apache/2.4.41 (Ubuntu)', xPoweredBy: 'PHP/7.4.3' } }),
        // Same hostname via another observation: the PHP without version loses.
        http(
          { url: 'http://www.example.com/' },
          { evidence: { server: 'Apache', xPoweredBy: 'PHP' } },
        ),
        http(
          { url: 'https://api.example.com/' },
          { status: 'error', evidence: { server: 'nginx/1.18.0' } },
        ),
      ],
      ports: [
        port(
          { port: 22, service: 'ssh' },
          { evidence: { product: 'OpenSSH', version: '8.2p1 Ubuntu 4ubuntu0.5' } },
        ),
        port({ port: 23, state: 'closed' }, { evidence: { product: 'OpenSSH', version: '8.2p1' } }),
        port({ port: 80 }, { evidence: { product: 'Unknown thing', version: '1.0' } }),
        port(
          { ipAddress: '2001:DB8::1', port: 443 },
          { evidence: { product: 'nginx', version: '1.18.0' } },
        ),
      ],
    });
    const out = extractSoftware(set);
    expect(
      out.map((s) => [
        s.source,
        s.hostname,
        s.ipAddress,
        s.port,
        s.product,
        s.version,
        s.backportDistribution,
      ]),
    ).toEqual([
      ['http_header', 'www.example.com', null, null, 'apache_httpd', '2.4.41', 'Ubuntu'],
      ['http_header', 'www.example.com', null, null, 'php', '7.4.3', null],
      ['service_identification', null, '203.0.113.10', 22, 'openssh', '8.2p1', 'Ubuntu'],
      ['service_identification', null, '2001:db8::1', 443, 'nginx', '1.18.0', null],
    ]);
    expect(out[2]?.banner).toBe('OpenSSH 8.2p1 Ubuntu 4ubuntu0.5');
  });

  it('caps the stored banner at 200 characters', () => {
    const long = `PHP/8.1.2 ${'x'.repeat(400)}`;
    const [s] = extractSoftware(
      observations({ http: [http({}, { evidence: { xPoweredBy: long } })] }),
    );
    expect(s?.banner).toHaveLength(200);
  });

  it('is exposed as the contract object', () => {
    expect(softwareApi.compareVersions('1.0', '2.0')).toBe(-1);
  });
});
