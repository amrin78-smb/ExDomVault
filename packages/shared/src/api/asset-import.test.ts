import { describe, expect, it } from 'vitest';
import {
  absoluteName,
  assetImportRequestSchema,
  ASSET_IMPORT_MAX_ENTRIES,
  extractHostEntriesFromRows,
  extractHostEntriesFromZone,
  looksLikeZoneFile,
} from './asset-import.ts';

describe('absoluteName', () => {
  it.each([
    ['', 'example.com', 'example.com'],
    ['@', 'example.com.', 'example.com'],
    ['www', 'example.com', 'www.example.com'],
    ['WWW.Example.com', 'example.com', 'www.example.com'],
    ['host.other.org.', 'example.com', 'host.other.org'],
    ['a.b', 'example.com', 'a.b.example.com'],
  ])('%s against %s → %s', (name, origin, expected) => {
    expect(absoluteName(name, origin)).toBe(expected);
  });
});

describe('extractHostEntriesFromRows', () => {
  const zoneExport = [
    ['zoneName', 'name', 'type', 'ttl', 'data'],
    ['example.com.', '', 'A', '600', '192.0.2.1'],
    ['example.com.', 'app', 'A', '600', '192.0.2.2'],
    ['example.com.', 'www', 'CNAME', '600', 'd111.cloudfront.net.'],
    ['example.com.', '', 'MX', '600', '10 mail.example.com.'],
    ['example.com.', '_dmarc', 'TXT', '600', 'v=DMARC1; p=reject'],
    ['example.com.', 'k1._domainkey', 'CNAME', '600', 'dkim.provider.net.'],
    ['example.com.', '*', 'A', '600', '192.0.2.9'],
    ['', '', '', '', ''],
  ];

  it('keeps A/AAAA/CNAME host rows and makes names absolute against the zone column', () => {
    const r = extractHostEntriesFromRows(zoneExport, 'example.com');
    expect(r.format).toBe('records');
    expect(r.entries).toEqual([
      { hostname: 'example.com' },
      { hostname: 'app.example.com' },
      { hostname: 'www.example.com', cnameTarget: 'd111.cloudfront.net' },
    ]);
    expect(r.skipped).toEqual({ recordType: 2, serviceName: 1, wildcard: 1, empty: 0 });
  });

  it('accepts other header spellings and no type column', () => {
    const r = extractHostEntriesFromRows(
      [
        ['Hostname', 'Notes'],
        ['portal.example.com', 'x'],
        ['vpn', ''],
      ],
      'example.com',
    );
    expect(r.entries.map((e) => e.hostname)).toEqual(['portal.example.com', 'vpn.example.com']);
  });

  it('treats a headerless sheet as a plain list of hostnames', () => {
    const r = extractHostEntriesFromRows(
      [['a.example.com'], ['b'], [''], ['_sip._tls']],
      'example.com',
    );
    expect(r.format).toBe('list');
    expect(r.entries.map((e) => e.hostname)).toEqual(['a.example.com', 'b.example.com']);
    expect(r.skipped.serviceName).toBe(1);
  });

  it('passes out-of-domain names through for the server to classify', () => {
    const r = extractHostEntriesFromRows([['name'], ['evil.example.org.']], 'example.com');
    expect(r.entries).toEqual([{ hostname: 'evil.example.org' }]);
  });
});

describe('extractHostEntriesFromZone', () => {
  const zone = [
    '$ORIGIN example.com.',
    '$TTL 3600',
    '@ IN SOA ns1.example.com. hostmaster.example.com. (',
    '   2026010101 7200 3600 1209600 300 )',
    '@ 300 IN A 192.0.2.1',
    '      IN AAAA 2001:db8::1 ; same owner',
    'www IN CNAME edge.example.net.',
    'api 600 A 192.0.2.3',
    '_dmarc IN TXT "v=DMARC1; p=none"',
    '* IN A 192.0.2.9',
    '$ORIGIN eu.example.com.',
    'edi IN A 192.0.2.4',
    'mail IN MX 10 mx.example.com.',
  ].join('\n');

  it('handles $ORIGIN, inherited owners, optional TTL/class and multi-line SOA', () => {
    expect(looksLikeZoneFile(zone)).toBe(true);
    const r = extractHostEntriesFromZone(zone, 'example.com');
    expect(r.entries).toEqual([
      { hostname: 'example.com' },
      { hostname: 'example.com' },
      { hostname: 'www.example.com', cnameTarget: 'edge.example.net' },
      { hostname: 'api.example.com' },
      { hostname: 'edi.eu.example.com' },
    ]);
    expect(r.skipped).toEqual({ recordType: 3, serviceName: 0, wildcard: 1, empty: 0 });
  });

  it('does not mistake CSV or a plain list for a zone file', () => {
    expect(looksLikeZoneFile('name,type,data\nwww,A,192.0.2.1')).toBe(false);
    expect(looksLikeZoneFile('a.example.com\nb.example.com')).toBe(false);
    expect(looksLikeZoneFile('www 300 IN A 192.0.2.1')).toBe(true);
  });
});

describe('assetImportRequestSchema', () => {
  it('defaults dryRun to false and caps entries', () => {
    expect(
      assetImportRequestSchema.parse({ entries: [{ hostname: 'a.example.com' }] }).dryRun,
    ).toBe(false);
    expect(assetImportRequestSchema.safeParse({ entries: [] }).success).toBe(false);
    const many = Array.from({ length: ASSET_IMPORT_MAX_ENTRIES + 1 }, (_, i) => ({
      hostname: `h${i}.example.com`,
    }));
    expect(assetImportRequestSchema.safeParse({ entries: many }).success).toBe(false);
  });
});
