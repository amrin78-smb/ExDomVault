/**
 * Red-team attacks on the server-side IP/CIDR scope primitives (Milestone 6 gate).
 * Every test asserts the SAFE behaviour: a failing test is an open vulnerability.
 */
import { describe, expect, it } from 'vitest';
import { isWithinDomain } from '../hostname/normalise.ts';
import {
  canonicalCidr,
  canonicalIp,
  cidrContains,
  cidrsOverlap,
  isProhibitedAddress,
  isPublicCidr,
  parseCidr,
  parseIp,
} from './ip.ts';

describe('RT-IP: alternative IPv4 encodings are never parsed (fail closed)', () => {
  it.each([
    ['octal', '0177.0.0.1'],
    ['octal leading zero', '010.0.0.1'],
    ['leading zero last octet', '8.8.8.08'],
    ['hex octet', '0x7f.0.0.1'],
    ['hex uppercase', '0X7F.0.0.1'],
    ['hex integer', '0x7f000001'],
    ['decimal integer', '2130706433'],
    ['short form a.b', '127.1'],
    ['short form a.b.c', '127.0.1'],
    ['short form a.b.c public', '8.8.2056'],
    ['five parts', '1.2.3.4.5'],
    ['trailing dot', '8.8.8.8.'],
    ['leading dot', '.8.8.8.8'],
    ['octet overflow', '256.0.0.1'],
    ['octet overflow 2', '8.8.8.999'],
    ['negative', '-1.0.0.1'],
    ['plus sign', '+8.8.8.8'],
    ['arabic-indic digits', '١٢٧.0.0.1'],
    ['fullwidth digits', '１２７.0.0.1'],
    ['fullwidth dot', '127．0．0．1'],
    ['ideographic full stop', '127。0。0。1'],
    ['leading space', ' 8.8.8.8'],
    ['trailing space', '8.8.8.8 '],
    ['trailing newline', '8.8.8.8\n'],
    ['tab', '8.8.8.8\t'],
    ['NUL suffix', '8.8.8.8\u0000'],
    ['zero-width space', '​8.8.8.8'],
    ['CIDR text as an address', '8.8.8.8/32'],
    ['port suffix', '8.8.8.8:443'],
    ['empty', ''],
  ])('%s (%j)', (_label, text) => {
    expect(parseIp(text)).toBeNull();
    expect(canonicalIp(text)).toBeNull();
    expect(isProhibitedAddress(text)).toBe(true);
  });
});

describe('RT-IP: IPv6 spellings', () => {
  it.each([
    ['bracketed loopback', '[::1]'],
    ['bracketed public', '[2606:4700::1111]'],
    ['zone id', 'fe80::1%eth0'],
    ['numeric zone id on public', '2606:4700::1111%1'],
    ['url-encoded zone id', 'fe80::1%25eth0'],
    ['5-digit group', '02606:4700::1111'],
    ['triple colon', '2606:::1'],
    ['two compressions', '2606::4700::1'],
    ['trailing single colon', '2606:4700::1:'],
    ['leading single colon', ':2606:4700::1'],
    ['9 groups', '1:2:3:4:5:6:7:8:9'],
    ['8 groups plus ::', '1:2:3:4::5:6:7:8'],
    ['dotted quad not last', '::1.2.3.4:5'],
    ['dotted quad at head', '1.2.3.4::'],
    ['dotted quad in head before ::', '1.2.3.4::1'],
    ['bad dotted part', '::ffff:1.2.3'],
    ['octal dotted part', '::ffff:0177.0.0.1'],
    ['hex dotted part', '::ffff:0x7f.0.0.1'],
    ['dotted part too many groups', '1:2:3:4:5:6:7:1.2.3.4'],
    ['fullwidth hex', 'ｆｅ８０::1'],
    ['whitespace', ' ::1'],
    ['g hex digit', '2606:470g::1'],
    ['too long (46 chars)', '0000:0000:0000:0000:0000:ffff:255.255.255.2550'],
  ])('rejects %s (%j)', (_label, text) => {
    expect(parseIp(text)).toBeNull();
    expect(isProhibitedAddress(text)).toBe(true);
  });

  it.each([
    ['IPv4-mapped loopback', '::ffff:127.0.0.1'],
    ['IPv4-mapped loopback, hex', '::ffff:7f00:1'],
    ['IPv4-mapped loopback, padded groups', '::ffff:7f00:0001'],
    ['IPv4-mapped loopback, uppercase', '::FFFF:7F00:1'],
    ['IPv4-mapped loopback, full form', '0:0:0:0:0:ffff:7f00:1'],
    ['IPv4-mapped loopback, padded full', '0000:0000:0000:0000:0000:ffff:127.0.0.1'],
    ['IPv4-mapped PUBLIC (still refused)', '::ffff:8.8.8.8'],
    ['IPv4-mapped public, hex', '::ffff:808:808'],
    ['IPv4-compatible loopback', '::127.0.0.1'],
    ['IPv4-compatible public', '::8.8.8.8'],
    ['IPv4-compatible hex', '::7f00:1'],
    ['IPv4-translated (SIIT)', '::ffff:0:127.0.0.1'],
    ['IPv4-translated public', '::ffff:0:8.8.8.8'],
    ['NAT64 well-known', '64:ff9b::127.0.0.1'],
    ['NAT64 well-known public', '64:ff9b::8.8.8.8'],
    ['NAT64 local-use', '64:ff9b:1::a00:1'],
    ['6to4 of loopback', '2002:7f00:1::'],
    ['6to4 of public', '2002:808:808::1'],
    ['Teredo', '2001:0:4136:e378:8000:63bf:3fff:fdd2'],
    ['Teredo short', '2001::1'],
    ['loopback', '::1'],
    ['loopback full', '0:0:0:0:0:0:0:1'],
    ['unspecified', '::'],
    ['link-local uppercase', 'FE80::1'],
    ['link-local top of range', 'febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff'],
    ['site-local', 'fec0::1'],
    ['ULA', 'fd00:ec2::254'],
    ['ULA fc', 'fc00::1'],
    ['multicast', 'ff02::1'],
    ['discard-only', '100::1'],
    ['documentation 2001:db8', '2001:db8::1'],
    ['documentation 2001:DB8 uppercase', '2001:DB8::1'],
    ['benchmarking', '2001:2::1'],
    ['ORCHIDv2', '2001:20::1'],
    ['outside 2000::/3 (low)', '1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'],
    ['outside 2000::/3 (high)', '4000::1'],
    ['SRv6 SID space', '5f00::1'],
    ['embedded dotted quad (loopback) in mapped slot via full form', '0:0:0:0:0:ffff:127.0.0.1'],
  ])('prohibits %s (%s)', (_label, text) => {
    expect(isProhibitedAddress(text)).toBe(true);
  });

  it('accepts public global unicast spellings and canonicalises them identically', () => {
    for (const text of [
      '2606:4700::1111',
      '2606:4700:0:0:0:0:0:1111',
      '2606:4700:0000:0000:0000:0000:0000:1111',
      '2606:4700::0:1111',
      '2606:4700::0000:1111',
      '2606:4700::1111'.toUpperCase(),
      '2606:4700:0:0:0:0:0.0.17.17', // embedded dotted quad in a non-mapped position
    ]) {
      expect(isProhibitedAddress(text)).toBe(false);
      expect(canonicalIp(text)).toBe('2606:4700::1111');
    }
  });

  it('embedded dotted quad in a public prefix is just a public address, not the IPv4 one', () => {
    // 2606:4700::10.0.0.1 is a public IPv6 address whose low bits look like 10.0.0.1. Fine, but it
    // must never be treated as (or canonicalised to) 10.0.0.1.
    expect(canonicalIp('2606:4700::10.0.0.1')).toBe('2606:4700::a00:1');
    expect(cidrContains('10.0.0.0/8', '2606:4700::10.0.0.1')).toBe(false);
  });
});

describe('RT-IP: IPv4 range boundaries', () => {
  it.each([
    ['0.255.255.255', true],
    ['1.0.0.0', false],
    ['9.255.255.255', false],
    ['10.0.0.0', true],
    ['10.255.255.255', true],
    ['11.0.0.0', false],
    ['100.63.255.255', false],
    ['100.64.0.0', true],
    ['100.100.100.200', true], // cloud metadata (CGNAT)
    ['100.127.255.255', true],
    ['100.128.0.0', false],
    ['126.255.255.255', false],
    ['127.0.0.0', true],
    ['127.255.255.255', true],
    ['128.0.0.0', false],
    ['169.253.255.255', false],
    ['169.254.169.254', true],
    ['169.255.0.0', false],
    ['172.15.255.255', false],
    ['172.16.0.0', true],
    ['172.31.255.255', true],
    ['172.32.0.0', false],
    ['192.0.0.0', true],
    ['192.0.0.255', true],
    ['192.0.1.0', false],
    ['192.0.2.255', true],
    ['192.0.3.0', false],
    ['192.88.98.255', false],
    ['192.88.99.0', true],
    ['192.88.99.255', true],
    ['192.88.100.0', false],
    ['192.167.255.255', false],
    ['192.168.0.0', true],
    ['192.169.0.0', false],
    ['198.17.255.255', false],
    ['198.18.0.0', true],
    ['198.19.255.255', true],
    ['198.20.0.0', false],
    ['198.51.100.1', true],
    ['203.0.113.255', true],
    ['223.255.255.255', false],
    ['224.0.0.0', true],
    ['239.255.255.255', true],
    ['240.0.0.0', true],
    ['255.255.255.255', true],
  ])('%s prohibited=%s', (ip, prohibited) => {
    expect(isProhibitedAddress(ip)).toBe(prohibited);
  });
});

describe('RT-IP: parity with the Python worker prohibited tables (worker/app/policy.py)', () => {
  // The worker refuses these; the server must not approve or accept evidence for them either.
  it.each([
    ['6to4 relay anycast', '192.88.99.1'],
    ['IETF protocol assignments 2001::/23 (outside Teredo/ORCHID)', '2001:100::1'],
    ['IETF protocol assignments 2001::/23 top', '2001:1ff:ffff::1'],
    ['AMT 2001:3::/32 (inside 2001::/23)', '2001:3::1'],
    ['DRIP 2001:30::/28 (inside 2001::/23)', '2001:30::1'],
    ['IPv6 documentation 3fff::/20 (RFC 9637)', '3fff::1'],
    ['IPv6 documentation 3fff::/20 top', '3fff:fff:ffff::1'],
    ['broadcast', '255.255.255.255'],
  ])('prohibits %s (%s)', (_label, ip) => {
    expect(isProhibitedAddress(ip)).toBe(true);
  });

  it.each([
    ['2001:200::/23 boundary is public (WIDE)', '2001:200::1'],
    ['3fff:1000:: just above the /20 is public', '3fff:1000::1'],
  ])('%s', (_label, ip) => {
    expect(isProhibitedAddress(ip)).toBe(false);
  });

  it.each([
    ['2001:100::/32', '2001:100::/32'],
    ['3fff::/32', '3fff::/32'],
    ['2001::/23 itself', '2001::/23'],
  ])('a network inside worker-prohibited space is not public: %s', (_label, cidr) => {
    expect(isPublicCidr(cidr)).toBe(false);
  });
});

describe('RT-CIDR: canonicalisation tricks', () => {
  it.each([
    ['negative prefix', '8.8.8.0/-1'],
    ['prefix 33', '8.8.8.0/33'],
    ['IPv6 prefix 129', '2606:4700::/129'],
    ['leading-zero prefix', '8.8.8.0/024'],
    ['plus prefix', '8.8.8.0/+24'],
    ['hex prefix', '8.8.8.0/0x18'],
    ['fractional prefix', '8.8.8.0/24.0'],
    ['empty prefix', '8.8.8.0/'],
    ['double prefix', '8.8.8.0/24/24'],
    ['space before slash', '8.8.8.0 /24'],
    ['space after slash', '8.8.8.0/ 24'],
    ['trailing whitespace (untrimmed)', '10.0.0.0/8 '],
    ['fullwidth prefix digits', '8.8.8.0/２４'],
    ['bracketed v6', '[2606:4700::]/32'],
    ['zone id v6', '2606:4700::%eth0/32'],
    ['alternative v4 encoding', '0x08.8.8.0/24'],
    ['integer v4', '134744064/24'],
    ['short v4', '8.8.2048/24'],
  ])('parseCidr rejects %s (%j)', (_label, text) => {
    expect(parseCidr(text)).toBeNull();
    expect(isPublicCidr(text)).toBe(false);
  });

  it('canonicalCidr trims but still refuses non-public space after trimming', () => {
    expect(canonicalCidr('10.0.0.0/8 ')).toBe('10.0.0.0/8');
    expect(isPublicCidr(canonicalCidr('10.0.0.0/8 ') as string)).toBe(false);
  });

  it('clears host bits so a set host bit cannot smuggle a different network', () => {
    expect(canonicalCidr('8.8.8.255/24')).toBe('8.8.8.0/24');
    expect(canonicalCidr('2606:4700::ffff/32')).toBe('2606:4700::/32');
    // 10.255.255.255/8 must canonicalise into 10/8 (and therefore be refused).
    expect(canonicalCidr('10.255.255.255/8')).toBe('10.0.0.0/8');
    expect(isPublicCidr('10.255.255.255/8')).toBe(false);
  });

  it.each(['0.0.0.0/0', '::/0', '8.0.0.0/0', '2000::/3', '2000::/0', '0.0.0.0/1', '128.0.0.0/1'])(
    'whole-space and huge networks are never public: %s',
    (cidr) => {
      expect(isPublicCidr(cidr)).toBe(false);
    },
  );

  it('a mapped-IPv6 spelling of a public IPv4 network is not public', () => {
    expect(isPublicCidr('::ffff:8.8.8.0/120')).toBe(false);
    expect(isPublicCidr('::ffff:808:800/120')).toBe(false);
    expect(isPublicCidr('64:ff9b::808:800/120')).toBe(false);
    expect(isPublicCidr('2002:808:800::/40')).toBe(false);
  });
});

describe('RT-CIDR: overlap at boundaries', () => {
  it.each([
    ['100.63.255.255/32', '100.64.0.0/32', false],
    ['100.63.255.255/32', '100.64.0.0/10', false],
    ['100.64.0.0/32', '100.64.0.0/10', true],
    ['8.8.8.0/24', '8.8.9.0/24', false],
    ['8.8.8.0/23', '8.8.9.0/24', true],
    ['8.8.8.255/32', '8.8.8.0/24', true],
    ['8.8.9.0/32', '8.8.8.0/24', false],
    ['2001::/31', '2001::/32', true],
    ['2001:1::/32', '2001::/32', false],
    ['2606:4700::/32', '2606:4701::/32', false],
    ['::ffff:8.8.8.0/120', '8.8.8.0/24', false], // different families never "overlap"
  ])('%s vs %s overlap=%s', (a, b, expected) => {
    expect(cidrsOverlap(a, b)).toBe(expected);
    expect(cidrsOverlap(b, a)).toBe(expected);
  });

  it.each([
    ['2001::/31 contains Teredo', '2001::/31'],
    ['/16 straddling 192.0.0.0/24', '192.0.0.0/16'],
    ['/16 straddling 192.0.2.0/24', '192.0.0.0/16'],
    ['/16 straddling 192.88.99.0/24', '192.88.0.0/16'],
    ['/16 straddling 198.51.100.0/24', '198.51.0.0/16'],
    ['/16 straddling 203.0.113.0/24', '203.0.0.0/16'],
    ['/8 containing RFC1918 172.16/12', '172.0.0.0/8'],
    ['/9 overlapping CGNAT', '100.0.0.0/9'],
    ['/15 inside benchmarking', '198.18.0.0/15'],
    ['/32 IPv6 that contains documentation', '2001:db8::/31'],
  ])('%s is not public', (_label, cidr) => {
    expect(isPublicCidr(cidr)).toBe(false);
  });

  it.each(['172.32.0.0/16', '100.128.0.0/16', '192.0.1.0/24', '198.20.0.0/16', '2606:4700::/32'])(
    'neighbouring public ranges stay public: %s',
    (cidr) => {
      expect(isPublicCidr(cidr)).toBe(true);
    },
  );

  it('cidrContains is strict and family-aware', () => {
    expect(cidrContains('8.8.8.0/24', '8.8.8.8')).toBe(true);
    expect(cidrContains('8.8.8.0/24', '8.8.9.0')).toBe(false);
    expect(cidrContains('8.8.8.0/24', '8.8.7.255')).toBe(false);
    expect(cidrContains('8.8.8.0/24', '::ffff:8.8.8.8')).toBe(false);
    expect(cidrContains('8.8.8.0/24', '8.8.8.8 ')).toBe(false);
    expect(cidrContains('8.8.8.0/24', '010.8.8.8')).toBe(false);
    expect(cidrContains('8.8.8.0/24 ', '8.8.8.8')).toBe(false);
    expect(cidrContains('2606:4700::/32', '2606:4700:ffff::1')).toBe(true);
    expect(cidrContains('2606:4700::/32', '2606:4701::1')).toBe(false);
  });
});

describe('RT-HOST: label-boundary checks', () => {
  it.each([
    ['suffix lookalike', 'evil-example.com'],
    ['prefix glued', 'wwwexample.com'],
    ['domain as a left label', 'example.com.evil.net'],
    ['trailing dot', 'www.example.com.'],
    ['uppercase', 'WWW.EXAMPLE.COM'],
    ['homograph A-label', 'xn--exmple-cua.com'],
    ['cyrillic e', 'www.еxample.com'],
    ['different TLD', 'www.example.co'],
    ['NUL', 'www.example.com\u0000'],
    ['empty', ''],
  ])('%s is not within example.com', (_label, host) => {
    expect(isWithinDomain(host, 'example.com')).toBe(false);
  });

  it.each([
    ['empty leading label', '.example.com'],
    ['empty inner label', 'www..example.com'],
  ])('malformed name with %s is not within example.com', (_label, host) => {
    expect(isWithinDomain(host, 'example.com')).toBe(false);
  });
});
