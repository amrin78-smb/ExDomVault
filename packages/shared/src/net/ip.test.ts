import { describe, expect, it } from 'vitest';
import {
  canonicalCidr,
  canonicalIp,
  cidrContains,
  cidrsOverlap,
  isProhibitedAddress,
  isPublicCidr,
  parseCidr,
  parseIp,
  PROHIBITED_RANGES,
} from './ip.ts';

describe('parseIp', () => {
  it.each([
    ['0.0.0.0', 4],
    ['8.8.8.8', 4],
    ['255.255.255.255', 4],
    ['::', 6],
    ['::1', 6],
    ['2606:4700::1111', 6],
    ['2606:4700:0:0:0:0:0:1111', 6],
    ['2606:4700:0000:0000:0000:0000:0000:1111', 6],
    ['2606:4700::', 6],
    ['1:2:3:4:5:6:7::', 6],
    ['::2:3:4:5:6:7:8', 6],
    ['2001:DB8::ABCD', 6],
    ['::ffff:192.0.2.1', 6],
    ['64:ff9b::8.8.8.8', 6],
  ])('accepts %s', (text, version) => {
    expect(parseIp(text)?.version).toBe(version);
  });

  it.each([
    '',
    ' 8.8.8.8',
    '8.8.8.8 ',
    '8.8.8',
    '8.8.8.8.8',
    '127.1',
    '0x7f.1',
    '0x7f.0.0.1',
    '017.0.0.1',
    '010.0.0.1',
    '00.0.0.0',
    '2130706433',
    '0x7f000001',
    '256.0.0.1',
    '1.2.3.-4',
    '1.2.3.4/32',
    '1..2.3',
    '+1.2.3.4',
    '１.2.3.4',
    'fe80::1%eth0',
    'fe80::1%25eth0',
    '[::1]',
    ':::',
    '1::2::3',
    ':1::',
    '1:2:3:4:5:6:7:8:9',
    '1:2:3:4:5:6:7',
    '1:2:3:4:5:6:7:8::',
    '12345::',
    'g::1',
    '::1.2.3',
    '::01.2.3.4',
    '1.2.3.4::',
    '::1.2.3.4:5',
    'localhost',
  ])('rejects %j', (text) => {
    expect(parseIp(text)).toBeNull();
    expect(isProhibitedAddress(text)).toBe(true);
  });

  it('canonicalises addresses (RFC 5952)', () => {
    expect(canonicalIp('2606:4700:0000:0000:0000:0000:0000:1111')).toBe('2606:4700::1111');
    expect(canonicalIp('2001:DB8:0:0:1:0:0:1')).toBe('2001:db8::1:0:0:1');
    expect(canonicalIp('2001:db8:0:1:1:1:1:1')).toBe('2001:db8:0:1:1:1:1:1');
    expect(canonicalIp('::ffff:c000:0201')).toBe('::ffff:192.0.2.1');
    expect(canonicalIp('0:0:0:0:0:0:0:0')).toBe('::');
    expect(canonicalIp('8.8.4.4')).toBe('8.8.4.4');
  });
});

describe('isProhibitedAddress', () => {
  it.each([
    '0.0.0.0',
    '0.1.2.3',
    '10.0.0.1',
    '100.64.0.1',
    '100.127.255.255',
    '127.0.0.1',
    '127.255.255.254',
    '169.254.169.254',
    '172.16.0.1',
    '172.31.255.255',
    '192.0.0.8',
    '192.0.2.10',
    '192.88.99.1',
    '192.168.1.1',
    '198.18.0.1',
    '198.19.255.255',
    '198.51.100.7',
    '203.0.113.9',
    '224.0.0.1',
    '239.255.255.250',
    '240.0.0.1',
    '255.255.255.255',
    '::',
    '::1',
    '::127.0.0.1',
    '::8.8.8.8',
    '::ffff:127.0.0.1',
    '::ffff:8.8.8.8',
    '::ffff:7f00:1',
    '64:ff9b::7f00:1',
    '64:ff9b::8.8.8.8',
    '64:ff9b:1::1',
    '100::1',
    '2001::1',
    '2001:0:4136:e378:8000:63bf:3fff:fdd2',
    '2001:2::1',
    '2001:10::1',
    '2001:20::1',
    '2001:db8::1',
    '2002:7f00:1::1',
    '2002:808:808::1',
    'fc00::1',
    'fd12:3456:789a::1',
    'fe80::1',
    'febf::1',
    'fec0::1',
    'ff02::1',
    '4000::1',
    '1::1',
  ])('prohibits %s', (ip) => {
    expect(isProhibitedAddress(ip)).toBe(true);
  });

  it.each([
    '8.8.8.8',
    '1.1.1.1',
    '100.63.255.255',
    '100.128.0.0',
    '172.15.255.255',
    '172.32.0.0',
    '192.0.1.255',
    '198.17.255.255',
    '198.20.0.0',
    '223.255.255.255',
    '2606:4700:4700::1111',
    '2a00:1450:4001::200e',
    '2001:4860:4860::8888',
    '2003::1',
  ])('allows public %s', (ip) => {
    expect(isProhibitedAddress(ip)).toBe(false);
  });

  it('has only valid prohibited ranges', () => {
    for (const r of PROHIBITED_RANGES) expect(parseCidr(r.cidr), r.cidr).not.toBeNull();
  });
});

describe('CIDR helpers', () => {
  it('canonicalises networks and single addresses', () => {
    expect(canonicalCidr('8.8.8.8')).toBe('8.8.8.8/32');
    expect(canonicalCidr('8.8.8.77/24')).toBe('8.8.8.0/24');
    expect(canonicalCidr(' 8.8.0.0/16 ')).toBe('8.8.0.0/16');
    expect(canonicalCidr('2606:4700::1')).toBe('2606:4700::1/128');
    expect(canonicalCidr('2606:4700:ABCD:1::/48')).toBe('2606:4700:abcd::/48');
    expect(canonicalCidr('0.0.0.0/0')).toBe('0.0.0.0/0');
  });

  it.each(['8.8.8.8/33', '8.8.8.8/', '8.8.8.8/024', '8.8.8.8/-1', '::/129', '8.8.8.8/24/1', 'x/8'])(
    'rejects %j',
    (text) => {
      expect(canonicalCidr(text)).toBeNull();
    },
  );

  it('checks containment', () => {
    expect(cidrContains('8.8.8.0/24', '8.8.8.255')).toBe(true);
    expect(cidrContains('8.8.8.0/24', '8.8.9.0')).toBe(false);
    expect(cidrContains('8.8.8.8/32', '8.8.8.8')).toBe(true);
    expect(cidrContains('2606:4700::/32', '2606:4700:1::1')).toBe(true);
    expect(cidrContains('2606:4700::/32', '2606:4701::1')).toBe(false);
    // Versions never mix: a mapped IPv6 address is not inside an IPv4 network.
    expect(cidrContains('8.8.8.0/24', '::ffff:8.8.8.8')).toBe(false);
    expect(cidrContains('8.8.8.0/24', '8.8.8.08')).toBe(false);
    expect(cidrContains('bad', '8.8.8.8')).toBe(false);
  });

  it('detects overlap', () => {
    expect(cidrsOverlap('8.8.0.0/16', '8.8.8.0/24')).toBe(true);
    expect(cidrsOverlap('8.8.8.0/24', '8.8.0.0/16')).toBe(true);
    expect(cidrsOverlap('8.8.8.0/24', '8.8.9.0/24')).toBe(false);
  });

  it('requires the whole range to be public', () => {
    expect(isPublicCidr('8.8.8.0/24')).toBe(true);
    expect(isPublicCidr('2606:4700::/32')).toBe(true);
    expect(isPublicCidr('10.0.0.0/24')).toBe(false);
    // Covers prohibited space even though its network address is public.
    expect(isPublicCidr('192.0.0.0/16')).toBe(false);
    expect(isPublicCidr('100.0.0.0/8')).toBe(false);
    expect(isPublicCidr('0.0.0.0/0')).toBe(false);
    expect(isPublicCidr('2000::/3')).toBe(false);
    expect(isPublicCidr('2001::/16')).toBe(false);
    expect(isPublicCidr('::/0')).toBe(false);
    expect(isPublicCidr('garbage')).toBe(false);
  });
});
