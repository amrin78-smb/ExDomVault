/**
 * The single list of address ranges that are never valid scan destinations (non-public,
 * special-purpose or embedding another address). The Python worker keeps its own copy in
 * `worker/app/policy.py` (`_IPV4_PROHIBITED`, `_IPV6_PROHIBITED`); `prohibited-ranges.test.ts`
 * fails if the two lists drift apart.
 *
 * A plain `.ts` constant (not JSON) so it bundles identically in the Worker, the SPA and Node.
 */
export interface ProhibitedRange {
  cidr: string;
  /** Category, matching the worker's refusal reason where one exists. */
  category: string;
  label: string;
}

export const PROHIBITED_RANGES: readonly ProhibitedRange[] = Object.freeze([
  // IPv4
  { cidr: '0.0.0.0/8', category: 'unspecified', label: 'unspecified / "this network"' },
  { cidr: '10.0.0.0/8', category: 'private', label: 'private (RFC 1918)' },
  { cidr: '100.64.0.0/10', category: 'cgnat', label: 'carrier-grade NAT' },
  { cidr: '127.0.0.0/8', category: 'loopback', label: 'loopback' },
  { cidr: '169.254.0.0/16', category: 'link_local', label: 'link-local' },
  { cidr: '172.16.0.0/12', category: 'private', label: 'private (RFC 1918)' },
  { cidr: '192.0.0.0/24', category: 'reserved', label: 'IETF protocol assignments' },
  { cidr: '192.0.2.0/24', category: 'documentation', label: 'documentation' },
  { cidr: '192.88.99.0/24', category: '6to4', label: '6to4 relay anycast (deprecated)' },
  { cidr: '192.168.0.0/16', category: 'private', label: 'private (RFC 1918)' },
  { cidr: '198.18.0.0/15', category: 'benchmarking', label: 'benchmarking' },
  { cidr: '198.51.100.0/24', category: 'documentation', label: 'documentation' },
  { cidr: '203.0.113.0/24', category: 'documentation', label: 'documentation' },
  { cidr: '224.0.0.0/4', category: 'multicast', label: 'multicast' },
  { cidr: '255.255.255.255/32', category: 'broadcast', label: 'broadcast' },
  { cidr: '240.0.0.0/4', category: 'reserved', label: 'reserved (class E)' },
  // IPv6
  { cidr: '::/128', category: 'unspecified', label: 'unspecified' },
  { cidr: '::1/128', category: 'loopback', label: 'loopback' },
  { cidr: '::ffff:0:0/96', category: 'ipv4_mapped', label: 'IPv4-mapped' },
  { cidr: '::ffff:0:0:0/96', category: 'ipv4_mapped', label: 'IPv4-translated (SIIT)' },
  { cidr: '::/96', category: 'ipv4_compatible', label: 'IPv4-compatible' },
  { cidr: '64:ff9b::/96', category: 'nat64', label: 'NAT64' },
  { cidr: '64:ff9b:1::/48', category: 'nat64', label: 'NAT64 (local use)' },
  { cidr: '100::/64', category: 'discard', label: 'discard-only' },
  { cidr: '2001::/32', category: 'teredo', label: 'Teredo' },
  { cidr: '2001:2::/48', category: 'benchmarking', label: 'benchmarking' },
  { cidr: '2001:10::/28', category: 'reserved', label: 'ORCHID' },
  { cidr: '2001:20::/28', category: 'reserved', label: 'ORCHIDv2' },
  { cidr: '2001::/23', category: 'reserved', label: 'IETF protocol assignments' },
  { cidr: '2001:db8::/32', category: 'documentation', label: 'documentation' },
  { cidr: '3fff::/20', category: 'documentation', label: 'documentation (RFC 9637)' },
  { cidr: '2002::/16', category: '6to4', label: '6to4' },
  { cidr: 'fc00::/7', category: 'ula', label: 'unique local' },
  { cidr: 'fe80::/10', category: 'link_local', label: 'link-local' },
  { cidr: 'fec0::/10', category: 'site_local', label: 'site-local (deprecated)' },
  { cidr: 'ff00::/8', category: 'multicast', label: 'multicast' },
]);
