/**
 * Strict IP address and CIDR handling for the server-side scope checks (approved networks,
 * observation re-validation). Pure TypeScript (BigInt only): runs in Workers, browsers and Node.
 *
 * Parsing is deliberately strict. Only the canonical textual forms are accepted:
 *  - IPv4: exactly four dotted decimal octets, 0–255, no leading zeros (`017.0.0.1`, `0x7f.1`,
 *    `127.1`, `2130706433` are all rejected — the alternative encodings `inet_aton` would accept);
 *  - IPv6: RFC 4291 text form, optionally with a trailing dotted IPv4 part; no zone ids (`%eth0`),
 *    no brackets, no whitespace.
 * Anything that does not parse is treated as prohibited by `isProhibitedAddress` (fail closed).
 */

export type IpVersion = 4 | 6;

export interface ParsedIp {
  version: IpVersion;
  value: bigint;
}

export interface ParsedCidr {
  version: IpVersion;
  /** Network address (host bits zero). */
  network: bigint;
  prefix: number;
}

const BITS: Record<IpVersion, number> = { 4: 32, 6: 128 };

const OCTET_RE = /^(0|[1-9][0-9]{0,2})$/;
const HEXTET_RE = /^[0-9a-fA-F]{1,4}$/;
const PREFIX_RE = /^(0|[1-9][0-9]{0,2})$/;

function parseIpv4Value(text: string): bigint | null {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!OCTET_RE.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = (value << 8n) | BigInt(n);
  }
  return value;
}

function parseHextets(groups: string[]): bigint[] | null {
  const out: bigint[] = [];
  for (let i = 0; i < groups.length; i++) {
    const g = groups[i] as string;
    if (i === groups.length - 1 && g.includes('.')) {
      const v4 = parseIpv4Value(g);
      if (v4 === null) return null;
      out.push(v4 >> 16n, v4 & 0xffffn);
    } else {
      if (!HEXTET_RE.test(g)) return null;
      out.push(BigInt(parseInt(g, 16)));
    }
  }
  return out;
}

function parseIpv6Value(text: string): bigint | null {
  if (!/^[0-9a-fA-F:.]+$/.test(text)) return null; // also rejects zone ids, brackets, spaces
  const halves = text.split('::');
  if (halves.length > 2) return null;
  let groups: bigint[];
  if (halves.length === 2) {
    const [h, t] = halves as [string, string];
    const head = h === '' ? [] : parseHextets(h.split(':'));
    // An embedded IPv4 part is only valid at the very end.
    if (head && h.includes('.')) return null;
    const tail = t === '' ? [] : parseHextets(t.split(':'));
    if (!head || !tail) return null;
    const missing = 8 - head.length - tail.length;
    if (missing < 1) return null;
    groups = [...head, ...Array<bigint>(missing).fill(0n), ...tail];
  } else {
    const parsed = parseHextets(text.split(':'));
    if (!parsed || parsed.length !== 8) return null;
    groups = parsed;
  }
  return groups.reduce((acc, g) => (acc << 16n) | g, 0n);
}

/** Parses a single IPv4 or IPv6 address in strict canonical text form. */
export function parseIp(text: string): ParsedIp | null {
  if (typeof text !== 'string' || text.length === 0 || text.length > 45) return null;
  if (text.includes(':')) {
    const value = parseIpv6Value(text);
    return value === null ? null : { version: 6, value };
  }
  const value = parseIpv4Value(text);
  return value === null ? null : { version: 4, value };
}

/** Canonical text: dotted quad, or RFC 5952 IPv6 (lowercase, longest zero run compressed). */
export function formatIp(ip: ParsedIp): string {
  if (ip.version === 4) {
    return [24n, 16n, 8n, 0n].map((s) => ((ip.value >> s) & 0xffn).toString()).join('.');
  }
  const groups = Array.from({ length: 8 }, (_, i) =>
    Number((ip.value >> BigInt((7 - i) * 16)) & 0xffffn),
  );
  // IPv4-mapped addresses use the mixed notation (RFC 5952 §5).
  if (ip.value >> 32n === 0xffffn) {
    return `::ffff:${formatIp({ version: 4, value: ip.value & 0xffffffffn })}`;
  }
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = (gs: number[]) => gs.map((g) => g.toString(16)).join(':');
  if (bestLen < 2) return hex(groups);
  return `${hex(groups.slice(0, bestStart))}::${hex(groups.slice(bestStart + bestLen))}`;
}

const mask = (version: IpVersion, prefix: number): bigint => {
  const bits = BITS[version];
  const all = (1n << BigInt(bits)) - 1n;
  return prefix === 0 ? 0n : (all >> BigInt(bits - prefix)) << BigInt(bits - prefix);
};

/**
 * Parses `address/prefix` or a bare address (→ /32 or /128). Host bits are cleared, so
 * `192.0.2.7/24` becomes `192.0.2.0/24`.
 */
export function parseCidr(text: string): ParsedCidr | null {
  if (typeof text !== 'string') return null;
  const slash = text.indexOf('/');
  const addrText = slash === -1 ? text : text.slice(0, slash);
  const ip = parseIp(addrText);
  if (!ip) return null;
  let prefix = BITS[ip.version];
  if (slash !== -1) {
    const p = text.slice(slash + 1);
    if (!PREFIX_RE.test(p)) return null;
    prefix = Number(p);
    if (prefix > BITS[ip.version]) return null;
  }
  return { version: ip.version, network: ip.value & mask(ip.version, prefix), prefix };
}

export function formatCidr(c: ParsedCidr): string {
  return `${formatIp({ version: c.version, value: c.network })}/${c.prefix}`;
}

/** Canonical CIDR text (network address, explicit prefix), or null when invalid. */
export function canonicalCidr(input: string): string | null {
  const c = parseCidr(input.trim());
  return c ? formatCidr(c) : null;
}

/** Canonical text for an address, or null when invalid. */
export function canonicalIp(input: string): string | null {
  const ip = parseIp(input);
  return ip ? formatIp(ip) : null;
}

function contains(outer: ParsedCidr, inner: ParsedCidr): boolean {
  return (
    outer.version === inner.version &&
    outer.prefix <= inner.prefix &&
    (inner.network & mask(outer.version, outer.prefix)) === outer.network
  );
}

/** Two ranges overlap exactly when one contains the other. */
export function cidrsOverlap(a: string | ParsedCidr, b: string | ParsedCidr): boolean {
  const x = typeof a === 'string' ? parseCidr(a) : a;
  const y = typeof b === 'string' ? parseCidr(b) : b;
  if (!x || !y) return false;
  return contains(x, y) || contains(y, x);
}

/** Whether `ip` lies inside `cidr`. False when either does not parse or the versions differ. */
export function cidrContains(cidr: string, ip: string): boolean {
  const c = parseCidr(cidr);
  const a = parseIp(ip);
  if (!c || !a) return false;
  return contains(c, { version: a.version, network: a.value, prefix: BITS[a.version] });
}

/** Ranges that are never valid scan destinations (non-public, special-purpose or embedding). */
export const PROHIBITED_RANGES: readonly { cidr: string; label: string }[] = [
  // IPv4
  { cidr: '0.0.0.0/8', label: 'unspecified / "this network"' },
  { cidr: '10.0.0.0/8', label: 'private (RFC 1918)' },
  { cidr: '100.64.0.0/10', label: 'carrier-grade NAT' },
  { cidr: '127.0.0.0/8', label: 'loopback' },
  { cidr: '169.254.0.0/16', label: 'link-local' },
  { cidr: '172.16.0.0/12', label: 'private (RFC 1918)' },
  { cidr: '192.0.0.0/24', label: 'IETF protocol assignments' },
  { cidr: '192.0.2.0/24', label: 'documentation' },
  { cidr: '192.88.99.0/24', label: '6to4 relay anycast (deprecated)' },
  { cidr: '192.168.0.0/16', label: 'private (RFC 1918)' },
  { cidr: '198.18.0.0/15', label: 'benchmarking' },
  { cidr: '198.51.100.0/24', label: 'documentation' },
  { cidr: '203.0.113.0/24', label: 'documentation' },
  { cidr: '224.0.0.0/4', label: 'multicast' },
  { cidr: '240.0.0.0/4', label: 'reserved (incl. broadcast)' },
  // IPv6
  { cidr: '::/128', label: 'unspecified' },
  { cidr: '::1/128', label: 'loopback' },
  { cidr: '::/96', label: 'IPv4-compatible' },
  { cidr: '::ffff:0:0/96', label: 'IPv4-mapped' },
  { cidr: '64:ff9b::/96', label: 'NAT64' },
  { cidr: '64:ff9b:1::/48', label: 'NAT64 (local use)' },
  { cidr: '100::/64', label: 'discard-only' },
  { cidr: '2001::/32', label: 'Teredo' },
  { cidr: '2001:2::/48', label: 'benchmarking' },
  { cidr: '2001:10::/28', label: 'ORCHID' },
  { cidr: '2001:20::/28', label: 'ORCHIDv2' },
  { cidr: '2001:db8::/32', label: 'documentation' },
  { cidr: '2002::/16', label: '6to4' },
  { cidr: 'fc00::/7', label: 'unique local' },
  { cidr: 'fe80::/10', label: 'link-local' },
  { cidr: 'fec0::/10', label: 'site-local (deprecated)' },
  { cidr: 'ff00::/8', label: 'multicast' },
];

const PROHIBITED = PROHIBITED_RANGES.map((r) => parseCidr(r.cidr) as ParsedCidr);
/** Only global unicast space (2000::/3) is ever public IPv6; everything else is reserved. */
const IPV6_GLOBAL_UNICAST = parseCidr('2000::/3') as ParsedCidr;

/** Why a range is not public, or null when it lies entirely in public unicast space. */
export function prohibitedReason(range: ParsedCidr): string | null {
  for (const [i, p] of PROHIBITED.entries()) {
    if (contains(p, range) || contains(range, p)) return PROHIBITED_RANGES[i]?.label ?? 'reserved';
  }
  if (range.version === 6 && !contains(IPV6_GLOBAL_UNICAST, range)) {
    return 'reserved (outside global unicast)';
  }
  return null;
}

/**
 * True unless `ip` is a strictly formatted, public unicast address. Invalid or alternatively
 * encoded input is prohibited (fail closed).
 */
export function isProhibitedAddress(ip: string): boolean {
  const a = parseIp(ip);
  if (!a) return true;
  return (
    prohibitedReason({ version: a.version, network: a.value, prefix: BITS[a.version] }) !== null
  );
}

/** True when the whole range (CIDR text) is public: it overlaps no prohibited range. */
export function isPublicCidr(cidr: string): boolean {
  const c = parseCidr(cidr);
  return c !== null && prohibitedReason(c) === null;
}
