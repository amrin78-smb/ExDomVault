import { z } from 'zod';
import { assetStatusSchema, hostingHintSchema } from './assets.ts';

/**
 * Host import (owner request 2026-10-26): add known hostnames of a domain (a DNS zone export, a
 * CSV/XLSX record list or a plain list) as `pending` assets. Discovery from CT logs misses hosts
 * behind wildcard certificates or without public certificates; this closes that gap.
 *
 *   POST /api/v1/domains/:id/assets/import   (`domains:write`)
 *
 * - The browser extracts entries from the file (`extractHostEntries`); the server re-validates
 *   every hostname (normalisation, exact label boundary within the domain) and never trusts the
 *   client's classification.
 * - New hostnames become `pending` assets with source `import`. Importing NEVER approves, never
 *   changes an existing asset, and never schedules a scan: approval stays the only way into scope.
 * - A CNAME target from the file feeds `classifyHosting`, so third-party hosting needs the usual
 *   acknowledgement on approval. The hint is refreshed from live DNS once the asset is monitored.
 * - `dryRun: true` returns the same per-row outcome without writing (the preview). A real import is
 *   one transaction, audited once as `asset.imported` with counts and the file name.
 */

export const ASSET_IMPORT_MAX_ENTRIES = 5000;

export const assetImportEntrySchema = z.object({
  hostname: z.string().min(1).max(253),
  /** CNAME target from the file (absolute, trailing dot optional), used only for the hosting hint. */
  cnameTarget: z.string().min(1).max(253).optional(),
});
export type AssetImportEntry = z.infer<typeof assetImportEntrySchema>;

export const assetImportRequestSchema = z.object({
  entries: z.array(assetImportEntrySchema).min(1).max(ASSET_IMPORT_MAX_ENTRIES),
  dryRun: z.boolean().default(false),
  /** Original file name, for the audit record only. */
  fileName: z.string().max(255).optional(),
});
export type AssetImportRequest = z.input<typeof assetImportRequestSchema>;

export const ASSET_IMPORT_OUTCOMES = [
  /** Will be (or was) added as a pending asset. */
  'new',
  /** Already an asset of this domain; left untouched. */
  'existing',
  /** Same hostname earlier in the request. */
  'duplicate',
  /** Not a valid hostname (after normalisation). */
  'invalid',
  /** Valid, but not the domain itself or beneath it. */
  'out_of_domain',
] as const;
export type AssetImportOutcome = (typeof ASSET_IMPORT_OUTCOMES)[number];

export const assetImportRowSchema = z.object({
  /** Normalised hostname, or the input as given when invalid. */
  hostname: z.string(),
  outcome: z.enum(ASSET_IMPORT_OUTCOMES),
  /** Status of the existing asset (`existing`) — e.g. already approved. */
  existingStatus: assetStatusSchema.optional(),
  hostingHint: hostingHintSchema.nullable(),
});
export type AssetImportRow = z.infer<typeof assetImportRowSchema>;

export const assetImportResponseSchema = z.object({
  dryRun: z.boolean(),
  summary: z.object({
    total: z.number().int(),
    new: z.number().int(),
    existing: z.number().int(),
    duplicate: z.number().int(),
    invalid: z.number().int(),
    outOfDomain: z.number().int(),
    thirdPartyHosted: z.number().int(),
  }),
  rows: z.array(assetImportRowSchema),
});
export type AssetImportResponse = z.infer<typeof assetImportResponseSchema>;

// ---------------------------------------------------------------------------------------------
// File → entries (pure; used by the browser before upload, and by tests)
// ---------------------------------------------------------------------------------------------

/** Record types that name a host worth monitoring. Everything else (TXT, MX, NS, SRV…) is skipped. */
const HOST_RECORD_TYPES = new Set(['A', 'AAAA', 'CNAME']);

export interface ExtractedHosts {
  entries: AssetImportEntry[];
  /** Rows ignored before upload, by reason (for the preview). */
  skipped: { recordType: number; serviceName: number; wildcard: number; empty: number };
  format: 'records' | 'zone' | 'list';
}

const NAME_HEADERS = ['name', 'host', 'hostname', 'fqdn', 'record', 'record name', 'subdomain'];
const TYPE_HEADERS = ['type', 'record type', 'rrtype'];
const DATA_HEADERS = ['data', 'value', 'target', 'content', 'answer', 'rdata', 'points to'];
const ZONE_HEADERS = ['zone', 'zonename', 'zone name', 'origin'];

const strip = (s: string) => s.trim().replace(/^"|"$/g, '').trim();

/**
 * Makes a record name absolute. `''`/`@` = the origin; a trailing dot = already absolute; a name
 * equal to or ending with the origin = absolute without the dot; anything else is relative.
 */
export function absoluteName(name: string, origin: string): string {
  const o = origin.toLowerCase().replace(/\.$/, '');
  const n = name.trim().toLowerCase();
  if (n === '' || n === '@') return o;
  if (n.endsWith('.')) return n.slice(0, -1);
  if (n === o || n.endsWith(`.${o}`)) return n;
  return `${n}.${o}`;
}

function classify(name: string, out: ExtractedHosts, push: () => void): void {
  if (name === '') out.skipped.empty++;
  else if (name.split('.').some((l) => l.startsWith('_'))) out.skipped.serviceName++;
  else if (name.split('.').includes('*')) out.skipped.wildcard++;
  else push();
}

/**
 * Extracts host entries from tabular rows (CSV or spreadsheet). With a header row naming a host
 * column (and optionally type / data / zone), only A, AAAA and CNAME rows are kept and relative
 * names are made absolute against the zone column or `origin`. Without a recognised header, every
 * non-empty first cell is taken as a hostname.
 */
export function extractHostEntriesFromRows(
  rows: readonly string[][],
  origin: string,
): ExtractedHosts {
  const out: ExtractedHosts = {
    entries: [],
    skipped: { recordType: 0, serviceName: 0, wildcard: 0, empty: 0 },
    format: 'records',
  };
  const header = (rows[0] ?? []).map((c) => strip(c).toLowerCase());
  const col = (names: string[]) => header.findIndex((h) => names.includes(h));
  const nameCol = col(NAME_HEADERS);
  if (nameCol < 0) {
    out.format = 'list';
    for (const row of rows) {
      const cell = strip(row[0] ?? '');
      if (cell === '') continue;
      const name = absoluteName(cell, origin);
      classify(name, out, () => out.entries.push({ hostname: name }));
    }
    return out;
  }
  const typeCol = col(TYPE_HEADERS);
  const dataCol = col(DATA_HEADERS);
  const zoneCol = col(ZONE_HEADERS);
  for (const row of rows.slice(1)) {
    if (row.every((c) => strip(c) === '')) continue;
    const type = typeCol >= 0 ? strip(row[typeCol] ?? '').toUpperCase() : '';
    if (typeCol >= 0 && !HOST_RECORD_TYPES.has(type)) {
      out.skipped.recordType++;
      continue;
    }
    const zone =
      zoneCol >= 0 && strip(row[zoneCol] ?? '') !== '' ? strip(row[zoneCol] ?? '') : origin;
    const name = absoluteName(strip(row[nameCol] ?? ''), zone);
    const data = dataCol >= 0 ? strip(row[dataCol] ?? '') : '';
    classify(name, out, () =>
      out.entries.push(
        type === 'CNAME' && data !== ''
          ? { hostname: name, cnameTarget: absoluteName(data, zone) }
          : { hostname: name },
      ),
    );
  }
  return out;
}

const RR_TYPES =
  /^(A|AAAA|CNAME|MX|NS|TXT|SRV|SOA|CAA|PTR|DS|DNSKEY|HTTPS|SVCB|TLSA|SPF|NAPTR|SSHFP|ALIAS)$/i;

/**
 * Extracts host entries from a BIND-style zone file (`$ORIGIN`, `@`, relative names, owner names
 * inherited by indented lines, optional TTL/class). Comments (`;`) are ignored; parenthesised
 * multi-line records (SOA, long TXT) are skipped as non-host records.
 */
export function extractHostEntriesFromZone(text: string, origin: string): ExtractedHosts {
  const out: ExtractedHosts = {
    entries: [],
    skipped: { recordType: 0, serviceName: 0, wildcard: 0, empty: 0 },
    format: 'zone',
  };
  let currentOrigin = origin;
  let lastOwner = origin;
  let inParens = false;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/;.*$/, '');
    if (inParens) {
      if (line.includes(')')) inParens = false;
      continue;
    }
    if (line.trim() === '') continue;
    if (line.includes('(') && !line.includes(')')) inParens = true;
    const tokens = line.trim().split(/\s+/);
    const directive = tokens[0]?.toUpperCase();
    if (directive === '$ORIGIN' && tokens[1]) {
      currentOrigin = absoluteName(tokens[1], origin);
      continue;
    }
    if (directive?.startsWith('$')) continue;
    const inherited = /^\s/.test(line);
    const owner = inherited ? lastOwner : absoluteName(tokens.shift() ?? '', currentOrigin);
    lastOwner = owner;
    // Skip optional TTL and class to reach the type.
    while (tokens.length > 0 && !RR_TYPES.test(tokens[0] ?? '')) tokens.shift();
    const type = (tokens.shift() ?? '').toUpperCase();
    if (!HOST_RECORD_TYPES.has(type)) {
      out.skipped.recordType++;
      continue;
    }
    const data = tokens[0] ?? '';
    classify(owner, out, () =>
      out.entries.push(
        type === 'CNAME' && data !== ''
          ? { hostname: owner, cnameTarget: absoluteName(data, currentOrigin) }
          : { hostname: owner },
      ),
    );
  }
  return out;
}

/** True when the text looks like a BIND zone file rather than CSV or a plain list. */
export function looksLikeZoneFile(text: string): boolean {
  return (
    /^\$ORIGIN\s/im.test(text) ||
    /^\S+\s+(\d+\s+)?(IN\s+)?SOA\s/im.test(text) ||
    /^\S+\s+(\d+\s+)?(IN\s+)?(A|AAAA|CNAME)\s+[^\s,]+\s*$/im.test(text)
  );
}
