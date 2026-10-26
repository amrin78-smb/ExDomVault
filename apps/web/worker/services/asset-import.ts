import { schema, type Database } from '@exdomainvault/database';
import {
  classifyHosting,
  hostingHintSchema,
  type AssetImportEntry,
  type AssetImportResponse,
  type AssetImportRow,
  type AssetStatus,
  type HostingHint,
} from '@exdomainvault/shared';
import { normaliseDomain, isWithinDomain } from '@exdomainvault/shared/hostname';
import { and, eq, inArray } from 'drizzle-orm';
import { writeAudit } from './audit.ts';
import { getDomainRow, type Actor } from './domains.ts';

const { assets } = schema;

/**
 * Host import (contract: packages/shared/src/api/asset-import.ts). Every hostname is re-validated
 * here; the client's extraction is never trusted. New hostnames become `pending` assets with source
 * `import` and monitoring off. Existing assets are never changed, nothing is approved, nothing is
 * queued. Set-based: one select of existing hostnames and one insert (chunked) per request.
 */

/**
 * Body cap for this route only: 5 000 entries with a 253-character hostname and CNAME target each
 * is about 2.7 MB of JSON, above the 300 KB default of `parseJsonBody`.
 */
export const ASSET_IMPORT_MAX_BODY_BYTES = 4 * 1024 * 1024;

/** Rows per statement: keeps bind parameters far below PostgreSQL's 65 535 limit. */
const CHUNK = 1000;

/**
 * `normaliseDomain` rejections that mean the name itself is malformed. Every other rejection
 * (`not_registrable`, `public_suffix`, `private_suffix`, …) is about registrability, so the name is
 * a syntactically valid hostname — what matters here is only whether it is within the domain.
 */
const SYNTAX_REJECTIONS = new Set([
  'empty',
  'too_long',
  'invalid_characters',
  'wildcard',
  'ip_address',
  'invalid_label',
  'invalid_idn',
  'single_label',
]);

/** Canonical hostname (lowercase A-labels, no trailing dot), or null when it is not a valid host. */
export function normaliseImportHostname(input: string): string | null {
  const trimmed = input.trim();
  const labels = trimmed.replace(/\.$/, '').split('.');
  // Service names (`_dmarc`) and wildcards are DNS records, not hosts to monitor.
  if (labels.some((l) => l === '*' || l.startsWith('_'))) return null;
  const n = normaliseDomain(trimmed);
  if (n.ok) return n.fqdn;
  if (SYNTAX_REJECTIONS.has(n.reason)) return null;
  // Same canonicalisation normaliseDomain applied before its registrability checks.
  try {
    const host = new URL(`http://${trimmed}`).hostname.replace(/\.$/, '');
    return host.length > 0 && host.length <= 253 ? host : null;
  } catch {
    return null;
  }
}

function chunks<T>(items: readonly T[]): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += CHUNK) out.push(items.slice(i, i + CHUNK));
  return out;
}

const storedHint = (value: unknown): HostingHint | null => {
  const parsed = hostingHintSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
};

interface Plan {
  rows: AssetImportRow[];
  /** Hostnames planned as new, with their hint (first occurrence order). */
  fresh: Map<string, HostingHint | null>;
}

async function existingAssets(
  db: Database,
  domainId: string,
  hostnames: readonly string[],
): Promise<Map<string, { status: AssetStatus; hint: HostingHint | null }>> {
  const found = new Map<string, { status: AssetStatus; hint: HostingHint | null }>();
  for (const part of chunks(hostnames)) {
    const rows = await db
      .select({
        hostname: assets.hostname,
        status: assets.verificationStatus,
        hostingHint: assets.hostingHint,
      })
      .from(assets)
      .where(and(eq(assets.domainId, domainId), inArray(assets.hostname, part)));
    for (const r of rows)
      found.set(r.hostname, { status: r.status, hint: storedHint(r.hostingHint) });
  }
  return found;
}

async function plan(
  db: Database,
  domainId: string,
  fqdn: string,
  entries: readonly AssetImportEntry[],
): Promise<Plan> {
  const normalised = entries.map((e) => normaliseImportHostname(e.hostname));

  // Hosting hint per hostname over every CNAME target given for it (duplicate rows included).
  const targets = new Map<string, string[]>();
  normalised.forEach((h, i) => {
    const target = entries[i]?.cnameTarget;
    if (h === null) return;
    const list = targets.get(h) ?? [];
    if (target) list.push(target);
    targets.set(h, list);
  });
  const hints = new Map<string, HostingHint | null>();
  for (const [h, list] of targets) hints.set(h, list.length > 0 ? classifyHosting(list) : null);

  const inDomain = [...targets.keys()].filter((h) => isWithinDomain(h, fqdn));
  const existing = await existingAssets(db, domainId, inDomain);

  const seen = new Set<string>();
  const fresh = new Map<string, HostingHint | null>();
  const rows = entries.map((entry, i): AssetImportRow => {
    const h = normalised[i] ?? null;
    if (h === null) {
      return {
        hostname: entry.hostname.trim().slice(0, 253),
        outcome: 'invalid',
        hostingHint: null,
      };
    }
    const hint = hints.get(h) ?? null;
    if (!isWithinDomain(h, fqdn))
      return { hostname: h, outcome: 'out_of_domain', hostingHint: hint };
    if (seen.has(h)) return { hostname: h, outcome: 'duplicate', hostingHint: hint };
    seen.add(h);
    const asset = existing.get(h);
    if (asset) {
      return {
        hostname: h,
        outcome: 'existing',
        existingStatus: asset.status,
        hostingHint: asset.hint,
      };
    }
    fresh.set(h, hint);
    return { hostname: h, outcome: 'new', hostingHint: hint };
  });
  return { rows, fresh };
}

function summarise(rows: readonly AssetImportRow[]): AssetImportResponse['summary'] {
  const count = (o: AssetImportRow['outcome']) => rows.filter((r) => r.outcome === o).length;
  return {
    total: rows.length,
    new: count('new'),
    existing: count('existing'),
    duplicate: count('duplicate'),
    invalid: count('invalid'),
    outOfDomain: count('out_of_domain'),
    thirdPartyHosted: rows.filter((r) => r.outcome === 'new' && r.hostingHint !== null).length,
  };
}

export async function importAssets(
  db: Database,
  domainId: string,
  input: { entries: AssetImportEntry[]; dryRun: boolean; fileName?: string | undefined },
  actor: Actor,
  now: Date,
): Promise<AssetImportResponse> {
  const domain = await getDomainRow(db, domainId); // 404 when unknown

  if (input.dryRun) {
    const { rows } = await plan(db, domainId, domain.fqdn, input.entries);
    return { dryRun: true, summary: summarise(rows), rows };
  }

  return db.transaction(async (rawTx) => {
    const tx = rawTx as unknown as Database;
    const { rows, fresh } = await plan(tx, domainId, domain.fqdn, input.entries);

    const inserted = new Set<string>();
    for (const part of chunks([...fresh])) {
      const created = await tx
        .insert(assets)
        .values(
          part.map(([hostname, hint]) => ({
            domainId,
            hostname,
            assetType: hostname === domain.fqdn ? ('apex' as const) : ('subdomain' as const),
            discoverySource: 'import' as const,
            verificationStatus: 'pending' as const,
            monitoringEnabled: false,
            hostingHint: hint as Record<string, unknown> | null,
            firstSeenAt: now,
            lastSeenAt: now,
          })),
        )
        // A concurrent insert of the same hostname must not fail the import.
        .onConflictDoNothing({ target: [assets.domainId, assets.hostname] })
        .returning({ hostname: assets.hostname });
      for (const r of created) inserted.add(r.hostname);
    }

    // Hostnames that lost a race were created by someone else in the meantime: report as existing.
    const lost = [...fresh.keys()].filter((h) => !inserted.has(h));
    if (lost.length > 0) {
      const raced = await existingAssets(tx, domainId, lost);
      for (const row of rows) {
        if (row.outcome !== 'new' || inserted.has(row.hostname)) continue;
        const asset = raced.get(row.hostname);
        row.outcome = 'existing';
        if (asset) row.existingStatus = asset.status;
        row.hostingHint = asset?.hint ?? null;
      }
    }

    const summary = summarise(rows);
    await writeAudit(tx, {
      actorType: 'user',
      actorUserId: actor.userId,
      action: 'asset.imported',
      resourceType: 'domain',
      resourceId: domainId,
      requestId: actor.requestId,
      metadata: { fileName: input.fileName ?? null, ...summary },
    });
    return { dryRun: false, summary, rows };
  });
}
