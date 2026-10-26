import { schema, type Database } from '@exdomainvault/database';
import {
  EXPORT_COLUMNS,
  type AssetListQuery,
  type AuditListQuery,
  type CurrentUser,
  type DomainListQuery,
  type ExportResource,
  type ScanJobListQuery,
  type SoftwareListQuery,
  type UserListQuery,
} from '@exdomainvault/shared';
import { and, count, eq, sql } from 'drizzle-orm';
import { toCsv, type CsvValue } from '../lib/csv-export.ts';
import { assetBaseQuery, assetListWhere, ASSET_ORDER, currentIpsOf, toAssetDto } from './assets.ts';
import { AUDIT_ORDER, auditListWhere } from './audit-log.ts';
import { writeAudit } from './audit.ts';
import { domainListOrder, domainListWhere, toDomainDto, type Actor } from './domains.ts';
import { ADVISORY_ORDER, advisoryListWhere } from './findings.ts';
import {
  certificateItems,
  countCertificates,
  countPorts,
  portItems,
  vulnerabilityItems,
  type CertificatesFilter,
  type PortsFilter,
  type VulnerabilitiesFilter,
} from './inventory.ts';
import { baseJobQuery, SCAN_ORDER, scanListWhere, targetCounts } from './scans.ts';
import {
  matchesStatus,
  SOFTWARE_ORDER,
  softwareConditions,
  softwareRowSelect,
  statusCandidateConditions,
  statusComputer,
  toSoftwareItem,
} from './software.ts';
import { userListWhere } from './user-admin.ts';

/**
 * CSV exports (`GET /exports/<resource>.csv`, contract in packages/shared/src/api/exports.ts).
 * Each loader reuses its list endpoint's WHERE / ORDER BY builders (visibility included), so an
 * export contains exactly the rows the list would page through. Loaders fetch `limit` rows
 * (the cap + 1, to detect truncation); the total is only counted when the cap was exceeded.
 */

type User = Pick<CurrentUser, 'id' | 'role'>;
type Paging = 'page' | 'pageSize';

const { advisories, assets, auditLogs, domains, findings, scanJobs, softwareInventory, users } =
  schema;

export interface Loaded {
  rows: CsvValue[][];
  /** Rows that matched in total (a thunk: only evaluated when the cap was exceeded). */
  total: number | (() => Promise<number>);
  /** The loader stopped scanning early, so more rows may have matched than `total`. */
  incomplete?: boolean;
}

export type Loader<Q> = (
  tx: Database,
  user: User,
  q: Q,
  now: Date,
  limit: number,
) => Promise<Loaded>;

export interface ExportResult {
  csv: string;
  rows: number;
  truncated: boolean;
  totalRows: number;
}

/**
 * Runs one export in a transaction: loads at most `maxRows` rows (+1 to detect truncation), builds
 * the CSV and writes the `report.exported` audit record in the same transaction as the read.
 */
export async function runExport(
  db: Database,
  args: {
    resource: ExportResource;
    filters: Record<string, unknown>;
    actor: Actor;
    maxRows: number;
  },
  load: (tx: Database, limit: number) => Promise<Loaded>,
): Promise<ExportResult> {
  return db.transaction(async (raw) => {
    const tx = raw as unknown as Database;
    const loaded = await load(tx, args.maxRows + 1);
    const over = loaded.rows.length > args.maxRows;
    const kept = over ? loaded.rows.slice(0, args.maxRows) : loaded.rows;
    const truncated = over || loaded.incomplete === true;
    const totalRows = !truncated
      ? kept.length
      : typeof loaded.total === 'number'
        ? loaded.total
        : await loaded.total();
    const csv = toCsv(EXPORT_COLUMNS[args.resource], kept);
    await writeAudit(tx, {
      actorType: 'user',
      actorUserId: args.actor.userId,
      action: 'report.exported',
      resourceType: 'report',
      resourceId: `${args.resource}.csv`,
      requestId: args.actor.requestId,
      metadata: {
        resource: args.resource,
        filters: args.filters,
        rows: kept.length,
        truncated,
      },
    });
    return { csv, rows: kept.length, truncated, totalRows };
  });
}

const countOf = async (q: Promise<{ n: number }[]>) => (await q)[0]?.n ?? 0;

// --- Domains ------------------------------------------------------------------------------------

// Written with explicit table names: drizzle renders columns unqualified in a single-table select,
// which would bind `domain_id = id` inside the subquery to the findings table.
const openFindingCount = sql<number>`(
  select count(*)::int from findings f
  where f.domain_id = "domains"."id" and f.status <> 'resolved'
)`;

export const loadDomains: Loader<Omit<DomainListQuery, Paging>> = async (
  tx,
  _user,
  q,
  _now,
  limit,
) => {
  const where = domainListWhere(q);
  const rows = await tx
    .select({ d: domains, open: openFindingCount })
    .from(domains)
    .where(where)
    .orderBy(...domainListOrder(q.sort))
    .limit(limit);
  return {
    rows: rows.map(({ d, open }) => {
      const dto = toDomainDto(d);
      return [
        d.fqdn,
        dto.unicodeFqdn,
        d.verificationStatus,
        d.verificationMethod,
        d.verificationExpiresAt,
        d.criticality,
        d.businessOwner,
        d.monitoringEnabled,
        d.registrar,
        d.expiresAt,
        Number(open),
        d.createdAt,
      ];
    }),
    total: () => countOf(tx.select({ n: count() }).from(domains).where(where)),
  };
};

// --- Assets -------------------------------------------------------------------------------------

export const loadAssets: Loader<Omit<AssetListQuery, Paging>> = async (
  tx,
  user,
  q,
  _now,
  limit,
) => {
  const where = assetListWhere(user, q);
  const rows = await assetBaseQuery(tx)
    .where(where)
    .orderBy(...ASSET_ORDER[q.sort])
    .limit(limit);
  const ips = await currentIpsOf(
    tx,
    rows.map((r) => r.a.id),
  );
  return {
    rows: rows.map((r) => {
      const a = toAssetDto(r, ips.get(r.a.id) ?? []);
      return [
        a.hostname,
        a.domain.fqdn,
        a.assetType,
        a.status,
        a.source,
        a.currentIps,
        a.hostingHint?.provider ?? null,
        a.wildcardOnly,
        a.owner?.email ?? null,
        a.decidedBy?.email ?? null,
        a.decidedAt,
        a.decisionReason,
        a.firstSeenAt,
        a.lastSeenAt,
        a.activeFindings,
      ];
    }),
    total: () => countOf(tx.select({ n: count() }).from(assets).where(where)),
  };
};

// --- Advisories ---------------------------------------------------------------------------------

export const loadAdvisories: Loader<{ status: 'active' | 'all' }> = async (
  tx,
  user,
  q,
  _now,
  limit,
) => {
  const where = advisoryListWhere(tx, user, q.status);
  const rows = await tx
    .select({ a: advisories, f: findings, fqdn: domains.fqdn })
    .from(advisories)
    .innerJoin(findings, eq(findings.id, advisories.findingId))
    .innerJoin(domains, eq(domains.id, findings.domainId))
    .where(where)
    .orderBy(...ADVISORY_ORDER)
    .limit(limit);
  return {
    rows: rows.map(({ a, f, fqdn }) => [
      f.id,
      f.ruleId,
      f.severity,
      f.riskScore,
      f.status,
      fqdn,
      f.hostname,
      a.title,
      a.summary,
      a.businessImpact,
      a.recommendedActions,
      a.referenceLinks,
    ]),
    total: () =>
      countOf(
        tx
          .select({ n: count() })
          .from(advisories)
          .innerJoin(findings, eq(findings.id, advisories.findingId))
          .where(where),
      ),
  };
};

// --- Software -----------------------------------------------------------------------------------

/** Inventory rows read per batch when filtering by computed status (eol / kev). */
export const SOFTWARE_EXPORT_BATCH = 2500;
/** Candidate rows scanned at most for a status-filtered export; beyond it the export is truncated. */
export const SOFTWARE_EXPORT_SCAN_LIMIT = 50_000;

type SoftwareRow = { row: typeof softwareInventory.$inferSelect; fqdn: string };
type Status = Parameters<typeof toSoftwareItem>[1];

function softwareCells(r: SoftwareRow, s: Status): CsvValue[] {
  const item = toSoftwareItem(r, s);
  return [
    item.domain.fqdn,
    item.hostname,
    item.ipAddress,
    item.port,
    item.source,
    item.product,
    item.version,
    item.eol?.cycle ?? null,
    item.eol?.eolDate ?? null,
    item.eol ? item.eol.isEol : null,
    item.knownExploited.map((k) => k.cveId),
    item.backportHint?.distribution ?? null,
    item.banner,
    item.firstSeenAt,
    item.lastSeenAt,
  ];
}

/**
 * Software: end-of-life and known-exploited status are computed per row exactly as GET /software
 * does, from intelligence loaded ONCE for every product the export can contain, then matched in
 * memory. `status=eol|kev` scans the candidate rows in batches (bounded by
 * SOFTWARE_EXPORT_SCAN_LIMIT) and keeps only matching ones.
 */
export const loadSoftware: Loader<Omit<SoftwareListQuery, Paging>> = async (
  tx,
  user,
  q,
  now,
  limit,
) => {
  const base = softwareConditions(tx, user, q);
  const from = () =>
    tx
      .select(softwareRowSelect)
      .from(softwareInventory)
      .innerJoin(domains, eq(domains.id, softwareInventory.domainId));

  if (q.status === 'all') {
    const where = and(...base);
    const rows = await from()
      .where(where)
      .orderBy(...SOFTWARE_ORDER)
      .limit(limit);
    const status = await statusComputer(
      tx,
      rows.map((r) => r.row.product),
      now,
    );
    return {
      rows: rows.map((r) => softwareCells(r, status(r.row.product, r.row.version))),
      total: () =>
        countOf(
          tx
            .select({ n: count() })
            .from(softwareInventory)
            .innerJoin(domains, eq(domains.id, softwareInventory.domainId))
            .where(where),
        ),
    };
  }

  const filter = q.status;
  const where = and(...base, ...statusCandidateConditions(tx, filter));
  const products = await tx
    .selectDistinct({ p: softwareInventory.product })
    .from(softwareInventory)
    .innerJoin(domains, eq(domains.id, softwareInventory.domainId))
    .where(where);
  const status = await statusComputer(
    tx,
    products.map((p) => p.p),
    now,
  );
  const out: CsvValue[][] = [];
  let matched = 0;
  let incomplete = false;
  for (let offset = 0; ; offset += SOFTWARE_EXPORT_BATCH) {
    if (offset >= SOFTWARE_EXPORT_SCAN_LIMIT) {
      incomplete = true;
      break;
    }
    const batch = await from()
      .where(where)
      .orderBy(...SOFTWARE_ORDER)
      .limit(SOFTWARE_EXPORT_BATCH)
      .offset(offset);
    for (const r of batch) {
      const s = status(r.row.product, r.row.version);
      if (!matchesStatus(filter, s)) continue;
      matched++;
      if (out.length < limit) out.push(softwareCells(r, s));
    }
    if (batch.length < SOFTWARE_EXPORT_BATCH) break;
  }
  return { rows: out, total: matched, incomplete };
};

// --- Scans --------------------------------------------------------------------------------------

export const loadScans: Loader<Omit<ScanJobListQuery, Paging>> = async (
  tx,
  _user,
  q,
  _now,
  limit,
) => {
  const where = scanListWhere(q);
  const rows = await baseJobQuery(tx)
    .where(where)
    .orderBy(...SCAN_ORDER)
    .limit(limit);
  const counts = await targetCounts(
    tx,
    rows.map((r) => r.job.id),
  );
  return {
    rows: rows.map((r) => {
      const j = r.job;
      const c = counts.get(j.id);
      const targets = c ? Object.values(c).reduce((n, v) => n + v, 0) : 0;
      const trigger = (j.scopeSnapshot as { trigger?: unknown }).trigger;
      return [
        j.id,
        j.jobType,
        r.fqdn,
        j.profile,
        trigger === 'schedule' ? 'schedule' : 'manual',
        j.status,
        r.requesterEmail,
        j.createdAt,
        j.startedAt,
        j.completedAt,
        j.startedAt && j.completedAt
          ? Math.max(0, Math.round((j.completedAt.getTime() - j.startedAt.getTime()) / 1000))
          : null,
        targets,
        c?.failed ?? 0,
        j.attempts,
        j.errorCode,
      ];
    }),
    total: () => countOf(tx.select({ n: count() }).from(scanJobs).where(where)),
  };
};

// --- Users --------------------------------------------------------------------------------------

export const loadUsers: Loader<Omit<UserListQuery, Paging>> = async (tx, _user, q, _now, limit) => {
  const where = userListWhere(q);
  const rows = await tx.select().from(users).where(where).orderBy(users.email).limit(limit);
  return {
    rows: rows.map((u) => [
      u.email,
      u.displayName,
      u.role,
      u.isActive,
      u.authProviderSubject !== null,
      u.lastLoginAt,
      u.createdAt,
    ]),
    total: () => countOf(tx.select({ n: count() }).from(users).where(where)),
  };
};

// --- Audit log ----------------------------------------------------------------------------------

export const loadAuditLogs: Loader<Omit<AuditListQuery, Paging>> = async (
  tx,
  _user,
  q,
  _now,
  limit,
) => {
  const where = auditListWhere(q);
  const rows = await tx
    .select({ a: auditLogs, email: users.email })
    .from(auditLogs)
    .leftJoin(users, eq(users.id, auditLogs.actorUserId))
    .where(where)
    .orderBy(...AUDIT_ORDER)
    .limit(limit);
  return {
    rows: rows.map(({ a, email }) => [
      a.createdAt,
      a.actorType,
      email,
      a.action,
      a.resourceType,
      a.resourceId,
      a.requestId,
      JSON.stringify(a.metadata),
    ]),
    total: () => countOf(tx.select({ n: count() }).from(auditLogs).where(where)),
  };
};

// --- Inventory views (Milestone 13) -------------------------------------------------------------

/** Ports: the rows GET /ports would page through (same CTEs, visibility and order). */
export const loadPorts: Loader<PortsFilter> = async (tx, user, q, _now, limit) => {
  const items = await portItems(tx, user, q, { limit, offset: 0 });
  return {
    rows: items.map((p) => [
      p.ipAddress,
      p.port,
      p.protocol,
      p.state,
      p.service,
      p.hostnames.map((h) => h.hostname),
      p.domain?.fqdn ?? null,
      p.country,
      p.policyViolation,
      p.firstObservedAt,
      p.lastObservedAt,
    ]),
    total: () => countPorts(tx, user, q),
  };
};

/** Certificates: the rows GET /certificates would page through; `days_left` relative to `now`. */
export const loadCertificates: Loader<CertificatesFilter> = async (tx, user, q, now, limit) => {
  const items = await certificateItems(tx, user, q, now, { limit, offset: 0 });
  return {
    rows: items.map((c) => [
      c.hostname,
      c.domain.fqdn,
      c.ipAddress,
      c.port,
      c.status,
      c.issuer,
      c.subject,
      c.subjectAltNames,
      c.notBefore,
      c.notAfter,
      c.daysLeft,
      c.hostnameMatches,
      c.trusted,
      c.protocolVersion,
      c.observedAt,
    ]),
    total: () => countCertificates(tx, user, q, now),
  };
};

/**
 * Vulnerabilities: GET /vulnerabilities computes the whole (bounded) CVE set in memory, so the
 * export takes its first `limit` rows and the total is known.
 */
export const loadVulnerabilities: Loader<VulnerabilitiesFilter> = async (
  tx,
  user,
  q,
  _now,
  limit,
) => {
  const items = await vulnerabilityItems(tx, user, q);
  return {
    rows: items
      .slice(0, limit)
      .map((v) => [
        v.cve,
        v.title,
        v.cvss === null ? null : Math.round(v.cvss * 10) / 10,
        v.kev,
        v.knownRansomwareUse,
        v.products.map((p) => p.product),
        v.affectedHosts,
        v.affectedDomains,
        v.openFindings,
        v.kevDateAdded,
      ]),
    total: items.length,
  };
};
