import { schema, type Database } from '@exdomainvault/database';
import type { Rule } from '@exdomainvault/rules';
import {
  RULE_CATEGORIES,
  SEVERITIES,
  type AdvisoryDto,
  type AdvisoryListResponse,
  type CurrentUser,
  type Finding,
  type FindingDetailResponse,
  type FindingListQuery,
  type FindingListResponse,
  type FindingSummaryResponse,
  type RiskInputsDto,
  type RuleCatalogueEntry,
} from '@exdomainvault/shared';
import { and, asc, count, desc, eq, ilike, inArray, ne, or, type SQL } from 'drizzle-orm';
import { ApiError } from '../lib/errors.ts';

const { advisories, assets, domains, findingStatusHistory, findings, users } = schema;

type FindingRow = typeof findings.$inferSelect;
type AdvisoryRow = typeof advisories.$inferSelect;

/**
 * Read model for findings and advisories. Visibility is enforced here, server-side: asset owners
 * see only findings on assets they own (domain-level findings, which have no asset, are not
 * visible to them); every other role with `findings:read` sees everything.
 */
export function visibleTo(db: Database, user: Pick<CurrentUser, 'id' | 'role'>): SQL | undefined {
  if (user.role !== 'asset_owner') return undefined;
  return inArray(
    findings.assetId,
    db.select({ id: assets.id }).from(assets).where(eq(assets.ownerUserId, user.id)),
  );
}

const iso = (d: Date | null) => (d ? d.toISOString() : null);

export function toFindingDto(row: FindingRow, domain: { id: string; fqdn: string }): Finding {
  return {
    id: row.id,
    ruleId: row.ruleId,
    ruleVersion: row.ruleVersion,
    category: row.category as Finding['category'],
    domain,
    hostname: row.hostname,
    component: row.component,
    assetId: row.assetId,
    title: row.title,
    description: row.description,
    severity: row.severity,
    confidence: row.confidence,
    riskScore: row.riskScore,
    riskInputs: row.riskInputs as unknown as RiskInputsDto,
    status: row.status,
    evidence: row.evidence,
    firstSeenAt: row.firstSeenAt.toISOString(),
    lastSeenAt: row.lastSeenAt.toISOString(),
    resolvedAt: iso(row.resolvedAt),
    recurrenceCount: row.recurrenceCount,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

function toAdvisoryDto(row: AdvisoryRow): AdvisoryDto {
  return {
    id: row.id,
    findingId: row.findingId,
    title: row.title,
    summary: row.summary,
    businessImpact: row.businessImpact,
    recommendedActions: row.recommendedActions,
    references: row.referenceLinks,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

const escapeLike = (s: string) => s.replace(/[\\%_]/g, (m) => `\\${m}`);

function statusFilter(status: FindingListQuery['status']): SQL | undefined {
  if (status === 'all') return undefined;
  if (status === 'active') return ne(findings.status, 'resolved');
  return eq(findings.status, status);
}

function orderFor(sort: FindingListQuery['sort']): SQL[] {
  switch (sort) {
    case 'riskScore':
      return [asc(findings.riskScore), desc(findings.lastSeenAt), asc(findings.id)];
    case '-lastSeenAt':
      return [desc(findings.lastSeenAt), desc(findings.riskScore), asc(findings.id)];
    case '-firstSeenAt':
      return [desc(findings.firstSeenAt), desc(findings.riskScore), asc(findings.id)];
    case '-severity':
      // The severity enum is declared in ascending order, so DESC puts critical first.
      return [desc(findings.severity), desc(findings.riskScore), asc(findings.id)];
    case '-riskScore':
    default:
      return [desc(findings.riskScore), desc(findings.lastSeenAt), asc(findings.id)];
  }
}

export async function listFindings(
  db: Database,
  user: Pick<CurrentUser, 'id' | 'role'>,
  q: FindingListQuery,
): Promise<FindingListResponse> {
  const filters: (SQL | undefined)[] = [
    visibleTo(db, user),
    statusFilter(q.status),
    q.severity ? eq(findings.severity, q.severity) : undefined,
    q.category ? eq(findings.category, q.category) : undefined,
    q.domainId ? eq(findings.domainId, q.domainId.toLowerCase()) : undefined,
    q.ruleId ? eq(findings.ruleId, q.ruleId.toUpperCase()) : undefined,
  ];
  if (q.q) {
    const term = `%${escapeLike(q.q.toLowerCase())}%`;
    filters.push(or(ilike(findings.title, term), ilike(findings.hostname, term)));
  }
  const where = and(...filters);
  const [rows, [totalRow]] = await Promise.all([
    db
      .select({ f: findings, domainFqdn: domains.fqdn })
      .from(findings)
      .innerJoin(domains, eq(domains.id, findings.domainId))
      .where(where)
      .orderBy(...orderFor(q.sort))
      .limit(q.pageSize)
      .offset((q.page - 1) * q.pageSize),
    db.select({ total: count() }).from(findings).where(where),
  ]);
  return {
    items: rows.map((r) => toFindingDto(r.f, { id: r.f.domainId, fqdn: r.domainFqdn })),
    page: q.page,
    pageSize: q.pageSize,
    total: totalRow?.total ?? 0,
  };
}

export async function findingSummary(
  db: Database,
  user: Pick<CurrentUser, 'id' | 'role'>,
  domainId: string | undefined,
): Promise<FindingSummaryResponse> {
  const where = and(
    visibleTo(db, user),
    ne(findings.status, 'resolved'),
    domainId ? eq(findings.domainId, domainId.toLowerCase()) : undefined,
  );
  const rows = await db
    .select({ severity: findings.severity, category: findings.category, n: count() })
    .from(findings)
    .where(where)
    .groupBy(findings.severity, findings.category);
  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<
    (typeof SEVERITIES)[number],
    number
  >;
  const byCategory = Object.fromEntries(RULE_CATEGORIES.map((c) => [c, 0])) as Record<
    (typeof RULE_CATEGORIES)[number],
    number
  >;
  let total = 0;
  for (const r of rows) {
    bySeverity[r.severity] += r.n;
    if (r.category in byCategory) byCategory[r.category as keyof typeof byCategory] += r.n;
    total += r.n;
  }
  return { bySeverity, byCategory, total };
}

export async function getFindingDetail(
  db: Database,
  user: Pick<CurrentUser, 'id' | 'role'>,
  id: string,
  rules: readonly Rule[],
): Promise<FindingDetailResponse> {
  const [row] = await db
    .select({ f: findings, domainFqdn: domains.fqdn })
    .from(findings)
    .innerJoin(domains, eq(domains.id, findings.domainId))
    .where(and(eq(findings.id, id), visibleTo(db, user)))
    .limit(1);
  // Not visible and not existing are indistinguishable.
  if (!row) throw new ApiError(404, 'not_found', 'The requested resource was not found.');

  const [advisory] = await db.select().from(advisories).where(eq(advisories.findingId, id));
  const history = await db
    .select({ h: findingStatusHistory, email: users.email })
    .from(findingStatusHistory)
    .leftJoin(users, eq(users.id, findingStatusHistory.changedBy))
    .where(eq(findingStatusHistory.findingId, id))
    .orderBy(asc(findingStatusHistory.createdAt), asc(findingStatusHistory.id));
  const rule = rules.find((r) => r.id === row.f.ruleId);

  return {
    finding: toFindingDto(row.f, { id: row.f.domainId, fqdn: row.domainFqdn }),
    advisory: advisory ? toAdvisoryDto(advisory) : null,
    history: history.map(({ h, email }) => ({
      id: h.id,
      fromStatus: h.fromStatus,
      toStatus: h.toStatus,
      changedBy: h.changedBy && email ? { id: h.changedBy, email } : null,
      reason: h.reason,
      note: h.note,
      scanJobId: h.scanJobId,
      createdAt: h.createdAt.toISOString(),
    })),
    rule: rule
      ? {
          id: rule.id,
          version: rule.version,
          detection: rule.detection,
          resolution: rule.resolution,
          evidenceRequirements: rule.evidenceRequirements,
        }
      : null,
  };
}

export async function listAdvisories(
  db: Database,
  user: Pick<CurrentUser, 'id' | 'role'>,
  q: { page: number; pageSize: number; status: 'active' | 'all' },
): Promise<AdvisoryListResponse> {
  const where = and(
    visibleTo(db, user),
    q.status === 'active' ? ne(findings.status, 'resolved') : undefined,
  );
  const [rows, [totalRow]] = await Promise.all([
    db
      .select({ a: advisories, f: findings, domainFqdn: domains.fqdn })
      .from(advisories)
      .innerJoin(findings, eq(findings.id, advisories.findingId))
      .innerJoin(domains, eq(domains.id, findings.domainId))
      .where(where)
      .orderBy(desc(findings.riskScore), desc(findings.lastSeenAt), asc(advisories.id))
      .limit(q.pageSize)
      .offset((q.page - 1) * q.pageSize),
    db
      .select({ total: count() })
      .from(advisories)
      .innerJoin(findings, eq(findings.id, advisories.findingId))
      .where(where),
  ]);
  return {
    items: rows.map(({ a, f, domainFqdn }) => ({
      ...toAdvisoryDto(a),
      finding: {
        id: f.id,
        ruleId: f.ruleId,
        title: f.title,
        severity: f.severity,
        status: f.status,
        domain: { id: f.domainId, fqdn: domainFqdn },
        hostname: f.hostname,
        riskScore: f.riskScore,
      },
    })),
    page: q.page,
    pageSize: q.pageSize,
    total: totalRow?.total ?? 0,
  };
}

export function ruleCatalogue(rules: readonly Rule[]): RuleCatalogueEntry[] {
  return rules.map((r) => ({
    id: r.id,
    version: r.version,
    category: r.category,
    title: r.title,
    defaultSeverity: r.defaultSeverity,
    defaultConfidence: r.defaultConfidence,
    requires: [...r.requires],
    detection: r.detection,
    resolution: r.resolution,
    evidenceRequirements: r.evidenceRequirements,
  }));
}
