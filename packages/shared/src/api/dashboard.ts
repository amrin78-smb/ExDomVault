import { z } from 'zod';
import { assetRoleSchema } from '../domain/asset-roles.ts';
import { severitySchema } from '../domain/severity.ts';
import { assetStatusSchema, assetSourceSchema } from './assets.ts';

/**
 * Overview dashboard (Milestone 13). `GET /api/v1/dashboard?range=7|30|90` (`domains:read`).
 * One request for the overview's headline cards; scoped like every list (asset owners see only
 * their assets and findings; domain-level counts are 0 for them). All numbers are real database
 * aggregates — nothing estimated or invented.
 *
 * Series semantics (`stat.series`, one point per UTC day from range start to today inclusive):
 * - domains / approved assets: count existing at end of that day (created_at / approved_at);
 * - open findings / critical+high: findings with first_seen_at ≤ day end and (resolved_at null or
 *   > day end). A finding resolved and later reopened is counted from its current resolved_at only
 *   (documented approximation);
 * - certificates expiring and EOL software have no history: `series` empty, `delta` null.
 * `delta` = last point − first point.
 * Pure SQL aggregation; at most one statement per card.
 */

export const DASHBOARD_RANGES = [7, 30, 90] as const;
export type DashboardRange = (typeof DASHBOARD_RANGES)[number];

export const dashboardQuerySchema = z.object({
  range: z.coerce
    .number()
    .int()
    .refine((n): n is DashboardRange => (DASHBOARD_RANGES as readonly number[]).includes(n), {
      message: 'range must be 7, 30 or 90',
    })
    .default(30),
});

const isoDateTime = z.iso.datetime();
const day = z.iso.date();
const ref = z.object({ id: z.uuid(), fqdn: z.string() });

export const dashboardStatSchema = z.object({
  value: z.int(),
  delta: z.int().nullable(),
  series: z.array(z.int()),
});
export type DashboardStat = z.infer<typeof dashboardStatSchema>;

export const dashboardResponseSchema = z.object({
  generatedAt: isoDateTime,
  range: z.int(),
  /** Completion time of the most recent succeeded scan or discovery job (any domain visible). */
  lastScanAt: isoDateTime.nullable(),
  stats: z.object({
    /** Registered domains; `active` = monitoring enabled. */
    domains: dashboardStatSchema.extend({ active: z.int() }),
    /** Approved assets; `pending` = awaiting review. */
    assets: dashboardStatSchema.extend({ pending: z.int() }),
    openFindings: dashboardStatSchema,
    criticalHigh: dashboardStatSchema,
    /** Distinct hostnames whose latest successful certificate expires within 30 days (or expired). */
    expiringCertificates: dashboardStatSchema,
    /** Software inventory rows on an end-of-life cycle; `kev` = rows with a possible KEV match. */
    eolSoftware: dashboardStatSchema.extend({ kev: z.int() }),
  }),
  /** Open (not resolved) findings by severity. */
  severity: z.record(severitySchema, z.int()),
  /** Findings first seen per day, by severity, plus resolutions per day. */
  trend: z.array(
    z.object({
      date: day,
      critical: z.int(),
      high: z.int(),
      medium: z.int(),
      low: z.int(),
      informational: z.int(),
      resolved: z.int(),
    }),
  ),
  /** Highest risk_score open findings (max 5). */
  topRemediation: z.array(
    z.object({
      findingId: z.uuid(),
      title: z.string(),
      ruleId: z.string(),
      severity: severitySchema,
      riskScore: z.int(),
      domain: ref,
      hostname: z.string().nullable(),
      /** CVE ids named by the finding's evidence (SOFT-002), else empty. */
      cves: z.array(z.string()),
      assetRole: assetRoleSchema.nullable(),
    }),
  ),
  /** Most recent scan/discovery jobs (max 5). */
  latestScans: z.array(
    z.object({
      id: z.uuid(),
      jobType: z.enum(['scan', 'discovery']),
      domain: ref,
      profile: z.string(),
      status: z.string(),
      createdAt: isoDateTime,
      completedAt: isoDateTime.nullable(),
    }),
  ),
  /** Soonest-expiring certificates by latest successful observation per hostname (max 5). */
  certificateExpiry: z.array(
    z.object({
      hostname: z.string(),
      domain: ref,
      notAfter: isoDateTime,
      /** Negative when already expired. */
      daysLeft: z.int(),
      issuer: z.string().nullable(),
    }),
  ),
  /** Most recently first-seen assets (max 5). */
  recentAssets: z.array(
    z.object({
      id: z.uuid(),
      hostname: z.string(),
      domain: ref,
      status: assetStatusSchema,
      source: assetSourceSchema,
      role: assetRoleSchema,
      firstSeenAt: isoDateTime,
    }),
  ),
  /** Products by number of distinct hosts reporting them (max 5). */
  topSoftware: z.array(
    z.object({
      product: z.string(),
      productLabel: z.string(),
      /** Most common disclosed versions, max 3. */
      versions: z.array(z.string()),
      hosts: z.int(),
      eolHosts: z.int(),
      /** Distinct KEV CVEs possibly affecting reported versions. */
      kevCves: z.int(),
    }),
  ),
});
export type DashboardResponse = z.infer<typeof dashboardResponseSchema>;
