import { z } from 'zod';
import { FINDING_STATUSES, ruleCategorySchema } from './findings.ts';
import { criticalitySchema, severitySchema } from '../domain/severity.ts';
import { gradeSchema } from '../domain/security-score.ts';
import { gradeDistributionSchema } from './scores.ts';
import { slaReportSchema } from './sla.ts';

/**
 * Portfolio summary report (`GET /reports/summary`, `reports:read`; design §10, §14). Everything is
 * derived from stored findings, observations and inventory — no estimates. Asset owners get a
 * summary of the findings they can see only (domain-level sections are empty for them).
 * All windows are UTC; `trend` covers the last `trendDays` days including today.
 */

const isoDateTime = z.iso.datetime();
const day = z.iso.date();

export const REPORT_TREND_DAYS = 30;
export const REPORT_EXPIRY_DAYS = { registration: 60, certificate: 30, acceptedRisk: 30 } as const;

export const reportSummaryResponseSchema = z.object({
  generatedAt: isoDateTime,
  coverage: z.object({
    domains: z.int(),
    monitoredDomains: z.int(),
    verifiedDomains: z.int(),
    approvedAssets: z.int(),
    pendingAssets: z.int(),
    /** Completion time of the newest succeeded scan or discovery job. */
    lastScanAt: isoDateTime.nullable(),
  }),
  findings: z.object({
    /** Non-resolved findings. */
    open: z.int(),
    bySeverity: z.record(severitySchema, z.int()),
    byStatus: z.record(z.enum(FINDING_STATUSES), z.int()),
    byCategory: z.record(ruleCategorySchema, z.int()),
    /** Mean days from first seen to resolved for findings resolved in the last 90 days; null if none. */
    meanDaysToResolve: z.number().nullable(),
  }),
  /** Per UTC day, oldest first: findings first seen and findings resolved that day. */
  trendDays: z.int(),
  trend: z.array(z.object({ date: day, created: z.int(), resolved: z.int() })),
  /** Up to 10 domains by total risk score of their open findings. */
  topDomains: z.array(
    z.object({
      domain: z.object({ id: z.uuid(), fqdn: z.string() }),
      criticality: criticalitySchema,
      openFindings: z.int(),
      riskTotal: z.int(),
      highestSeverity: severitySchema,
    }),
  ),
  /** Open findings per business owner (domains without one are grouped under `null`). */
  byBusinessOwner: z.array(
    z.object({
      businessOwner: z.string().nullable(),
      domains: z.int(),
      openFindings: z.int(),
      highOrCritical: z.int(),
      /** Open findings past their SLA due date. */
      overdue: z.int(),
      /** Mean latest security score of the group's scored domains; null when none is scored. */
      averageScore: z.number().nullable(),
      /** Grade of `averageScore`. */
      grade: gradeSchema.nullable(),
      grades: gradeDistributionSchema,
    }),
  ),
  /** Remediation SLAs (findings visible to the user). */
  sla: slaReportSchema,
  /** Registrations expiring within REPORT_EXPIRY_DAYS.registration (or already expired), soonest first, ≤ 50. */
  expiringRegistrations: z.array(
    z.object({
      domain: z.object({ id: z.uuid(), fqdn: z.string() }),
      expiresAt: isoDateTime,
      daysLeft: z.int(),
    }),
  ),
  /** Latest successful TLS observation per hostname expiring within 30 days (or expired), ≤ 50. */
  expiringCertificates: z.array(
    z.object({
      domain: z.object({ id: z.uuid(), fqdn: z.string() }),
      hostname: z.string(),
      notAfter: isoDateTime,
      daysLeft: z.int(),
      issuer: z.string().nullable(),
    }),
  ),
  /** Accepted risks whose review date is within 30 days (or passed), soonest first, ≤ 50. */
  acceptedRisksDue: z.array(
    z.object({
      findingId: z.uuid(),
      title: z.string(),
      domain: z.object({ id: z.uuid(), fqdn: z.string() }),
      reviewAt: isoDateTime,
    }),
  ),
});
export type ReportSummaryResponse = z.infer<typeof reportSummaryResponseSchema>;

/**
 * `GET /reports/findings.csv` (`reports:generate`): the findings list as CSV, same filters as
 * `GET /findings` (no paging), at most REPORT_CSV_MAX_ROWS rows (header `X-Truncated: true` when
 * more matched). Columns are fixed (REPORT_CSV_COLUMNS); cells starting with = + - @ tab or CR are
 * prefixed with `'` (CSV injection). Audited (`report.exported`).
 */
export const REPORT_CSV_MAX_ROWS = 5000;
export const REPORT_CSV_COLUMNS = [
  'finding_id',
  'rule_id',
  'severity',
  'risk_score',
  'status',
  'domain',
  'hostname',
  'component',
  'title',
  'first_seen_at',
  'last_seen_at',
  'resolved_at',
  'assignee',
  'business_owner',
] as const;
