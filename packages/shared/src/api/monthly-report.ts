import { z } from 'zod';
import { gradeSchema } from '../domain/security-score.ts';
import { criticalitySchema, severitySchema } from '../domain/severity.ts';
import { gradeDistributionSchema } from './scores.ts';
import { slaPolicySchema } from './sla.ts';

/**
 * Monthly executive report (Milestone 14). A point-in-time snapshot of the organisation's external
 * exposure for one calendar month (UTC), computed by SQL aggregation when generated and stored
 * unchanged in `monthly_reports.data`. The cron generates the previous month's report once, on or
 * after the 1st; an administrator may (re)generate any past or current month
 * (`POST /reports/monthly/generate`, audited `report.monthly_generated`; regenerating replaces).
 *
 * Organisation-wide: readable with `reports:read` except by asset owners (403), whose access is
 * limited to their own assets.
 *
 * "At month end" values are reconstructed from finding status history (the status each finding had
 * at the end of the month); severity, risk score and due date are the finding's current values.
 */

export const MONTHLY_REPORT_VERSION = 1;
export const monthlyPeriodSchema = z
  .string()
  .regex(/^\d{4}-(0[1-9]|1[0-2])$/, 'Use the form YYYY-MM.');
export type MonthlyPeriod = z.infer<typeof monthlyPeriodSchema>;

const isoDateTime = z.iso.datetime();
const bySeverity = z.record(severitySchema, z.int());
const domainRef = z.object({ id: z.uuid(), fqdn: z.string() });

export const monthlyReportSchema = z.object({
  version: z.int(),
  period: monthlyPeriodSchema,
  /** Start (inclusive) and end (exclusive) of the month, UTC. */
  periodStart: isoDateTime,
  periodEnd: isoDateTime,
  generatedAt: isoDateTime,
  totals: z.object({
    domains: z.int(),
    monitoredDomains: z.int(),
    assets: z.int(),
    approvedAssets: z.int(),
    /** Assets first recorded during the month (any source: discovery, import, manual). */
    newAssets: z.int(),
  }),
  findings: z.object({
    /** First detected during the month. */
    opened: bySeverity,
    openedTotal: z.int(),
    /** Reopened by a recurrence during the month. */
    reopened: z.int(),
    /** Resolved during the month (by a successful scan or by hand). */
    resolved: bySeverity,
    resolvedTotal: z.int(),
    /** Not resolved at month end (accepted risk included). */
    openAtEnd: bySeverity,
    openAtEndTotal: z.int(),
    acceptedRiskAtEnd: z.int(),
    /** Open at month end, not accepted risk, due date before month end. */
    overdueAtEnd: z.int(),
    overdueAtEndBySeverity: bySeverity,
  }),
  sla: z.object({
    policy: slaPolicySchema,
    /** Findings resolved during the month that had a due date. */
    resolvedWithSla: z.int(),
    resolvedWithinSla: z.int(),
    compliancePercent: z.number().nullable(),
    /** Mean days from first seen to resolved for findings resolved during the month. */
    meanDaysToResolve: z.number().nullable(),
    meanDaysToResolveBySeverity: z.record(severitySchema, z.number().nullable()),
  }),
  /** Highest risk score first, open at month end, ≤ 10. */
  topFindings: z.array(
    z.object({
      id: z.uuid(),
      ruleId: z.string(),
      title: z.string(),
      severity: severitySchema,
      riskScore: z.int(),
      domain: domainRef,
      hostname: z.string(),
      firstSeenAt: isoDateTime,
      dueAt: isoDateTime.nullable(),
      overdue: z.boolean(),
    }),
  ),
  /** Domains by total risk score of findings open at month end, ≤ 10. */
  topDomains: z.array(
    z.object({
      domain: domainRef,
      criticality: criticalitySchema,
      businessOwner: z.string().nullable(),
      openFindings: z.int(),
      riskTotal: z.int(),
      highestSeverity: severitySchema,
      grade: gradeSchema.nullable(),
    }),
  ),
  securityScore: z.object({
    /** Domains with a score snapshot on or before the last day of the month. */
    scoredDomains: z.int(),
    averageScore: z.number().nullable(),
    grades: gradeDistributionSchema,
    /** Average of the previous month's end-of-month scores; null when there were none. */
    previousAverageScore: z.number().nullable(),
    /** averageScore − previousAverageScore (one decimal), null when either is missing. */
    change: z.number().nullable(),
    best: z.array(z.object({ domain: domainRef, score: z.int(), grade: gradeSchema })),
    worst: z.array(z.object({ domain: domainRef, score: z.int(), grade: gradeSchema })),
  }),
  exposure: z.object({
    /** Latest successful TLS certificate per hostname expiring within 30 days after month end (or expired). */
    certificatesExpiring30d: z.int(),
    /** Open at month end: end-of-life software (SOFT-001) and KEV-affected versions (SOFT-002). */
    endOfLifeSoftware: z.int(),
    knownExploitedSoftware: z.int(),
  }),
});
export type MonthlyReport = z.infer<typeof monthlyReportSchema>;

export const monthlyReportListResponseSchema = z.object({
  items: z.array(
    z.object({
      period: monthlyPeriodSchema,
      generatedAt: isoDateTime,
      /** Headline numbers for the list. */
      openAtEndTotal: z.int(),
      overdueAtEnd: z.int(),
      averageScore: z.number().nullable(),
    }),
  ),
});
export type MonthlyReportListResponse = z.infer<typeof monthlyReportListResponseSchema>;

export const monthlyReportResponseSchema = z.object({ report: monthlyReportSchema });
export type MonthlyReportResponse = z.infer<typeof monthlyReportResponseSchema>;

/** Optional period; defaults to the previous month (UTC). Future months are refused. */
export const monthlyReportGenerateRequestSchema = z
  .object({ period: monthlyPeriodSchema.optional() })
  .strict();
export type MonthlyReportGenerateRequest = z.infer<typeof monthlyReportGenerateRequestSchema>;

/** First day (UTC) of the month `period` and of the following month. */
export function monthBounds(period: MonthlyPeriod): { start: Date; end: Date } {
  const [y, m] = period.split('-').map(Number) as [number, number];
  return { start: new Date(Date.UTC(y, m - 1, 1)), end: new Date(Date.UTC(y, m, 1)) };
}

/** The calendar month (UTC) before the one containing `now`. */
export function previousPeriod(now: Date): MonthlyPeriod {
  const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1));
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
}

export function periodOf(d: Date): MonthlyPeriod {
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
}
