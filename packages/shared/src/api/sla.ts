import { z } from 'zod';
import { severitySchema, type Severity } from '../domain/severity.ts';

/**
 * Remediation SLAs (Milestone 14). A finding is due a fixed number of days after its SLA clock
 * starts; `null` days means the severity has no SLA (no due date, never overdue).
 *
 * SLA clock start (server, `services/sla.ts`): the finding's `first_seen_at`, or — if later — the
 * last time it left `resolved` (recurrence) or `accepted_risk` (acceptance lapsed or withdrawn) for
 * a working status. Other moves (e.g. acknowledged → open) do not restart the clock.
 *
 * A finding is overdue when it is neither resolved nor accepted risk and `dueAt` has passed.
 *
 * Stored in `application_settings` under SLA_POLICY_SETTING_KEY; changed by administrators
 * (`settings:manage`, audited `settings.sla_updated`). Changing the policy recomputes the due date
 * of every non-resolved finding; resolved findings keep the due date they had (compliance history).
 */

export const SLA_POLICY_SETTING_KEY = 'sla_policy';
export const SLA_MAX_DAYS = 3650;
/** Window for SLA compliance and mean days to resolve. */
export const SLA_COMPLIANCE_WINDOW_DAYS = 90;

const slaDays = z.int().min(1).max(SLA_MAX_DAYS).nullable();

export const slaPolicySchema = z
  .object({
    critical: slaDays,
    high: slaDays,
    medium: slaDays,
    low: slaDays,
    informational: slaDays,
  })
  .strict();
export type SlaPolicy = z.infer<typeof slaPolicySchema>;

export const DEFAULT_SLA_POLICY: SlaPolicy = {
  critical: 7,
  high: 30,
  medium: 90,
  low: 180,
  informational: null,
};

const DAY_MS = 86_400_000;

/** Due date for a finding of `severity` whose SLA clock started at `openedAt`; null = no SLA. */
export function dueAtFor(severity: Severity, openedAt: Date, policy: SlaPolicy): Date | null {
  const days = policy[severity];
  return days === null ? null : new Date(openedAt.getTime() + days * DAY_MS);
}

/** Overdue: not resolved, not accepted risk, and the due date has passed. */
export function isOverdue(f: { status: string; dueAt: Date | string | null }, now: Date): boolean {
  if (f.dueAt === null || f.status === 'resolved' || f.status === 'accepted_risk') return false;
  const due = f.dueAt instanceof Date ? f.dueAt : new Date(f.dueAt);
  return due.getTime() < now.getTime();
}

export const slaPolicyResponseSchema = z.object({
  policy: slaPolicySchema,
  updatedAt: z.iso.datetime().nullable(),
  updatedBy: z.object({ id: z.uuid(), email: z.string() }).nullable(),
});
export type SlaPolicyResponse = z.infer<typeof slaPolicyResponseSchema>;

export const slaPolicyUpdateResponseSchema = slaPolicyResponseSchema.extend({
  /** Non-resolved findings whose due date was recomputed. */
  recomputed: z.int(),
});
export type SlaPolicyUpdateResponse = z.infer<typeof slaPolicyUpdateResponseSchema>;

/** The `sla` section of GET /reports/summary. */
export const slaReportSchema = z.object({
  policy: slaPolicySchema,
  /** Open (not resolved, not accepted risk) findings past their due date. */
  overdue: z.int(),
  overdueBySeverity: z.record(severitySchema, z.int()),
  windowDays: z.int(),
  /** Findings resolved in the window that had a due date. */
  resolvedWithSla: z.int(),
  resolvedWithinSla: z.int(),
  /** resolvedWithinSla / resolvedWithSla × 100 (one decimal); null when nothing was resolved. */
  compliancePercent: z.number().nullable(),
  /** Mean days from first seen to resolved, findings resolved in the window; null if none. */
  meanDaysToResolveBySeverity: z.record(severitySchema, z.number().nullable()),
});
export type SlaReport = z.infer<typeof slaReportSchema>;
