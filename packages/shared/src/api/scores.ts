import { z } from 'zod';
import { gradeSchema, GRADES, securityScoreSchema } from '../domain/security-score.ts';

/**
 * Security score API (Milestone 14). `GET /domains/:id/score` (`domains:read`): the current score
 * computed live from the domain's non-resolved findings, plus the daily snapshot trend
 * (domain_score_snapshots, one row per domain per UTC day, written by the cron and on demand).
 *
 * A domain without any successfully completed scan has no score (`current: null`): "no findings"
 * would otherwise read as grade A for a domain nobody has looked at.
 */

export const SCORE_TREND_DAYS = 90;

export const domainScoreResponseSchema = z.object({
  domain: z.object({ id: z.uuid(), fqdn: z.string() }),
  current: securityScoreSchema.nullable(),
  /** Oldest first, one point per UTC day that has a snapshot (today reflects `current`). */
  trend: z.array(z.object({ day: z.iso.date(), score: z.int(), grade: gradeSchema })),
  trendDays: z.int(),
});
export type DomainScoreResponse = z.infer<typeof domainScoreResponseSchema>;

/** Count of domains per grade. */
export const gradeDistributionSchema = z.record(gradeSchema, z.int());
export type GradeDistribution = z.infer<typeof gradeDistributionSchema>;

export const emptyGradeDistribution = (): GradeDistribution =>
  Object.fromEntries(GRADES.map((g) => [g, 0])) as GradeDistribution;
