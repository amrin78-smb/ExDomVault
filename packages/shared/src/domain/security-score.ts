import { z } from 'zod';
import { SEVERITIES, severitySchema, type Severity } from './severity.ts';

/**
 * Domain security score (Milestone 14) — deterministic, explainable, no estimates. See
 * docs/security-score.md.
 *
 *   score = clamp(0, 100, round(100 − Σ_category min(CATEGORY_CAP, Σ deductions in category)))
 *
 * Each non-resolved finding deducts SEVERITY_WEIGHT[severity] points, multiplied by:
 *   - OVERDUE_MULTIPLIER (1.5) when it is past its remediation due date (not accepted risk);
 *   - ACCEPTED_RISK_MULTIPLIER (0.25) when its risk is formally accepted (never overdue).
 * Deductions are summed per rule category (dns, email, tls, …) and each category is capped at
 * CATEGORY_CAP points, so one noisy rule or category cannot zero the score on its own.
 *
 * Grade: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, otherwise F. This is a posture summary, not a severity:
 * severity always comes from the rules.
 */

export const SECURITY_SCORE_VERSION = 1;
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 25,
  high: 10,
  medium: 4,
  low: 1,
  informational: 0,
};
export const OVERDUE_MULTIPLIER = 1.5;
export const ACCEPTED_RISK_MULTIPLIER = 0.25;
export const CATEGORY_CAP = 40;

export const GRADES = ['A', 'B', 'C', 'D', 'F'] as const;
export const gradeSchema = z.enum(GRADES);
export type Grade = z.infer<typeof gradeSchema>;
export const GRADE_THRESHOLDS: readonly { grade: Grade; min: number }[] = [
  { grade: 'A', min: 90 },
  { grade: 'B', min: 80 },
  { grade: 'C', min: 70 },
  { grade: 'D', min: 60 },
  { grade: 'F', min: 0 },
];

export function gradeFor(score: number): Grade {
  for (const t of GRADE_THRESHOLDS) if (score >= t.min) return t.grade;
  return 'F';
}

/** How a finding counts: open (not overdue), overdue, or accepted risk. */
export const SCORE_FINDING_STATES = ['open', 'overdue', 'accepted_risk'] as const;
export const scoreFindingStateSchema = z.enum(SCORE_FINDING_STATES);
export type ScoreFindingState = z.infer<typeof scoreFindingStateSchema>;

/** Aggregated input: number of non-resolved findings per category, severity and state. */
export const scoreInputGroupSchema = z.object({
  category: z.string(),
  severity: severitySchema,
  state: scoreFindingStateSchema,
  count: z.int().min(0),
});
export type ScoreInputGroup = z.infer<typeof scoreInputGroupSchema>;

export interface SecurityScoreInput {
  findings: readonly ScoreInputGroup[];
}

export const scoreDeductionSchema = z.object({
  category: z.string(),
  /** Points actually deducted (after the cap), two decimals. */
  points: z.number(),
  /** Points before the cap. */
  uncapped: z.number(),
  capped: z.boolean(),
  items: z.array(
    z.object({
      severity: severitySchema,
      state: scoreFindingStateSchema,
      count: z.int(),
      /** Points per finding (weight × multiplier). */
      each: z.number(),
      points: z.number(),
    }),
  ),
});
export type ScoreDeduction = z.infer<typeof scoreDeductionSchema>;

export const securityScoreSchema = z.object({
  version: z.int(),
  score: z.int().min(0).max(100),
  grade: gradeSchema,
  /** Largest deduction first. */
  deductions: z.array(scoreDeductionSchema),
  inputs: z.array(scoreInputGroupSchema),
});
export type SecurityScore = z.infer<typeof securityScoreSchema>;

const round2 = (n: number) => Math.round(n * 100) / 100;

const STATE_MULTIPLIER: Record<ScoreFindingState, number> = {
  open: 1,
  overdue: OVERDUE_MULTIPLIER,
  accepted_risk: ACCEPTED_RISK_MULTIPLIER,
};

/** Pure and deterministic: the same input always gives the same score, deductions and order. */
export function computeSecurityScore(input: SecurityScoreInput): SecurityScore {
  // Merge duplicate groups and drop empty ones so the stored inputs are canonical.
  const merged = new Map<string, ScoreInputGroup>();
  for (const g of input.findings) {
    if (g.count <= 0) continue;
    const key = `${g.category}|${g.severity}|${g.state}`;
    const prev = merged.get(key);
    merged.set(key, prev ? { ...prev, count: prev.count + g.count } : { ...g });
  }
  const inputs = [...merged.values()].sort(
    (a, b) =>
      a.category.localeCompare(b.category) ||
      SEVERITIES.indexOf(b.severity) - SEVERITIES.indexOf(a.severity) ||
      SCORE_FINDING_STATES.indexOf(a.state) - SCORE_FINDING_STATES.indexOf(b.state),
  );

  const byCategory = new Map<string, ScoreDeduction>();
  for (const g of inputs) {
    const each = SEVERITY_WEIGHT[g.severity] * STATE_MULTIPLIER[g.state];
    if (each === 0) continue;
    const d = byCategory.get(g.category) ?? {
      category: g.category,
      points: 0,
      uncapped: 0,
      capped: false,
      items: [],
    };
    d.items.push({
      severity: g.severity,
      state: g.state,
      count: g.count,
      each: round2(each),
      points: round2(each * g.count),
    });
    d.uncapped += each * g.count;
    byCategory.set(g.category, d);
  }

  const deductions = [...byCategory.values()]
    .map((d) => ({
      ...d,
      uncapped: round2(d.uncapped),
      points: round2(Math.min(CATEGORY_CAP, d.uncapped)),
      capped: d.uncapped > CATEGORY_CAP,
    }))
    .sort((a, b) => b.points - a.points || a.category.localeCompare(b.category));
  const total = deductions.reduce((s, d) => s + d.points, 0);
  const score = Math.max(0, Math.min(100, Math.round(100 - total)));
  return { version: SECURITY_SCORE_VERSION, score, grade: gradeFor(score), deductions, inputs };
}
