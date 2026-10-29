import { describe, expect, it } from 'vitest';
import {
  CATEGORY_CAP,
  computeSecurityScore,
  gradeFor,
  type ScoreInputGroup,
} from './security-score.ts';

const g = (
  category: string,
  severity: ScoreInputGroup['severity'],
  count: number,
  state: ScoreInputGroup['state'] = 'open',
): ScoreInputGroup => ({ category, severity, state, count });

describe('gradeFor', () => {
  it.each([
    [100, 'A'],
    [90, 'A'],
    [89, 'B'],
    [80, 'B'],
    [79, 'C'],
    [70, 'C'],
    [69, 'D'],
    [60, 'D'],
    [59, 'F'],
    [0, 'F'],
  ] as const)('%i → %s', (score, grade) => {
    expect(gradeFor(score)).toBe(grade);
  });
});

describe('computeSecurityScore', () => {
  it('is 100 / A with no findings', () => {
    const s = computeSecurityScore({ findings: [] });
    expect(s).toMatchObject({ score: 100, grade: 'A', deductions: [], inputs: [] });
  });

  it('deducts the severity weights', () => {
    const s = computeSecurityScore({
      findings: [
        g('dns', 'medium', 1),
        g('tls', 'high', 1),
        g('http', 'low', 2),
        g('dns', 'informational', 5),
      ],
    });
    // 4 + 10 + 2 (informational weighs 0)
    expect(s.score).toBe(84);
    expect(s.grade).toBe('B');
    expect(s.deductions.map((d) => [d.category, d.points])).toEqual([
      ['tls', 10],
      ['dns', 4],
      ['http', 2],
    ]);
  });

  it('adds 50% for overdue findings', () => {
    const s = computeSecurityScore({ findings: [g('tls', 'high', 1, 'overdue')] });
    expect(s.score).toBe(85);
    expect(s.deductions[0]?.items[0]).toMatchObject({ each: 15, points: 15, state: 'overdue' });
  });

  it('counts accepted risk at 25%', () => {
    const s = computeSecurityScore({ findings: [g('tls', 'critical', 1, 'accepted_risk')] });
    expect(s.score).toBe(94); // 100 − 6.25 → 93.75 → 94
    expect(s.deductions[0]?.items[0]?.each).toBe(6.25);
  });

  it('caps each category so one noisy rule cannot zero the score', () => {
    const s = computeSecurityScore({ findings: [g('email', 'medium', 50)] });
    expect(s.deductions[0]).toMatchObject({ uncapped: 200, points: CATEGORY_CAP, capped: true });
    expect(s.score).toBe(100 - CATEGORY_CAP);
  });

  it('clamps at 0 across categories', () => {
    const s = computeSecurityScore({
      findings: ['dns', 'tls', 'http', 'exposure'].map((c) => g(c, 'critical', 3)),
    });
    expect(s.score).toBe(0);
    expect(s.grade).toBe('F');
  });

  it('is deterministic: input order and duplicate groups do not matter', () => {
    const a = computeSecurityScore({
      findings: [g('dns', 'low', 1), g('tls', 'high', 1), g('dns', 'low', 2), g('x', 'low', 0)],
    });
    const b = computeSecurityScore({ findings: [g('tls', 'high', 1), g('dns', 'low', 3)] });
    expect(a).toEqual(b);
    expect(a.inputs).toEqual([g('dns', 'low', 3), g('tls', 'high', 1)]);
  });
});
