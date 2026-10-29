import { describe, expect, it } from 'vitest';
import { monthBounds, periodOf, previousPeriod } from './monthly-report.ts';
import { DEFAULT_SLA_POLICY, dueAtFor, isOverdue, slaPolicySchema } from './sla.ts';

const opened = new Date('2026-10-01T12:00:00.000Z');

describe('dueAtFor', () => {
  it('adds the policy days for the severity', () => {
    expect(dueAtFor('critical', opened, DEFAULT_SLA_POLICY)?.toISOString()).toBe(
      '2026-10-08T12:00:00.000Z',
    );
    expect(dueAtFor('high', opened, DEFAULT_SLA_POLICY)?.toISOString()).toBe(
      '2026-10-31T12:00:00.000Z',
    );
    expect(dueAtFor('medium', opened, DEFAULT_SLA_POLICY)?.toISOString()).toBe(
      '2026-12-30T12:00:00.000Z',
    );
    expect(dueAtFor('low', opened, DEFAULT_SLA_POLICY)?.toISOString()).toBe(
      '2027-03-30T12:00:00.000Z',
    );
  });

  it('returns null when the severity has no SLA', () => {
    expect(dueAtFor('informational', opened, DEFAULT_SLA_POLICY)).toBeNull();
    expect(dueAtFor('critical', opened, { ...DEFAULT_SLA_POLICY, critical: null })).toBeNull();
  });
});

describe('isOverdue', () => {
  const now = new Date('2026-10-10T00:00:00.000Z');
  const past = '2026-10-09T23:59:59.000Z';
  it('is overdue only for working statuses past the due date', () => {
    expect(isOverdue({ status: 'open', dueAt: past }, now)).toBe(true);
    expect(isOverdue({ status: 'acknowledged', dueAt: new Date(past) }, now)).toBe(true);
    expect(isOverdue({ status: 'remediation_in_progress', dueAt: past }, now)).toBe(true);
    expect(isOverdue({ status: 'resolved', dueAt: past }, now)).toBe(false);
    expect(isOverdue({ status: 'accepted_risk', dueAt: past }, now)).toBe(false);
    expect(isOverdue({ status: 'open', dueAt: null }, now)).toBe(false);
    expect(isOverdue({ status: 'open', dueAt: now }, now)).toBe(false);
  });
});

describe('slaPolicySchema', () => {
  it('accepts 1–3650 days or null per severity', () => {
    expect(slaPolicySchema.safeParse(DEFAULT_SLA_POLICY).success).toBe(true);
    expect(slaPolicySchema.safeParse({ ...DEFAULT_SLA_POLICY, low: 3650 }).success).toBe(true);
  });
  it.each([0, 3651, 1.5, -1, '7'])('rejects %s', (v) => {
    expect(slaPolicySchema.safeParse({ ...DEFAULT_SLA_POLICY, high: v }).success).toBe(false);
  });
  it('rejects missing and unknown keys', () => {
    const { low: _low, ...missing } = DEFAULT_SLA_POLICY;
    expect(slaPolicySchema.safeParse(missing).success).toBe(false);
    expect(slaPolicySchema.safeParse({ ...DEFAULT_SLA_POLICY, extra: 1 }).success).toBe(false);
  });
});

describe('monthly periods', () => {
  it('computes UTC month bounds and neighbours', () => {
    const { start, end } = monthBounds('2026-12');
    expect(start.toISOString()).toBe('2026-12-01T00:00:00.000Z');
    expect(end.toISOString()).toBe('2027-01-01T00:00:00.000Z');
    expect(previousPeriod(new Date('2026-01-01T00:00:00Z'))).toBe('2025-12');
    expect(previousPeriod(new Date('2026-10-29T10:00:00Z'))).toBe('2026-09');
    expect(periodOf(new Date('2026-10-31T23:59:59Z'))).toBe('2026-10');
  });
});
