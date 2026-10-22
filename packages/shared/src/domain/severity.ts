import { z } from 'zod';

/** Severity categories from design §8, ordered from least to most severe. */
export const SEVERITIES = ['informational', 'low', 'medium', 'high', 'critical'] as const;
export const severitySchema = z.enum(SEVERITIES);
export type Severity = z.infer<typeof severitySchema>;

export const SEVERITY_LABELS: Record<Severity, string> = {
  informational: 'Informational',
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
};

/** Sort comparator: most severe first. */
export function compareSeverityDesc(a: Severity, b: Severity): number {
  return SEVERITIES.indexOf(b) - SEVERITIES.indexOf(a);
}

export const CRITICALITIES = ['low', 'medium', 'high', 'critical'] as const;
export const criticalitySchema = z.enum(CRITICALITIES);
export type Criticality = z.infer<typeof criticalitySchema>;

export const CRITICALITY_LABELS: Record<Criticality, string> = {
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
};
