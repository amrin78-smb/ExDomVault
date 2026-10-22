import { describe, expect, it } from 'vitest';
import { compareSeverityDesc, severitySchema, type Severity } from './severity.ts';

describe('severity', () => {
  it('sorts most severe first', () => {
    const input: Severity[] = ['low', 'critical', 'informational', 'high', 'medium'];
    expect([...input].sort(compareSeverityDesc)).toEqual([
      'critical',
      'high',
      'medium',
      'low',
      'informational',
    ]);
  });

  it('rejects unknown severities', () => {
    expect(severitySchema.safeParse('severe').success).toBe(false);
  });
});
