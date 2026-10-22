import {
  ACCEPTED_RISK_DEFAULT_DAYS,
  ACCEPTED_RISK_MAX_DAYS,
  type FindingBulkUpdateResponse,
  type Permission,
} from '@exdomainvault/shared';
import { addMonthsIso } from '../../lib/format.ts';
import { SKIP_CODE_LABELS } from './labels.ts';

/** Earliest and latest review dates the API accepts for accepted risk (YYYY-MM-DD, UTC). */
export const reviewDateBounds = (now = new Date()) => ({
  min: addMonthsIso(0, 1, now),
  max: addMonthsIso(0, ACCEPTED_RISK_MAX_DAYS, now),
  default: addMonthsIso(0, ACCEPTED_RISK_DEFAULT_DAYS, now),
});

/** Permissions that make at least one bulk action available (used to show row selection). */
export const BULK_PERMISSIONS = [
  'findings:triage',
  'findings:remediate',
  'findings:accept_risk',
  'findings:assign',
] as const satisfies readonly Permission[];

/** "Updated 3, skipped 2 (1 already in that state; 1 not found or not visible to you)." */
export function bulkResultText(result: FindingBulkUpdateResponse): string {
  const base = `Updated ${result.updated}, skipped ${result.skipped.length}`;
  if (result.skipped.length === 0) return `${base}.`;
  const counts = new Map<string, number>();
  for (const s of result.skipped) counts.set(s.code, (counts.get(s.code) ?? 0) + 1);
  const parts = [...counts].map(([code, n]) => `${n} ${SKIP_CODE_LABELS[code] ?? code}`);
  return `${base} (${parts.join('; ')}).`;
}
