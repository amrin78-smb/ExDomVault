import type { Finding } from '@exdomainvault/shared';
import { formatDate } from '../../lib/format.ts';

const DAY_MS = 86_400_000;
/** Due within this many days: amber warning. */
const DUE_SOON_DAYS = 7;

const PILL =
  'inline-flex items-center whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset';
const OVERDUE = 'bg-red-50 text-red-800 ring-red-600/25 dark:ring-red-400/55';
const SOON = 'bg-amber-50 text-amber-800 ring-amber-600/30 dark:ring-amber-400/55';

/** Whole days between `now` and `iso` (positive: in the future), rounded away from zero. */
function daysUntil(iso: string, now: Date): number {
  const ms = new Date(iso).getTime() - now.getTime();
  return ms >= 0 ? Math.ceil(ms / DAY_MS) : -Math.ceil(-ms / DAY_MS);
}

/**
 * Remediation due date of a finding (SLA). Red "Overdue 5d" when the server says it is overdue,
 * amber "Due in 3d" within DUE_SOON_DAYS, otherwise the date. Resolved and accepted-risk findings
 * are never overdue; findings whose severity has no SLA show "No SLA". The text always carries
 * the meaning (colour is never the only cue).
 */
export function DueBadge({
  finding,
  now = new Date(),
  withDate = false,
}: {
  finding: Pick<Finding, 'dueAt' | 'overdue' | 'status'>;
  now?: Date;
  /** Also show the due date next to an Overdue / Due-soon pill. */
  withDate?: boolean;
}) {
  const pill = (cls: string, text: string, title: string) =>
    withDate && finding.dueAt ? (
      <span className="inline-flex flex-wrap items-center gap-2">
        <span>{formatDate(finding.dueAt)}</span>
        <span className={`${PILL} ${cls}`}>{text}</span>
      </span>
    ) : (
      <span className={`${PILL} ${cls}`} title={title}>
        {text}
      </span>
    );
  const { dueAt, overdue, status } = finding;
  if (!dueAt) return <span className="text-xs text-fg-faint">No SLA</span>;
  const title = `Due ${formatDate(dueAt)}`;
  if (overdue) {
    const days = Math.max(1, -daysUntil(dueAt, now));
    return pill(OVERDUE, `Overdue ${days}d`, title);
  }
  if (status === 'resolved' || status === 'accepted_risk') {
    return (
      <span className="whitespace-nowrap text-xs text-fg-subtle" title={title}>
        {formatDate(dueAt)}
      </span>
    );
  }
  const days = Math.max(0, daysUntil(dueAt, now));
  if (days <= DUE_SOON_DAYS) {
    return pill(SOON, days === 0 ? 'Due today' : `Due in ${days}d`, title);
  }
  return (
    <span className="whitespace-nowrap text-xs text-fg-muted" title={title}>
      {formatDate(dueAt)}
    </span>
  );
}
