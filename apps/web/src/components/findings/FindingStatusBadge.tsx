import { FINDING_STATUS_LABELS, type FindingStatus } from '@exdomainvault/shared';

const STYLES: Record<FindingStatus, string> = {
  open: 'bg-surface-3 text-fg ring-slate-500/25 dark:ring-slate-500/40',
  acknowledged: 'bg-sky-50 text-sky-800 ring-sky-600/20 dark:ring-sky-400/45',
  remediation_in_progress: 'bg-sky-50 text-sky-800 ring-sky-600/20 dark:ring-sky-400/45',
  resolved: 'bg-emerald-50 text-emerald-800 ring-emerald-600/20 dark:ring-emerald-400/45',
  accepted_risk: 'bg-surface-2 text-fg-muted ring-slate-500/20 dark:ring-slate-500/40',
};

/** Workflow state of a finding. Deliberately not severity colours (SeverityBadge owns those). */
export function FindingStatusBadge({ status }: { status: FindingStatus }) {
  return (
    <span
      className={`inline-flex items-center whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${STYLES[status]}`}
    >
      {FINDING_STATUS_LABELS[status]}
    </span>
  );
}
