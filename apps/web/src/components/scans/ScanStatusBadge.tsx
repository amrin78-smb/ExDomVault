import { SCAN_JOB_STATUS_LABELS, type ScanJobStatus } from '@exdomainvault/shared';

const STYLES: Record<ScanJobStatus, string> = {
  queued: 'bg-surface-3 text-fg-2 ring-slate-500/20 dark:ring-slate-500/40',
  claimed: 'bg-sky-50 text-sky-800 ring-sky-600/20 dark:ring-sky-400/45',
  running: 'bg-sky-50 text-sky-800 ring-sky-600/20 dark:ring-sky-400/45',
  succeeded: 'bg-emerald-50 text-emerald-800 ring-emerald-600/20 dark:ring-emerald-400/45',
  failed: 'bg-red-50 text-red-800 ring-red-600/20 dark:ring-red-400/45',
  cancelled: 'bg-surface-3 text-fg-muted ring-slate-500/20 dark:ring-slate-500/40',
};

/** Job state. Deliberately not severity colours: a failed scan is not a finding. */
export function ScanStatusBadge({ status }: { status: ScanJobStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${STYLES[status]}`}
    >
      {SCAN_JOB_STATUS_LABELS[status]}
    </span>
  );
}
