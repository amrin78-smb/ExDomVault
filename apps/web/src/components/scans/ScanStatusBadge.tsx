import { SCAN_JOB_STATUS_LABELS, type ScanJobStatus } from '@exdomainvault/shared';

const STYLES: Record<ScanJobStatus, string> = {
  queued: 'bg-slate-100 text-slate-700 ring-slate-500/20',
  claimed: 'bg-sky-50 text-sky-800 ring-sky-600/20',
  running: 'bg-sky-50 text-sky-800 ring-sky-600/20',
  succeeded: 'bg-emerald-50 text-emerald-800 ring-emerald-600/20',
  failed: 'bg-red-50 text-red-800 ring-red-600/20',
  cancelled: 'bg-slate-100 text-slate-600 ring-slate-500/20',
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
