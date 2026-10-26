import type { CertificateStatus } from '@exdomainvault/shared';
import { CERTIFICATE_STATUS_LABELS, daysLeftText, daysLeftTone } from './format.ts';

const pill =
  'inline-flex items-center whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset';

const STATUS_STYLES: Record<CertificateStatus, string> = {
  expired: 'bg-red-50 text-red-800 ring-red-600/25',
  expiring: 'bg-amber-50 text-amber-900 ring-amber-600/30',
  mismatch: 'bg-orange-50 text-orange-800 ring-orange-600/25',
  untrusted: 'bg-orange-50 text-orange-800 ring-orange-600/25',
  valid: 'bg-emerald-50 text-emerald-800 ring-emerald-600/25',
};

/** The certificate's primary status (server precedence: expired > mismatch > untrusted > expiring). */
export function CertificateStatusChip({ status }: { status: CertificateStatus }) {
  return (
    <span className={`${pill} ${STATUS_STYLES[status]}`}>{CERTIFICATE_STATUS_LABELS[status]}</span>
  );
}

const TONE_STYLES = {
  red: 'bg-red-50 text-red-800 ring-red-600/25',
  amber: 'bg-amber-50 text-amber-900 ring-amber-600/30',
  blue: 'bg-blue-50 text-blue-800 ring-blue-600/25',
  neutral: 'bg-surface-3 text-fg-2 ring-line-strong',
} as const;

/** Days until `notAfter`, as text (colour is never the only cue). */
export function DaysLeftPill({ daysLeft }: { daysLeft: number | null }) {
  if (daysLeft === null) return <span className="text-xs text-fg-faint">Unknown</span>;
  const tone = daysLeftTone(daysLeft);
  return (
    <span className={`${pill} tabular-nums ${TONE_STYLES[tone]}`} data-tone={tone}>
      {daysLeftText(daysLeft)}
    </span>
  );
}
