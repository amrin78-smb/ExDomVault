import {
  CRITICALITY_LABELS,
  DOMAIN_VERIFICATION_STATUS_LABELS,
  type Criticality,
  type DomainVerificationStatus,
} from '@exdomainvault/shared';
import { CircleDashed, Clock, ShieldCheck, ShieldOff } from 'lucide-react';

const VERIFICATION_STYLES: Record<DomainVerificationStatus, { cls: string; Icon: typeof Clock }> = {
  verified: { cls: 'bg-emerald-50 text-emerald-800 ring-emerald-600/20', Icon: ShieldCheck },
  pending: { cls: 'bg-amber-50 text-amber-800 ring-amber-600/20', Icon: Clock },
  unverified: { cls: 'bg-slate-100 text-slate-700 ring-slate-500/20', Icon: CircleDashed },
  revoked: { cls: 'bg-red-50 text-red-800 ring-red-600/20', Icon: ShieldOff },
};

export function VerificationBadge({ status }: { status: DomainVerificationStatus }) {
  const { cls, Icon } = VERIFICATION_STYLES[status];
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${cls}`}
    >
      <Icon className="size-3" aria-hidden />
      {DOMAIN_VERIFICATION_STATUS_LABELS[status]}
    </span>
  );
}

/** Business criticality of a domain. Deliberately neutral styling: this is not finding severity. */
export function CriticalityLabel({ criticality }: { criticality: Criticality }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-sm text-slate-700">
      <span
        className={`inline-block h-2 w-2 rounded-full ${
          {
            low: 'bg-slate-300',
            medium: 'bg-slate-400',
            high: 'bg-slate-600',
            critical: 'bg-slate-900',
          }[criticality]
        }`}
        aria-hidden
      />
      {CRITICALITY_LABELS[criticality]}
    </span>
  );
}
