import {
  CRITICALITY_LABELS,
  DOMAIN_VERIFICATION_STATUS_LABELS,
  type Criticality,
  type DomainVerificationStatus,
  type VerificationMethod,
} from '@exdomainvault/shared';
import { CircleDashed, Clock, ShieldCheck, ShieldOff, UserCheck } from 'lucide-react';

const VERIFICATION_STYLES: Record<DomainVerificationStatus, { cls: string; Icon: typeof Clock }> = {
  verified: {
    cls: 'bg-emerald-50 text-emerald-800 ring-emerald-600/20 dark:ring-emerald-400/45',
    Icon: ShieldCheck,
  },
  pending: {
    cls: 'bg-amber-50 text-amber-800 ring-amber-600/20 dark:ring-amber-400/45',
    Icon: Clock,
  },
  unverified: {
    cls: 'bg-surface-3 text-fg-2 ring-slate-500/20 dark:ring-slate-500/40',
    Icon: CircleDashed,
  },
  revoked: { cls: 'bg-red-50 text-red-800 ring-red-600/20 dark:ring-red-400/45', Icon: ShieldOff },
};

/**
 * Verification state. Verified domains also show how: DNS proof and administrator authorisation are
 * deliberately distinguishable.
 */
export function VerificationBadge({
  status,
  method,
}: {
  status: DomainVerificationStatus;
  method?: VerificationMethod | null;
}) {
  const attested = status === 'verified' && method === 'admin_attestation';
  const { cls, Icon } = attested
    ? { cls: 'bg-sky-50 text-sky-800 ring-sky-600/20 dark:ring-sky-400/45', Icon: UserCheck }
    : VERIFICATION_STYLES[status];
  const label = attested
    ? 'Authorised (admin)'
    : status === 'verified' && method === 'dns_txt'
      ? 'Verified (DNS)'
      : DOMAIN_VERIFICATION_STATUS_LABELS[status];
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${cls}`}
    >
      <Icon className="size-3" aria-hidden />
      {label}
    </span>
  );
}

/** Business criticality of a domain. Deliberately neutral styling: this is not finding severity. */
export function CriticalityLabel({ criticality }: { criticality: Criticality }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-sm text-fg-2">
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
