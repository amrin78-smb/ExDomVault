import { ASSET_STATUS_LABELS, type AssetStatus, type HostingHint } from '@exdomainvault/shared';
import { Cloud } from 'lucide-react';
import { HOSTING_KIND_LABELS } from './labels.ts';

const STATUS_STYLES: Record<AssetStatus, string> = {
  pending: 'bg-amber-50 text-amber-800 ring-amber-600/20',
  approved: 'bg-emerald-50 text-emerald-800 ring-emerald-600/20',
  rejected: 'bg-slate-100 text-slate-600 ring-slate-500/20',
  suspended: 'bg-slate-100 text-slate-800 ring-slate-500/25',
};

/** Review state of a hostname. Deliberately not severity colours. */
export function AssetStatusBadge({ status }: { status: AssetStatus }) {
  return (
    <span
      className={`inline-flex items-center whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${STATUS_STYLES[status]}`}
    >
      {ASSET_STATUS_LABELS[status]}
    </span>
  );
}

/** Third-party hosting matched from the hostname's CNAME chain (a hint, not proof). */
export function HostingHintChip({ hint }: { hint: HostingHint }) {
  return (
    <span
      className="inline-flex items-center gap-1 whitespace-nowrap rounded-full bg-violet-50 px-2 py-0.5 text-xs font-medium text-violet-800 ring-1 ring-inset ring-violet-600/20"
      title={`Matched ${hint.matchedName}`}
    >
      <Cloud className="size-3" aria-hidden />
      {hint.provider}
      <span className="font-normal text-violet-700">· {HOSTING_KIND_LABELS[hint.kind]}</span>
    </span>
  );
}

/** The name was only seen as a wildcard certificate entry: no concrete host is known. */
export function WildcardOnlyMarker() {
  return (
    <span
      className="inline-flex items-center whitespace-nowrap rounded-full bg-slate-50 px-2 py-0.5 text-xs text-slate-600 ring-1 ring-inset ring-slate-400/30"
      title="Seen only in wildcard certificate names"
    >
      Wildcard only
    </span>
  );
}
