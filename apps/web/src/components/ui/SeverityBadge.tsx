import { SEVERITY_LABELS, type Severity } from '@exdomainvault/shared';

const STYLES: Record<Severity, string> = {
  critical: 'bg-red-50 text-sev-critical ring-red-600/25',
  high: 'bg-orange-50 text-sev-high ring-orange-600/25',
  medium: 'bg-yellow-50 text-sev-medium ring-yellow-600/30',
  low: 'bg-blue-50 text-sev-low ring-blue-600/25',
  informational: 'bg-slate-100 text-sev-info ring-slate-500/25',
};

/** The single source of severity styling. Label text is always shown; colour is never the only cue. */
export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium ring-1 ring-inset ${STYLES[severity]}`}
    >
      {SEVERITY_LABELS[severity]}
    </span>
  );
}
