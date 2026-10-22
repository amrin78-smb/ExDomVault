import { SEVERITIES, compareSeverityDesc, type Severity } from '@exdomainvault/shared';
import { SeverityBadge } from '../ui/SeverityBadge.tsx';

const ORDERED = [...SEVERITIES].sort(compareSeverityDesc);

/** Active finding counts per severity, most severe first. */
export function SeverityCounts({ bySeverity }: { bySeverity: Partial<Record<Severity, number>> }) {
  return (
    <ul className="space-y-2" aria-label="Active findings by severity">
      {ORDERED.map((sev) => (
        <li key={sev} className="flex items-center justify-between text-sm">
          <SeverityBadge severity={sev} />
          <span className="tabular-nums font-medium text-slate-800" data-testid={`count-${sev}`}>
            {bySeverity[sev] ?? 0}
          </span>
        </li>
      ))}
    </ul>
  );
}
