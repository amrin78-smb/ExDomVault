import type { Finding } from '@exdomainvault/shared';
import { Link } from 'react-router';
import { formatDateTime } from '../../lib/format.ts';
import { SeverityBadge } from '../ui/SeverityBadge.tsx';
import { userLabel } from './labels.ts';
import { RiskScore } from './RiskScore.tsx';

type FindingListItem = Pick<
  Finding,
  'id' | 'title' | 'severity' | 'hostname' | 'riskScore' | 'ruleId' | 'lastSeenAt'
> &
  Partial<Pick<Finding, 'assignee'>>;

/** Compact list of findings (dashboards and cards): severity, title, host, rule, assignee, risk. */
export function FindingList({
  items,
  showLastSeen = false,
}: {
  items: FindingListItem[];
  showLastSeen?: boolean;
}) {
  return (
    <ul className="divide-y divide-line-soft">
      {items.map((f) => (
        <li key={f.id} className="flex items-center justify-between gap-3 py-2 text-sm">
          <div className="min-w-0">
            <Link
              to={`/findings/${f.id}`}
              className="block truncate font-medium text-sky-800 hover:underline"
            >
              {f.title}
            </Link>
            <div className="truncate text-xs text-fg-subtle">
              <span className="font-mono">{f.hostname}</span> · {f.ruleId}
              {f.assignee && <> · assigned to {userLabel(f.assignee)}</>}
              {showLastSeen && <> · last seen {formatDateTime(f.lastSeenAt)}</>}
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-3">
            <SeverityBadge severity={f.severity} />
            <RiskScore score={f.riskScore} />
          </div>
        </li>
      ))}
    </ul>
  );
}
