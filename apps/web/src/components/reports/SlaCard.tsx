import { SEVERITIES, compareSeverityDesc, type SlaReport } from '@exdomainvault/shared';
import { Link } from 'react-router';
import { Card } from '../ui/Card.tsx';
import { SeverityBadge } from '../ui/SeverityBadge.tsx';

const ORDER = [...SEVERITIES].sort(compareSeverityDesc);

const days = (n: number | null) => (n === null ? '—' : n.toFixed(1));

/** Remediation SLA performance (reports summary `sla` section). */
export function SlaCard({ sla }: { sla: SlaReport }) {
  return (
    <Card title="Remediation SLAs">
      <div className="grid gap-6 md:grid-cols-[14rem_1fr]">
        <div className="space-y-4">
          <div>
            <div className="text-xs font-medium uppercase tracking-wider text-fg-subtle">
              Overdue now
            </div>
            <Link
              to="/findings?overdue=true"
              className={`mt-1 block text-3xl font-semibold tabular-nums hover:underline ${
                sla.overdue > 0 ? 'text-red-800' : 'text-fg'
              }`}
              data-testid="sla-overdue"
            >
              {sla.overdue}
            </Link>
            <div className="text-xs text-fg-subtle">Open findings past their due date</div>
          </div>
          <div>
            <div className="text-xs font-medium uppercase tracking-wider text-fg-subtle">
              SLA compliance
            </div>
            <div
              className="mt-1 text-3xl font-semibold tabular-nums text-fg"
              data-testid="sla-compliance"
            >
              {sla.compliancePercent === null ? (
                <span className="text-fg-faint" aria-label="No data">
                  —
                </span>
              ) : (
                `${sla.compliancePercent}%`
              )}
            </div>
            <div className="text-xs text-fg-subtle">
              {sla.resolvedWithSla === 0
                ? `No finding with a due date was resolved in the last ${sla.windowDays} days`
                : `${sla.resolvedWithinSla} of ${sla.resolvedWithSla} resolved on time, last ${sla.windowDays} days`}
            </div>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b border-line text-left text-xs font-medium uppercase tracking-wide text-fg-subtle">
                <th scope="col" className="py-2 pr-4">
                  Severity
                </th>
                <th scope="col" className="py-2 pr-4 text-right">
                  SLA
                </th>
                <th scope="col" className="py-2 pr-4 text-right">
                  Overdue
                </th>
                <th scope="col" className="py-2 text-right">
                  Avg days to fix
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line-soft">
              {ORDER.map((s) => (
                <tr key={s}>
                  <td className="py-1.5 pr-4">
                    <SeverityBadge severity={s} />
                  </td>
                  <td className="py-1.5 pr-4 text-right tabular-nums text-fg-muted">
                    {sla.policy[s] === null ? 'None' : `${sla.policy[s]} d`}
                  </td>
                  <td className="py-1.5 pr-4 text-right tabular-nums">
                    {sla.overdueBySeverity[s] > 0 ? (
                      <Link
                        to={`/findings?overdue=true&severity=${s}`}
                        className="font-medium text-sky-800 hover:underline"
                      >
                        {sla.overdueBySeverity[s]}
                      </Link>
                    ) : (
                      0
                    )}
                  </td>
                  <td className="py-1.5 text-right tabular-nums">
                    {days(sla.meanDaysToResolveBySeverity[s])}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-2 text-xs text-fg-subtle">
            Average days from first seen to resolved, findings resolved in the last {sla.windowDays}{' '}
            days.{' '}
            <Link to="/settings?tab=sla" className="text-sky-800 hover:underline">
              SLA policy
            </Link>
          </p>
        </div>
      </div>
    </Card>
  );
}
