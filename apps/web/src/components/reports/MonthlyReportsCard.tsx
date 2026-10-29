import { previousPeriod } from '@exdomainvault/shared';
import { FileText } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router';
import { api } from '../../lib/api.ts';
import { formatDateTime } from '../../lib/format.ts';
import { usePermission } from '../../lib/session.ts';
import { useAsync } from '../../lib/use-async.ts';
import { periodLabel } from './period.ts';
import { Button } from '../ui/Button.tsx';
import { Card } from '../ui/Card.tsx';
import { EmptyState } from '../ui/EmptyState.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';
import { LoadError } from '../ui/LoadError.tsx';

/**
 * Monthly executive reports: generated automatically after each month ends; administrators can
 * generate (or regenerate) last month now.
 */
export function MonthlyReportsCard() {
  const [reload, setReload] = useState(0);
  const state = useAsync((signal) => api.reports.monthly.list({ signal }), [reload]);
  const canGenerate = usePermission('settings:manage');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const last = previousPeriod(new Date());

  const generate = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.reports.monthly.generate(last);
      setReload((k) => k + 1);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card
      title="Monthly reports"
      actions={
        canGenerate ? (
          <Button onClick={generate} disabled={busy}>
            {busy ? 'Generating…' : `Generate ${periodLabel(last)}`}
          </Button>
        ) : undefined
      }
    >
      {error && <ErrorAlert error={error} title="Could not generate the report" />}
      {state.status === 'loading' && (
        <p role="status" className="text-sm text-fg-subtle">
          Loading monthly reports…
        </p>
      )}
      {state.status === 'error' && (
        <LoadError
          error={state.error}
          title="Could not load monthly reports"
          deniedTitle="Monthly reports cover the whole organisation"
        />
      )}
      {state.status === 'success' && state.data.items.length === 0 && (
        <EmptyState title="No monthly report yet" icon={FileText}>
          The report for each month is generated automatically on the 1st of the following month
          (UTC).
        </EmptyState>
      )}
      {state.status === 'success' && state.data.items.length > 0 && (
        <ul className="divide-y divide-line-soft text-sm" aria-label="Monthly reports">
          {state.data.items.map((r) => (
            <li key={r.period} className="flex flex-wrap items-center justify-between gap-3 py-2">
              <div>
                <Link
                  to={`/reports/monthly/${r.period}`}
                  className="font-medium text-sky-800 hover:underline"
                >
                  {periodLabel(r.period)}
                </Link>
                <div className="text-xs text-fg-subtle">
                  Generated {formatDateTime(r.generatedAt)}
                </div>
              </div>
              <div className="flex gap-4 text-xs text-fg-muted tabular-nums">
                <span>{r.openAtEndTotal} open</span>
                <span>{r.overdueAtEnd} overdue</span>
                <span>Avg score {r.averageScore === null ? '—' : r.averageScore.toFixed(1)}</span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
