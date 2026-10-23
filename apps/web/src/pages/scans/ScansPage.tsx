import { SCAN_JOB_STATUSES, SCAN_JOB_STATUS_LABELS } from '@exdomainvault/shared';
import { Radar, RefreshCw } from 'lucide-react';
import { Link, useSearchParams } from 'react-router';
import { JOB_TYPE_LABELS } from '../../components/scans/labels.ts';
import { ScanStatusBadge } from '../../components/scans/ScanStatusBadge.tsx';
import { Button } from '../../components/ui/Button.tsx';
import { Card } from '../../components/ui/Card.tsx';
import { EmptyState } from '../../components/ui/EmptyState.tsx';
import { LoadError } from '../../components/ui/LoadError.tsx';
import { StaleDataNotice } from '../../components/ui/StaleDataNotice.tsx';
import { PageHeader } from '../../components/ui/PageHeader.tsx';
import { api } from '../../lib/api.ts';
import { formatDateTime } from '../../lib/format.ts';
import { useRefreshableAsync } from '../../lib/use-refreshable-async.ts';

const selectClass =
  'rounded-md border border-slate-300 bg-white px-2 py-1.5 text-sm text-slate-700 shadow-sm';

export function ScansPage() {
  const [params, setParams] = useSearchParams();
  const query = {
    page: params.get('page') ?? undefined,
    status: params.get('status') ?? undefined,
    domainId: params.get('domainId') ?? undefined,
  };
  const { state, stale, refreshing, retry } = useRefreshableAsync(
    (signal) => api.scans.list(query, { signal }),
    [params.toString()],
  );

  const setParam = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== 'page') next.delete('page');
    setParams(next);
  };

  return (
    <>
      <PageHeader
        title="Scans"
        description="Scan jobs, their progress and history. Start scans from a domain's page."
        actions={
          <Button onClick={retry} disabled={refreshing || state.status === 'loading'}>
            <RefreshCw className="size-4" aria-hidden />
            {refreshing ? 'Refreshing…' : 'Refresh'}
          </Button>
        }
      />
      <Card>
        <div className="mb-4 flex flex-wrap items-end gap-3">
          <label className="text-xs text-slate-600">
            <span className="mb-1 block">Status</span>
            <select
              className={selectClass}
              value={params.get('status') ?? ''}
              onChange={(e) => setParam('status', e.target.value)}
            >
              <option value="">All</option>
              {SCAN_JOB_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {SCAN_JOB_STATUS_LABELS[s]}
                </option>
              ))}
            </select>
          </label>
          {params.get('domainId') && (
            <Button onClick={() => setParam('domainId', '')}>Show all domains</Button>
          )}
        </div>

        {stale && (
          <StaleDataNotice
            loadedAt={stale.loadedAt}
            error={stale.error}
            onRetry={retry}
            retrying={refreshing}
          />
        )}
        {state.status === 'loading' && (
          <p className="py-8 text-center text-sm text-slate-500" role="status">
            Loading scans…
          </p>
        )}
        {state.status === 'error' && (
          <LoadError error={state.error} title="Could not load scans" onRetry={retry} />
        )}
        {state.status === 'success' && state.data.items.length === 0 && (
          <EmptyState title="No scans yet" icon={Radar}>
            Passive monitoring scans are scheduled daily for domains with monitoring on. You can
            also start one from a domain&apos;s page.
          </EmptyState>
        )}
        {state.status === 'success' && state.data.items.length > 0 && (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
                  <th scope="col" className="py-2 pr-4">
                    Domain
                  </th>
                  <th scope="col" className="py-2 pr-4">
                    Type
                  </th>
                  <th scope="col" className="py-2 pr-4">
                    Profile
                  </th>
                  <th scope="col" className="py-2 pr-4">
                    Status
                  </th>
                  <th scope="col" className="py-2 pr-4">
                    Targets
                  </th>
                  <th scope="col" className="py-2 pr-4">
                    Trigger
                  </th>
                  <th scope="col" className="py-2">
                    Created
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {state.data.items.map((j) => {
                  const total = Object.values(j.targetCounts).reduce((a, b) => a + b, 0);
                  return (
                    <tr key={j.id} className="hover:bg-slate-50">
                      <td className="py-2.5 pr-4">
                        <Link
                          to={`/scans/${j.id}`}
                          className="font-mono text-sm font-medium text-sky-800 hover:underline"
                        >
                          {j.domain?.fqdn ?? 'Deleted domain'}
                        </Link>
                      </td>
                      <td className="py-2.5 pr-4">{JOB_TYPE_LABELS[j.jobType]}</td>
                      <td className="py-2.5 pr-4 capitalize">{j.profile}</td>
                      <td className="py-2.5 pr-4">
                        <ScanStatusBadge status={j.status} />
                        {j.cancelRequestedAt && j.status !== 'cancelled' && (
                          <span className="ml-2 text-xs text-slate-500">cancelling</span>
                        )}
                      </td>
                      <td className="py-2.5 pr-4 tabular-nums text-slate-700">
                        {j.targetCounts.succeeded}/{total}
                      </td>
                      <td className="py-2.5 pr-4 text-slate-600">
                        {j.trigger === 'schedule' ? 'Scheduled' : (j.requestedBy?.email ?? 'User')}
                      </td>
                      <td className="py-2.5 text-slate-600">{formatDateTime(j.createdAt)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <nav
              aria-label="Pagination"
              className="mt-4 flex items-center justify-between border-t border-slate-100 pt-3 text-sm text-slate-600"
            >
              <span>{state.data.total} scans</span>
              <div className="flex gap-2">
                <Button
                  onClick={() => setParam('page', String(state.data.page - 1))}
                  disabled={state.data.page <= 1}
                >
                  Previous
                </Button>
                <Button
                  onClick={() => setParam('page', String(state.data.page + 1))}
                  disabled={state.data.page * state.data.pageSize >= state.data.total}
                >
                  Next
                </Button>
              </div>
            </nav>
          </div>
        )}
      </Card>
    </>
  );
}
