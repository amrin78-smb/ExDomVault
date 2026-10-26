import { FileText } from 'lucide-react';
import { Link, useSearchParams } from 'react-router';
import { FindingStatusBadge } from '../../components/findings/FindingStatusBadge.tsx';
import { Pagination } from '../../components/findings/Pagination.tsx';
import { RiskScore } from '../../components/findings/RiskScore.tsx';
import { Card } from '../../components/ui/Card.tsx';
import { EmptyState } from '../../components/ui/EmptyState.tsx';
import { LoadError } from '../../components/ui/LoadError.tsx';
import { StaleDataNotice } from '../../components/ui/StaleDataNotice.tsx';
import { ExportCsvButton } from '../../components/reports/ExportCsvButton.tsx';
import { PageHeader } from '../../components/ui/PageHeader.tsx';
import { SeverityBadge } from '../../components/ui/SeverityBadge.tsx';
import { api } from '../../lib/api.ts';
import { useRefreshableAsync } from '../../lib/use-refreshable-async.ts';

const selectClass =
  'rounded-md border border-line-strong bg-surface px-2 py-1.5 text-sm text-fg-2 shadow-sm';

export function AdvisoriesPage() {
  const [params, setParams] = useSearchParams();
  const query = {
    page: params.get('page') ?? undefined,
    status: params.get('status') ?? undefined,
  };
  const { state, stale, refreshing, retry } = useRefreshableAsync(
    (signal) => api.advisories.list(query, { signal }),
    [params.toString()],
  );

  const setParam = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== 'page') next.delete('page');
    setParams(next);
  };

  // Highest remediation priority first (the API orders by risk too; this keeps the page stable).
  const items =
    state.status === 'success'
      ? [...state.data.items].sort((a, b) => b.finding.riskScore - a.finding.riskScore)
      : [];

  return (
    <>
      <PageHeader
        title="Advisories"
        description="Plain-language remediation guidance for findings, highest risk first. Advisories are generated from deterministic rules and recorded evidence."
        actions={
          <>
            <label className="text-xs text-fg-muted">
              <span className="mb-1 block">Findings</span>
              <select
                className={selectClass}
                value={params.get('status') ?? ''}
                onChange={(e) => setParam('status', e.target.value)}
              >
                <option value="">Active (not resolved)</option>
                <option value="all">All, including resolved</option>
              </select>
            </label>
            <ExportCsvButton resource="advisories" filters={query} />
          </>
        }
      />

      {stale && (
        <StaleDataNotice
          loadedAt={stale.loadedAt}
          error={stale.error}
          onRetry={retry}
          retrying={refreshing}
        />
      )}
      {state.status === 'loading' && (
        <p className="py-8 text-center text-sm text-fg-subtle" role="status">
          Loading advisories…
        </p>
      )}
      {state.status === 'error' && (
        <LoadError error={state.error} title="Could not load advisories" onRetry={retry} />
      )}
      {state.status === 'success' && items.length === 0 && (
        <Card>
          <EmptyState title="No advisories" icon={FileText}>
            Advisories are written for findings raised by rules on completed scans. None are
            currently active.
          </EmptyState>
        </Card>
      )}
      {state.status === 'success' && items.length > 0 && (
        <>
          <ul className="space-y-4">
            {items.map((a) => (
              <li key={a.id}>
                <article
                  aria-label={a.title}
                  className="rounded-lg border border-line bg-surface p-4 shadow-sm"
                >
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0">
                      <h2 className="font-semibold text-fg">{a.title}</h2>
                      <p className="mt-0.5 font-mono text-xs text-fg-subtle">
                        {a.finding.domain.fqdn}
                        {a.finding.hostname !== a.finding.domain.fqdn && ` · ${a.finding.hostname}`}
                        {` · ${a.finding.ruleId}`}
                      </p>
                    </div>
                    <div className="flex shrink-0 items-center gap-3">
                      <SeverityBadge severity={a.finding.severity} />
                      <FindingStatusBadge status={a.finding.status} />
                      <RiskScore score={a.finding.riskScore} />
                    </div>
                  </div>
                  <p className="mt-3 text-sm text-fg-2">{a.summary}</p>
                  <div className="mt-3 grid gap-4 text-sm md:grid-cols-2">
                    <div>
                      <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-fg-subtle">
                        Business impact
                      </h3>
                      <p className="text-fg-2">{a.businessImpact}</p>
                    </div>
                    {a.recommendedActions.length > 0 && (
                      <div>
                        <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-fg-subtle">
                          Recommended actions
                        </h3>
                        <ol className="list-decimal space-y-1 pl-5 text-fg-2">
                          {a.recommendedActions.map((action) => (
                            <li key={action}>{action}</li>
                          ))}
                        </ol>
                      </div>
                    )}
                  </div>
                  <Link
                    to={`/findings/${a.finding.id}`}
                    className="mt-3 inline-block text-sm text-sky-800 hover:underline"
                  >
                    View finding and evidence
                  </Link>
                </article>
              </li>
            ))}
          </ul>
          <Pagination
            page={state.data.page}
            pageSize={state.data.pageSize}
            total={state.data.total}
            onPage={(p) => setParam('page', String(p))}
          />
        </>
      )}
    </>
  );
}
