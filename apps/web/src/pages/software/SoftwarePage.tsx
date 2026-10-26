import { SOFTWARE_PRODUCTS } from '@exdomainvault/shared';
import { PackageSearch, Search, X } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router';
import { TableSkeleton } from '../../components/inventory/ListBody.tsx';
import { ScheduledScansHint } from '../../components/settings/ScheduledScansHint.tsx';
import { Pagination } from '../../components/findings/Pagination.tsx';
import { SoftwareExplainer } from '../../components/software/SoftwareExplainer.tsx';
import { SoftwareRollup } from '../../components/software/SoftwareRollup.tsx';
import { SoftwareTable } from '../../components/software/SoftwareTable.tsx';
import { Button } from '../../components/ui/Button.tsx';
import { Card } from '../../components/ui/Card.tsx';
import { EmptyState } from '../../components/ui/EmptyState.tsx';
import { LoadError } from '../../components/ui/LoadError.tsx';
import { ExportCsvButton } from '../../components/reports/ExportCsvButton.tsx';
import { PageHeader } from '../../components/ui/PageHeader.tsx';
import { StaleDataNotice } from '../../components/ui/StaleDataNotice.tsx';
import { api } from '../../lib/api.ts';
import { useAsync } from '../../lib/use-async.ts';
import { useRefreshableAsync } from '../../lib/use-refreshable-async.ts';

const FILTER_KEYS = ['domainId', 'product', 'status', 'q'] as const;
const QUERY_KEYS = ['page', 'pageSize', ...FILTER_KEYS] as const;

const STATUS_LABELS = {
  all: 'All software',
  eol: 'End of life only',
  kev: 'Possibly KEV-affected only',
} as const;

const selectClass =
  'rounded-md border border-line-strong bg-surface px-2 py-1.5 text-sm text-fg-2 shadow-sm';

export function SoftwarePage() {
  const [params, setParams] = useSearchParams();
  const [searchDraft, setSearchDraft] = useState(params.get('q') ?? '');
  const query = Object.fromEntries(QUERY_KEYS.map((k) => [k, params.get(k) ?? undefined]));
  const { state, stale, refreshing, retry } = useRefreshableAsync(
    (signal) => api.software.list(query, { signal }),
    [params.toString()],
  );
  const summary = useAsync((signal) => api.software.summary({ signal }), []);
  const filtered = FILTER_KEYS.some((k) => params.get(k));

  const setParam = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== 'page') next.delete('page');
    setParams(next);
  };

  const productHref = (product: string) => {
    const next = new URLSearchParams(params);
    next.set('product', product);
    next.delete('page');
    return `?${next.toString()}`;
  };

  const onSearch = (e: FormEvent) => {
    e.preventDefault();
    setParam('q', searchDraft.trim());
  };

  const domainId = params.get('domainId');
  const domainLabel =
    (state.status === 'success'
      ? state.data.items.find((s) => s.domain.id === domainId)?.domain.fqdn
      : undefined) ?? 'selected domain';

  return (
    <>
      <PageHeader
        title="Software"
        description="Products and versions your hosts report about themselves, checked against end-of-life dates and CISA's Known Exploited Vulnerabilities catalogue."
      />

      <div className="space-y-6">
        <SoftwareExplainer />

        <Card title="Portfolio by product">
          {summary.status === 'loading' && (
            <p className="text-sm text-fg-subtle" role="status">
              Loading summary…
            </p>
          )}
          {summary.status === 'error' && (
            <LoadError error={summary.error} title="Could not load the software summary" />
          )}
          {summary.status === 'success' &&
            (summary.data.products.length === 0 ? (
              <p className="text-sm text-fg-subtle">No software recorded yet.</p>
            ) : (
              <SoftwareRollup products={summary.data.products} productHref={productHref} />
            ))}
        </Card>

        <Card title="Inventory" actions={<ExportCsvButton resource="software" filters={query} />}>
          <div className="mb-4 flex flex-wrap items-end gap-3">
            <form onSubmit={onSearch} role="search" className="flex items-center gap-2">
              <label htmlFor="software-search" className="sr-only">
                Search software
              </label>
              <div className="relative">
                <Search
                  className="pointer-events-none absolute left-2 top-2 size-4 text-fg-faint"
                  aria-hidden
                />
                <input
                  id="software-search"
                  type="search"
                  value={searchDraft}
                  onChange={(e) => setSearchDraft(e.target.value)}
                  placeholder="Hostname, domain or version"
                  className="w-60 rounded-md border border-line-strong py-1.5 pl-8 pr-2 text-sm shadow-sm"
                />
              </div>
              <Button type="submit">Search</Button>
            </form>
            <label className="text-xs text-fg-muted">
              <span className="mb-1 block">Product</span>
              <select
                className={selectClass}
                value={params.get('product') ?? ''}
                onChange={(e) => setParam('product', e.target.value)}
              >
                <option value="">All products</option>
                {SOFTWARE_PRODUCTS.map((p) => (
                  <option key={p.key} value={p.key}>
                    {p.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="text-xs text-fg-muted">
              <span className="mb-1 block">Show</span>
              <select
                className={selectClass}
                value={params.get('status') ?? 'all'}
                onChange={(e) => setParam('status', e.target.value === 'all' ? '' : e.target.value)}
              >
                {Object.entries(STATUS_LABELS).map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
          </div>

          {domainId && (
            <div className="mb-4 flex flex-wrap gap-2">
              <span className="inline-flex items-center gap-1 rounded-full bg-surface-3 py-0.5 pl-2.5 pr-1 text-xs text-fg-2">
                Domain: {domainLabel}
                <button
                  type="button"
                  onClick={() => setParam('domainId', '')}
                  aria-label={`Clear filter Domain: ${domainLabel}`}
                  className="rounded-full p-0.5 hover:bg-line"
                >
                  <X className="size-3" aria-hidden />
                </button>
              </span>
            </div>
          )}

          {stale && (
            <StaleDataNotice
              loadedAt={stale.loadedAt}
              error={stale.error}
              onRetry={retry}
              retrying={refreshing}
            />
          )}
          {state.status === 'loading' && <TableSkeleton label="Loading software…" columns={8} />}
          {state.status === 'error' && (
            <LoadError error={state.error} title="Could not load software" onRetry={retry} />
          )}
          {state.status === 'success' && state.data.items.length === 0 && (
            <EmptyState
              title={filtered ? 'No software matches these filters' : 'No software recorded yet'}
              icon={PackageSearch}
            >
              {filtered ? (
                'Clear the filters to see the whole inventory.'
              ) : (
                <>
                  Software is read from completed scans. Run a <strong>Quick</strong> scan to record
                  HTTP server headers, or a <strong>Standard</strong> scan to also identify service
                  versions on open ports, from a{' '}
                  <Link to="/domains" className="text-sky-800 hover:underline">
                    domain page
                  </Link>
                  .
                  <ScheduledScansHint />
                </>
              )}
            </EmptyState>
          )}
          {state.status === 'success' && state.data.items.length > 0 && (
            <>
              <SoftwareTable items={state.data.items} />
              <Pagination
                page={state.data.page}
                pageSize={state.data.pageSize}
                total={state.data.total}
                onPage={(p) => setParam('page', String(p))}
              />
            </>
          )}
        </Card>
      </div>
    </>
  );
}
