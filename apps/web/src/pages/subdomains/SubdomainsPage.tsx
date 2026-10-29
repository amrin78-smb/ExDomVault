import {
  ASSET_ROLES,
  ASSET_ROLE_LABELS,
  ASSET_SORTS,
  ASSET_SOURCES,
  ASSET_STATUSES,
  ASSET_STATUS_LABELS,
  type Asset,
} from '@exdomainvault/shared';
import { ChevronRight, Network, Search, X } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router';
import {
  AssetRoleChip,
  AssetStatusBadge,
  HostingHintChip,
  WildcardOnlyMarker,
} from '../../components/assets/AssetBadges.tsx';
import { Pagination } from '../../components/findings/Pagination.tsx';
import { ExportCsvButton } from '../../components/reports/ExportCsvButton.tsx';
import { Button } from '../../components/ui/Button.tsx';
import { buttonClass } from '../../components/ui/button-styles.ts';
import { Card } from '../../components/ui/Card.tsx';
import { EmptyState } from '../../components/ui/EmptyState.tsx';
import { LoadError } from '../../components/ui/LoadError.tsx';
import { PageHeader } from '../../components/ui/PageHeader.tsx';
import { StaleDataNotice } from '../../components/ui/StaleDataNotice.tsx';
import { api } from '../../lib/api.ts';
import { formatDate } from '../../lib/format.ts';
import { usePermission } from '../../lib/session.ts';
import { useAsync } from '../../lib/use-async.ts';
import { useRefreshableAsync } from '../../lib/use-refreshable-async.ts';

/** Short source labels for the discovery view. */
const SUBDOMAIN_SOURCE_LABELS: Record<(typeof ASSET_SOURCES)[number], string> = {
  certificate_transparency: 'CT logs',
  import: 'Import',
  // Milestone 15: reverse DNS of IP ranges registered to the organisation.
  dns: 'DNS (reverse lookup)',
  manual: 'Manual',
};

const SORT_LABELS: Record<(typeof ASSET_SORTS)[number], string> = {
  hostname: 'Hostname (A–Z)',
  '-lastSeenAt': 'Most recently seen',
  '-firstSeenAt': 'Newest first',
};

const FILTER_KEYS = ['domainId', 'status', 'source', 'role', 'q'] as const;

const selectClass =
  'rounded-md border border-line-strong bg-surface px-2 py-1.5 text-sm text-fg-2 shadow-sm';

/**
 * Subdomains (Milestone 13): the asset inventory seen as discovery results — every hostname
 * beneath a registered domain except the apex, flat or grouped by domain. Decisions stay on the
 * Assets page; this view links to it.
 */
export function SubdomainsPage() {
  const [params, setParams] = useSearchParams();
  const [searchDraft, setSearchDraft] = useState(params.get('q') ?? '');
  const canReadDomains = usePermission('domains:read');
  const canImport = usePermission('domains:write');
  const grouped = params.get('view') === 'grouped';

  const query = {
    assetType: 'subdomain',
    page: params.get('page') ?? undefined,
    pageSize: params.get('pageSize') ?? undefined,
    status: params.get('status') ?? undefined,
    domainId: params.get('domainId') ?? undefined,
    source: params.get('source') ?? undefined,
    role: params.get('role') ?? undefined,
    q: params.get('q') ?? undefined,
    sort: params.get('sort') ?? undefined,
  };
  const { state, stale, refreshing, retry } = useRefreshableAsync(
    (signal) => api.assets.list(query, { signal }),
    [params.toString()],
  );
  const domainId = params.get('domainId') ?? '';
  const pending = useAsync(
    (signal) =>
      api.assets.list(
        { assetType: 'subdomain', status: 'pending', pageSize: 1, domainId: domainId || undefined },
        { signal },
      ),
    [domainId],
  );
  const domains = useAsync(
    (signal) =>
      canReadDomains
        ? api.domains.list({ pageSize: 100 }, { signal })
        : Promise.resolve({ items: [], page: 1, pageSize: 100, total: 0 }),
    [canReadDomains],
  );
  const filtered = FILTER_KEYS.some((k) => params.get(k));

  const setParam = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== 'page' && key !== 'view') next.delete('page');
    setParams(next);
  };

  const onSearch = (e: FormEvent) => {
    e.preventDefault();
    setParam('q', searchDraft.trim());
  };

  const domainOptions = domains.status === 'success' ? domains.data.items : [];
  const items = state.status === 'success' ? state.data.items : [];
  const pendingCount = pending.status === 'success' ? pending.data.total : 0;

  return (
    <>
      <PageHeader
        title="Subdomains"
        description="Hostnames found beneath your registered domains — from Certificate Transparency logs, DNS, imports or added by hand. Only approved hostnames are ever scanned."
        actions={
          <>
            {canImport && domainId && (
              <Link to={`/domains/${domainId}/import-hosts`} className={buttonClass('secondary')}>
                Import hosts
              </Link>
            )}
            <ExportCsvButton resource="assets" filters={query} label="Export subdomains (CSV)" />
          </>
        }
      />

      {pendingCount > 0 && params.get('status') !== 'pending' && (
        <div
          role="status"
          className="mb-4 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-amber-200 bg-amber-50 px-4 py-2.5 text-sm text-amber-900"
        >
          <span>
            {pendingCount === 1
              ? '1 discovered subdomain is waiting for review.'
              : `${pendingCount.toLocaleString()} discovered subdomains are waiting for review.`}{' '}
            Nothing is scanned until it is approved.
          </span>
          <Link
            to={`/assets?status=pending${domainId ? `&domainId=${domainId}` : ''}`}
            className="font-medium underline underline-offset-2"
          >
            Review pending
          </Link>
        </div>
      )}

      <Card>
        <div className="mb-4 flex flex-wrap items-end gap-3">
          <form onSubmit={onSearch} role="search" className="flex items-center gap-2">
            <label htmlFor="subdomain-search" className="sr-only">
              Search subdomains
            </label>
            <div className="relative">
              <Search
                className="pointer-events-none absolute left-2 top-2 size-4 text-fg-faint"
                aria-hidden
              />
              <input
                id="subdomain-search"
                type="search"
                value={searchDraft}
                onChange={(e) => setSearchDraft(e.target.value)}
                placeholder="Hostname"
                className="w-56 rounded-md border border-line-strong bg-surface py-1.5 pl-8 pr-2 text-sm shadow-sm"
              />
            </div>
            <Button type="submit">Search</Button>
          </form>
          {(domainOptions.length > 0 || domainId) && (
            <label className="text-xs text-fg-muted">
              <span className="mb-1 block">Domain</span>
              <select
                className={selectClass}
                value={domainId}
                onChange={(e) => setParam('domainId', e.target.value)}
              >
                <option value="">All domains</option>
                {domainId && !domainOptions.some((d) => d.id === domainId) && (
                  <option value={domainId}>
                    {items.find((a) => a.domain.id === domainId)?.domain.fqdn ?? 'Selected domain'}
                  </option>
                )}
                {domainOptions.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.fqdn}
                  </option>
                ))}
              </select>
            </label>
          )}
          <label className="text-xs text-fg-muted">
            <span className="mb-1 block">Status</span>
            <select
              className={selectClass}
              value={params.get('status') ?? ''}
              onChange={(e) => setParam('status', e.target.value)}
            >
              <option value="">All statuses</option>
              {ASSET_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {ASSET_STATUS_LABELS[s]}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs text-fg-muted">
            <span className="mb-1 block">Source</span>
            <select
              className={selectClass}
              value={params.get('source') ?? ''}
              onChange={(e) => setParam('source', e.target.value)}
            >
              <option value="">Any</option>
              {ASSET_SOURCES.map((s) => (
                <option key={s} value={s}>
                  {SUBDOMAIN_SOURCE_LABELS[s]}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs text-fg-muted">
            <span className="mb-1 block">Role</span>
            <select
              className={selectClass}
              value={params.get('role') ?? ''}
              onChange={(e) => setParam('role', e.target.value)}
            >
              <option value="">Any</option>
              {ASSET_ROLES.map((r) => (
                <option key={r} value={r}>
                  {ASSET_ROLE_LABELS[r]}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs text-fg-muted">
            <span className="mb-1 block">Sort</span>
            <select
              className={selectClass}
              value={params.get('sort') ?? 'hostname'}
              onChange={(e) =>
                setParam('sort', e.target.value === 'hostname' ? '' : e.target.value)
              }
            >
              {ASSET_SORTS.map((s) => (
                <option key={s} value={s}>
                  {SORT_LABELS[s]}
                </option>
              ))}
            </select>
          </label>
          <div
            role="group"
            aria-label="Layout"
            className="ml-auto inline-flex overflow-hidden rounded-md border border-line-strong text-sm"
          >
            <button
              type="button"
              aria-pressed={!grouped}
              onClick={() => setParam('view', '')}
              className={`px-3 py-1.5 ${!grouped ? 'bg-accent-soft font-medium text-fg' : 'text-fg-muted hover:bg-surface-3'}`}
            >
              Flat
            </button>
            <button
              type="button"
              aria-pressed={grouped}
              onClick={() => setParam('view', 'grouped')}
              className={`border-l border-line-strong px-3 py-1.5 ${grouped ? 'bg-accent-soft font-medium text-fg' : 'text-fg-muted hover:bg-surface-3'}`}
            >
              By domain
            </button>
          </div>
          {params.get('q') && (
            <span className="inline-flex items-center gap-1 self-center rounded-full bg-surface-3 py-0.5 pl-2.5 pr-1 text-xs text-fg-2">
              Search: {params.get('q')}
              <button
                type="button"
                onClick={() => {
                  setSearchDraft('');
                  setParam('q', '');
                }}
                aria-label="Clear search"
                className="rounded-full p-0.5 hover:bg-line"
              >
                <X className="size-3" aria-hidden />
              </button>
            </span>
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
        {state.status === 'loading' && <TableSkeleton />}
        {state.status === 'error' && (
          <LoadError error={state.error} title="Could not load subdomains" onRetry={retry} />
        )}
        {state.status === 'success' && state.data.items.length === 0 && (
          <EmptyState
            title={filtered ? 'No subdomains match these filters' : 'No subdomains yet'}
            icon={Network}
          >
            {filtered
              ? 'Clear the filters to see more hostnames.'
              : 'Run discovery from a domain’s page to search public Certificate Transparency logs, or import a list of hosts. Discovered names wait for review before anything is scanned.'}
          </EmptyState>
        )}
        {state.status === 'success' && state.data.items.length > 0 && (
          <>
            {grouped ? (
              <GroupedTables items={state.data.items} />
            ) : (
              <SubdomainTable items={state.data.items} />
            )}
            <Pagination
              page={state.data.page}
              pageSize={state.data.pageSize}
              total={state.data.total}
              onPage={(p) => setParam('page', String(p))}
            />
          </>
        )}
      </Card>
    </>
  );
}

function TableSkeleton() {
  return (
    <div role="status" aria-label="Loading subdomains" className="space-y-2 py-2">
      {[0, 1, 2, 3, 4].map((i) => (
        <div key={i} className="h-9 animate-pulse rounded-md bg-surface-3" />
      ))}
    </div>
  );
}

/** Groups by domain in first-appearance order (the list is already sorted). */
function groupByDomain(items: Asset[]) {
  const groups = new Map<string, { fqdn: string; id: string; items: Asset[] }>();
  for (const a of items) {
    const g = groups.get(a.domain.id) ?? { fqdn: a.domain.fqdn, id: a.domain.id, items: [] };
    g.items.push(a);
    groups.set(a.domain.id, g);
  }
  return [...groups.values()];
}

function GroupedTables({ items }: { items: Asset[] }) {
  const [closed, setClosed] = useState<ReadonlySet<string>>(new Set());
  const toggle = (id: string) =>
    setClosed((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  return (
    <div className="space-y-3">
      {groupByDomain(items).map((g) => {
        const open = !closed.has(g.id);
        const bodyId = `subdomain-group-${g.id}`;
        return (
          <section key={g.id} aria-label={g.fqdn} className="rounded-lg border border-line-soft">
            <h2 className="text-sm">
              <button
                type="button"
                aria-expanded={open}
                aria-controls={bodyId}
                onClick={() => toggle(g.id)}
                className="flex w-full items-center gap-2 rounded-t-lg bg-surface-2 px-3 py-2 text-left hover:bg-surface-3"
              >
                <ChevronRight
                  className={`size-4 text-fg-faint transition-transform ${open ? 'rotate-90' : ''}`}
                  aria-hidden
                />
                <span className="font-mono font-medium text-fg">{g.fqdn}</span>
                <span className="rounded-full bg-surface-3 px-2 py-0.5 text-xs tabular-nums text-fg-muted">
                  {g.items.length} on this page
                </span>
              </button>
            </h2>
            <div id={bodyId} hidden={!open} className="px-3">
              <SubdomainTable items={g.items} showDomain={false} />
            </div>
          </section>
        );
      })}
    </div>
  );
}

function SubdomainTable({ items, showDomain = true }: { items: Asset[]; showDomain?: boolean }) {
  const th = 'py-2 pr-4';
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-sm">
        <thead>
          <tr className="border-b border-line text-left text-xs font-medium uppercase tracking-wide text-fg-subtle">
            <th scope="col" className={th}>
              Hostname
            </th>
            {showDomain && (
              <th scope="col" className={th}>
                Domain
              </th>
            )}
            <th scope="col" className={th}>
              Source
            </th>
            <th scope="col" className={th}>
              Status
            </th>
            <th scope="col" className={th}>
              Role
            </th>
            <th scope="col" className={th}>
              Current IPs
            </th>
            <th scope="col" className={th}>
              Hosting
            </th>
            <th scope="col" className={th}>
              First seen
            </th>
            <th scope="col" className="py-2">
              Last seen
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line-soft">
          {items.map((a) => (
            <tr key={a.id} className="hover:bg-surface-2">
              <td className="py-2.5 pr-4">
                <Link
                  to={`/assets/${a.id}`}
                  className="break-all font-mono font-medium text-sky-800 hover:underline"
                >
                  {a.hostname}
                </Link>
                {a.wildcardOnly && (
                  <div className="mt-1">
                    <WildcardOnlyMarker />
                  </div>
                )}
              </td>
              {showDomain && <td className="py-2.5 pr-4 font-mono text-fg-2">{a.domain.fqdn}</td>}
              <td className="whitespace-nowrap py-2.5 pr-4 text-fg-2">
                {SUBDOMAIN_SOURCE_LABELS[a.source]}
              </td>
              <td className="py-2.5 pr-4">
                <AssetStatusBadge status={a.status} />
              </td>
              <td className="py-2.5 pr-4">
                {a.role ? (
                  <AssetRoleChip role={a.role} />
                ) : (
                  <span className="text-fg-faint">—</span>
                )}
              </td>
              <td className="py-2.5 pr-4 font-mono text-xs text-fg-2">
                {a.currentIps.length === 0 ? (
                  <span className="font-sans text-fg-faint">None resolved</span>
                ) : (
                  <>
                    {a.currentIps.slice(0, 2).map((ip) => (
                      <span key={ip} className="block">
                        {ip}
                      </span>
                    ))}
                    {a.currentIps.length > 2 && (
                      <span className="block font-sans text-fg-subtle">
                        +{a.currentIps.length - 2} more
                      </span>
                    )}
                  </>
                )}
              </td>
              <td className="py-2.5 pr-4">
                {a.hostingHint ? (
                  <HostingHintChip hint={a.hostingHint} />
                ) : (
                  <span className="text-fg-faint">—</span>
                )}
              </td>
              <td className="whitespace-nowrap py-2.5 pr-4 text-fg-muted">
                {formatDate(a.firstSeenAt)}
              </td>
              <td className="whitespace-nowrap py-2.5 text-fg-muted">{formatDate(a.lastSeenAt)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
