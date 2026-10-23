import {
  ASSET_SORTS,
  ASSET_SOURCES,
  ASSET_STATUSES,
  ASSET_STATUS_LABELS,
  type AssetBulkDecisionResponse,
  type AssetStatus,
} from '@exdomainvault/shared';
import { Search, Server, X } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router';
import {
  AssetStatusBadge,
  HostingHintChip,
  WildcardOnlyMarker,
} from '../../components/assets/AssetBadges.tsx';
import { BulkAssetActions } from '../../components/assets/BulkAssetActions.tsx';
import {
  ASSET_ACTION_DONE,
  assetBulkResultText,
  sourceLabel,
  type AssetAction,
} from '../../components/assets/labels.ts';
import { Pagination } from '../../components/findings/Pagination.tsx';
import { Button } from '../../components/ui/Button.tsx';
import { Card } from '../../components/ui/Card.tsx';
import { EmptyState } from '../../components/ui/EmptyState.tsx';
import { LoadError } from '../../components/ui/LoadError.tsx';
import { StaleDataNotice } from '../../components/ui/StaleDataNotice.tsx';
import { PageHeader } from '../../components/ui/PageHeader.tsx';
import { api } from '../../lib/api.ts';
import { formatDateTime } from '../../lib/format.ts';
import { usePermission } from '../../lib/session.ts';
import { useAsync } from '../../lib/use-async.ts';
import { useRefreshableAsync } from '../../lib/use-refreshable-async.ts';

/** Status shown when the URL names none: the review queue. */
const DEFAULT_STATUS = 'pending';

const SORT_LABELS: Record<(typeof ASSET_SORTS)[number], string> = {
  hostname: 'Hostname (A–Z)',
  '-lastSeenAt': 'Most recently seen',
  '-firstSeenAt': 'Newest first',
};

const selectClass =
  'rounded-md border border-slate-300 bg-white px-2 py-1.5 text-sm text-slate-700 shadow-sm';

export function AssetsPage() {
  const [params, setParams] = useSearchParams();
  const [searchDraft, setSearchDraft] = useState(params.get('q') ?? '');
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const [reloadKey, setReloadKey] = useState(0);
  const [bulkResult, setBulkResult] = useState<{
    result: AssetBulkDecisionResponse;
    action: AssetAction;
  } | null>(null);
  const canDecide = usePermission('assets:approve');
  const canReadDomains = usePermission('domains:read');

  const status = params.get('status') ?? DEFAULT_STATUS;
  const query = {
    page: params.get('page') ?? undefined,
    pageSize: params.get('pageSize') ?? undefined,
    status: status === 'all' ? undefined : status,
    domainId: params.get('domainId') ?? undefined,
    source: params.get('source') ?? undefined,
    thirdParty: params.get('thirdParty') ?? undefined,
    q: params.get('q') ?? undefined,
    sort: params.get('sort') ?? undefined,
  };
  const { state, stale, refreshing, retry } = useRefreshableAsync(
    (signal) => api.assets.list(query, { signal }),
    [params.toString()],
    reloadKey,
  );
  const domains = useAsync(
    (signal) =>
      canReadDomains
        ? api.domains.list({ pageSize: 100 }, { signal })
        : Promise.resolve({ items: [], page: 1, pageSize: 100, total: 0 }),
    [canReadDomains],
  );
  const filtered = ['domainId', 'source', 'thirdParty', 'q'].some((k) => params.get(k));

  const setParam = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== 'page') next.delete('page');
    // A selection made under other filters or on another page may include hidden rows: start over.
    setSelected(new Set());
    setParams(next);
  };

  const onSearch = (e: FormEvent) => {
    e.preventDefault();
    setParam('q', searchDraft.trim());
  };

  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const domainId = params.get('domainId') ?? '';
  const domainOptions = domains.status === 'success' ? domains.data.items : [];
  const items = state.status === 'success' ? state.data.items : [];
  const selectedAssets = items.filter((a) => selected.has(a.id));

  return (
    <>
      <PageHeader
        title="Assets"
        description="Hostnames beneath your registered domains. Names found by passive discovery wait here for review; only approved hostnames are ever included in scans."
      />

      <Card>
        <div className="mb-4 flex flex-wrap items-end gap-3">
          <form onSubmit={onSearch} role="search" className="flex items-center gap-2">
            <label htmlFor="asset-search" className="sr-only">
              Search hostnames
            </label>
            <div className="relative">
              <Search
                className="pointer-events-none absolute left-2 top-2 size-4 text-slate-400"
                aria-hidden
              />
              <input
                id="asset-search"
                type="search"
                value={searchDraft}
                onChange={(e) => setSearchDraft(e.target.value)}
                placeholder="Hostname"
                className="w-56 rounded-md border border-slate-300 py-1.5 pl-8 pr-2 text-sm shadow-sm"
              />
            </div>
            <Button type="submit">Search</Button>
          </form>
          <label className="text-xs text-slate-600">
            <span className="mb-1 block">Status</span>
            <select
              className={selectClass}
              value={status}
              onChange={(e) =>
                setParam('status', e.target.value === DEFAULT_STATUS ? '' : e.target.value)
              }
            >
              {ASSET_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {ASSET_STATUS_LABELS[s]}
                </option>
              ))}
              <option value="all">All statuses</option>
            </select>
          </label>
          {(domainOptions.length > 0 || domainId) && (
            <label className="text-xs text-slate-600">
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
          <label className="text-xs text-slate-600">
            <span className="mb-1 block">Source</span>
            <select
              className={selectClass}
              value={params.get('source') ?? ''}
              onChange={(e) => setParam('source', e.target.value)}
            >
              <option value="">Any</option>
              {ASSET_SOURCES.map((s) => (
                <option key={s} value={s}>
                  {sourceLabel(s)}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs text-slate-600">
            <span className="mb-1 block">Third-party hosting</span>
            <select
              className={selectClass}
              value={params.get('thirdParty') ?? ''}
              onChange={(e) => setParam('thirdParty', e.target.value)}
            >
              <option value="">Any</option>
              <option value="true">Yes (provider detected)</option>
              <option value="false">No provider detected</option>
            </select>
          </label>
          <label className="text-xs text-slate-600">
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
          {params.get('q') && (
            <span className="inline-flex items-center gap-1 self-center rounded-full bg-slate-100 py-0.5 pl-2.5 pr-1 text-xs text-slate-700">
              Search: {params.get('q')}
              <button
                type="button"
                onClick={() => {
                  setSearchDraft('');
                  setParam('q', '');
                }}
                aria-label="Clear search"
                className="rounded-full p-0.5 hover:bg-slate-200"
              >
                <X className="size-3" aria-hidden />
              </button>
            </span>
          )}
        </div>

        <div aria-live="polite">
          {bulkResult && (
            <p
              role="status"
              className="mb-4 rounded-md border border-sky-200 bg-sky-50 px-3 py-2 text-sm text-sky-900"
            >
              {assetBulkResultText(bulkResult.result)}
              {bulkResult.result.updated > 0 &&
                ` ${bulkResult.result.updated === 1 ? 'The asset was' : 'Assets were'} ${ASSET_ACTION_DONE[bulkResult.action]}.`}
            </p>
          )}
        </div>
        {canDecide && selectedAssets.length > 0 && (
          <BulkAssetActions
            assets={selectedAssets}
            onDone={(result, action) => {
              setBulkResult({ result, action });
              setSelected(new Set());
              setReloadKey((k) => k + 1);
            }}
            onClear={() => setSelected(new Set())}
          />
        )}

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
            Loading assets…
          </p>
        )}
        {state.status === 'error' && (
          <LoadError error={state.error} title="Could not load assets" onRetry={retry} />
        )}
        {state.status === 'success' && state.data.items.length === 0 && (
          <EmptyState
            title={
              filtered
                ? 'No assets match these filters'
                : status === 'pending'
                  ? 'Nothing waiting for review'
                  : status === 'all'
                    ? 'No assets yet'
                    : `No assets with status ${statusLabel(status)}`
            }
            icon={Server}
          >
            {filtered ? (
              'Clear the filters to see more hostnames.'
            ) : (
              <>
                Discovery looks for hostnames in public Certificate Transparency logs. A name found
                there proves neither that your organisation owns it nor that the host is live, so
                each one waits here as Pending review. Nothing is scanned until it is approved. Run
                discovery from a domain&apos;s page.
              </>
            )}
          </EmptyState>
        )}
        {state.status === 'success' && state.data.items.length > 0 && (
          <>
            <div className="overflow-x-auto">
              <table className="min-w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-200 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
                    {canDecide && (
                      <th scope="col" className="w-8 py-2 pr-2">
                        <input
                          type="checkbox"
                          aria-label="Select all assets on this page"
                          checked={state.data.items.every((a) => selected.has(a.id))}
                          onChange={(e) =>
                            setSelected(
                              e.target.checked
                                ? new Set(state.data.items.map((a) => a.id))
                                : new Set(),
                            )
                          }
                        />
                      </th>
                    )}
                    <th scope="col" className="py-2 pr-4">
                      Hostname
                    </th>
                    <th scope="col" className="py-2 pr-4">
                      Domain
                    </th>
                    <th scope="col" className="py-2 pr-4">
                      Status
                    </th>
                    <th scope="col" className="py-2 pr-4">
                      Source
                    </th>
                    <th scope="col" className="py-2 pr-4">
                      Hosting
                    </th>
                    <th scope="col" className="py-2 pr-4">
                      Current IPs
                    </th>
                    <th scope="col" className="py-2 pr-4">
                      Last seen
                    </th>
                    <th scope="col" className="py-2 text-right">
                      Active findings
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {state.data.items.map((a) => (
                    <tr key={a.id} className="hover:bg-slate-50">
                      {canDecide && (
                        <td className="py-2.5 pr-2">
                          <input
                            type="checkbox"
                            aria-label={`Select ${a.hostname}`}
                            checked={selected.has(a.id)}
                            onChange={() => toggle(a.id)}
                          />
                        </td>
                      )}
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
                      <td className="py-2.5 pr-4 font-mono text-slate-700">{a.domain.fqdn}</td>
                      <td className="py-2.5 pr-4">
                        <AssetStatusBadge status={a.status} />
                      </td>
                      <td className="py-2.5 pr-4 text-slate-700">{sourceLabel(a.source)}</td>
                      <td className="py-2.5 pr-4">
                        {a.hostingHint ? (
                          <HostingHintChip hint={a.hostingHint} />
                        ) : (
                          <span className="text-slate-400">—</span>
                        )}
                      </td>
                      <td className="py-2.5 pr-4 font-mono text-xs text-slate-700">
                        <IpSummary ips={a.currentIps} />
                      </td>
                      <td className="whitespace-nowrap py-2.5 pr-4 text-slate-600">
                        {formatDateTime(a.lastSeenAt)}
                      </td>
                      <td className="py-2.5 text-right tabular-nums text-slate-700">
                        {a.activeFindings > 0 ? (
                          <Link
                            to={`/findings?q=${encodeURIComponent(a.hostname)}&domainId=${a.domain.id}`}
                            className="text-sky-800 hover:underline"
                            aria-label={`${a.activeFindings} active findings on ${a.hostname}`}
                          >
                            {a.activeFindings}
                          </Link>
                        ) : (
                          '0'
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
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

const statusLabel = (status: string) =>
  (ASSET_STATUSES as readonly string[]).includes(status)
    ? ASSET_STATUS_LABELS[status as AssetStatus]
    : status;

/** First two current addresses and how many more. */
function IpSummary({ ips }: { ips: string[] }) {
  if (ips.length === 0) return <span className="font-sans text-slate-400">None resolved</span>;
  const shown = ips.slice(0, 2);
  const more = ips.length - shown.length;
  return (
    <span>
      {shown.map((ip) => (
        <span key={ip} className="block">
          {ip}
        </span>
      ))}
      {more > 0 && <span className="block font-sans text-slate-500">+{more} more</span>}
    </span>
  );
}
