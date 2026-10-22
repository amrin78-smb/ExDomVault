import {
  FINDING_SORTS,
  FINDING_STATUSES,
  FINDING_STATUS_LABELS,
  RULE_CATEGORIES,
  SEVERITIES,
  SEVERITY_LABELS,
  compareSeverityDesc,
} from '@exdomainvault/shared';
import { Bug, Search, X } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router';
import { FindingStatusBadge } from '../../components/findings/FindingStatusBadge.tsx';
import { CATEGORY_LABELS, SORT_LABELS } from '../../components/findings/labels.ts';
import { Pagination } from '../../components/findings/Pagination.tsx';
import { RiskScore } from '../../components/findings/RiskScore.tsx';
import { Button } from '../../components/ui/Button.tsx';
import { Card } from '../../components/ui/Card.tsx';
import { EmptyState } from '../../components/ui/EmptyState.tsx';
import { ErrorAlert } from '../../components/ui/ErrorAlert.tsx';
import { PageHeader } from '../../components/ui/PageHeader.tsx';
import { SeverityBadge } from '../../components/ui/SeverityBadge.tsx';
import { api } from '../../lib/api.ts';
import { formatDateTime } from '../../lib/format.ts';
import { useAsync } from '../../lib/use-async.ts';

const FILTER_KEYS = ['status', 'severity', 'category', 'domainId', 'ruleId', 'q'] as const;
const QUERY_KEYS = ['page', 'pageSize', ...FILTER_KEYS, 'sort'] as const;

const selectClass =
  'rounded-md border border-slate-300 bg-white px-2 py-1.5 text-sm text-slate-700 shadow-sm';

export function FindingsPage() {
  const [params, setParams] = useSearchParams();
  const [searchDraft, setSearchDraft] = useState(params.get('q') ?? '');

  const query = Object.fromEntries(QUERY_KEYS.map((k) => [k, params.get(k) ?? undefined]));
  const state = useAsync((signal) => api.findings.list(query, { signal }), [params.toString()]);
  const filtered = FILTER_KEYS.some((k) => params.get(k));

  const setParam = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== 'page') next.delete('page');
    setParams(next);
  };

  const onSearch = (e: FormEvent) => {
    e.preventDefault();
    setParam('q', searchDraft.trim());
  };

  const domainId = params.get('domainId');
  const domainLabel =
    state.status === 'success'
      ? (state.data.items.find((f) => f.domain.id === domainId)?.domain.fqdn ?? 'selected domain')
      : 'selected domain';

  return (
    <>
      <PageHeader
        title="Findings"
        description="Evidence-backed observations about DNS, email, certificates, web and network exposure. A finding describes a configuration or exposure condition, not a confirmed compromise."
      />

      <Card>
        <div className="mb-4 flex flex-wrap items-end gap-3">
          <form onSubmit={onSearch} role="search" className="flex items-center gap-2">
            <label htmlFor="finding-search" className="sr-only">
              Search findings
            </label>
            <div className="relative">
              <Search
                className="pointer-events-none absolute left-2 top-2 size-4 text-slate-400"
                aria-hidden
              />
              <input
                id="finding-search"
                type="search"
                value={searchDraft}
                onChange={(e) => setSearchDraft(e.target.value)}
                placeholder="Title, hostname or domain"
                className="w-60 rounded-md border border-slate-300 py-1.5 pl-8 pr-2 text-sm shadow-sm"
              />
            </div>
            <Button type="submit">Search</Button>
          </form>
          <label className="text-xs text-slate-600">
            <span className="mb-1 block">Status</span>
            <select
              className={selectClass}
              value={params.get('status') ?? ''}
              onChange={(e) => setParam('status', e.target.value)}
            >
              <option value="">Active (not resolved)</option>
              <option value="all">All, including resolved</option>
              {FINDING_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {FINDING_STATUS_LABELS[s]}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs text-slate-600">
            <span className="mb-1 block">Severity</span>
            <select
              className={selectClass}
              value={params.get('severity') ?? ''}
              onChange={(e) => setParam('severity', e.target.value)}
            >
              <option value="">All</option>
              {[...SEVERITIES].sort(compareSeverityDesc).map((s) => (
                <option key={s} value={s}>
                  {SEVERITY_LABELS[s]}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs text-slate-600">
            <span className="mb-1 block">Category</span>
            <select
              className={selectClass}
              value={params.get('category') ?? ''}
              onChange={(e) => setParam('category', e.target.value)}
            >
              <option value="">All</option>
              {RULE_CATEGORIES.map((c) => (
                <option key={c} value={c}>
                  {CATEGORY_LABELS[c] ?? c}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs text-slate-600">
            <span className="mb-1 block">Sort</span>
            <select
              className={selectClass}
              value={params.get('sort') ?? '-riskScore'}
              onChange={(e) =>
                setParam('sort', e.target.value === '-riskScore' ? '' : e.target.value)
              }
            >
              {FINDING_SORTS.map((s) => (
                <option key={s} value={s}>
                  {SORT_LABELS[s] ?? s}
                </option>
              ))}
            </select>
          </label>
        </div>

        {(domainId ?? params.get('ruleId')) && (
          <div className="mb-4 flex flex-wrap gap-2">
            {domainId && (
              <FilterChip
                label={`Domain: ${domainLabel}`}
                onClear={() => setParam('domainId', '')}
              />
            )}
            {params.get('ruleId') && (
              <FilterChip
                label={`Rule: ${params.get('ruleId')}`}
                onClear={() => setParam('ruleId', '')}
              />
            )}
          </div>
        )}

        {state.status === 'loading' && (
          <p className="py-8 text-center text-sm text-slate-500" role="status">
            Loading findings…
          </p>
        )}
        {state.status === 'error' && (
          <ErrorAlert error={state.error} title="Could not load findings" />
        )}
        {state.status === 'success' && state.data.items.length === 0 && (
          <EmptyState
            title={filtered ? 'No findings match these filters' : 'No active findings'}
            icon={Bug}
          >
            {filtered
              ? 'Clear the filters to see every active finding.'
              : 'Findings come from deterministic rules run against the evidence of completed scans. They appear within about five minutes of a scan finishing; failed or incomplete scans never create or resolve findings.'}
          </EmptyState>
        )}
        {state.status === 'success' && state.data.items.length > 0 && (
          <>
            <div className="overflow-x-auto">
              <table className="min-w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-200 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
                    <th scope="col" className="py-2 pr-4">
                      Severity
                    </th>
                    <th scope="col" className="py-2 pr-4">
                      Finding
                    </th>
                    <th scope="col" className="py-2 pr-4">
                      Domain / host
                    </th>
                    <th scope="col" className="py-2 pr-4">
                      Risk
                    </th>
                    <th scope="col" className="py-2 pr-4">
                      Status
                    </th>
                    <th scope="col" className="py-2">
                      Last seen
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {state.data.items.map((f) => (
                    <tr key={f.id} className="hover:bg-slate-50">
                      <td className="py-2.5 pr-4">
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="py-2.5 pr-4">
                        <Link
                          to={`/findings/${f.id}`}
                          className="font-medium text-sky-800 hover:underline"
                        >
                          {f.title}
                        </Link>
                        <div className="font-mono text-xs text-slate-500">{f.ruleId}</div>
                      </td>
                      <td className="py-2.5 pr-4">
                        <div className="font-mono text-slate-800">{f.domain.fqdn}</div>
                        {f.hostname !== f.domain.fqdn && (
                          <div className="font-mono text-xs text-slate-500">{f.hostname}</div>
                        )}
                      </td>
                      <td className="py-2.5 pr-4">
                        <RiskScore score={f.riskScore} />
                      </td>
                      <td className="py-2.5 pr-4">
                        <FindingStatusBadge status={f.status} />
                      </td>
                      <td className="whitespace-nowrap py-2.5 text-slate-600">
                        {formatDateTime(f.lastSeenAt)}
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

function FilterChip({ label, onClear }: { label: string; onClear: () => void }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-slate-100 py-0.5 pl-2.5 pr-1 text-xs text-slate-700">
      {label}
      <button
        type="button"
        onClick={onClear}
        aria-label={`Clear filter ${label}`}
        className="rounded-full p-0.5 hover:bg-slate-200"
      >
        <X className="size-3" aria-hidden />
      </button>
    </span>
  );
}
