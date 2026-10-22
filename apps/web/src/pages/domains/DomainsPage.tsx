import {
  CRITICALITIES,
  CRITICALITY_LABELS,
  DOMAIN_VERIFICATION_STATUSES,
  DOMAIN_VERIFICATION_STATUS_LABELS,
} from '@exdomainvault/shared';
import { AlertTriangle, Globe, Plus, Search, Upload } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router';
import { AddDomainForm } from '../../components/domains/AddDomainForm.tsx';
import { CriticalityLabel, VerificationBadge } from '../../components/domains/DomainBadges.tsx';
import { Button } from '../../components/ui/Button.tsx';
import { buttonClass } from '../../components/ui/button-styles.ts';
import { Card } from '../../components/ui/Card.tsx';
import { EmptyState } from '../../components/ui/EmptyState.tsx';
import { ErrorAlert } from '../../components/ui/ErrorAlert.tsx';
import { PageHeader } from '../../components/ui/PageHeader.tsx';
import { api } from '../../lib/api.ts';
import { formatDate } from '../../lib/format.ts';
import { usePermission } from '../../lib/session.ts';
import { useAsync } from '../../lib/use-async.ts';

const PAGE_SIZE = 25;
const FILTER_KEYS = ['q', 'verificationStatus', 'criticality', 'monitoring'] as const;

const selectClass =
  'rounded-md border border-slate-300 bg-white px-2 py-1.5 text-sm text-slate-700 shadow-sm';

export function DomainsPage() {
  const [params, setParams] = useSearchParams();
  const canWrite = usePermission('domains:write');
  const [adding, setAdding] = useState(false);
  const [searchDraft, setSearchDraft] = useState(params.get('q') ?? '');

  const query = {
    page: params.get('page') ?? undefined,
    pageSize: PAGE_SIZE,
    q: params.get('q') ?? undefined,
    verificationStatus: params.get('verificationStatus') ?? undefined,
    criticality: params.get('criticality') ?? undefined,
    monitoring: params.get('monitoring') ?? undefined,
    sort: params.get('sort') ?? undefined,
  };
  const state = useAsync((signal) => api.domains.list(query, { signal }), [params.toString()]);
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

  return (
    <>
      <PageHeader
        title="Domains"
        description="Registered domains, ownership verification and monitoring status."
        actions={
          canWrite && (
            <>
              <Link to="/domains/import" className={buttonClass('secondary')}>
                <Upload className="size-4" aria-hidden />
                Import CSV
              </Link>
              <Button variant="primary" onClick={() => setAdding(true)} disabled={adding}>
                <Plus className="size-4" aria-hidden />
                Add domain
              </Button>
            </>
          )
        }
      />

      {adding && (
        <div className="mb-6">
          <AddDomainForm onCancel={() => setAdding(false)} />
        </div>
      )}

      <Card>
        <div className="mb-4 flex flex-wrap items-end gap-3">
          <form onSubmit={onSearch} role="search" className="flex items-center gap-2">
            <label htmlFor="domain-search" className="sr-only">
              Search domains
            </label>
            <div className="relative">
              <Search
                className="pointer-events-none absolute left-2 top-2 size-4 text-slate-400"
                aria-hidden
              />
              <input
                id="domain-search"
                type="search"
                value={searchDraft}
                onChange={(e) => setSearchDraft(e.target.value)}
                placeholder="Search domains"
                className="w-56 rounded-md border border-slate-300 py-1.5 pl-8 pr-2 text-sm shadow-sm"
              />
            </div>
            <Button type="submit">Search</Button>
          </form>
          <label className="text-xs text-slate-600">
            <span className="mb-1 block">Verification</span>
            <select
              className={selectClass}
              value={params.get('verificationStatus') ?? ''}
              onChange={(e) => setParam('verificationStatus', e.target.value)}
            >
              <option value="">All</option>
              {DOMAIN_VERIFICATION_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {DOMAIN_VERIFICATION_STATUS_LABELS[s]}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs text-slate-600">
            <span className="mb-1 block">Criticality</span>
            <select
              className={selectClass}
              value={params.get('criticality') ?? ''}
              onChange={(e) => setParam('criticality', e.target.value)}
            >
              <option value="">All</option>
              {CRITICALITIES.map((c) => (
                <option key={c} value={c}>
                  {CRITICALITY_LABELS[c]}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs text-slate-600">
            <span className="mb-1 block">Monitoring</span>
            <select
              className={selectClass}
              value={params.get('monitoring') ?? ''}
              onChange={(e) => setParam('monitoring', e.target.value)}
            >
              <option value="">All</option>
              <option value="true">On</option>
              <option value="false">Off</option>
            </select>
          </label>
          <label className="text-xs text-slate-600">
            <span className="mb-1 block">Sort</span>
            <select
              className={selectClass}
              value={params.get('sort') ?? 'fqdn'}
              onChange={(e) => setParam('sort', e.target.value)}
            >
              <option value="fqdn">Name (A–Z)</option>
              <option value="-createdAt">Newest first</option>
              <option value="createdAt">Oldest first</option>
              <option value="-criticality">Most critical first</option>
            </select>
          </label>
        </div>

        {state.status === 'loading' && (
          <p className="py-8 text-center text-sm text-slate-500" role="status">
            Loading domains…
          </p>
        )}
        {state.status === 'error' && (
          <ErrorAlert error={state.error} title="Could not load domains" />
        )}
        {state.status === 'success' && state.data.items.length === 0 && (
          <EmptyState
            title={filtered ? 'No domains match these filters' : 'No domains yet'}
            icon={Globe}
          >
            {filtered
              ? 'Clear the filters to see every domain.'
              : canWrite
                ? 'Add a domain you own, then verify it with a DNS TXT record.'
                : 'An administrator has not registered any domains yet.'}
          </EmptyState>
        )}
        {state.status === 'success' && state.data.items.length > 0 && (
          <>
            <div className="overflow-x-auto">
              <table className="min-w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-200 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
                    <th scope="col" className="py-2 pr-4">
                      Domain
                    </th>
                    <th scope="col" className="py-2 pr-4">
                      Verification
                    </th>
                    <th scope="col" className="py-2 pr-4">
                      Criticality
                    </th>
                    <th scope="col" className="py-2 pr-4">
                      Business owner
                    </th>
                    <th scope="col" className="py-2 pr-4">
                      Monitoring
                    </th>
                    <th scope="col" className="py-2">
                      Added
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {state.data.items.map((d) => (
                    <tr key={d.id} className="hover:bg-slate-50">
                      <td className="py-2.5 pr-4">
                        <Link
                          to={`/domains/${d.id}`}
                          className="font-mono text-sm font-medium text-sky-800 hover:underline"
                        >
                          {d.fqdn}
                        </Link>
                        {d.unicodeFqdn !== d.fqdn && (
                          <span className="ml-2 text-xs text-slate-500">({d.unicodeFqdn})</span>
                        )}
                        {d.warnings.includes('mixed_script') && (
                          <AlertTriangle
                            className="ml-1 inline size-3.5 text-amber-600"
                            aria-label="Mixed-script name: possible homograph"
                          />
                        )}
                      </td>
                      <td className="py-2.5 pr-4">
                        <VerificationBadge status={d.verificationStatus} />
                      </td>
                      <td className="py-2.5 pr-4">
                        <CriticalityLabel criticality={d.criticality} />
                      </td>
                      <td className="py-2.5 pr-4 text-slate-700">
                        {d.businessOwner ?? <span className="text-slate-400">Not set</span>}
                      </td>
                      <td className="py-2.5 pr-4 text-slate-700">
                        {d.monitoringEnabled ? 'On' : 'Off'}
                      </td>
                      <td className="py-2.5 text-slate-600">{formatDate(d.createdAt)}</td>
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

function Pagination({
  page,
  pageSize,
  total,
  onPage,
}: {
  page: number;
  pageSize: number;
  total: number;
  onPage: (page: number) => void;
}) {
  const first = (page - 1) * pageSize + 1;
  const last = Math.min(page * pageSize, total);
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <nav
      aria-label="Pagination"
      className="mt-4 flex items-center justify-between border-t border-slate-100 pt-3 text-sm text-slate-600"
    >
      <span>
        {first}–{last} of {total}
      </span>
      <div className="flex gap-2">
        <Button onClick={() => onPage(page - 1)} disabled={page <= 1}>
          Previous
        </Button>
        <Button onClick={() => onPage(page + 1)} disabled={page >= pages}>
          Next
        </Button>
      </div>
    </nav>
  );
}
