import {
  ATTESTATION_DEFAULT_MONTHS,
  CRITICALITIES,
  type AuthorisationInput,
  type BulkAuthoriseResponse,
  type BulkMonitoringResponse,
  CRITICALITY_LABELS,
  DOMAIN_VERIFICATION_STATUSES,
  DOMAIN_VERIFICATION_STATUS_LABELS,
} from '@exdomainvault/shared';
import { AlertTriangle, Globe, Plus, Radio, Search, Upload } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router';
import { AddDomainForm } from '../../components/domains/AddDomainForm.tsx';
import { AuthorisationFields } from '../../components/domains/AuthorisationFields.tsx';
import { CriticalityLabel, VerificationBadge } from '../../components/domains/DomainBadges.tsx';
import { Button } from '../../components/ui/Button.tsx';
import { buttonClass } from '../../components/ui/button-styles.ts';
import { Card } from '../../components/ui/Card.tsx';
import { EmptyState } from '../../components/ui/EmptyState.tsx';
import { ErrorAlert } from '../../components/ui/ErrorAlert.tsx';
import { LoadError } from '../../components/ui/LoadError.tsx';
import { StaleDataNotice } from '../../components/ui/StaleDataNotice.tsx';
import { PageHeader } from '../../components/ui/PageHeader.tsx';
import { api } from '../../lib/api.ts';
import { addMonthsIso, formatDate } from '../../lib/format.ts';
import { usePermission } from '../../lib/session.ts';
import { useRefreshableAsync } from '../../lib/use-refreshable-async.ts';

const PAGE_SIZES = ['25', '50', '100'] as const;
const FILTER_KEYS = ['q', 'verificationStatus', 'criticality', 'monitoring'] as const;

const selectClass =
  'rounded-md border border-slate-300 bg-white px-2 py-1.5 text-sm text-slate-700 shadow-sm';

export function DomainsPage() {
  const [params, setParams] = useSearchParams();
  const canWrite = usePermission('domains:write');
  const canVerify = usePermission('domains:verify');
  const canSelect = canWrite || canVerify;
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const [reloadKey, setReloadKey] = useState(0);
  const [bulkResult, setBulkResult] = useState<BulkAuthoriseResponse | null>(null);
  const [monitoringResult, setMonitoringResult] = useState<MonitoringResult | null>(null);
  const [confirmMonitoring, setConfirmMonitoring] = useState<MonitoringTarget | null>(null);
  const [adding, setAdding] = useState(false);
  const [searchDraft, setSearchDraft] = useState(params.get('q') ?? '');

  const query = {
    page: params.get('page') ?? undefined,
    pageSize: params.get('pageSize') ?? undefined,
    q: params.get('q') ?? undefined,
    verificationStatus: params.get('verificationStatus') ?? undefined,
    criticality: params.get('criticality') ?? undefined,
    monitoring: params.get('monitoring') ?? undefined,
    sort: params.get('sort') ?? undefined,
  };
  const { state, stale, refreshing, retry } = useRefreshableAsync(
    (signal) => api.domains.list(query, { signal }),
    [params.toString()],
    reloadKey,
  );
  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
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
              <Button
                onClick={() => setConfirmMonitoring({ all: true })}
                disabled={confirmMonitoring !== null}
              >
                <Radio className="size-4" aria-hidden />
                Turn on monitoring for all domains
              </Button>
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

      {bulkResult && (
        <p
          role="status"
          className="mb-4 rounded-md border border-sky-200 bg-sky-50 px-3 py-2 text-sm text-sky-900"
        >
          Authorised {bulkResult.authorised.length} domain
          {bulkResult.authorised.length === 1 ? '' : 's'}
          {bulkResult.skipped.length > 0 &&
            `; skipped ${bulkResult.skipped.length} (already verified or not found)`}
          .
        </p>
      )}
      {monitoringResult && (
        <p
          role="status"
          className="mb-4 rounded-md border border-sky-200 bg-sky-50 px-3 py-2 text-sm text-sky-900"
        >
          Monitoring turned {monitoringResult.enabled ? 'on' : 'off'} for {monitoringResult.updated}{' '}
          domain{monitoringResult.updated === 1 ? '' : 's'}
          {monitoringResult.updated === 0 && ' (already in that state)'}.
        </p>
      )}
      {confirmMonitoring && (
        <div className="mb-6">
          <ConfirmMonitoring
            target={confirmMonitoring}
            onDone={(result) => {
              setMonitoringResult({ enabled: true, updated: result.updated });
              setConfirmMonitoring(null);
              setSelected(new Set());
              setReloadKey((k) => k + 1);
            }}
            onCancel={() => setConfirmMonitoring(null)}
          />
        </div>
      )}
      {canWrite && selected.size > 0 && (
        <div className="mb-4">
          <BulkMonitoring
            ids={[...selected]}
            showClear={!canVerify}
            onTurnOn={() => setConfirmMonitoring({ domainIds: [...selected] })}
            onDone={(result) => {
              setMonitoringResult({ enabled: false, updated: result.updated });
              setSelected(new Set());
              setReloadKey((k) => k + 1);
            }}
            onClear={() => setSelected(new Set())}
          />
        </div>
      )}
      {canVerify && selected.size > 0 && (
        <div className="mb-6">
          <BulkAuthorise
            ids={[...selected]}
            onDone={(result) => {
              setBulkResult(result);
              setSelected(new Set());
              setReloadKey((k) => k + 1);
            }}
            onCancel={() => setSelected(new Set())}
          />
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
          <label className="text-xs text-slate-600">
            <span className="mb-1 block">Per page</span>
            <select
              className={selectClass}
              value={params.get('pageSize') ?? '25'}
              onChange={(e) => setParam('pageSize', e.target.value === '25' ? '' : e.target.value)}
            >
              {PAGE_SIZES.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </label>
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
            Loading domains…
          </p>
        )}
        {state.status === 'error' && (
          <LoadError error={state.error} title="Could not load domains" onRetry={retry} />
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
                    {canSelect && (
                      <th scope="col" className="w-8 py-2 pr-2">
                        <input
                          type="checkbox"
                          aria-label="Select all domains on this page"
                          checked={state.data.items.every((d) => selected.has(d.id))}
                          onChange={(e) =>
                            setSelected((prev) => {
                              const next = new Set(prev);
                              for (const d of state.data.items) {
                                if (e.target.checked) next.add(d.id);
                                else next.delete(d.id);
                              }
                              return next;
                            })
                          }
                        />
                      </th>
                    )}
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
                      {canSelect && (
                        <td className="py-2.5 pr-2">
                          <input
                            type="checkbox"
                            aria-label={`Select ${d.fqdn}`}
                            checked={selected.has(d.id)}
                            onChange={() => toggle(d.id)}
                          />
                        </td>
                      )}
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
                        <VerificationBadge
                          status={d.verificationStatus}
                          method={d.verificationMethod}
                        />
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

/** Administrator authorisation for the selected domains, with one shared reason and review date. */
function BulkAuthorise({
  ids,
  onDone,
  onCancel,
}: {
  ids: string[];
  onDone: (result: BulkAuthoriseResponse) => void;
  onCancel: () => void;
}) {
  const [input, setInput] = useState<AuthorisationInput>(() => ({
    reason: '',
    reference: '',
    reviewBy: addMonthsIso(ATTESTATION_DEFAULT_MONTHS),
  }));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onDone(await api.domains.authoriseMany(ids, input));
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card
      title={`Authorise ${ids.length} selected domain${ids.length === 1 ? '' : 's'} without DNS`}
    >
      <form onSubmit={submit} className="space-y-3 text-sm">
        <p className="text-slate-600">
          Records that the organisation owns these domains and authorises active scanning of them.
          Already-verified domains are skipped. Each domain gets its own audit record with your
          name, this reason and reference; the authorisation lapses on the review date.
        </p>
        <AuthorisationFields value={input} onChange={setInput} />
        {error && <ErrorAlert error={error} />}
        <div className="flex gap-2">
          <Button
            type="submit"
            variant="primary"
            disabled={busy || input.reason.trim().length < 10}
          >
            Authorise {ids.length} domain{ids.length === 1 ? '' : 's'}
          </Button>
          <Button onClick={onCancel} disabled={busy}>
            Clear selection
          </Button>
        </div>
      </form>
    </Card>
  );
}

type MonitoringTarget = { domainIds: string[] } | { all: true };
interface MonitoringResult {
  enabled: boolean;
  updated: number;
}

/** Monitoring actions for the selected rows. Turning monitoring on asks for confirmation first. */
function BulkMonitoring({
  ids,
  showClear,
  onTurnOn,
  onDone,
  onClear,
}: {
  ids: string[];
  showClear: boolean;
  onTurnOn: () => void;
  onDone: (result: BulkMonitoringResponse) => void;
  onClear: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const turnOff = async () => {
    setBusy(true);
    setError(null);
    try {
      onDone(await api.domains.setMonitoring({ domainIds: ids }, false));
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      role="group"
      aria-label="Monitoring for selected domains"
      className="flex flex-wrap items-center gap-2 rounded-md border border-slate-200 bg-white px-3 py-2 text-sm shadow-sm"
    >
      <span className="text-slate-600">{ids.length} selected — monitoring:</span>
      <Button onClick={onTurnOn} disabled={busy}>
        Turn on monitoring for selected
      </Button>
      <Button onClick={turnOff} disabled={busy}>
        Turn off monitoring for selected
      </Button>
      {showClear && (
        <Button onClick={onClear} disabled={busy}>
          Clear selection
        </Button>
      )}
      {error && (
        <div className="w-full">
          <ErrorAlert error={error} title="Monitoring was not changed" />
        </div>
      )}
    </div>
  );
}

/** Explains what monitoring does before turning it on for the selected domains or all domains. */
function ConfirmMonitoring({
  target,
  onDone,
  onCancel,
}: {
  target: MonitoringTarget;
  onDone: (result: BulkMonitoringResponse) => void;
  onCancel: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const all = 'all' in target;
  const scope = all
    ? 'every registered domain'
    : `${target.domainIds.length} selected domain${target.domainIds.length === 1 ? '' : 's'}`;

  const confirm = async () => {
    setBusy(true);
    setError(null);
    try {
      onDone(await api.domains.setMonitoring(target, true));
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
      setBusy(false);
    }
  };

  return (
    <div
      role="alertdialog"
      aria-labelledby="confirm-monitoring-title"
      aria-describedby="confirm-monitoring-body"
      className="rounded-lg border border-amber-300 bg-amber-50 p-4 text-sm shadow-sm"
    >
      <h2 id="confirm-monitoring-title" className="font-semibold text-amber-950">
        Turn on monitoring for {scope}?
      </h2>
      <div id="confirm-monitoring-body" className="mt-2 space-y-1 text-amber-900">
        <p>
          Each monitored domain gets a daily passive scan of public DNS and registration data.
          Passive scans never contact your hosts and are allowed before ownership is verified.
        </p>
        <p>
          Active checks (certificates, web and ports) are not started by monitoring: they run only
          for verified domains, and only when someone with permission requests them.
        </p>
      </div>
      {error && (
        <div className="mt-3">
          <ErrorAlert error={error} title="Monitoring was not changed" />
        </div>
      )}
      <div className="mt-3 flex gap-2">
        <Button variant="primary" onClick={confirm} disabled={busy}>
          {all ? 'Turn on for all domains' : 'Turn on for selected'}
        </Button>
        <Button onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
      </div>
    </div>
  );
}
