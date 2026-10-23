import type { AuditEntry } from '@exdomainvault/shared';
import { ScrollText } from 'lucide-react';
import { useId, useState, type FormEvent } from 'react';
import { useSearchParams } from 'react-router';
import { api } from '../../lib/api.ts';
import { formatDateTime } from '../../lib/format.ts';
import { useAsync } from '../../lib/use-async.ts';
import { Pagination } from '../findings/Pagination.tsx';
import { ExportCsvButton } from '../reports/ExportCsvButton.tsx';
import { Button } from '../ui/Button.tsx';
import { Card } from '../ui/Card.tsx';
import { EmptyState } from '../ui/EmptyState.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';

const PAGE_SIZE = 50;
const inputClass = 'rounded-md border border-slate-300 px-2.5 py-1.5 text-sm shadow-sm';
const selectClass = 'rounded-md border border-slate-300 bg-white px-2 py-1.5 text-sm shadow-sm';

const ACTION_RE = /^[a-z_.]+$/;
const RESOURCE_RE = /^[a-z_]+$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const ACTOR_TYPES = ['user', 'worker', 'system'] as const;
type ActorType = (typeof ACTOR_TYPES)[number];

const ACTION_SUGGESTIONS = [
  'user.',
  'domain.',
  'asset.',
  'scan.',
  'finding.',
  'worker.',
  'approved_network.',
];
const RESOURCE_SUGGESTIONS = [
  'user',
  'domain',
  'asset',
  'scan_job',
  'finding',
  'worker',
  'approved_network',
];

/** The filters as stored in the URL query (`?tab=audit&action=finding.&from=2026-10-01`). */
interface Filters {
  action: string;
  resourceType: string;
  actorType: '' | ActorType;
  from: string;
  to: string;
}

const FILTER_KEYS = ['action', 'resourceType', 'actorType', 'from', 'to'] as const;

function readFilters(params: URLSearchParams): Filters {
  const actorType = params.get('actorType');
  return {
    action: params.get('action') ?? '',
    resourceType: params.get('resourceType') ?? '',
    actorType: ACTOR_TYPES.includes(actorType as ActorType) ? (actorType as ActorType) : '',
    from: params.get('from') ?? '',
    to: params.get('to') ?? '',
  };
}

/** Client-side checks mirroring the API's query schema, so an invalid filter is never sent. */
function validate(f: Filters): Partial<Record<keyof Filters, string>> {
  const errors: Partial<Record<keyof Filters, string>> = {};
  if (f.action && (f.action.length > 64 || !ACTION_RE.test(f.action))) {
    errors.action = 'Use lowercase letters, dots and underscores, e.g. finding. or user.created.';
  }
  if (f.resourceType && (f.resourceType.length > 32 || !RESOURCE_RE.test(f.resourceType))) {
    errors.resourceType = 'Use lowercase letters and underscores, e.g. finding.';
  }
  if (f.from && !DATE_RE.test(f.from)) errors.from = 'Enter a valid date.';
  if (f.to && !DATE_RE.test(f.to)) errors.to = 'Enter a valid date.';
  if (!errors.from && !errors.to && f.from && f.to && f.from > f.to) {
    errors.to = 'The end date must not be before the start date.';
  }
  return errors;
}

/** Read-only, append-only audit log (`audit:read`). Filters live in the URL query. */
export function AuditLogSection() {
  const [params, setParams] = useSearchParams();
  const applied = readFilters(params);
  const appliedErrors = validate(applied);
  const page = Math.max(1, Number(params.get('page')) || 1);

  const query = {
    page,
    pageSize: PAGE_SIZE,
    action: appliedErrors.action ? undefined : applied.action || undefined,
    resourceType: appliedErrors.resourceType ? undefined : applied.resourceType || undefined,
    actorType: applied.actorType || undefined,
    from: applied.from && !appliedErrors.from ? `${applied.from}T00:00:00.000Z` : undefined,
    to: applied.to && !appliedErrors.to ? `${applied.to}T23:59:59.999Z` : undefined,
  };
  const state = useAsync((signal) => api.audit.list(query, { signal }), [query]);

  const writeParams = (filters: Filters, nextPage?: number) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      for (const k of FILTER_KEYS) {
        const v = filters[k].trim();
        if (v) next.set(k, v);
        else next.delete(k);
      }
      if (nextPage && nextPage > 1) next.set('page', String(nextPage));
      else next.delete('page');
      return next;
    });
  };

  return (
    <Card title="Audit log" actions={<ExportCsvButton resource="audit-logs" filters={query} />}>
      <div className="space-y-4 text-sm">
        <p className="text-slate-600">
          Every privileged change is recorded here and cannot be edited or deleted. Times are UTC.
        </p>
        <AuditFilters
          // Remount when the URL changes (back/forward) so the form shows the applied filters.
          key={FILTER_KEYS.map((k) => applied[k]).join('|')}
          initial={applied}
          onApply={(f) => writeParams(f)}
        />

        {state.status === 'loading' && (
          <p role="status" className="text-slate-500">
            Loading audit entries…
          </p>
        )}
        {state.status === 'error' && (
          <ErrorAlert error={state.error} title="Could not load the audit log" />
        )}
        {state.status === 'success' &&
          (state.data.items.length === 0 ? (
            <EmptyState title="No audit entries match these filters" icon={ScrollText} />
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="min-w-full text-sm">
                  <caption className="sr-only">Audit log entries, newest first</caption>
                  <thead>
                    <tr className="border-b border-slate-200 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
                      <th scope="col" className="py-2 pr-4">
                        Time
                      </th>
                      <th scope="col" className="py-2 pr-4">
                        Actor
                      </th>
                      <th scope="col" className="py-2 pr-4">
                        Action
                      </th>
                      <th scope="col" className="py-2 pr-4">
                        Resource
                      </th>
                      <th scope="col" className="py-2">
                        Details
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 align-top">
                    {state.data.items.map((e) => (
                      <AuditRow key={e.id} entry={e} />
                    ))}
                  </tbody>
                </table>
              </div>
              <Pagination
                page={state.data.page}
                pageSize={state.data.pageSize}
                total={state.data.total}
                onPage={(p) => writeParams(applied, p)}
              />
            </>
          ))}
      </div>
    </Card>
  );
}

function AuditFilters({ initial, onApply }: { initial: Filters; onApply: (f: Filters) => void }) {
  const [value, setValue] = useState<Filters>(initial);
  const [errors, setErrors] = useState(() => validate(initial));
  const id = useId();
  const set = (patch: Partial<Filters>) => setValue((v) => ({ ...v, ...patch }));

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const trimmed = {
      ...value,
      action: value.action.trim(),
      resourceType: value.resourceType.trim(),
    };
    const found = validate(trimmed);
    setErrors(found);
    if (Object.keys(found).length === 0) onApply(trimmed);
  };

  const errorFor = (key: keyof Filters) =>
    errors[key] ? (
      <p id={`${id}-${key}-error`} className="mt-1 max-w-48 text-xs text-red-700">
        {errors[key]}
      </p>
    ) : null;
  const describe = (key: keyof Filters) =>
    errors[key] ? { 'aria-invalid': true as const, 'aria-describedby': `${id}-${key}-error` } : {};

  return (
    <form
      onSubmit={submit}
      noValidate
      aria-label="Filter the audit log"
      className="flex flex-wrap items-end gap-3"
    >
      <div>
        <label className="block text-xs font-medium text-slate-600">
          Action or prefix
          <input
            className={`${inputClass} mt-1 block w-48 font-mono`}
            value={value.action}
            onChange={(e) => set({ action: e.target.value })}
            placeholder="finding."
            list={`${id}-actions`}
            maxLength={64}
            spellCheck={false}
            {...describe('action')}
          />
        </label>
        {errorFor('action')}
      </div>
      <datalist id={`${id}-actions`}>
        {ACTION_SUGGESTIONS.map((a) => (
          <option key={a} value={a} />
        ))}
      </datalist>
      <div>
        <label className="block text-xs font-medium text-slate-600">
          Resource type
          <input
            className={`${inputClass} mt-1 block w-40 font-mono`}
            value={value.resourceType}
            onChange={(e) => set({ resourceType: e.target.value })}
            list={`${id}-resources`}
            maxLength={32}
            spellCheck={false}
            {...describe('resourceType')}
          />
        </label>
        {errorFor('resourceType')}
      </div>
      <datalist id={`${id}-resources`}>
        {RESOURCE_SUGGESTIONS.map((r) => (
          <option key={r} value={r} />
        ))}
      </datalist>
      <label className="block text-xs font-medium text-slate-600">
        Actor type
        <select
          className={`${selectClass} mt-1 block`}
          value={value.actorType}
          onChange={(e) => set({ actorType: e.target.value as Filters['actorType'] })}
        >
          <option value="">Any</option>
          <option value="user">User</option>
          <option value="worker">Worker</option>
          <option value="system">System</option>
        </select>
      </label>
      <div>
        <label className="block text-xs font-medium text-slate-600">
          From
          <input
            type="date"
            className={`${inputClass} mt-1 block`}
            value={value.from}
            onChange={(e) => set({ from: e.target.value })}
            {...describe('from')}
          />
        </label>
        {errorFor('from')}
      </div>
      <div>
        <label className="block text-xs font-medium text-slate-600">
          To
          <input
            type="date"
            className={`${inputClass} mt-1 block`}
            value={value.to}
            onChange={(e) => set({ to: e.target.value })}
            {...describe('to')}
          />
        </label>
        {errorFor('to')}
      </div>
      <div className="flex gap-2">
        <Button type="submit" variant="primary">
          Apply filters
        </Button>
        <Button
          onClick={() => {
            const empty: Filters = {
              action: '',
              resourceType: '',
              actorType: '',
              from: '',
              to: '',
            };
            setValue(empty);
            setErrors({});
            onApply(empty);
          }}
        >
          Clear
        </Button>
      </div>
    </form>
  );
}

const ACTOR_LABELS: Record<AuditEntry['actorType'], string> = {
  user: 'User',
  worker: 'Scanning worker',
  system: 'System',
};

function AuditRow({ entry: e }: { entry: AuditEntry }) {
  const fields = Object.keys(e.metadata).length;
  return (
    <tr>
      <td className="whitespace-nowrap py-2 pr-4 text-slate-600">
        <time dateTime={e.createdAt}>{formatDateTime(e.createdAt)}</time>
      </td>
      <td className="py-2 pr-4">
        {e.actor ? (
          <span className="break-all">{e.actor.email}</span>
        ) : (
          <span className="text-slate-600">{ACTOR_LABELS[e.actorType]}</span>
        )}
        {e.actor && e.actorType !== 'user' && (
          <span className="block text-xs text-slate-500">{ACTOR_LABELS[e.actorType]}</span>
        )}
      </td>
      <td className="py-2 pr-4 font-mono text-xs text-slate-800">{e.action}</td>
      <td className="py-2 pr-4">
        <span className="font-mono text-xs text-slate-800">{e.resourceType}</span>
        {e.resourceId && (
          <span className="block break-all font-mono text-xs text-slate-500">{e.resourceId}</span>
        )}
      </td>
      <td className="py-2">
        {fields === 0 && !e.requestId ? (
          <span className="text-slate-400">—</span>
        ) : (
          <details>
            <summary className="cursor-pointer text-sky-800">
              {fields === 0 ? 'Request' : fields === 1 ? '1 field' : `${fields} fields`}
              <span className="sr-only">
                {' '}
                of {e.action} at {formatDateTime(e.createdAt)}
              </span>
            </summary>
            {/* Rendered as text: metadata is never interpreted as HTML. */}
            {fields > 0 && (
              <pre className="mt-1 max-w-xl overflow-x-auto whitespace-pre-wrap break-all rounded bg-slate-100 p-2 font-mono text-xs text-slate-700">
                {JSON.stringify(e.metadata, null, 2)}
              </pre>
            )}
            {e.requestId && (
              <p className="mt-1 text-xs text-slate-500">
                Request ID: <span className="font-mono">{e.requestId}</span>
              </p>
            )}
          </details>
        )}
      </td>
    </tr>
  );
}
