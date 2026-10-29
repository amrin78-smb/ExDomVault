import {
  SEVERITIES,
  SEVERITY_LABELS,
  SLA_MAX_DAYS,
  compareSeverityDesc,
  type Severity,
  type SlaPolicy,
  type SlaPolicyResponse,
} from '@exdomainvault/shared';
import { useState, type FormEvent } from 'react';
import { api } from '../../lib/api.ts';
import { formatDateTime } from '../../lib/format.ts';
import { usePermission } from '../../lib/session.ts';
import { useAsync } from '../../lib/use-async.ts';
import { Button } from '../ui/Button.tsx';
import { Card } from '../ui/Card.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';
import { SeverityBadge } from '../ui/SeverityBadge.tsx';

const ORDER = [...SEVERITIES].sort(compareSeverityDesc);
const days = (n: number | null) => (n === null ? 'No SLA' : n === 1 ? '1 day' : `${n} days`);

/**
 * Remediation SLAs (Milestone 14): days to remediate per severity. Everyone who reads findings sees
 * the policy (due dates derive from it); administrators (`settings:manage`) change it, which
 * recomputes the due date of every finding that is not resolved.
 */
export function SlaPolicySection() {
  const state = useAsync((signal) => api.settings.sla.get({ signal }), []);
  const canManage = usePermission('settings:manage');
  const [saved, setSaved] = useState<(SlaPolicyResponse & { recomputed: number }) | null>(null);
  const data = saved ?? (state.status === 'success' ? state.data : null);

  return (
    <Card title="Remediation SLAs">
      <div className="space-y-4 text-sm">
        <p className="text-fg-muted">
          Each finding is due a set number of days after it is first seen (or after it recurs, or
          its accepted risk ends). Findings past their due date are shown as overdue and lower the
          domain&apos;s security score. Resolved and accepted-risk findings are never overdue.
        </p>
        {state.status === 'loading' && (
          <p role="status" className="text-fg-subtle">
            Loading the SLA policy…
          </p>
        )}
        {state.status === 'error' && (
          <ErrorAlert error={state.error} title="Could not load the SLA policy" />
        )}
        {data && (
          <>
            <div role="status">
              {saved && (
                <p className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-emerald-900">
                  Saved. Due dates of {saved.recomputed}{' '}
                  {saved.recomputed === 1 ? 'finding were' : 'findings were'} recalculated.
                </p>
              )}
            </div>
            {canManage ? (
              <SlaForm
                key={`${JSON.stringify(data.policy)}|${data.updatedAt ?? ''}`}
                policy={data.policy}
                onSaved={setSaved}
              />
            ) : (
              <dl aria-label="Current SLA policy" className="grid gap-3 sm:grid-cols-5">
                {ORDER.map((s) => (
                  <div key={s}>
                    <dt>
                      <SeverityBadge severity={s} />
                    </dt>
                    <dd className="mt-1 text-fg">{days(data.policy[s])}</dd>
                  </div>
                ))}
              </dl>
            )}
            <p className="text-xs text-fg-subtle">
              Last changed:{' '}
              {data.updatedAt ? (
                <>
                  {formatDateTime(data.updatedAt)}
                  {data.updatedBy && <> by {data.updatedBy.email}</>}
                </>
              ) : (
                'never (default policy)'
              )}
              {!canManage && ' · Only administrators can change the policy.'}
            </p>
          </>
        )}
      </div>
    </Card>
  );
}

type Draft = Record<Severity, { enabled: boolean; days: string }>;

function SlaForm({
  policy,
  onSaved,
}: {
  policy: SlaPolicy;
  onSaved: (r: SlaPolicyResponse & { recomputed: number }) => void;
}) {
  const [draft, setDraft] = useState<Draft>(
    () =>
      Object.fromEntries(
        SEVERITIES.map((s) => [
          s,
          { enabled: policy[s] !== null, days: policy[s] === null ? '' : String(policy[s]) },
        ]),
      ) as Draft,
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [invalid, setInvalid] = useState<Severity[]>([]);

  const set = (s: Severity, patch: Partial<Draft[Severity]>) =>
    setDraft((d) => ({ ...d, [s]: { ...d[s], ...patch } }));

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const bad: Severity[] = [];
    const next = {} as SlaPolicy;
    for (const s of SEVERITIES) {
      if (!draft[s].enabled) {
        next[s] = null;
        continue;
      }
      const n = Number(draft[s].days);
      if (!/^\d+$/.test(draft[s].days.trim()) || n < 1 || n > SLA_MAX_DAYS) bad.push(s);
      else next[s] = n;
    }
    setInvalid(bad);
    if (bad.length > 0) return;
    setBusy(true);
    setError(null);
    try {
      onSaved(await api.settings.sla.update(next));
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={onSubmit} className="space-y-4" aria-label="SLA policy">
      <table className="text-sm">
        <thead>
          <tr className="text-left text-xs font-medium uppercase tracking-wide text-fg-subtle">
            <th scope="col" className="py-1.5 pr-6">
              Severity
            </th>
            <th scope="col" className="py-1.5 pr-6">
              SLA applies
            </th>
            <th scope="col" className="py-1.5">
              Days to remediate
            </th>
          </tr>
        </thead>
        <tbody>
          {ORDER.map((s) => {
            const id = `sla-${s}`;
            const isInvalid = invalid.includes(s);
            return (
              <tr key={s}>
                <td className="py-1.5 pr-6">
                  <SeverityBadge severity={s} />
                </td>
                <td className="py-1.5 pr-6">
                  <input
                    type="checkbox"
                    aria-label={`${SEVERITY_LABELS[s]} has an SLA`}
                    checked={draft[s].enabled}
                    onChange={(e) =>
                      set(s, {
                        enabled: e.target.checked,
                        days: e.target.checked && !draft[s].days ? '30' : draft[s].days,
                      })
                    }
                  />
                </td>
                <td className="py-1.5">
                  <label htmlFor={id} className="sr-only">
                    {SEVERITY_LABELS[s]} days to remediate
                  </label>
                  <input
                    id={id}
                    inputMode="numeric"
                    disabled={!draft[s].enabled}
                    value={draft[s].enabled ? draft[s].days : ''}
                    placeholder={draft[s].enabled ? '' : 'No SLA'}
                    onChange={(e) => set(s, { days: e.target.value })}
                    aria-invalid={isInvalid || undefined}
                    aria-describedby={isInvalid ? `${id}-error` : undefined}
                    className="w-24 rounded-md border border-line-strong px-2 py-1 text-sm shadow-sm disabled:bg-surface-2"
                  />
                  {isInvalid && (
                    <span id={`${id}-error`} className="ml-2 text-xs text-red-700">
                      Enter 1–{SLA_MAX_DAYS} days.
                    </span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <p className="text-xs text-fg-subtle">
        Saving recalculates the due date of every finding that is not resolved. The change is
        recorded in the audit log.
      </p>
      {error && <ErrorAlert error={error} title="Could not save the SLA policy" />}
      <Button type="submit" variant="primary" disabled={busy}>
        {busy ? 'Saving…' : 'Save SLA policy'}
      </Button>
    </form>
  );
}
