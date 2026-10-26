import {
  APPROVED_NETWORK_MAX_MONTHS,
  type ApprovedNetwork,
  type CreateApprovedNetworkRequest,
} from '@exdomainvault/shared';
import { Network, ShieldCheck } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { api } from '../../lib/api.ts';
import { addMonthsIso, formatDate, formatDateTime } from '../../lib/format.ts';
import { useAsync } from '../../lib/use-async.ts';
import { Button } from '../ui/Button.tsx';
import { Card } from '../ui/Card.tsx';
import { EmptyState } from '../ui/EmptyState.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';

const DAY_MS = 86_400_000;
const REVIEW_WARNING_DAYS = 30;
const inputClass = 'w-full rounded-md border border-line-strong px-2.5 py-1.5 text-sm shadow-sm';

const toError = (err: unknown) => (err instanceof Error ? err : new Error(String(err)));

/**
 * Admin-approved networks: the only destinations of port probes and service identification.
 * Shown only to holders of `scan_policies:manage`; the API enforces the permission itself.
 */
export function ApprovedNetworksSection({ now = new Date() }: { now?: Date }) {
  const [reload, setReload] = useState(0);
  const state = useAsync((signal) => api.approvedNetworks.list({ signal }), [reload]);
  const refresh = () => setReload((r) => r + 1);

  return (
    <Card title="Approved networks">
      <div className="space-y-5 text-sm">
        <div className="space-y-2 text-fg-muted">
          <p>
            Port probes and service identification only ever run against addresses inside these
            networks. Approve only ranges your organisation operates (for example your own server or
            office ranges), never shared hosting, CDN or cloud provider space you do not control.
          </p>
          <p>
            Browser-like TLS certificate and HTTP checks of a verified domain do not need an
            approval here: they connect once, as any visitor would.
          </p>
        </div>

        <CreateNetworkForm onCreated={refresh} />

        {state.status === 'loading' && <p className="text-fg-subtle">Loading networks…</p>}
        {state.status === 'error' && <ErrorAlert error={state.error} />}
        {state.status === 'success' &&
          (state.data.items.length === 0 ? (
            <EmptyState title="No approved networks" icon={Network}>
              Until a network is approved, active scans skip port probes and service identification.
            </EmptyState>
          ) : (
            <ul
              aria-label="Approved networks"
              className="divide-y divide-line-soft rounded-md border border-line"
            >
              {state.data.items.map((n) => (
                <NetworkRow key={n.id} network={n} now={now} onChanged={refresh} />
              ))}
            </ul>
          ))}
      </div>
    </Card>
  );
}

function emptyForm(): CreateApprovedNetworkRequest {
  return { cidr: '', label: '', reason: '', reference: '', reviewBy: addMonthsIso(12) };
}

function CreateNetworkForm({ onCreated }: { onCreated: () => void }) {
  const [value, setValue] = useState<CreateApprovedNetworkRequest>(emptyForm);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const set = (patch: Partial<CreateApprovedNetworkRequest>) =>
    setValue((v) => ({ ...v, ...patch }));

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.approvedNetworks.create({
        ...value,
        reference: value.reference?.trim() ? value.reference : null,
      });
      setValue(emptyForm());
      onCreated();
    } catch (err) {
      setError(toError(err));
    } finally {
      setBusy(false);
    }
  };

  const ready =
    value.cidr.trim() !== '' && value.label.trim() !== '' && value.reason.trim().length >= 10;

  return (
    <form onSubmit={submit} aria-label="Approve a network" className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-3">
        <label className="block font-medium text-fg-2">
          Network (CIDR)
          <input
            className={`${inputClass} mt-1 font-mono`}
            value={value.cidr}
            onChange={(e) => set({ cidr: e.target.value })}
            placeholder="203.0.113.0/24"
            spellCheck={false}
            autoComplete="off"
            maxLength={64}
            required
          />
        </label>
        <label className="block font-medium text-fg-2 sm:col-span-2">
          Label
          <input
            className={`${inputClass} mt-1`}
            value={value.label}
            onChange={(e) => set({ label: e.target.value })}
            placeholder="e.g. Head office web servers"
            maxLength={100}
            required
          />
        </label>
        <label className="block font-medium text-fg-2 sm:col-span-3">
          Reason
          <textarea
            className={`${inputClass} mt-1`}
            rows={2}
            value={value.reason}
            onChange={(e) => set({ reason: e.target.value })}
            minLength={10}
            maxLength={500}
            required
            placeholder="Why the organisation operates this range and may probe it"
          />
        </label>
        <label className="block font-medium text-fg-2 sm:col-span-2">
          Reference <span className="font-normal text-fg-subtle">(optional: ticket, contract)</span>
          <input
            className={`${inputClass} mt-1`}
            value={value.reference ?? ''}
            onChange={(e) => set({ reference: e.target.value })}
            maxLength={200}
          />
        </label>
        <label className="block font-medium text-fg-2">
          Review by
          <input
            type="date"
            className={`${inputClass} mt-1`}
            value={value.reviewBy}
            min={addMonthsIso(0, 1)}
            max={addMonthsIso(APPROVED_NETWORK_MAX_MONTHS)}
            onChange={(e) => set({ reviewBy: e.target.value })}
            required
          />
        </label>
      </div>
      <p className="text-xs text-fg-subtle">
        At most a /16 (IPv4) or /32 (IPv6), public addresses only. The approval lapses on the review
        date (at most {APPROVED_NETWORK_MAX_MONTHS} months ahead) unless renewed.
      </p>
      {error && <ErrorAlert error={error} title="The network was not approved" />}
      <Button type="submit" variant="primary" disabled={busy || !ready}>
        <ShieldCheck className="size-4" aria-hidden />
        Approve network
      </Button>
    </form>
  );
}

function ReviewDate({ iso, now }: { iso: string; now: Date }) {
  const days = Math.floor((new Date(iso).getTime() - now.getTime()) / DAY_MS);
  let note = '';
  let tone = 'text-fg-muted';
  if (days < 0) {
    note = ' (lapsed)';
    tone = 'rounded bg-red-50 px-1.5 py-0.5 font-medium text-red-800';
  } else if (days <= REVIEW_WARNING_DAYS) {
    note = days === 0 ? ' (today)' : ` (in ${days} day${days === 1 ? '' : 's'})`;
    tone = 'rounded bg-amber-50 px-1.5 py-0.5 font-medium text-amber-900';
  }
  return (
    <span className={tone} data-testid="review-date">
      Review by {formatDate(iso)}
      {note}
    </span>
  );
}

function NetworkRow({
  network: n,
  now,
  onChanged,
}: {
  network: ApprovedNetwork;
  now: Date;
  onChanged: () => void;
}) {
  const [revoking, setRevoking] = useState(false);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const revoked = n.revokedAt !== null;

  const revoke = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.approvedNetworks.revoke(n.id, reason);
      setRevoking(false);
      setReason('');
      onChanged();
    } catch (err) {
      setError(toError(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <li className={`space-y-2 p-3 ${revoked ? 'bg-surface-2' : ''}`} aria-label={n.label}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="font-medium text-fg">
            {n.label} <span className="ml-1 font-mono text-xs font-normal text-fg-2">{n.cidr}</span>
            {revoked && (
              <span className="ml-2 rounded bg-line px-1.5 py-0.5 text-xs font-medium text-fg-2">
                Revoked
              </span>
            )}
          </p>
          <p className="mt-1 text-fg-muted">{n.reason}</p>
          {n.reference && <p className="text-xs text-fg-subtle">Reference: {n.reference}</p>}
          <p className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-fg-subtle">
            <span>
              Approved by {n.createdBy?.email ?? 'unknown user'} on {formatDateTime(n.createdAt)}
            </span>
            {!revoked && <ReviewDate iso={n.expiresAt} now={now} />}
          </p>
          {revoked && n.revokedAt && (
            <p className="mt-1 text-xs text-fg-muted">
              Revoked {formatDateTime(n.revokedAt)}
              {n.revokeReason ? `: ${n.revokeReason}` : ''}
            </p>
          )}
        </div>
        {!revoked && !revoking && (
          <Button variant="secondary" onClick={() => setRevoking(true)} disabled={busy}>
            Revoke
          </Button>
        )}
      </div>
      {revoking && (
        <div
          role="alertdialog"
          aria-label={`Confirm revoking ${n.cidr}`}
          className="space-y-2 rounded-md border border-red-200 bg-red-50 p-3"
        >
          <label className="block text-sm font-medium text-fg-2">
            Why is this approval being revoked?
            <textarea
              className={`${inputClass} mt-1`}
              rows={2}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              maxLength={500}
            />
          </label>
          <p className="text-xs text-red-800">
            Port probes and service identification of addresses in {n.cidr} stop with the next scan.
          </p>
          <div className="flex gap-2">
            <Button variant="danger" onClick={revoke} disabled={busy || reason.trim().length < 10}>
              Revoke approval
            </Button>
            <Button onClick={() => setRevoking(false)} disabled={busy}>
              Cancel
            </Button>
          </div>
        </div>
      )}
      {error && <ErrorAlert error={error} title="The approval was not revoked" />}
    </li>
  );
}
