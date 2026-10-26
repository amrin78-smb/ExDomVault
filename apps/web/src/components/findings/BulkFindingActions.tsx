import {
  FINDING_BULK_MAX,
  transitionRequirements,
  type FindingBulkUpdateResponse,
  type FindingStatus,
} from '@exdomainvault/shared';
import { useId, useState, type FormEvent } from 'react';
import { api } from '../../lib/api.ts';
import { usePermissions } from '../../lib/session.ts';
import { useAsync } from '../../lib/use-async.ts';
import { Button } from '../ui/Button.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';
import { userLabel } from './labels.ts';
import { StatusChangeForm, type StatusChangeValues } from './StatusChangeForm.tsx';

type BulkStatus = Extract<
  FindingStatus,
  'acknowledged' | 'remediation_in_progress' | 'accepted_risk'
>;

const STATUS_ACTIONS = [
  { to: 'acknowledged', label: 'Acknowledge', permission: 'findings:triage' },
  { to: 'remediation_in_progress', label: 'Start remediation', permission: 'findings:remediate' },
  { to: 'accepted_risk', label: 'Accept risk', permission: 'findings:accept_risk' },
] as const satisfies readonly { to: BulkStatus; label: string; permission: string }[];

/**
 * Actions for the selected findings. Each finding is checked by the server individually: ones
 * whose current status does not allow the change are skipped and reported, never forced.
 */
export function BulkFindingActions({
  ids,
  onDone,
  onClear,
}: {
  ids: string[];
  onDone: (result: FindingBulkUpdateResponse) => void;
  onClear: () => void;
}) {
  const can = usePermissions();
  const [pending, setPending] = useState<BulkStatus | 'assign' | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const tooMany = ids.length > FINDING_BULK_MAX;
  const n = `${ids.length} finding${ids.length === 1 ? '' : 's'}`;

  const send = async (body: {
    status?: FindingStatus;
    assigneeId?: string | null;
    reason?: string;
    acceptedRiskReviewAt?: string;
  }) => {
    setError(null);
    try {
      onDone(await api.findings.bulkUpdate({ ids, ...body }));
      setPending(null);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    }
  };

  const open = (action: BulkStatus | 'assign') => {
    setPending(action);
    setError(null);
  };

  const statusAction = STATUS_ACTIONS.find((a) => a.to === pending);

  return (
    <div
      role="group"
      aria-label="Actions for selected findings"
      className="mb-4 space-y-3 rounded-md border border-line bg-surface px-3 py-2 text-sm shadow-sm"
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-fg-muted">{ids.length} selected:</span>
        {STATUS_ACTIONS.filter((a) => can(a.permission)).map((a) => (
          <Button
            key={a.to}
            onClick={() => open(a.to)}
            disabled={tooMany}
            aria-expanded={pending === a.to}
          >
            {a.label}
          </Button>
        ))}
        {can('findings:assign') && (
          <Button
            onClick={() => open('assign')}
            disabled={tooMany}
            aria-expanded={pending === 'assign'}
          >
            Assign to…
          </Button>
        )}
        <Button onClick={onClear}>Clear selection</Button>
      </div>
      {tooMany && (
        <p className="text-amber-900">Select at most {FINDING_BULK_MAX} findings for one change.</p>
      )}
      {statusAction && (
        <StatusChangeForm
          key={statusAction.to}
          title={`${statusAction.label}: ${n}`}
          confirmLabel={`${statusAction.label} for ${n}`}
          requirements={transitionRequirements('open', statusAction.to)}
          description="Findings whose current status does not allow this change are skipped."
          error={error}
          onSubmit={(values: StatusChangeValues) => send({ status: statusAction.to, ...values })}
          onCancel={() => setPending(null)}
        />
      )}
      {pending === 'assign' && (
        <BulkAssign
          count={n}
          error={error}
          onSubmit={(assigneeId) => send({ assigneeId })}
          onCancel={() => setPending(null)}
        />
      )}
    </div>
  );
}

function BulkAssign({
  count,
  error,
  onSubmit,
  onCancel,
}: {
  count: string;
  error: Error | null;
  onSubmit: (assigneeId: string | null) => Promise<void>;
  onCancel: () => void;
}) {
  const id = useId();
  const users = useAsync((signal) => api.users.assignable({ signal }), []);
  const [value, setValue] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    await onSubmit(value || null);
    setBusy(false);
  };

  return (
    <form
      onSubmit={submit}
      aria-label={`Assign ${count}`}
      className="space-y-3 rounded-md border border-line bg-surface-2 p-3"
    >
      <div>
        <label htmlFor={`${id}-user`} className="block font-medium text-fg-2">
          Assign {count} to
        </label>
        <select
          id={`${id}-user`}
          className="mt-1 rounded-md border border-line-strong bg-surface px-2 py-1.5 text-sm shadow-sm"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          disabled={users.status === 'loading'}
        >
          <option value="">Unassigned</option>
          {users.status === 'success' &&
            users.data.items.map((u) => (
              <option key={u.id} value={u.id}>
                {userLabel(u)} ({u.role.replace('_', ' ')})
              </option>
            ))}
        </select>
      </div>
      {users.status === 'error' && <ErrorAlert error={users.error} title="Could not load users" />}
      {error && <ErrorAlert error={error} title="The change was not saved" />}
      <div className="flex gap-2">
        <Button type="submit" variant="primary" disabled={busy || users.status !== 'success'}>
          {value ? 'Assign' : 'Unassign'} {count}
        </Button>
        <Button onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
      </div>
    </form>
  );
}
