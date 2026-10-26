import {
  FINDING_STATUS_LABELS,
  allowedTransitions,
  transitionRequirements,
  type Finding,
  type FindingReassessResponse,
  type FindingStatus,
  type FindingUserRef,
} from '@exdomainvault/shared';
import { AlertTriangle, RefreshCw } from 'lucide-react';
import { useId, useState, type FormEvent, type ReactNode } from 'react';
import { Link } from 'react-router';
import { ApiClientError, api } from '../../lib/api.ts';
import { formatDate } from '../../lib/format.ts';
import { usePermissions } from '../../lib/session.ts';
import { useAsync } from '../../lib/use-async.ts';
import { Button } from '../ui/Button.tsx';
import { Card } from '../ui/Card.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';
import { FindingStatusBadge } from './FindingStatusBadge.tsx';
import { transitionLabel, userLabel } from './labels.ts';
import { StatusChangeForm, type StatusChangeValues } from './StatusChangeForm.tsx';

const REVIEW_WARNING_DAYS = 14;
const DAY_MS = 24 * 60 * 60 * 1000;

const CONFLICT_MESSAGE =
  'This finding changed since you opened it. The latest version has been loaded; review it and try again.';

type Notice = { kind: 'success' | 'warning'; content: ReactNode };

const asError = (err: unknown) => (err instanceof Error ? err : new Error(String(err)));
/**
 * The finding changed since it was loaded: 409 `conflict` with the detail on `expectedStatus`.
 * Other errors (409 `conflict` on `status`: change impossible for anyone; 403 `forbidden`;
 * 404 `not_found`; 400 `validation_failed` on reason/acceptedRiskReviewAt/assigneeId) are shown
 * with the server's message and details, and the form stays open.
 */
const isConflict = (err: unknown) =>
  err instanceof ApiClientError &&
  err.status === 409 &&
  err.code === 'conflict' &&
  (err.details ?? []).some((d) => d.path === 'expectedStatus');

/**
 * Status, assignment, accepted risk and re-check for one finding. Actions are offered only when
 * the lifecycle matrix and the user's permissions allow them; the API enforces both again.
 */
export function FindingWorkflow({
  finding,
  onRefresh,
}: {
  finding: Finding;
  /** Reloads the finding (and its history and comments) after a change. */
  onRefresh: () => Promise<void>;
}) {
  const can = usePermissions();
  const [notice, setNotice] = useState<Notice | null>(null);
  const [pending, setPending] = useState<FindingStatus | null>(null);
  const [formError, setFormError] = useState<Error | null>(null);

  const transitions = allowedTransitions(finding.status, {
    can,
    manualResolution: finding.manualResolution,
  });
  const statusActions = transitions.filter((t) => t !== 'resolved');
  const canResolve = transitions.includes('resolved');
  const canAssign = can('findings:assign');
  const canRecheck = can('scans:request');
  const readOnly = transitions.length === 0 && !canAssign && !canRecheck;

  /** PATCHes the finding; on a conflict, reloads it and explains why nothing changed. */
  const update = async (
    body: { status?: FindingStatus; assigneeId?: string | null } & StatusChangeValues,
    success: string,
  ): Promise<Error | null> => {
    try {
      await api.findings.update(finding.id, { expectedStatus: finding.status, ...body });
      setNotice({ kind: 'success', content: success });
      await onRefresh();
      return null;
    } catch (err) {
      if (isConflict(err)) {
        setNotice({ kind: 'warning', content: CONFLICT_MESSAGE });
        setPending(null);
        await onRefresh().catch(() => undefined);
        return null;
      }
      return asError(err);
    }
  };

  const open = (to: FindingStatus) => {
    setPending(to);
    setFormError(null);
    setNotice(null);
  };

  const submitStatus = async (to: FindingStatus, values: StatusChangeValues) => {
    setFormError(null);
    const err = await update(
      { status: to, ...values },
      `Status changed to ${FINDING_STATUS_LABELS[to]}.`,
    );
    if (err) setFormError(err);
    else setPending(null);
  };

  return (
    <Card title="Workflow" className="mb-4">
      <div className="space-y-4 text-sm">
        <dl className="grid gap-3 sm:grid-cols-2">
          <div>
            <dt className="text-fg-subtle">Status</dt>
            <dd className="mt-1">
              <FindingStatusBadge status={finding.status} />
            </dd>
          </div>
          <div>
            <dt className="text-fg-subtle">Assigned to</dt>
            <dd className="mt-1 text-fg" data-testid="assignee">
              {finding.assignee ? userLabel(finding.assignee) : 'Unassigned'}
            </dd>
          </div>
        </dl>

        {finding.acceptedRisk && <AcceptedRiskBlock acceptedRisk={finding.acceptedRisk} />}

        {statusActions.length > 0 && (
          <div role="group" aria-label="Change status" className="flex flex-wrap gap-2">
            {statusActions.map((to) => (
              <Button
                key={to}
                onClick={() => open(to)}
                aria-expanded={pending === to}
                variant={pending === to ? 'primary' : 'secondary'}
              >
                {transitionLabel(finding.status, to)}
              </Button>
            ))}
          </div>
        )}

        {finding.status !== 'resolved' && (
          <div className="rounded-md border border-line px-3 py-2">
            {finding.manualResolution ? (
              <>
                <p className="text-fg-muted">
                  This rule reports a change (for example a new record or service). It does not
                  clear by itself: once someone has reviewed the change, they can mark it as
                  reviewed to resolve it.
                </p>
                {canResolve && (
                  <Button className="mt-2" onClick={() => open('resolved')}>
                    {transitionLabel(finding.status, 'resolved')}
                  </Button>
                )}
              </>
            ) : (
              <p className="text-fg-muted">
                This finding resolves automatically when a later successful scan shows the condition
                is gone. Failed or incomplete scans never resolve it.
              </p>
            )}
          </div>
        )}

        {pending && (
          <StatusChangeForm
            key={pending}
            title={transitionLabel(finding.status, pending)}
            confirmLabel={`Confirm: ${transitionLabel(finding.status, pending)}`}
            requirements={transitionRequirements(finding.status, pending)}
            description={describeTransition(pending)}
            error={formError}
            onSubmit={(values) => submitStatus(pending, values)}
            onCancel={() => setPending(null)}
          />
        )}

        {canAssign && (
          <AssigneePicker
            key={finding.assignee?.id ?? 'none'}
            current={finding.assignee}
            onSave={(assigneeId, name) =>
              update(
                { assigneeId },
                assigneeId ? `Assigned to ${name}.` : 'The finding is now unassigned.',
              )
            }
          />
        )}

        {canRecheck && <Recheck findingId={finding.id} onNotice={setNotice} />}

        {readOnly && (
          <p className="text-fg-subtle">
            You can view this finding but your role cannot change it.
          </p>
        )}

        <div aria-live="polite" role="status">
          {notice && (
            <div
              className={
                notice.kind === 'success'
                  ? 'rounded-md border border-sky-200 bg-sky-50 px-3 py-2 text-sky-900'
                  : 'flex gap-2 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-amber-950'
              }
            >
              {notice.kind === 'warning' && (
                <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden />
              )}
              <div>{notice.content}</div>
            </div>
          )}
        </div>
      </div>
    </Card>
  );
}

function describeTransition(to: FindingStatus): ReactNode {
  switch (to) {
    case 'accepted_risk':
      return 'Records that the organisation accepts this risk for now. Your name is recorded as the approver; on the review date the finding reopens automatically.';
    case 'resolved':
      return 'Confirms you have reviewed this change. If a later scan observes the condition again, the finding reopens.';
    case 'open':
      return 'Returns the finding to the open queue.';
    default:
      return null;
  }
}

function AcceptedRiskBlock({
  acceptedRisk,
}: {
  acceptedRisk: NonNullable<Finding['acceptedRisk']>;
}) {
  const [now] = useState(() => Date.now());
  const msLeft = new Date(acceptedRisk.reviewAt).getTime() - now;
  const lapsed = msLeft <= 0;
  const soon = !lapsed && msLeft <= REVIEW_WARNING_DAYS * DAY_MS;
  return (
    <section
      aria-label="Accepted risk"
      className="rounded-md border border-line bg-surface-2 px-3 py-2"
    >
      <h3 className="mb-2 font-semibold text-fg">Accepted risk</h3>
      <dl className="grid gap-2 sm:grid-cols-[9rem_1fr]">
        <dt className="text-fg-subtle">Reason</dt>
        <dd className="whitespace-pre-wrap text-fg">{acceptedRisk.reason}</dd>
        <dt className="text-fg-subtle">Approved by</dt>
        <dd className="text-fg">{userLabel(acceptedRisk.approvedBy)}</dd>
        <dt className="text-fg-subtle">Review date</dt>
        <dd className="text-fg">{formatDate(acceptedRisk.reviewAt)}</dd>
      </dl>
      {(soon || lapsed) && (
        <p className="mt-2 flex gap-2 text-amber-900" role="note">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden />
          {lapsed
            ? 'The review date has passed; the finding will reopen at the next maintenance run.'
            : `The review date is within ${REVIEW_WARNING_DAYS} days. Review the risk and accept it again, or reopen the finding.`}
        </p>
      )}
    </section>
  );
}

function AssigneePicker({
  current,
  onSave,
}: {
  current: Finding['assignee'];
  onSave: (assigneeId: string | null, name: string) => Promise<Error | null>;
}) {
  const id = useId();
  const users = useAsync((signal) => api.users.assignable({ signal }), []);
  const [value, setValue] = useState(current?.id ?? '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const options: (FindingUserRef & { role?: string })[] =
    users.status === 'success' ? [...users.data.items] : [];
  // Keep the current assignee selectable even if they are no longer assignable.
  if (current && !options.some((u) => u.id === current.id)) options.unshift(current);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const user = options.find((u) => u.id === value);
    const err = await onSave(value || null, userLabel(user));
    setBusy(false);
    if (err) setError(err);
  };

  return (
    <form onSubmit={submit} className="flex flex-wrap items-end gap-2">
      <div>
        <label htmlFor={`${id}-assignee`} className="block font-medium text-fg-2">
          Assignee
        </label>
        <select
          id={`${id}-assignee`}
          className="mt-1 rounded-md border border-line-strong bg-surface px-2 py-1.5 text-sm shadow-sm"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          disabled={users.status === 'loading'}
        >
          <option value="">Unassigned</option>
          {options.map((u) => (
            <option key={u.id} value={u.id}>
              {userLabel(u)}
              {u.role ? ` (${u.role.replace('_', ' ')})` : ''}
            </option>
          ))}
        </select>
      </div>
      <Button type="submit" disabled={busy || value === (current?.id ?? '')}>
        Save assignee
      </Button>
      {users.status === 'error' && (
        <div className="w-full">
          <ErrorAlert error={users.error} title="Could not load users" />
        </div>
      )}
      {error && (
        <div className="w-full">
          <ErrorAlert error={error} title="The assignee was not changed" />
        </div>
      )}
    </form>
  );
}

function Recheck({
  findingId,
  onNotice,
}: {
  findingId: string;
  onNotice: (notice: Notice) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      onNotice({
        kind: 'success',
        content: <RecheckResult result={await api.findings.reassess(findingId)} />,
      });
    } catch (err) {
      setError(asError(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-3">
        <Button onClick={run} disabled={busy}>
          <RefreshCw className="size-4" aria-hidden />
          Re-check now
        </Button>
        <span className="text-fg-subtle">
          Queues a scan of this domain that runs this rule&apos;s checks.
        </span>
      </div>
      {error && <ErrorAlert error={error} title="The re-check was not queued" />}
    </div>
  );
}

function RecheckResult({ result }: { result: FindingReassessResponse }) {
  return (
    <>
      {result.created
        ? `Re-check queued using the ${result.profile} profile. `
        : `A re-check using the ${result.profile} profile is already queued. `}
      <Link to={`/scans/${result.scanJobId}`} className="font-medium text-sky-800 hover:underline">
        View scan
      </Link>
    </>
  );
}
