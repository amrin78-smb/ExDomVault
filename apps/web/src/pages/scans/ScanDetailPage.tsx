import {
  ACTIVE_JOB_STATUSES,
  SCAN_TARGET_STATUSES,
  type ScanJobDetailResponse,
} from '@exdomainvault/shared';
import { ArrowLeft } from 'lucide-react';
import { useState } from 'react';
import { Link, useParams } from 'react-router';
import { JOB_TYPE_LABELS } from '../../components/scans/labels.ts';
import { ScanStatusBadge } from '../../components/scans/ScanStatusBadge.tsx';
import { Button } from '../../components/ui/Button.tsx';
import { Card } from '../../components/ui/Card.tsx';
import { ErrorAlert } from '../../components/ui/ErrorAlert.tsx';
import { useShowAll } from '../../components/ui/ShowAllButton.tsx';
import { api } from '../../lib/api.ts';
import { formatDateTime } from '../../lib/format.ts';
import { usePermission } from '../../lib/session.ts';
import { useAsync } from '../../lib/use-async.ts';
import { usePollingKey } from '../../lib/use-polling.ts';

const POLL_MS = 10_000;

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-1 text-sm text-slate-800">{children}</dd>
    </div>
  );
}

export function ScanDetailPage() {
  const { id = '' } = useParams();
  const canRequest = usePermission('scans:request');
  const [active, setActive] = useState(true);
  const tick = usePollingKey(active, POLL_MS);
  const [refresh, setRefresh] = useState(0);
  const state = useAsync((signal) => api.scans.get(id, { signal }), [id, tick, refresh]);
  // Keep showing the last good data while a refresh is loading.
  const [last, setLast] = useState<{ id: string; data: ScanJobDetailResponse } | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  if (state.status === 'success' && (last?.id !== id || last.data !== state.data)) {
    setLast({ id, data: state.data });
    setActive(ACTIVE_JOB_STATUSES.includes(state.data.job.status));
  }
  const data = state.status === 'success' ? state.data : last?.id === id ? last.data : null;

  if (!data) {
    if (state.status === 'error') {
      return (
        <>
          <BackLink />
          <ErrorAlert error={state.error} title="Could not load this scan" />
        </>
      );
    }
    return (
      <p className="py-8 text-center text-sm text-slate-500" role="status">
        Loading scan…
      </p>
    );
  }

  const { job, targets, scopeSnapshot } = data;
  const cancel = async () => {
    setCancelling(true);
    setError(null);
    try {
      await api.scans.cancel(id);
      setRefresh((r) => r + 1);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setCancelling(false);
    }
  };
  const isActive = ACTIVE_JOB_STATUSES.includes(job.status);
  const config = scopeSnapshot.profile.config;

  return (
    <>
      <BackLink />
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-slate-900">
            {job.jobType === 'discovery' ? (
              'Discovery for'
            ) : (
              <>
                <span className="capitalize">{job.profile}</span> scan of
              </>
            )}{' '}
            {job.domain ? (
              <Link
                to={`/domains/${job.domain.id}`}
                className="font-mono text-sky-800 hover:underline"
              >
                {job.domain.fqdn}
              </Link>
            ) : (
              <span className="font-mono">{scopeSnapshot.domain.fqdn}</span>
            )}
          </h1>
          <div className="mt-2 flex items-center gap-3">
            <ScanStatusBadge status={job.status} />
            <span className="text-xs text-slate-600">{JOB_TYPE_LABELS[job.jobType]} job</span>
            {job.cancelRequestedAt && isActive && (
              <span className="text-xs text-slate-500">Cancellation requested</span>
            )}
            {isActive && <span className="text-xs text-slate-500">Refreshes every 10 s</span>}
          </div>
        </div>
        {canRequest && isActive && !job.cancelRequestedAt && (
          <Button variant="danger" onClick={cancel} disabled={cancelling}>
            Cancel scan
          </Button>
        )}
      </div>
      {error && (
        <div className="mb-4">
          <ErrorAlert error={error} />
        </div>
      )}

      <div className="grid items-start gap-4 lg:grid-cols-2">
        <Card title="Job">
          <dl className="grid gap-4 sm:grid-cols-2">
            <Field label="Requested">
              {formatDateTime(job.createdAt)}
              <span className="block text-xs text-slate-500">
                {job.trigger === 'schedule'
                  ? 'Scheduled monitoring'
                  : (job.requestedBy?.email ?? '—')}
              </span>
            </Field>
            <Field label="Attempts">
              {job.attempts} of {job.maxAttempts}
            </Field>
            <Field label="Started">{job.startedAt ? formatDateTime(job.startedAt) : '—'}</Field>
            <Field label="Completed">
              {job.completedAt ? formatDateTime(job.completedAt) : '—'}
            </Field>
            <Field label="Worker">{job.worker?.name ?? '—'}</Field>
            <Field label="Lease expires">
              {job.leaseExpiresAt && isActive ? formatDateTime(job.leaseExpiresAt) : '—'}
            </Field>
            {job.progress && (
              <Field label="Progress">
                {job.progress.completedTargets ?? 0} / {job.progress.totalTargets ?? targets.length}{' '}
                targets
                {job.progress.message && (
                  <span className="block text-xs text-slate-500">{job.progress.message}</span>
                )}
              </Field>
            )}
            {job.errorCode && (
              <Field label="Last error">
                <code className="font-mono text-xs">{job.errorCode}</code>
                {job.errorSummary && (
                  <span className="block text-xs text-slate-600">{job.errorSummary}</span>
                )}
              </Field>
            )}
            {job.reason && <Field label="Reason">{job.reason}</Field>}
          </dl>
          {job.jobType === 'discovery' && (
            <p className="mt-4 text-xs text-slate-500" data-testid="discovery-note">
              Discovery looks up names in public Certificate Transparency logs and never contacts
              the domain&apos;s hosts. Hostnames it finds wait in{' '}
              <Link
                to={job.domain ? `/assets?domainId=${job.domain.id}` : '/assets'}
                className="text-sky-800 hover:underline"
              >
                Assets
              </Link>{' '}
              as Pending review; none is scanned until approved.
            </p>
          )}
          {job.status === 'queued' && !job.worker && (
            <p className="mt-4 text-xs text-slate-500">
              Waiting for the scanning worker to claim this job. Results appear once the home worker
              (Milestone 5) is running.
            </p>
          )}
        </Card>

        <Card
          title="Scope (fixed when the scan was requested)"
          collapsible="scan.scope"
          defaultOpen={false}
          summary={`${scopeSnapshot.profile.key} v${scopeSnapshot.profile.version} · ${config.active ? 'active' : 'passive'} · ${config.checks.length} check${config.checks.length === 1 ? '' : 's'}`}
        >
          <dl className="grid gap-4 sm:grid-cols-2">
            <Field label="Profile">
              <span className="capitalize">{scopeSnapshot.profile.key}</span> (v
              {scopeSnapshot.profile.version}) · {config.active ? 'active' : 'passive'}
            </Field>
            <Field label="Checks">{config.checks.join(', ')}</Field>
            {config.tcpPorts.length > 0 && (
              <Field label="TCP ports">
                <span className="font-mono text-xs">{config.tcpPorts.join(', ')}</span>
              </Field>
            )}
            <Field label="Limits">
              {config.concurrency} concurrent · {config.ratePerSecond}/s ·{' '}
              {config.timeouts.targetSeconds} s per target
            </Field>
            <Field label="Domain authorisation at request time">
              {scopeSnapshot.domain.verificationStatus}
              {scopeSnapshot.domain.verificationMethod
                ? ` (${scopeSnapshot.domain.verificationMethod.replace('_', ' ')})`
                : ''}
            </Field>
          </dl>
        </Card>

        <TargetsCard targets={targets} />
      </div>
    </>
  );
}

/** Per-target progress; a long target list shows its first entries until expanded. */
function TargetsCard({ targets }: { targets: ScanJobDetailResponse['targets'] }) {
  const { shown, toggle } = useShowAll(targets, { limit: 10, noun: 'targets' });
  const counts = SCAN_TARGET_STATUSES.map((s) => ({
    status: s,
    n: targets.filter((t) => t.status === s).length,
  })).filter((c) => c.n > 0);
  return (
    <Card
      title={`Targets (${targets.length})`}
      className="lg:col-span-2"
      collapsible="scan.targets"
      summary={counts.map((c) => `${c.n} ${c.status}`).join(', ') || 'None'}
    >
      <table className="min-w-full text-sm">
        <thead>
          <tr className="border-b border-slate-200 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
            <th scope="col" className="py-2 pr-4">
              Hostname
            </th>
            <th scope="col" className="py-2 pr-4">
              Status
            </th>
            <th scope="col" className="py-2 pr-4">
              Completed
            </th>
            <th scope="col" className="py-2">
              Error
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {shown.map((t) => (
            <tr key={t.id}>
              <td className="py-2 pr-4 font-mono text-xs">{t.hostname}</td>
              <td className="py-2 pr-4 capitalize">{t.status}</td>
              <td className="py-2 pr-4 text-slate-600">
                {t.completedAt ? formatDateTime(t.completedAt) : '—'}
              </td>
              <td className="py-2 font-mono text-xs text-slate-600">{t.errorCode ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {toggle && <div className="mt-3">{toggle}</div>}
    </Card>
  );
}

function BackLink() {
  return (
    <Link
      to="/scans"
      className="mb-4 inline-flex items-center gap-1 text-sm text-slate-600 hover:text-slate-900"
    >
      <ArrowLeft className="size-4" aria-hidden />
      Scans
    </Link>
  );
}
