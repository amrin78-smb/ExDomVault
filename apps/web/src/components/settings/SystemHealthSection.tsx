import type { OpsHealthResponse } from '@exdomainvault/shared';
import {
  CheckCircle2,
  CircleDashed,
  Clock,
  Database,
  OctagonAlert,
  RefreshCw,
  XCircle,
  type LucideIcon,
} from 'lucide-react';
import { api } from '../../lib/api.ts';
import { formatDateTime, formatDuration } from '../../lib/format.ts';
import { usePageVisible } from '../../lib/use-page-visible.ts';
import { usePollingKey } from '../../lib/use-polling.ts';
import { useRefreshableAsync } from '../../lib/use-refreshable-async.ts';
import { Button } from '../ui/Button.tsx';
import { Card } from '../ui/Card.tsx';
import { LoadError } from '../ui/LoadError.tsx';
import { StaleDataNotice } from '../ui/StaleDataNotice.tsx';
import { StatCard } from '../ui/StatCard.tsx';
import { FeedList } from './IntelFeedsSection.tsx';

/** Refresh interval while the tab is open and the browser tab is visible. */
export const HEALTH_REFRESH_MS = 60_000;

type Health = OpsHealthResponse;
type WorkerStatus = Health['workers'][number]['status'];
type ScanWindow = Health['scans']['last24h'];

/** Worker liveness in words plus an icon, never colour alone. */
const WORKER_STATUS: Record<WorkerStatus, { label: string; icon: LucideIcon; className: string }> =
  {
    online: { label: 'Online', icon: CheckCircle2, className: 'text-emerald-800' },
    stale: { label: 'Not seen recently', icon: Clock, className: 'text-amber-800' },
    offline: { label: 'Offline', icon: XCircle, className: 'text-red-800' },
    never_seen: { label: 'Never seen', icon: CircleDashed, className: 'text-slate-600' },
  };

const th = 'py-1.5 pr-4 text-left text-xs font-medium text-slate-500';
const td = 'py-1.5 pr-4';

const percent = (rate: number | null) => (rate === null ? '—' : `${Math.round(rate * 1000) / 10}%`);
const seconds = (s: number | null) => (s === null ? '—' : formatDuration(s));

/**
 * Settings → System health (`settings:manage`): worker liveness, queue, scan outcomes, failures,
 * database, feeds and retention, all computed by the server from stored state. Refreshes every
 * minute while visible; a failed refresh keeps the last data on screen, marked as stale.
 */
export function SystemHealthSection() {
  const visible = usePageVisible();
  const tick = usePollingKey(visible, HEALTH_REFRESH_MS);
  const { state, stale, refreshing, retry } = useRefreshableAsync(
    (signal) => api.ops.health({ signal }),
    [],
    tick,
  );

  if (state.status === 'loading') {
    return (
      <p role="status" className="py-8 text-center text-sm text-slate-500">
        Loading system health…
      </p>
    );
  }
  if (state.status === 'error') {
    return (
      <Card>
        <LoadError
          error={state.error}
          title="Could not load system health"
          onRetry={retry}
          deniedTitle="System health is visible to administrators"
        />
      </Card>
    );
  }

  const h = state.data;
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-slate-600">
        <p>
          Computed by the server at {formatDateTime(h.generatedAt)}. Refreshes every minute while
          this page is open.
        </p>
        <Button onClick={retry} disabled={refreshing}>
          <RefreshCw className={`size-3.5 ${refreshing ? 'animate-spin' : ''}`} aria-hidden />
          {refreshing ? 'Refreshing…' : 'Refresh'}
        </Button>
      </div>
      {stale && (
        <StaleDataNotice
          loadedAt={stale.loadedAt}
          error={stale.error}
          onRetry={retry}
          retrying={refreshing}
        />
      )}
      <OutageBlock outage={h.outage} />
      <div className="grid gap-6 lg:grid-cols-2">
        <WorkersCard workers={h.workers} />
        <QueueCard queue={h.queue} />
      </div>
      <ScansCard scans={h.scans} failures={h.failuresByCode} />
      <div className="grid gap-6 lg:grid-cols-2">
        <DatabaseCard database={h.database} />
        <RetentionCard retention={h.retention} />
      </div>
      <Card title="Intelligence feeds">
        <div className="text-sm">
          <FeedList feeds={h.feeds} />
        </div>
      </Card>
    </div>
  );
}

function OutageBlock({ outage }: { outage: Health['outage'] }) {
  if (!outage.active) {
    return (
      <section
        aria-label="Worker outage"
        className="flex items-start gap-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-900"
      >
        <CheckCircle2 className="mt-0.5 size-4 shrink-0" aria-hidden />
        <p>No worker outage. Queued scans are being picked up.</p>
      </section>
    );
  }
  return (
    <section
      aria-label="Worker outage"
      className="flex items-start gap-2 rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-900"
    >
      <OctagonAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div>
        <p className="font-medium">
          Worker outage
          {outage.since ? ` since ${formatDateTime(outage.since)}` : ''}
        </p>
        <p>
          No active worker has been seen while {outage.queuedJobs} job
          {outage.queuedJobs === 1 ? ' is' : 's are'} queued. Check the worker service on the
          scanning host (systemd status and logs) and its network connection.
        </p>
      </div>
    </section>
  );
}

function WorkersCard({ workers }: { workers: Health['workers'] }) {
  return (
    <Card title="Workers">
      {workers.length === 0 ? (
        <p className="text-sm text-slate-500">No workers registered.</p>
      ) : (
        <table className="min-w-full text-sm">
          <thead>
            <tr>
              <th scope="col" className={th}>
                Worker
              </th>
              <th scope="col" className={th}>
                Status
              </th>
              <th scope="col" className={th}>
                Last seen
              </th>
              <th scope="col" className={th}>
                Version
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {workers.map((w) => {
              const s = WORKER_STATUS[w.status];
              return (
                <tr key={w.id}>
                  <td className={`${td} font-mono`}>{w.name}</td>
                  <td className={td}>
                    <span
                      className={`inline-flex items-center gap-1 text-xs font-medium ${s.className}`}
                    >
                      <s.icon className="size-3.5" aria-hidden />
                      {s.label}
                    </span>
                  </td>
                  <td className={`${td} text-xs`}>
                    {w.lastSeenAt ? formatDateTime(w.lastSeenAt) : 'Never'}
                  </td>
                  <td className={`${td} font-mono text-xs`}>{w.version ?? '—'}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </Card>
  );
}

function QueueCard({ queue }: { queue: Health['queue'] }) {
  return (
    <Card title="Queue">
      <div className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-3">
          <StatCard label="Queued" value={queue.queued} />
          <StatCard label="Running" value={queue.running} />
          <StatCard
            label="Oldest queued"
            value={
              queue.oldestQueuedAgeSeconds === null
                ? null
                : formatDuration(queue.oldestQueuedAgeSeconds)
            }
          />
        </div>
        {queue.byProfile.length > 0 && (
          <table className="min-w-full text-sm" aria-label="Queue by profile">
            <thead>
              <tr>
                <th scope="col" className={th}>
                  Profile
                </th>
                <th scope="col" className={`${th} text-right`}>
                  Queued
                </th>
                <th scope="col" className={`${th} text-right`}>
                  Running
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 tabular-nums">
              {queue.byProfile.map((p) => (
                <tr key={p.profile}>
                  <td className={`${td} font-mono text-xs`}>{p.profile}</td>
                  <td className={`${td} text-right`}>{p.queued}</td>
                  <td className={`${td} text-right`}>{p.running}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Card>
  );
}

function ScansCard({
  scans,
  failures,
}: {
  scans: Health['scans'];
  failures: Health['failuresByCode'];
}) {
  const rows: [string, ScanWindow][] = [
    ['Last 24 hours', scans.last24h],
    ['Last 7 days', scans.last7d],
  ];
  return (
    <Card title="Scan outcomes">
      <div className="space-y-4">
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm" aria-label="Scan outcomes">
            <thead>
              <tr>
                <th scope="col" className={th}>
                  Window
                </th>
                <th scope="col" className={`${th} text-right`}>
                  Succeeded
                </th>
                <th scope="col" className={`${th} text-right`}>
                  Failed
                </th>
                <th scope="col" className={`${th} text-right`}>
                  Cancelled
                </th>
                <th scope="col" className={`${th} text-right`}>
                  Success rate
                </th>
                <th scope="col" className={`${th} text-right`}>
                  Median duration
                </th>
                <th scope="col" className={`${th} text-right`}>
                  95th percentile
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 tabular-nums">
              {rows.map(([label, w]) => (
                <tr key={label}>
                  <th scope="row" className={`${td} text-left font-medium text-slate-800`}>
                    {label}
                  </th>
                  <td className={`${td} text-right`}>{w.succeeded}</td>
                  <td className={`${td} text-right`}>{w.failed}</td>
                  <td className={`${td} text-right`}>{w.cancelled}</td>
                  <td className={`${td} text-right`}>{percent(w.successRate)}</td>
                  <td className={`${td} text-right`}>{seconds(w.p50DurationSeconds)}</td>
                  <td className={`${td} text-right`}>{seconds(w.p95DurationSeconds)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div>
          <h3 className="mb-1 text-xs font-medium text-slate-500">
            Top failure codes (last 24 hours)
          </h3>
          {failures.length === 0 ? (
            <p className="text-sm text-slate-500">No failures in the last 24 hours.</p>
          ) : (
            <ul className="divide-y divide-slate-100 text-sm" aria-label="Top failure codes">
              {failures.map((f) => (
                <li key={f.code} className="flex justify-between gap-4 py-1.5">
                  <span className="font-mono text-xs text-slate-800">{f.code}</span>
                  <span className="tabular-nums text-slate-700">{f.count}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </Card>
  );
}

function DatabaseCard({ database }: { database: Health['database'] }) {
  return (
    <Card title="Database">
      <div className="flex items-center gap-3 text-sm">
        <Database className="size-5 text-slate-400" aria-hidden />
        {database.ok ? (
          <span className="inline-flex items-center gap-1 font-medium text-emerald-800">
            <CheckCircle2 className="size-4" aria-hidden />
            Reachable
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 font-medium text-red-800">
            <XCircle className="size-4" aria-hidden />
            Not responding
          </span>
        )}
        <span className="text-slate-600">
          {database.latencyMs === null ? 'Latency unknown' : `${database.latencyMs} ms round trip`}
        </span>
      </div>
    </Card>
  );
}

function RetentionCard({ retention }: { retention: Health['retention'] }) {
  return (
    <Card title="Retention">
      <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
        <div>
          <dt className="text-xs text-slate-500">Last cleanup</dt>
          <dd className="text-slate-800">
            {retention.lastRunAt ? formatDateTime(retention.lastRunAt) : 'Not run yet'}
          </dd>
        </div>
        <div>
          <dt className="text-xs text-slate-500">Rows deleted in last cleanup</dt>
          <dd className="tabular-nums text-slate-800">{retention.deletedLastRun}</dd>
        </div>
        <div>
          <dt className="text-xs text-slate-500">Observations kept</dt>
          <dd className="text-slate-800">
            {retention.policy.observationDays} days (latest per key always kept)
          </dd>
        </div>
        <div>
          <dt className="text-xs text-slate-500">Finished scan jobs kept</dt>
          <dd className="text-slate-800">{retention.policy.scanJobDays} days</dd>
        </div>
      </dl>
      <p className="mt-3 text-xs text-slate-500">
        Findings, their status history, comments and the audit log are never deleted.
      </p>
    </Card>
  );
}
