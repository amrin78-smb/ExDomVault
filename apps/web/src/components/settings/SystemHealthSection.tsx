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
import { useCollapseAll } from '../ui/CollapseAllControls.tsx';
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
    never_seen: { label: 'Never seen', icon: CircleDashed, className: 'text-fg-muted' },
  };

const th = 'py-1.5 pr-4 text-left text-xs font-medium text-fg-subtle';
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
  const { controls, group } = useCollapseAll();

  if (state.status === 'loading') {
    return (
      <p role="status" className="py-8 text-center text-sm text-fg-subtle">
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
      <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-fg-muted">
        <p>
          Computed by the server at {formatDateTime(h.generatedAt)}. Refreshes every minute while
          this page is open.
        </p>
        <div className="flex flex-wrap items-center gap-2">
          {controls}
          <Button onClick={retry} disabled={refreshing}>
            <RefreshCw className={`size-3.5 ${refreshing ? 'animate-spin' : ''}`} aria-hidden />
            {refreshing ? 'Refreshing…' : 'Refresh'}
          </Button>
        </div>
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
      {group(
        <>
          <div className="grid items-start gap-6 lg:grid-cols-2">
            <WorkersCard workers={h.workers} />
            <QueueCard queue={h.queue} />
          </div>
          <ScansCard scans={h.scans} failures={h.failuresByCode} />
          <div className="grid items-start gap-6 lg:grid-cols-2">
            <DatabaseCard database={h.database} />
            <RetentionCard retention={h.retention} />
          </div>
          <Card
            title="Intelligence feeds"
            collapsible="settings.health.feeds"
            defaultOpen={false}
            summary={feedsSummary(h.feeds)}
          >
            <div className="text-sm">
              <FeedList feeds={h.feeds} />
            </div>
          </Card>
        </>,
      )}
    </div>
  );
}

const plural = (n: number, noun: string) => `${n} ${noun}${n === 1 ? '' : 's'}`;

function feedsSummary(feeds: Health['feeds']): string {
  if (feeds.length === 0) return 'None configured';
  const failing = feeds.filter((f) => f.lastError).length;
  const never = feeds.filter((f) => !f.lastError && !f.lastSuccessAt).length;
  const notes = [
    failing > 0 && `${failing} failing`,
    never > 0 && `${never} never synchronised`,
  ].filter(Boolean);
  return `${plural(feeds.length, 'feed')}${notes.length > 0 ? `, ${notes.join(', ')}` : ', all up to date'}`;
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
    <Card
      title="Workers"
      collapsible="settings.health.workers"
      summary={
        workers.length === 0
          ? 'None registered'
          : `${plural(workers.length, 'worker')}, ${workers.filter((w) => w.status === 'online').length} online`
      }
    >
      {workers.length === 0 ? (
        <p className="text-sm text-fg-subtle">No workers registered.</p>
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
          <tbody className="divide-y divide-line-soft">
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
    <Card
      title="Queue"
      collapsible="settings.health.queue"
      summary={`${queue.queued} queued, ${queue.running} running`}
    >
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
            <tbody className="divide-y divide-line-soft tabular-nums">
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
    <Card
      title="Scan outcomes"
      collapsible="settings.health.scans"
      summary={`Last 24 hours: ${scans.last24h.succeeded} succeeded, ${scans.last24h.failed} failed`}
    >
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
            <tbody className="divide-y divide-line-soft tabular-nums">
              {rows.map(([label, w]) => (
                <tr key={label}>
                  <th scope="row" className={`${td} text-left font-medium text-fg`}>
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
          <h3 className="mb-1 text-xs font-medium text-fg-subtle">
            Top failure codes (last 24 hours)
          </h3>
          {failures.length === 0 ? (
            <p className="text-sm text-fg-subtle">No failures in the last 24 hours.</p>
          ) : (
            <ul className="divide-y divide-line-soft text-sm" aria-label="Top failure codes">
              {failures.map((f) => (
                <li key={f.code} className="flex justify-between gap-4 py-1.5">
                  <span className="font-mono text-xs text-fg">{f.code}</span>
                  <span className="tabular-nums text-fg-2">{f.count}</span>
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
    <Card
      title="Database"
      collapsible="settings.health.database"
      summary={database.ok ? 'Reachable' : 'Not responding'}
    >
      <div className="flex items-center gap-3 text-sm">
        <Database className="size-5 text-fg-faint" aria-hidden />
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
        <span className="text-fg-muted">
          {database.latencyMs === null ? 'Latency unknown' : `${database.latencyMs} ms round trip`}
        </span>
      </div>
    </Card>
  );
}

function RetentionCard({ retention }: { retention: Health['retention'] }) {
  return (
    <Card
      title="Retention"
      collapsible="settings.health.retention"
      defaultOpen={false}
      summary={
        retention.lastRunAt
          ? `Last cleanup ${formatDateTime(retention.lastRunAt)}`
          : 'Cleanup not run yet'
      }
    >
      <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
        <div>
          <dt className="text-xs text-fg-subtle">Last cleanup</dt>
          <dd className="text-fg">
            {retention.lastRunAt ? formatDateTime(retention.lastRunAt) : 'Not run yet'}
          </dd>
        </div>
        <div>
          <dt className="text-xs text-fg-subtle">Rows deleted in last cleanup</dt>
          <dd className="tabular-nums text-fg">{retention.deletedLastRun}</dd>
        </div>
        <div>
          <dt className="text-xs text-fg-subtle">Observations kept</dt>
          <dd className="text-fg">
            {retention.policy.observationDays} days (latest per key always kept)
          </dd>
        </div>
        <div>
          <dt className="text-xs text-fg-subtle">Finished scan jobs kept</dt>
          <dd className="text-fg">{retention.policy.scanJobDays} days</dd>
        </div>
      </dl>
      <p className="mt-3 text-xs text-fg-subtle">
        Findings, their status history, comments and the audit log are never deleted.
      </p>
    </Card>
  );
}
