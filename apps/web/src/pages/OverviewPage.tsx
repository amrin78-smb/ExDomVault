import type { Finding, Permission } from '@exdomainvault/shared';
import { Activity, CalendarClock, ListChecks, Network, ShieldCheck } from 'lucide-react';
import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { FindingList } from '../components/findings/FindingList.tsx';
import { SeverityCounts } from '../components/findings/SeverityCounts.tsx';
import { ScanStatusBadge } from '../components/scans/ScanStatusBadge.tsx';
import { Card } from '../components/ui/Card.tsx';
import { EmptyState } from '../components/ui/EmptyState.tsx';
import { ErrorAlert } from '../components/ui/ErrorAlert.tsx';
import { PageHeader } from '../components/ui/PageHeader.tsx';
import { StatCard } from '../components/ui/StatCard.tsx';
import { api } from '../lib/api.ts';
import { formatDateTime } from '../lib/format.ts';
import { useSession } from '../lib/session.ts';
import { useAsync, type AsyncState } from '../lib/use-async.ts';

const FINDINGS_HINT =
  'Findings come from rules run on completed scans and appear within about five minutes of a scan finishing.';

/** Whether the signed-in user holds a permission, distinguishing "not yet known". */
function useAccess(permission: Permission): 'loading' | 'yes' | 'no' {
  const session = useSession();
  if (session.status === 'loading') return 'loading';
  return session.status === 'success' && session.data.permissions.includes(permission)
    ? 'yes'
    : 'no';
}

/**
 * Operational dashboard built only from live API data. Every card loads independently, so one
 * failing endpoint never hides the others.
 */
export function OverviewPage() {
  const domains = useAccess('domains:read');
  const findings = useAccess('findings:read');
  const scans = useAccess('scans:read');
  const workers = useAccess('settings:manage');

  return (
    <>
      <PageHeader
        title="Overview"
        description="External exposure across monitored domains, open findings and operational health."
      />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {domains === 'yes' ? (
          <DomainStats />
        ) : (
          <BlankStats labels={['Domains monitored', 'Verified domains']} />
        )}
        {findings === 'yes' ? (
          <FindingStats />
        ) : (
          <BlankStats labels={['Open findings', 'Critical and high']} />
        )}
      </div>

      <div className="mt-6 grid gap-4 lg:grid-cols-3">
        <Card title="Open findings by severity">
          <Gate access={findings}>
            <SeveritySummary />
          </Gate>
        </Card>

        <Card title="Latest scans">
          <Gate access={scans}>
            <LatestScans />
          </Gate>
        </Card>

        <Card title="Worker health">
          <Gate access={workers} denied="Worker health is visible to administrators.">
            <WorkerHealth />
          </Gate>
        </Card>
      </div>

      <div className="mt-6 grid gap-4 lg:grid-cols-2">
        <Card title="Top remediation priorities">
          <Gate access={findings}>
            <TopPriorities />
          </Gate>
        </Card>

        <Card title="Certificates approaching expiry">
          <Gate access={findings}>
            <FindingsByRules
              ruleIds={['TLS-001', 'TLS-003']}
              icon={CalendarClock}
              emptyTitle="No certificate expiry findings"
              emptyText="No certificate has expired or expires within 14 days, based on the latest completed TLS checks."
            />
          </Gate>
        </Card>

        <Card title="Recently changed DNS records" className="lg:col-span-2">
          <Gate access={findings}>
            <FindingsByRules
              ruleIds={['DNS-001', 'REG-002']}
              icon={Network}
              emptyTitle="No unexpected DNS or registration changes"
              emptyText="Changes to authoritative nameservers or registrar details detected by scans appear here as findings."
            />
          </Gate>
        </Card>
      </div>
    </>
  );
}

function Gate({
  access,
  denied = 'Your role cannot view this information.',
  children,
}: {
  access: 'loading' | 'yes' | 'no';
  denied?: string;
  children: ReactNode;
}) {
  if (access === 'loading') return <Loading />;
  if (access === 'no') return <p className="text-sm text-slate-500">{denied}</p>;
  return children;
}

function Loading() {
  return (
    <p className="text-sm text-slate-500" role="status">
      Loading…
    </p>
  );
}

/** Loading / error / success rendering shared by every card. */
function Loadable<T>({
  state,
  title,
  children,
}: {
  state: AsyncState<T>;
  title: string;
  children: (data: T) => ReactNode;
}) {
  if (state.status === 'loading') return <Loading />;
  if (state.status === 'error') return <ErrorAlert error={state.error} title={title} />;
  return children(state.data);
}

function BlankStats({ labels }: { labels: string[] }) {
  return labels.map((label) => <StatCard key={label} label={label} value={null} />);
}

const totalOf = (s: AsyncState<{ total: number }>) =>
  s.status === 'success' ? s.data.total : null;

function DomainStats() {
  const all = useAsync((signal) => api.domains.list({ pageSize: 1 }, { signal }), []);
  const monitored = useAsync(
    (signal) => api.domains.list({ monitoring: 'true', pageSize: 1 }, { signal }),
    [],
  );
  const verified = useAsync(
    (signal) => api.domains.list({ verificationStatus: 'verified', pageSize: 1 }, { signal }),
    [],
  );
  const failed = [all, monitored, verified].some((s) => s.status === 'error');
  const total = totalOf(all);
  return (
    <>
      <StatCard
        label="Domains monitored"
        value={totalOf(monitored)}
        hint={
          failed
            ? 'Could not load domain counts'
            : total !== null
              ? `of ${total} domains`
              : undefined
        }
      />
      <StatCard
        label="Verified domains"
        value={totalOf(verified)}
        hint="Eligible for active checks"
      />
    </>
  );
}

function FindingStats() {
  const summary = useAsync((signal) => api.findings.summary({}, { signal }), []);
  const data = summary.status === 'success' ? summary.data : null;
  return (
    <>
      <StatCard
        label="Open findings"
        value={data?.total ?? null}
        hint={summary.status === 'error' ? 'Could not load findings' : 'Not yet resolved'}
      />
      <StatCard
        label="Critical and high"
        value={data ? (data.bySeverity.critical ?? 0) + (data.bySeverity.high ?? 0) : null}
        hint="Open, by severity"
      />
    </>
  );
}

function SeveritySummary() {
  const state = useAsync((signal) => api.findings.summary({}, { signal }), []);
  return (
    <Loadable state={state} title="Could not load findings">
      {(data) =>
        data.total === 0 ? (
          <EmptyState title="No open findings">{FINDINGS_HINT}</EmptyState>
        ) : (
          <div className="space-y-3">
            <SeverityCounts bySeverity={data.bySeverity} />
            <Link to="/findings" className="text-xs text-sky-800 hover:underline">
              View all {data.total} open findings
            </Link>
          </div>
        )
      }
    </Loadable>
  );
}

function LatestScans() {
  const state = useAsync((signal) => api.scans.list({ pageSize: 5 }, { signal }), []);
  return (
    <Loadable state={state} title="Could not load scans">
      {(data) =>
        data.items.length === 0 ? (
          <EmptyState title="No scans have run" icon={Activity}>
            Scans run daily for monitored domains, or on request from a domain page.
          </EmptyState>
        ) : (
          <ul className="divide-y divide-slate-100 text-sm">
            {data.items.map((j) => (
              <li key={j.id} className="flex items-center justify-between gap-3 py-2">
                <Link to={`/scans/${j.id}`} className="min-w-0 text-sky-800 hover:underline">
                  <span className="block truncate font-mono">{j.domain?.fqdn ?? 'Discovery'}</span>
                  <span className="block text-xs text-slate-500">
                    <span className="capitalize">{j.profile}</span> ·{' '}
                    {formatDateTime(j.completedAt ?? j.createdAt)}
                  </span>
                </Link>
                <ScanStatusBadge status={j.status} />
              </li>
            ))}
          </ul>
        )
      }
    </Loadable>
  );
}

/** A worker is considered stale when it has not polled for 10 minutes. */
const STALE_MS = 10 * 60 * 1000;

function WorkerHealth() {
  const state = useAsync((signal) => api.workers.list({ signal }), []);
  return (
    <Loadable state={state} title="Could not load workers">
      {(data) =>
        data.items.length === 0 ? (
          <EmptyState title="No worker registered" icon={ShieldCheck}>
            Register the scanning worker in Settings.
          </EmptyState>
        ) : (
          <ul className="divide-y divide-slate-100 text-sm">
            {data.items.map((w) => {
              const stale =
                w.lastSeenAt === null || Date.now() - new Date(w.lastSeenAt).getTime() > STALE_MS;
              const label =
                w.status === 'disabled' ? 'Disabled' : stale ? 'Not seen recently' : 'Polling';
              return (
                <li key={w.id} className="flex items-center justify-between gap-3 py-2">
                  <div className="min-w-0">
                    <div className="truncate font-mono text-slate-800">{w.name}</div>
                    <div className="text-xs text-slate-500">
                      Last seen {w.lastSeenAt ? formatDateTime(w.lastSeenAt) : 'never'}
                    </div>
                  </div>
                  <span className="shrink-0 text-xs font-medium text-slate-700">{label}</span>
                </li>
              );
            })}
          </ul>
        )
      }
    </Loadable>
  );
}

function TopPriorities() {
  const state = useAsync(
    (signal) => api.findings.list({ pageSize: 5, sort: '-riskScore' }, { signal }),
    [],
  );
  return (
    <Loadable state={state} title="Could not load findings">
      {(data) =>
        data.items.length === 0 ? (
          <EmptyState title="Nothing to prioritise" icon={ListChecks}>
            {FINDINGS_HINT}
          </EmptyState>
        ) : (
          <FindingList items={data.items} />
        )
      }
    </Loadable>
  );
}

/** Active findings raised by any of the given rules, highest risk first. */
function FindingsByRules({
  ruleIds,
  icon,
  emptyTitle,
  emptyText,
}: {
  ruleIds: string[];
  icon: typeof Activity;
  emptyTitle: string;
  emptyText: string;
}) {
  const state = useAsync(
    async (signal): Promise<Finding[]> => {
      const pages = await Promise.all(
        ruleIds.map((ruleId) => api.findings.list({ ruleId, pageSize: 5 }, { signal })),
      );
      return pages
        .flatMap((p) => p.items)
        .sort((a, b) => b.riskScore - a.riskScore)
        .slice(0, 5);
    },
    [ruleIds.join(',')],
  );
  return (
    <Loadable state={state} title="Could not load findings">
      {(items) =>
        items.length === 0 ? (
          <EmptyState title={emptyTitle} icon={icon}>
            {emptyText}
          </EmptyState>
        ) : (
          <FindingList items={items} showLastSeen />
        )
      }
    </Loadable>
  );
}
