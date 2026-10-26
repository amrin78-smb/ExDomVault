import type {
  Finding,
  FindingSummaryResponse,
  Permission,
  ReportSummaryResponse,
  ScanJobListResponse,
  SoftwareSummaryResponse,
  Worker,
} from '@exdomainvault/shared';
import {
  Activity,
  CalendarClock,
  ListChecks,
  Lock,
  Network,
  PackageSearch,
  ShieldCheck,
} from 'lucide-react';
import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { FindingList } from '../components/findings/FindingList.tsx';
import { SeverityCounts } from '../components/findings/SeverityCounts.tsx';
import { TrendChart } from '../components/reports/TrendChart.tsx';
import { ScanStatusBadge } from '../components/scans/ScanStatusBadge.tsx';
import { Card } from '../components/ui/Card.tsx';
import { useCollapseAll } from '../components/ui/CollapseAllControls.tsx';
import { EmptyState } from '../components/ui/EmptyState.tsx';
import { LoadError } from '../components/ui/LoadError.tsx';
import { PageHeader } from '../components/ui/PageHeader.tsx';
import { StatCard } from '../components/ui/StatCard.tsx';
import { api } from '../lib/api.ts';
import { formatDateTime } from '../lib/format.ts';
import { useSession } from '../lib/session.ts';
import { useAsync, type AsyncState } from '../lib/use-async.ts';

const FINDINGS_HINT =
  'Findings come from rules run on completed scans and appear within about five minutes of a scan finishing.';

type Access = 'loading' | 'yes' | 'no';

/** Whether the signed-in user holds a permission, distinguishing "not yet known". */
function useAccess(permission: Permission): Access {
  const session = useSession();
  if (session.status === 'loading') return 'loading';
  return session.status === 'success' && session.data.permissions.includes(permission)
    ? 'yes'
    : 'no';
}

/** Loads only once access is known to be granted; never calls an endpoint the role cannot use. */
function useAsyncIf<T>(
  access: Access,
  load: (signal: AbortSignal) => Promise<T>,
): AsyncState<T | null> {
  return useAsync((signal) => (access === 'yes' ? load(signal) : Promise.resolve(null)), [access]);
}

/** A state that is still meaningful only when its request actually ran. */
const loaded = <T,>(s: AsyncState<T | null>): AsyncState<T> =>
  s.status === 'success' && s.data === null ? { status: 'loading' } : (s as AsyncState<T>);

/** A collapsed card's one-line summary, once its data has loaded. */
const summaryOf = <T,>(s: AsyncState<T>, line: (data: T) => string): string | undefined =>
  s.status === 'success' ? line(s.data) : undefined;

const plural = (n: number, noun: string) => `${n} ${noun}${n === 1 ? '' : 's'}`;

/** Active findings raised by any of the given rules, highest risk first (at most five). */
function useRuleFindings(access: Access, ruleIds: string[]): AsyncState<Finding[]> {
  return loaded(
    useAsyncIf(access, async (signal): Promise<Finding[]> => {
      const pages = await Promise.all(
        ruleIds.map((ruleId) => api.findings.list({ ruleId, pageSize: 5 }, { signal })),
      );
      return pages
        .flatMap((p) => p.items)
        .sort((a, b) => b.riskScore - a.riskScore)
        .slice(0, 5);
    }),
  );
}

const CERT_RULES = ['TLS-001', 'TLS-003'];
const DNS_RULES = ['DNS-001', 'REG-002'];

/**
 * Operational dashboard built only from live API data. Every card loads independently, so one
 * failing endpoint never hides the others. The report summary and the findings summary are each
 * fetched once and shared by the cards that use them.
 */
export function OverviewPage() {
  const domains = useAccess('domains:read');
  const assets = useAccess('assets:read');
  const findings = useAccess('findings:read');
  const scans = useAccess('scans:read');
  const workers = useAccess('settings:manage');
  const reports = useAccess('reports:read');

  const report = useAsyncIf(reports, (signal) => api.reports.summary({ signal }));
  const findingSummary = loaded(
    useAsyncIf(findings, (signal) => api.findings.summary({}, { signal })),
  );
  // Portfolio coverage comes from the report when available; otherwise from the list endpoints.
  const coverage =
    report.status === 'success' && report.data && domains === 'yes' ? report.data.coverage : null;
  const coverageFallback = reports === 'no' || report.status === 'error';
  // Card data is loaded here (only once access is granted) so collapsed cards can summarise it.
  const latestScans = loaded(
    useAsyncIf(scans, (signal) => api.scans.list({ pageSize: 5 }, { signal })),
  );
  const workerList = loaded(useAsyncIf(workers, (signal) => api.workers.list({ signal })));
  const software = loaded(useAsyncIf(findings, (signal) => api.software.summary({ signal })));
  const certFindings = useRuleFindings(findings, CERT_RULES);
  const dnsFindings = useRuleFindings(findings, DNS_RULES);
  const { controls, group } = useCollapseAll();

  return (
    <>
      <PageHeader
        title="Overview"
        description="External exposure across monitored domains, open findings and operational health."
        actions={controls}
      />

      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        {domains !== 'yes' ? (
          <BlankStats labels={['Domains monitored', 'Verified domains']} />
        ) : coverage ? (
          <>
            <StatCard
              label="Domains monitored"
              value={coverage.monitoredDomains}
              hint={`of ${coverage.domains} domains`}
            />
            <StatCard
              label="Verified domains"
              value={coverage.verifiedDomains}
              hint="Eligible for active checks"
            />
          </>
        ) : coverageFallback ? (
          <DomainStats />
        ) : (
          <BlankStats labels={['Domains monitored', 'Verified domains']} />
        )}
        {assets !== 'yes' || domains !== 'yes' ? (
          <BlankStats labels={['Approved assets', 'Pending assets']} />
        ) : coverage ? (
          <>
            <StatCard
              label="Approved assets"
              value={coverage.approvedAssets}
              hint="In scan scope"
            />
            <PendingAssets value={coverage.pendingAssets} />
          </>
        ) : coverageFallback ? (
          <AssetStats />
        ) : (
          <BlankStats labels={['Approved assets', 'Pending assets']} />
        )}
        {findings === 'yes' ? (
          <FindingStats state={findingSummary} />
        ) : (
          <BlankStats labels={['Open findings', 'Critical and high']} />
        )}
      </div>

      {group(
        <>
          <div className="mt-6 grid items-start gap-4 lg:grid-cols-3">
            <Card title="Open findings by severity">
              <Gate access={findings}>
                <SeveritySummary state={findingSummary} />
              </Gate>
            </Card>

            <Card
              title="Latest scans"
              collapsible="overview.scans"
              summary={summaryOf(latestScans, scansSummary)}
            >
              <Gate access={scans}>
                <LatestScans state={latestScans} />
              </Gate>
            </Card>

            <Card
              title="Worker health"
              collapsible="overview.workers"
              summary={summaryOf(workerList, workersSummary)}
            >
              <Gate access={workers} denied="Worker health is visible to administrators.">
                <WorkerHealth state={workerList} />
              </Gate>
            </Card>
          </div>

          <div className="mt-6 grid items-start gap-4 lg:grid-cols-3">
            <Card
              title="Findings created and resolved over time"
              className="lg:col-span-2"
              collapsible="overview.trend"
              summary={summaryOf(loaded(report), trendSummary)}
            >
              <Gate access={reports}>
                <Loadable state={loaded(report)} title="Could not load the trend">
                  {(data) => (
                    <div className="space-y-2">
                      <TrendChart trend={data.trend} compact />
                      <Link to="/reports" className="text-xs text-sky-800 hover:underline">
                        Open the full report
                      </Link>
                    </div>
                  )}
                </Loadable>
              </Gate>
            </Card>

            <Card
              title="Exposed software"
              collapsible="overview.software"
              summary={summaryOf(software, softwareSummary)}
            >
              <Gate access={findings}>
                <ExposedSoftware state={software} />
              </Gate>
            </Card>
          </div>

          <div className="mt-6 grid items-start gap-4 lg:grid-cols-2">
            <Card title="Top remediation priorities">
              <Gate access={findings}>
                <TopPriorities />
              </Gate>
            </Card>

            <Card
              title="Certificates approaching expiry"
              collapsible="overview.certificates"
              summary={summaryOf(certFindings, findingsSummary)}
            >
              <Gate access={findings}>
                <FindingsByRules
                  state={certFindings}
                  icon={CalendarClock}
                  emptyTitle="No certificate expiry findings"
                  emptyText="No certificate has expired or expires within 14 days, based on the latest completed TLS checks."
                />
              </Gate>
            </Card>

            <Card
              title="Recently changed DNS records"
              className="lg:col-span-2"
              collapsible="overview.dns"
              summary={summaryOf(dnsFindings, findingsSummary)}
            >
              <Gate access={findings}>
                <FindingsByRules
                  state={dnsFindings}
                  icon={Network}
                  emptyTitle="No unexpected DNS or registration changes"
                  emptyText="Changes to authoritative nameservers or registrar details detected by scans appear here as findings."
                />
              </Gate>
            </Card>
          </div>
        </>,
      )}
    </>
  );
}

function scansSummary(data: ScanJobListResponse): string {
  const latest = data.items[0];
  return latest
    ? `Latest ${formatDateTime(latest.completedAt ?? latest.createdAt)}`
    : 'No scans have run';
}

/** A worker is considered stale when it has not polled for 10 minutes. */
const STALE_MS = 10 * 60 * 1000;
const isStale = (w: Worker) =>
  w.lastSeenAt === null || Date.now() - new Date(w.lastSeenAt).getTime() > STALE_MS;

function workersSummary(data: { items: Worker[] }): string {
  if (data.items.length === 0) return 'No worker registered';
  const quiet = data.items.filter((w) => w.status !== 'disabled' && isStale(w)).length;
  return `${plural(data.items.length, 'worker')}${quiet > 0 ? `, ${quiet} not seen recently` : ''}`;
}

function trendSummary(data: ReportSummaryResponse): string {
  const created = data.trend.reduce((n, d) => n + d.created, 0);
  const resolved = data.trend.reduce((n, d) => n + d.resolved, 0);
  return `${created} created, ${resolved} resolved in ${data.trendDays} days`;
}

function softwareSummary(data: SoftwareSummaryResponse): string {
  if (data.products.length === 0) return 'No software recorded yet';
  const eol = data.products.reduce((n, p) => n + p.eol, 0);
  const kev = data.products.reduce((n, p) => n + p.knownExploited, 0);
  return `${eol} end-of-life, ${kev} possibly KEV-affected`;
}

const findingsSummary = (items: Finding[]) =>
  items.length === 0
    ? 'None'
    : `${items.length === 5 ? 'Top 5' : plural(items.length, 'finding')}, highest risk ${items[0]?.riskScore ?? 0}`;

function Gate({
  access,
  denied = 'Your role cannot view this information.',
  children,
}: {
  access: Access;
  denied?: string;
  children: ReactNode;
}) {
  if (access === 'loading') return <Loading />;
  if (access === 'no') {
    return (
      <p className="flex items-center gap-2 text-sm text-slate-500">
        <Lock className="size-4 shrink-0 text-slate-400" aria-hidden />
        {denied}
      </p>
    );
  }
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
  if (state.status === 'error') return <LoadError error={state.error} title={title} />;
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

function PendingAssets({ value, failed = false }: { value: number | null; failed?: boolean }) {
  return (
    <div className="relative">
      <StatCard
        label="Pending assets"
        value={value}
        hint={failed ? 'Could not load asset counts' : 'Discovered, awaiting review'}
      />
      {value !== null && value > 0 && (
        <Link
          to="/assets?status=pending"
          className="absolute right-3 top-3 text-xs text-sky-800 hover:underline"
        >
          Review
        </Link>
      )}
    </div>
  );
}

/** Asset counts from the inventory list, for when the report summary is unavailable. */
function AssetStats() {
  const approved = useAsync(
    (signal) => api.assets.list({ status: 'approved', pageSize: 1 }, { signal }),
    [],
  );
  const pending = useAsync(
    (signal) => api.assets.list({ status: 'pending', pageSize: 1 }, { signal }),
    [],
  );
  const failed = [approved, pending].some((s) => s.status === 'error');
  return (
    <>
      <StatCard
        label="Approved assets"
        value={totalOf(approved)}
        hint={failed ? 'Could not load asset counts' : 'In scan scope'}
      />
      <PendingAssets value={totalOf(pending)} failed={failed} />
    </>
  );
}

function FindingStats({ state: summary }: { state: AsyncState<FindingSummaryResponse> }) {
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

function SeveritySummary({ state }: { state: AsyncState<FindingSummaryResponse> }) {
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

function LatestScans({ state }: { state: AsyncState<ScanJobListResponse> }) {
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

function WorkerHealth({ state }: { state: AsyncState<{ items: Worker[] }> }) {
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
              const stale = isStale(w);
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

/** Active findings raised by the card's rules, highest risk first. */
function FindingsByRules({
  state,
  icon,
  emptyTitle,
  emptyText,
}: {
  state: AsyncState<Finding[]>;
  icon: typeof Activity;
  emptyTitle: string;
  emptyText: string;
}) {
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

/**
 * Software rollup: hosts on end-of-life versions and hosts possibly affected by a known-exploited
 * CVE, summed over products (a host running two flagged products counts twice).
 */
function ExposedSoftware({ state }: { state: AsyncState<SoftwareSummaryResponse> }) {
  return (
    <Loadable state={state} title="Could not load software">
      {(data) => {
        if (data.products.length === 0) {
          return (
            <EmptyState title="No software recorded yet" icon={PackageSearch}>
              Quick scans record HTTP server headers; Standard and Deep scans also identify service
              versions.
            </EmptyState>
          );
        }
        const eol = data.products.reduce((n, p) => n + p.eol, 0);
        const kev = data.products.reduce((n, p) => n + p.knownExploited, 0);
        return (
          <div className="space-y-3">
            <dl className="grid grid-cols-2 gap-3">
              <div>
                <dt className="text-xs text-slate-500">End-of-life installs</dt>
                <dd className="text-2xl font-semibold tabular-nums text-slate-900">{eol}</dd>
              </div>
              <div>
                <dt className="text-xs text-slate-500">Possibly KEV-affected</dt>
                <dd className="text-2xl font-semibold tabular-nums text-slate-900">{kev}</dd>
              </div>
            </dl>
            <p className="text-xs text-slate-500">
              Versions are self-reported; matches mean possibly affected — verify.
            </p>
            <Link to="/software" className="text-xs text-sky-800 hover:underline">
              Open the software inventory
            </Link>
          </div>
        );
      }}
    </Loadable>
  );
}
