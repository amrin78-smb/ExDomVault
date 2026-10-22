import { SEVERITIES, compareSeverityDesc } from '@exdomainvault/shared';
import { Activity, ShieldCheck } from 'lucide-react';
import { Card } from '../components/ui/Card.tsx';
import { EmptyState } from '../components/ui/EmptyState.tsx';
import { PageHeader } from '../components/ui/PageHeader.tsx';
import { SeverityBadge } from '../components/ui/SeverityBadge.tsx';
import { StatCard } from '../components/ui/StatCard.tsx';
import { useDataMode } from '../lib/data-mode.ts';
import { overviewFixture, type OverviewSummary } from '../lib/fixtures/overview.ts';

const dateFmt = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'medium',
  timeStyle: 'short',
  timeZone: 'UTC',
});
const formatDate = (iso: string) => `${dateFmt.format(new Date(iso))} UTC`;

const NO_DATA_HINT = 'No data yet — the database is connected in Milestone 2.';

export function OverviewPage() {
  const { fixtures } = useDataMode();
  // Real data arrives from GET /api/v1/reports/summary in Milestone 10. Until then, render
  // honest empty states unless labelled development fixtures are explicitly enabled.
  const summary: OverviewSummary | null = fixtures ? overviewFixture : null;

  const openTotal = summary
    ? SEVERITIES.reduce((sum, sev) => sum + summary.openFindingsBySeverity[sev], 0)
    : null;

  return (
    <>
      <PageHeader
        title="Overview"
        description="External exposure across monitored domains, open findings and operational health."
      />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Domains monitored" value={summary?.domainsMonitored ?? null} />
        <StatCard label="Verified assets" value={summary?.verifiedAssets ?? null} />
        <StatCard
          label="Pending assets"
          value={summary?.pendingAssets ?? null}
          hint="Awaiting approval"
        />
        <StatCard label="Open findings" value={openTotal} />
      </div>

      <div className="mt-6 grid gap-4 lg:grid-cols-3">
        <Card title="Open findings by severity">
          {summary ? (
            <ul className="space-y-2">
              {[...SEVERITIES].sort(compareSeverityDesc).map((sev) => (
                <li key={sev} className="flex items-center justify-between text-sm">
                  <SeverityBadge severity={sev} />
                  <span className="tabular-nums font-medium text-slate-800">
                    {summary.openFindingsBySeverity[sev]}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState title="No findings recorded">{NO_DATA_HINT}</EmptyState>
          )}
        </Card>

        <Card title="Latest scan">
          {summary?.latestScan ? (
            <dl className="space-y-2 text-sm">
              <Row label="Profile" value={summary.latestScan.profile} />
              <Row label="Status" value={summary.latestScan.status} />
              <Row label="Completed" value={formatDate(summary.latestScan.completedAt)} />
            </dl>
          ) : (
            <EmptyState title="No scans have run" icon={Activity}>
              {NO_DATA_HINT}
            </EmptyState>
          )}
        </Card>

        <Card title="Worker health">
          {summary?.worker ? (
            <dl className="space-y-2 text-sm">
              <Row label="Worker" value={summary.worker.name} />
              <Row label="Status" value={summary.worker.status} />
              <Row label="Last seen" value={formatDate(summary.worker.lastSeenAt)} />
            </dl>
          ) : (
            <EmptyState title="No worker registered" icon={ShieldCheck}>
              The home scanning worker is set up in Milestone 5.
            </EmptyState>
          )}
        </Card>
      </div>

      <div className="mt-6 grid gap-4 lg:grid-cols-2">
        <Card title="Top remediation priorities">
          {summary && summary.topPriorities.length > 0 ? (
            <ul className="divide-y divide-slate-100">
              {summary.topPriorities.map((p) => (
                <li key={p.id} className="flex items-center justify-between gap-3 py-2 text-sm">
                  <div className="min-w-0">
                    <div className="truncate font-medium text-slate-800">{p.title}</div>
                    <div className="truncate font-mono text-xs text-slate-500">{p.asset}</div>
                  </div>
                  <SeverityBadge severity={p.severity} />
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState title="Nothing to prioritise">{NO_DATA_HINT}</EmptyState>
          )}
        </Card>

        <Card title="Certificates approaching expiry">
          {summary && summary.expiringCertificates.length > 0 ? (
            <ul className="divide-y divide-slate-100">
              {summary.expiringCertificates.map((c) => (
                <li key={c.hostname} className="flex justify-between gap-3 py-2 text-sm">
                  <span className="truncate font-mono text-slate-800">{c.hostname}</span>
                  <span className="shrink-0 text-slate-600">{formatDate(c.expiresAt)}</span>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState title="No certificate data">{NO_DATA_HINT}</EmptyState>
          )}
        </Card>

        <Card title="Recently changed DNS records" className="lg:col-span-2">
          {summary && summary.recentDnsChanges.length > 0 ? (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="pb-2 font-medium">Hostname</th>
                  <th className="pb-2 font-medium">Record</th>
                  <th className="pb-2 font-medium">Change</th>
                  <th className="pb-2 font-medium">Observed</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {summary.recentDnsChanges.map((d) => (
                  <tr key={`${d.hostname}-${d.recordType}-${d.observedAt}`}>
                    <td className="py-2 font-mono text-slate-800">{d.hostname}</td>
                    <td className="py-2 text-slate-700">{d.recordType}</td>
                    <td className="py-2 text-slate-700">{d.change}</td>
                    <td className="py-2 text-slate-600">{formatDate(d.observedAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <EmptyState title="No DNS observations">{NO_DATA_HINT}</EmptyState>
          )}
        </Card>
      </div>
    </>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-3">
      <dt className="text-slate-500">{label}</dt>
      <dd className="font-medium text-slate-800">{value}</dd>
    </div>
  );
}
