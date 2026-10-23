import {
  FINDING_STATUSES,
  REPORT_EXPIRY_DAYS,
  SEVERITIES,
  compareSeverityDesc,
  type ReportSummaryResponse,
} from '@exdomainvault/shared';
import { RefreshCw } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { Link } from 'react-router';
import { CriticalityLabel } from '../../components/domains/DomainBadges.tsx';
import { FindingStatusBadge } from '../../components/findings/FindingStatusBadge.tsx';
import { ExportFindingsButton } from '../../components/reports/ExportFindingsButton.tsx';
import { TrendChart } from '../../components/reports/TrendChart.tsx';
import { Button } from '../../components/ui/Button.tsx';
import { Card } from '../../components/ui/Card.tsx';
import { EmptyState } from '../../components/ui/EmptyState.tsx';
import { LoadError } from '../../components/ui/LoadError.tsx';
import { PageHeader } from '../../components/ui/PageHeader.tsx';
import { PermissionDenied } from '../../components/ui/PermissionDenied.tsx';
import { SeverityBadge } from '../../components/ui/SeverityBadge.tsx';
import { StaleDataNotice } from '../../components/ui/StaleDataNotice.tsx';
import { StatCard } from '../../components/ui/StatCard.tsx';
import { api } from '../../lib/api.ts';
import { formatDate, formatDateTime } from '../../lib/format.ts';
import { useSession } from '../../lib/session.ts';
import { useRefreshableAsync } from '../../lib/use-refreshable-async.ts';

type Summary = ReportSummaryResponse;

const SEVERITY_ORDER = [...SEVERITIES].sort(compareSeverityDesc);
const DAY_MS = 86_400_000;

/** Whole UTC days from `from` to `to` (negative when `to` is in the past). */
function daysBetween(fromIso: string, toIso: string): number {
  const day = (iso: string) => Date.UTC(+iso.slice(0, 4), +iso.slice(5, 7) - 1, +iso.slice(8, 10));
  return Math.round((day(toIso) - day(fromIso)) / DAY_MS);
}

/** "12 days", "Today", "Expired 3 days ago" / "Overdue by 3 days" — never colour alone. */
function DaysLeft({ days, kind = 'expiry' }: { days: number; kind?: 'expiry' | 'review' }) {
  const plural = (n: number) => `${n} day${n === 1 ? '' : 's'}`;
  const past = kind === 'expiry' ? `Expired ${plural(-days)} ago` : `Overdue by ${plural(-days)}`;
  const text = days < 0 ? past : days === 0 ? 'Today' : plural(days);
  const tone =
    days <= 0 ? 'font-medium text-red-800' : days <= 14 ? 'text-amber-800' : 'text-slate-700';
  return <span className={`tabular-nums ${tone}`}>{text}</span>;
}

/**
 * Portfolio report built only from stored findings, observations and inventory
 * (`GET /reports/summary`). Domain-level sections need `domains:read`; asset owners see the
 * findings they can access.
 */
const DESCRIPTION =
  'Coverage, finding trends and upcoming expiries across the portfolio, from stored scan evidence. All dates are UTC.';

export function ReportsPage() {
  const session = useSession();
  if (session.status === 'success' && session.data.permissions.includes('reports:read')) {
    return <Reports canDomains={session.data.permissions.includes('domains:read')} />;
  }
  return (
    <>
      <PageHeader title="Reports" description={DESCRIPTION} />
      {session.status === 'loading' ? (
        <Loading />
      ) : (
        <Card>
          <PermissionDenied title="Reports are not available to your role" />
        </Card>
      )}
    </>
  );
}

function Reports({ canDomains }: { canDomains: boolean }) {
  const [refreshKey, setRefreshKey] = useState(0);
  const { state, stale, refreshing, retry } = useRefreshableAsync(
    (signal) => api.reports.summary({ signal }),
    [],
    refreshKey,
  );

  return (
    <>
      <PageHeader
        title="Reports"
        description={DESCRIPTION}
        actions={
          <>
            <Button
              onClick={() => setRefreshKey((k) => k + 1)}
              disabled={refreshing || state.status === 'loading'}
            >
              <RefreshCw className="size-4" aria-hidden />
              {refreshing ? 'Refreshing…' : 'Refresh'}
            </Button>
            <ExportFindingsButton />
          </>
        }
      />
      {stale && (
        <StaleDataNotice
          loadedAt={stale.loadedAt}
          error={stale.error}
          onRetry={retry}
          retrying={refreshing}
        />
      )}
      {state.status === 'loading' && <Loading />}
      {state.status === 'error' && (
        <Card>
          <LoadError
            error={state.error}
            title="Could not load the report"
            onRetry={retry}
            deniedTitle="Reports are not available to your role"
          />
        </Card>
      )}
      {state.status === 'success' && <ReportBody data={state.data} canDomains={canDomains} />}
    </>
  );
}

function Loading() {
  return (
    <p className="py-8 text-center text-sm text-slate-500" role="status">
      Loading report…
    </p>
  );
}

function ReportBody({ data, canDomains }: { data: Summary; canDomains: boolean }) {
  const { coverage, findings } = data;
  const sevMax = Math.max(1, ...SEVERITY_ORDER.map((s) => findings.bySeverity[s] ?? 0));
  return (
    <div className="space-y-6">
      <p className="text-xs text-slate-500">Generated {formatDateTime(data.generatedAt)}</p>

      {canDomains && (
        <section
          aria-label="Coverage"
          className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6"
        >
          <StatCard label="Domains" value={coverage.domains} hint="In the inventory" />
          <StatCard
            label="Monitored"
            value={coverage.monitoredDomains}
            hint="Passive monitoring on"
          />
          <StatCard
            label="Verified"
            value={coverage.verifiedDomains}
            hint="Eligible for active checks"
          />
          <StatCard label="Approved assets" value={coverage.approvedAssets} hint="In scan scope" />
          <StatCard label="Pending assets" value={coverage.pendingAssets} hint="Awaiting review" />
          <StatCard
            label="Last scan"
            value={coverage.lastScanAt ? formatDate(coverage.lastScanAt) : 'Never'}
            hint={coverage.lastScanAt ? formatDateTime(coverage.lastScanAt) : 'No completed scan'}
          />
        </section>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Open findings by severity">
          <ul className="space-y-2" aria-label="Open findings by severity">
            {SEVERITY_ORDER.map((sev) => {
              const n = findings.bySeverity[sev] ?? 0;
              return (
                <li
                  key={sev}
                  className="grid grid-cols-[6.5rem_1fr_3rem] items-center gap-3 text-sm"
                >
                  <SeverityBadge severity={sev} />
                  <span className="h-2 rounded-sm bg-slate-100" aria-hidden>
                    <span
                      className="block h-2 rounded-sm bg-slate-500"
                      style={{ width: `${(n / sevMax) * 100}%` }}
                    />
                  </span>
                  <Link
                    to={`/findings?severity=${sev}`}
                    className="text-right font-medium tabular-nums text-sky-800 hover:underline"
                    data-testid={`severity-${sev}`}
                  >
                    {n}
                  </Link>
                </li>
              );
            })}
          </ul>
          <p className="mt-3 text-xs text-slate-500">{findings.open} open findings in total.</p>
        </Card>

        <Card title="Findings by status">
          <table className="min-w-full text-sm">
            <thead className="sr-only">
              <tr>
                <th scope="col">Status</th>
                <th scope="col">Findings</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {FINDING_STATUSES.map((s) => (
                <tr key={s}>
                  <td className="py-1.5 pr-4">
                    <FindingStatusBadge status={s} />
                  </td>
                  <td className="py-1.5 text-right">
                    <Link
                      to={`/findings?status=${s}`}
                      className="font-medium tabular-nums text-sky-800 hover:underline"
                      data-testid={`status-${s}`}
                    >
                      {findings.byStatus[s] ?? 0}
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>

        <div className="space-y-4">
          <StatCard
            label="Mean days to resolve"
            value={
              findings.meanDaysToResolve === null ? null : findings.meanDaysToResolve.toFixed(1)
            }
            hint={
              findings.meanDaysToResolve === null
                ? 'No finding was resolved in the last 90 days'
                : 'First seen to resolved, findings resolved in the last 90 days'
            }
          />
          <StatCard
            label="Open findings"
            value={findings.open}
            hint="Every status except resolved"
          />
        </div>
      </div>

      <Card title={`Findings created and resolved, last ${data.trendDays} days`}>
        <TrendChart trend={data.trend} />
      </Card>

      {canDomains ? (
        <div className="grid gap-4 xl:grid-cols-2">
          <Card title="Top domains by risk">
            <TopDomains rows={data.topDomains} />
          </Card>
          <Card title="Open findings by business owner">
            <ByOwner rows={data.byBusinessOwner} />
          </Card>
          <Card title="Expiring registrations">
            <ExpiringRegistrations rows={data.expiringRegistrations} />
          </Card>
          <Card title="Expiring certificates">
            <ExpiringCertificates rows={data.expiringCertificates} />
          </Card>
        </div>
      ) : (
        <Card>
          <PermissionDenied title="Domain-level sections are not available to your role">
            Coverage, top domains, business owners and expiry lists need domain access. The figures
            above cover the findings you can see.
          </PermissionDenied>
        </Card>
      )}

      <Card title="Accepted risks due for review">
        <AcceptedRisksDue rows={data.acceptedRisksDue} generatedAt={data.generatedAt} />
      </Card>
    </div>
  );
}

/** Column headers; a trailing `#` marks a numeric (right-aligned) column. */
function Table({ headers, children }: { headers: string[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-sm">
        <thead>
          <tr className="border-b border-slate-200 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
            {headers.map((h, i) => (
              <th
                key={h}
                scope="col"
                className={`py-2 ${i === headers.length - 1 ? '' : 'pr-4'} ${h.endsWith('#') ? 'text-right' : ''}`}
              >
                {h.replace(/#$/, '')}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">{children}</tbody>
      </table>
    </div>
  );
}

const cell = 'py-2 pr-4';
const num = 'py-2 pr-4 text-right tabular-nums';
const domainLink = (d: { id: string; fqdn: string }) => (
  <Link to={`/domains/${d.id}`} className="font-mono text-sky-800 hover:underline">
    {d.fqdn}
  </Link>
);

function TopDomains({ rows }: { rows: Summary['topDomains'] }) {
  if (rows.length === 0) {
    return <EmptyState title="No open findings on any domain" />;
  }
  return (
    <Table headers={['Domain', 'Criticality', 'Highest', 'Open#', 'Risk total#']}>
      {rows.map((r) => (
        <tr key={r.domain.id}>
          <td className={cell}>{domainLink(r.domain)}</td>
          <td className={cell}>
            <CriticalityLabel criticality={r.criticality} />
          </td>
          <td className={cell}>
            <SeverityBadge severity={r.highestSeverity} />
          </td>
          <td className={num}>
            <Link
              to={`/findings?domainId=${r.domain.id}`}
              className="text-sky-800 hover:underline"
              aria-label={`${r.openFindings} open findings on ${r.domain.fqdn}`}
            >
              {r.openFindings}
            </Link>
          </td>
          <td className="py-2 text-right tabular-nums">{r.riskTotal}</td>
        </tr>
      ))}
    </Table>
  );
}

function ByOwner({ rows }: { rows: Summary['byBusinessOwner'] }) {
  if (rows.length === 0) {
    return <EmptyState title="No domains yet" />;
  }
  return (
    <Table headers={['Business owner', 'Domains#', 'Open findings#', 'High or critical#']}>
      {rows.map((r) => (
        <tr key={r.businessOwner ?? '\u0000none'}>
          <td className={cell}>
            {r.businessOwner ?? <span className="italic text-slate-500">No business owner</span>}
          </td>
          <td className={num}>{r.domains}</td>
          <td className={num}>{r.openFindings}</td>
          <td className="py-2 text-right tabular-nums">{r.highOrCritical}</td>
        </tr>
      ))}
    </Table>
  );
}

function ExpiringRegistrations({ rows }: { rows: Summary['expiringRegistrations'] }) {
  if (rows.length === 0) {
    return (
      <EmptyState title="No registrations expiring soon">
        No observed registration expires within {REPORT_EXPIRY_DAYS.registration} days.
      </EmptyState>
    );
  }
  return (
    <Table headers={['Domain', 'Expires', 'Days left#']}>
      {rows.map((r) => (
        <tr key={r.domain.id}>
          <td className={cell}>{domainLink(r.domain)}</td>
          <td className={`${cell} whitespace-nowrap`}>{formatDate(r.expiresAt)}</td>
          <td className="py-2 text-right">
            <DaysLeft days={r.daysLeft} />
          </td>
        </tr>
      ))}
    </Table>
  );
}

function ExpiringCertificates({ rows }: { rows: Summary['expiringCertificates'] }) {
  if (rows.length === 0) {
    return (
      <EmptyState title="No certificates expiring soon">
        No certificate seen by the latest successful TLS checks expires within{' '}
        {REPORT_EXPIRY_DAYS.certificate} days.
      </EmptyState>
    );
  }
  return (
    <Table headers={['Hostname', 'Issuer', 'Expires', 'Days left#']}>
      {rows.map((r) => (
        <tr key={`${r.domain.id}:${r.hostname}`}>
          <td className={cell}>
            <Link to={`/domains/${r.domain.id}`} className="font-mono text-sky-800 hover:underline">
              {r.hostname}
            </Link>
          </td>
          <td className={`${cell} text-slate-600`}>{r.issuer ?? '—'}</td>
          <td className={`${cell} whitespace-nowrap`}>{formatDate(r.notAfter)}</td>
          <td className="py-2 text-right">
            <DaysLeft days={r.daysLeft} />
          </td>
        </tr>
      ))}
    </Table>
  );
}

function AcceptedRisksDue({
  rows,
  generatedAt,
}: {
  rows: Summary['acceptedRisksDue'];
  generatedAt: string;
}) {
  if (rows.length === 0) {
    return (
      <EmptyState title="No accepted risks due for review">
        Accepted risks whose review date falls within {REPORT_EXPIRY_DAYS.acceptedRisk} days appear
        here.
      </EmptyState>
    );
  }
  return (
    <Table headers={['Finding', 'Domain', 'Review by', 'Days left#']}>
      {rows.map((r) => (
        <tr key={r.findingId}>
          <td className={cell}>
            <Link to={`/findings/${r.findingId}`} className="text-sky-800 hover:underline">
              {r.title}
            </Link>
          </td>
          <td className={cell}>{domainLink(r.domain)}</td>
          <td className={`${cell} whitespace-nowrap`}>{formatDate(r.reviewAt)}</td>
          <td className="py-2 text-right">
            <DaysLeft days={daysBetween(generatedAt, r.reviewAt)} kind="review" />
          </td>
        </tr>
      ))}
    </Table>
  );
}
