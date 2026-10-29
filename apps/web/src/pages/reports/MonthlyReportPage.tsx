import {
  GRADES,
  SEVERITIES,
  compareSeverityDesc,
  monthlyPeriodSchema,
  type Grade,
  type MonthlyReport,
} from '@exdomainvault/shared';
import { ArrowLeft, Printer } from 'lucide-react';
import { useEffect, type ReactNode } from 'react';
import { Link, useParams } from 'react-router';
import { DonutChart } from '../../components/charts/DonutChart.tsx';
import { CriticalityLabel } from '../../components/domains/DomainBadges.tsx';
import { periodLabel } from '../../components/reports/period.ts';
import { Button } from '../../components/ui/Button.tsx';
import { Card } from '../../components/ui/Card.tsx';
import { GradeBadge } from '../../components/ui/GradeBadge.tsx';
import { LoadError } from '../../components/ui/LoadError.tsx';
import { PageHeader } from '../../components/ui/PageHeader.tsx';
import { SeverityBadge } from '../../components/ui/SeverityBadge.tsx';
import { api } from '../../lib/api.ts';
import { formatDate, formatDateTime } from '../../lib/format.ts';
import { useAsync } from '../../lib/use-async.ts';

const SEVERITY_ORDER = [...SEVERITIES].sort(compareSeverityDesc);
// Fixed hues for the grade chart (A green … F red); the legend always carries the letter.
const GRADE_COLORS: Record<Grade, string> = {
  A: '#1baf7a',
  B: '#7cb342',
  C: '#eda100',
  D: '#eb6834',
  F: '#e34948',
};

/**
 * Prints in the light theme: the dark theme's tokens would put light text on white paper. The
 * document's theme class is removed for the print and restored afterwards (also for Ctrl+P).
 */
function usePrintInLightTheme() {
  useEffect(() => {
    const html = document.documentElement;
    let wasDark = false;
    const before = () => {
      wasDark = html.classList.contains('dark');
      html.classList.remove('dark');
    };
    const after = () => {
      if (wasDark) html.classList.add('dark');
      wasDark = false;
    };
    window.addEventListener('beforeprint', before);
    window.addEventListener('afterprint', after);
    return () => {
      window.removeEventListener('beforeprint', before);
      window.removeEventListener('afterprint', after);
      after();
    };
  }, []);
}

/** Monthly executive report (`/reports/monthly/:period`), laid out for screen and for print. */
export function MonthlyReportPage() {
  const { period = '' } = useParams();
  const valid = monthlyPeriodSchema.safeParse(period).success;
  const state = useAsync(
    (signal) =>
      valid ? api.reports.monthly.get(period, { signal }) : Promise.reject(new Error('invalid')),
    [period],
  );
  usePrintInLightTheme();

  const title = valid ? `Security report — ${periodLabel(period)}` : 'Security report';
  return (
    <article className="mx-auto max-w-5xl print:max-w-none">
      <div className="mb-4 print:hidden">
        <Link
          to="/reports"
          className="inline-flex items-center gap-1 text-sm text-sky-800 hover:underline"
        >
          <ArrowLeft className="size-4" aria-hidden /> Reports
        </Link>
      </div>
      <PageHeader
        title={title}
        description="External exposure of the organisation's internet-facing domains: evidence from completed scans, findings from deterministic rules. All dates are UTC."
        actions={
          state.status === 'success' ? (
            <span className="print:hidden">
              <Button variant="primary" onClick={() => window.print()}>
                <Printer className="size-4" aria-hidden />
                Print / Save as PDF
              </Button>
            </span>
          ) : undefined
        }
      />
      {!valid && (
        <Card>
          <p className="text-sm text-fg-muted">This is not a valid report month (use YYYY-MM).</p>
        </Card>
      )}
      {valid && state.status === 'loading' && (
        <p role="status" className="py-8 text-center text-sm text-fg-subtle">
          Loading the report…
        </p>
      )}
      {valid && state.status === 'error' && (
        <Card>
          <LoadError
            error={state.error}
            title="Could not load the report"
            deniedTitle="Monthly reports cover the whole organisation and are not available to your role"
          />
        </Card>
      )}
      {state.status === 'success' && <ReportBody report={state.data.report} />}
    </article>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="break-inside-avoid rounded-xl border border-line bg-surface p-5 shadow-card print:rounded-none print:border-0 print:p-0 print:shadow-none">
      <h2 className="mb-3 text-base font-semibold text-fg">{title}</h2>
      {children}
    </section>
  );
}

function Kpi({ label, value, hint }: { label: string; value: ReactNode; hint?: ReactNode }) {
  return (
    <div className="break-inside-avoid rounded-xl border border-line bg-surface p-4 print:rounded-md">
      <div className="text-xs font-medium uppercase tracking-wider text-fg-subtle">{label}</div>
      <div className="mt-1 text-2xl font-semibold tabular-nums text-fg">{value}</div>
      {hint && <div className="mt-1 text-xs text-fg-subtle">{hint}</div>}
    </div>
  );
}

const dash = (
  <span className="text-fg-faint" aria-label="No data">
    —
  </span>
);
const th = 'py-2 pr-4 text-left text-xs font-medium uppercase tracking-wide text-fg-subtle';
const thNum = `${th} text-right`;
const td = 'py-1.5 pr-4';
const tdNum = 'py-1.5 pr-4 text-right tabular-nums';
const domainLink = (d: { id: string; fqdn: string }) => (
  <Link to={`/domains/${d.id}`} className="font-mono text-sky-800 hover:underline print:text-fg">
    {d.fqdn}
  </Link>
);

function change(n: number | null) {
  if (n === null) return 'No previous month to compare';
  if (n === 0) return 'Unchanged from the previous month';
  return `${n > 0 ? '+' : '−'}${Math.abs(n).toFixed(1)} points vs the previous month`;
}

function ReportBody({ report: r }: { report: MonthlyReport }) {
  const partial = new Date(r.generatedAt).getTime() < new Date(r.periodEnd).getTime();
  const f = r.findings;
  const s = r.securityScore;
  return (
    <div className="space-y-6 print:space-y-5">
      <p className="text-xs text-fg-subtle">
        Period {formatDate(r.periodStart)} –{' '}
        {formatDate(new Date(Date.parse(r.periodEnd) - 1).toISOString())}
        {' · '}generated {formatDateTime(r.generatedAt)}
        {partial && (
          <strong className="ml-1 font-medium text-amber-800">
            · generated before the month ended (partial month)
          </strong>
        )}
      </p>

      <section aria-label="Summary" className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Kpi
          label="Average security score"
          value={s.averageScore === null ? dash : s.averageScore.toFixed(1)}
          hint={change(s.change)}
        />
        <Kpi
          label="Open findings at month end"
          value={f.openAtEndTotal}
          hint={`${f.acceptedRiskAtEnd} with accepted risk`}
        />
        <Kpi
          label="Overdue at month end"
          value={<span className={f.overdueAtEnd > 0 ? 'text-red-800' : ''}>{f.overdueAtEnd}</span>}
          hint="Past their remediation due date"
        />
        <Kpi
          label="SLA compliance"
          value={r.sla.compliancePercent === null ? dash : `${r.sla.compliancePercent}%`}
          hint={
            r.sla.resolvedWithSla === 0
              ? 'No finding with a due date resolved this month'
              : `${r.sla.resolvedWithinSla} of ${r.sla.resolvedWithSla} resolved on time`
          }
        />
        <Kpi label="New findings" value={f.openedTotal} hint={`${f.reopened} recurred`} />
        <Kpi label="Resolved" value={f.resolvedTotal} hint="During the month" />
        <Kpi
          label="Mean days to resolve"
          value={r.sla.meanDaysToResolve === null ? dash : r.sla.meanDaysToResolve.toFixed(1)}
          hint="First seen to resolved"
        />
        <Kpi
          label="Domains / assets"
          value={`${r.totals.domains} / ${r.totals.assets}`}
          hint={`${r.totals.monitoredDomains} monitored · ${r.totals.approvedAssets} approved assets · ${r.totals.newAssets} new`}
        />
      </section>

      <Section title="Findings by severity">
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b border-line">
                <th scope="col" className={th}>
                  Severity
                </th>
                <th scope="col" className={thNum}>
                  New this month
                </th>
                <th scope="col" className={thNum}>
                  Resolved this month
                </th>
                <th scope="col" className={thNum}>
                  Open at month end
                </th>
                <th scope="col" className={thNum}>
                  Overdue at month end
                </th>
                <th scope="col" className={`${thNum} pr-0`}>
                  SLA (days)
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line-soft">
              {SEVERITY_ORDER.map((sev) => (
                <tr key={sev}>
                  <td className={td}>
                    <SeverityBadge severity={sev} />
                  </td>
                  <td className={tdNum}>{f.opened[sev]}</td>
                  <td className={tdNum}>{f.resolved[sev]}</td>
                  <td className={tdNum}>{f.openAtEnd[sev]}</td>
                  <td className={tdNum}>{f.overdueAtEndBySeverity[sev]}</td>
                  <td className={`${tdNum} pr-0 text-fg-muted`}>{r.sla.policy[sev] ?? 'None'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      <Section title="Security score">
        {s.scoredDomains === 0 ? (
          <p className="text-sm text-fg-muted">No domain had a security score this month.</p>
        ) : (
          <div className="grid gap-6 lg:grid-cols-[1fr_1fr]">
            <DonutChart
              label="Domains by grade"
              centerValue={s.scoredDomains}
              centerLabel="domains"
              showZero
              slices={GRADES.map((g) => ({
                key: g,
                label: `Grade ${g}`,
                value: s.grades[g],
                color: GRADE_COLORS[g],
              }))}
            />
            <div className="grid gap-4 sm:grid-cols-2">
              <ScoreList title="Strongest" rows={s.best} />
              <ScoreList title="Weakest" rows={s.worst} />
            </div>
          </div>
        )}
        <p className="mt-3 text-xs text-fg-subtle">
          Each domain&apos;s last daily score of the month. Scores start at 100 and lose points for
          open findings by severity (more when overdue, less when the risk is accepted), capped per
          category.
        </p>
      </Section>

      <Section title="Highest-risk open findings">
        {r.topFindings.length === 0 ? (
          <p className="text-sm text-fg-muted">No finding was open at the end of the month.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b border-line">
                  <th scope="col" className={th}>
                    Severity
                  </th>
                  <th scope="col" className={th}>
                    Finding
                  </th>
                  <th scope="col" className={th}>
                    Host
                  </th>
                  <th scope="col" className={thNum}>
                    Risk
                  </th>
                  <th scope="col" className={`${th} pr-0`}>
                    Due
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line-soft">
                {r.topFindings.map((x) => (
                  <tr key={x.id} className="break-inside-avoid">
                    <td className={td}>
                      <SeverityBadge severity={x.severity} />
                    </td>
                    <td className={td}>
                      <Link
                        to={`/findings/${x.id}`}
                        className="text-sky-800 hover:underline print:text-fg"
                      >
                        {x.title}
                      </Link>
                      <div className="font-mono text-xs text-fg-subtle">{x.ruleId}</div>
                    </td>
                    <td className={`${td} font-mono text-xs`}>{x.hostname}</td>
                    <td className={tdNum}>{x.riskScore}</td>
                    <td className="whitespace-nowrap py-1.5">
                      {x.dueAt ? formatDate(x.dueAt) : 'No SLA'}
                      {x.overdue && (
                        <span className="ml-1 font-medium text-red-800">(overdue)</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section title="Domains with the most risk">
        {r.topDomains.length === 0 ? (
          <p className="text-sm text-fg-muted">
            No domain had open findings at the end of the month.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b border-line">
                  <th scope="col" className={th}>
                    Domain
                  </th>
                  <th scope="col" className={th}>
                    Grade
                  </th>
                  <th scope="col" className={th}>
                    Business owner
                  </th>
                  <th scope="col" className={th}>
                    Criticality
                  </th>
                  <th scope="col" className={th}>
                    Highest
                  </th>
                  <th scope="col" className={thNum}>
                    Open
                  </th>
                  <th scope="col" className={`${thNum} pr-0`}>
                    Risk total
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line-soft">
                {r.topDomains.map((d) => (
                  <tr key={d.domain.id} className="break-inside-avoid">
                    <td className={td}>{domainLink(d.domain)}</td>
                    <td className={td}>
                      <GradeBadge grade={d.grade} />
                    </td>
                    <td className={`${td} text-fg-muted`}>{d.businessOwner ?? '—'}</td>
                    <td className={td}>
                      <CriticalityLabel criticality={d.criticality} />
                    </td>
                    <td className={td}>
                      <SeverityBadge severity={d.highestSeverity} />
                    </td>
                    <td className={tdNum}>{d.openFindings}</td>
                    <td className={`${tdNum} pr-0`}>{d.riskTotal}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section title="Exposure watch">
        <dl className="grid gap-4 text-sm sm:grid-cols-3">
          <div>
            <dt className="text-fg-muted">Certificates expiring within 30 days of month end</dt>
            <dd className="mt-1 text-2xl font-semibold tabular-nums text-fg">
              {r.exposure.certificatesExpiring30d}
            </dd>
          </div>
          <div>
            <dt className="text-fg-muted">End-of-life software (open)</dt>
            <dd className="mt-1 text-2xl font-semibold tabular-nums text-fg">
              {r.exposure.endOfLifeSoftware}
            </dd>
          </div>
          <div>
            <dt className="text-fg-muted">Versions with known exploited vulnerabilities (open)</dt>
            <dd className="mt-1 text-2xl font-semibold tabular-nums text-fg">
              {r.exposure.knownExploitedSoftware}
            </dd>
          </div>
        </dl>
      </Section>

      <p className="text-xs text-fg-subtle">
        How to read this report: findings describe configuration or exposure conditions observed by
        scans, not confirmed compromises. Severity comes only from deterministic rules. Status at
        month end is taken from each finding&apos;s history; severity and risk are the current
        values. Due dates follow the remediation SLA policy shown above.
      </p>
    </div>
  );
}

function ScoreList({
  title,
  rows,
}: {
  title: string;
  rows: MonthlyReport['securityScore']['best'];
}) {
  return (
    <div>
      <h3 className="mb-2 text-xs font-medium uppercase tracking-wide text-fg-subtle">{title}</h3>
      <ul className="space-y-1.5 text-sm">
        {rows.map((x) => (
          <li key={x.domain.id} className="flex items-center justify-between gap-2">
            <span className="min-w-0 truncate">{domainLink(x.domain)}</span>
            <span className="flex shrink-0 items-center gap-2 tabular-nums">
              {x.score}
              <GradeBadge grade={x.grade} score={x.score} />
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
