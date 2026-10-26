import {
  SEVERITIES,
  SEVERITY_LABELS,
  compareSeverityDesc,
  type Domain,
  type FindingSummaryResponse,
} from '@exdomainvault/shared';
import { Link } from 'react-router';
import { api } from '../../lib/api.ts';
import { usePermission } from '../../lib/session.ts';
import { useAsync, type AsyncState } from '../../lib/use-async.ts';
import { ExportCsvButton } from '../reports/ExportCsvButton.tsx';
import { Card } from '../ui/Card.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';
import { FindingList } from './FindingList.tsx';
import { SeverityCounts } from './SeverityCounts.tsx';

const ORDERED = [...SEVERITIES].sort(compareSeverityDesc);

/** Non-zero severity counts, most severe first, e.g. "2 high · 5 medium · 3 low". */
function findingsSummary(state: AsyncState<FindingSummaryResponse | null>): string | undefined {
  if (state.status === 'loading') return undefined;
  if (state.status === 'error') return 'Could not load';
  if (!state.data) return 'Not available to your role';
  if (state.data.total === 0) return 'No active findings';
  const { bySeverity } = state.data;
  return ORDERED.filter((sev) => (bySeverity[sev] ?? 0) > 0)
    .map((sev) => `${bySeverity[sev]} ${SEVERITY_LABELS[sev].toLowerCase()}`)
    .join(' · ');
}

/** Active findings for one domain: counts by severity and the five highest-risk findings. */
export function DomainFindingsCard({ domain }: { domain: Domain }) {
  const canRead = usePermission('findings:read');
  // Fetched here so the collapsed title bar can show the counts too.
  const summary = useAsync(
    (signal) =>
      canRead ? api.findings.summary({ domainId: domain.id }, { signal }) : Promise.resolve(null),
    [domain.id, canRead],
  );
  return (
    <Card
      title="Findings"
      className="lg:col-span-2"
      collapsible="domain.findings"
      summary={findingsSummary(summary)}
      actions={canRead && <ExportCsvButton resource="findings" filters={{ domainId: domain.id }} />}
    >
      {canRead ? (
        <DomainFindings domainId={domain.id} summary={summary} />
      ) : (
        <p className="text-sm text-slate-500">Your role cannot view findings.</p>
      )}
    </Card>
  );
}

function DomainFindings({
  domainId,
  summary,
}: {
  domainId: string;
  summary: AsyncState<FindingSummaryResponse | null>;
}) {
  const top = useAsync(
    (signal) =>
      api.findings.list(
        { domainId, status: 'active', sort: '-riskScore', pageSize: 5 },
        { signal },
      ),
    [domainId],
  );

  if (summary.status === 'loading' || top.status === 'loading') {
    return (
      <p className="text-sm text-slate-500" role="status">
        Loading findings…
      </p>
    );
  }
  if (summary.status === 'error') {
    return <ErrorAlert error={summary.error} title="Could not load findings" />;
  }
  if (!summary.data || summary.data.total === 0) {
    return (
      <p className="text-sm text-slate-500">
        No active findings. Rules run on each completed scan; results appear within about five
        minutes of a scan finishing.
      </p>
    );
  }
  return (
    <div className="space-y-4">
      {/* Side by side on wide screens: the card spans the page, so stacking only adds length. */}
      <div className="grid gap-4 lg:grid-cols-[14rem_minmax(0,1fr)] lg:gap-6">
        <SeverityCounts bySeverity={summary.data.bySeverity} />
        <div>
          {top.status === 'error' && (
            <ErrorAlert error={top.error} title="Could not load findings" />
          )}
          {top.status === 'success' && (
            <>
              <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-slate-500">
                Highest risk
              </h3>
              <FindingList items={top.data.items} />
            </>
          )}
        </div>
      </div>
      <Link
        to={`/findings?domainId=${encodeURIComponent(domainId)}`}
        className="text-xs text-sky-800 hover:underline"
      >
        View all {summary.data.total} active findings
      </Link>
    </div>
  );
}
