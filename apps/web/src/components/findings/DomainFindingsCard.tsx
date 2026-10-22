import type { Domain } from '@exdomainvault/shared';
import { Link } from 'react-router';
import { api } from '../../lib/api.ts';
import { usePermission } from '../../lib/session.ts';
import { useAsync } from '../../lib/use-async.ts';
import { Card } from '../ui/Card.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';
import { FindingList } from './FindingList.tsx';
import { SeverityCounts } from './SeverityCounts.tsx';

/** Active findings for one domain: counts by severity and the five highest-risk findings. */
export function DomainFindingsCard({ domain }: { domain: Domain }) {
  const canRead = usePermission('findings:read');
  return (
    <Card title="Findings">
      {canRead ? (
        <DomainFindings domainId={domain.id} />
      ) : (
        <p className="text-sm text-slate-500">Your role cannot view findings.</p>
      )}
    </Card>
  );
}

function DomainFindings({ domainId }: { domainId: string }) {
  const summary = useAsync((signal) => api.findings.summary({ domainId }, { signal }), [domainId]);
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
  if (summary.data.total === 0) {
    return (
      <p className="text-sm text-slate-500">
        No active findings. Rules run on each completed scan; results appear within about five
        minutes of a scan finishing.
      </p>
    );
  }
  return (
    <div className="space-y-4">
      <SeverityCounts bySeverity={summary.data.bySeverity} />
      {top.status === 'error' && <ErrorAlert error={top.error} title="Could not load findings" />}
      {top.status === 'success' && (
        <div>
          <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-slate-500">
            Highest risk
          </h3>
          <FindingList items={top.data.items} />
        </div>
      )}
      <Link
        to={`/findings?domainId=${encodeURIComponent(domainId)}`}
        className="text-xs text-sky-800 hover:underline"
      >
        View all {summary.data.total} active findings
      </Link>
    </div>
  );
}
