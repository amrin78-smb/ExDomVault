import type { Domain } from '@exdomainvault/shared';
import { Link } from 'react-router';
import { api } from '../../lib/api.ts';
import { usePermission } from '../../lib/session.ts';
import { useAsync } from '../../lib/use-async.ts';
import { Card } from '../ui/Card.tsx';
import { LoadError } from '../ui/LoadError.tsx';
import { SoftwareTable } from './SoftwareTable.tsx';

const PAGE_SIZE = 10;

/** Software the domain's hosts report about themselves, with end-of-life and KEV matches. */
export function DomainSoftwareCard({ domain }: { domain: Domain }) {
  const canRead = usePermission('findings:read');
  return (
    <Card title="Software" className="lg:col-span-2">
      {canRead ? (
        <DomainSoftware domainId={domain.id} />
      ) : (
        <p className="text-sm text-slate-500">Your role cannot view the software inventory.</p>
      )}
    </Card>
  );
}

function DomainSoftware({ domainId }: { domainId: string }) {
  const state = useAsync(
    (signal) => api.software.forDomain(domainId, { pageSize: PAGE_SIZE }, { signal }),
    [domainId],
  );
  if (state.status === 'loading') {
    return (
      <p className="text-sm text-slate-500" role="status">
        Loading software…
      </p>
    );
  }
  if (state.status === 'error') {
    return <LoadError error={state.error} title="Could not load software" />;
  }
  if (state.data.items.length === 0) {
    return (
      <p className="text-sm text-slate-500">
        No software recorded. A Quick scan reads HTTP server headers; Standard and Deep scans also
        identify service versions on open ports.
      </p>
    );
  }
  return (
    <div className="space-y-3">
      <SoftwareTable items={state.data.items} compact />
      <p className="text-xs text-slate-500">
        Versions are self-reported and distributions may backport fixes: matches mean possibly
        affected — verify. A hidden version means unknown, not safe.
      </p>
      <Link
        to={`/software?domainId=${encodeURIComponent(domainId)}`}
        className="text-xs text-sky-800 hover:underline"
      >
        {state.data.total > state.data.items.length
          ? `View all ${state.data.total} software entries`
          : 'Open in the software inventory'}
      </Link>
    </div>
  );
}
