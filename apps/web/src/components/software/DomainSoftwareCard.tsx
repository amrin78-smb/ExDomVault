import type { Domain, SoftwareListResponse } from '@exdomainvault/shared';
import { Link } from 'react-router';
import { api } from '../../lib/api.ts';
import { usePermission } from '../../lib/session.ts';
import { useAsync, type AsyncState } from '../../lib/use-async.ts';
import { ExportCsvButton } from '../reports/ExportCsvButton.tsx';
import { Card } from '../ui/Card.tsx';
import { LoadError } from '../ui/LoadError.tsx';
import { SoftwareTable } from './SoftwareTable.tsx';

const PAGE_SIZE = 10;

/**
 * "22 items · 3 end-of-life · 1 KEV". Only the first page is loaded, so when there are more items
 * the end-of-life and KEV counts say which part they cover.
 */
function softwareSummary(state: AsyncState<SoftwareListResponse | null>): string | undefined {
  if (state.status === 'loading') return undefined;
  if (state.status === 'error') return 'Could not load';
  if (!state.data) return 'Not available to your role';
  const { items, total } = state.data;
  if (total === 0) return 'None recorded';
  const eol = items.filter((i) => i.eol?.isEol).length;
  const kev = items.filter((i) => i.knownExploited.length > 0).length;
  const parts = [`${total} item${total === 1 ? '' : 's'}`];
  if (eol > 0) parts.push(`${eol} end-of-life`);
  if (kev > 0) parts.push(`${kev} KEV`);
  if ((eol > 0 || kev > 0) && items.length < total) parts.push(`(in the first ${items.length})`);
  return parts.join(' · ');
}

/** Software the domain's hosts report about themselves, with end-of-life and KEV matches. */
export function DomainSoftwareCard({ domain }: { domain: Domain }) {
  const canRead = usePermission('findings:read');
  // Fetched here so the collapsed title bar can summarise it too.
  const state = useAsync(
    (signal) =>
      canRead
        ? api.software.forDomain(domain.id, { pageSize: PAGE_SIZE }, { signal })
        : Promise.resolve(null),
    [domain.id, canRead],
  );
  return (
    <Card
      title="Software"
      className="lg:col-span-2"
      collapsible="domain.software"
      summary={softwareSummary(state)}
      actions={canRead && <ExportCsvButton resource="software" filters={{ domainId: domain.id }} />}
    >
      {canRead ? (
        <DomainSoftware domainId={domain.id} state={state} />
      ) : (
        <p className="text-sm text-fg-subtle">Your role cannot view the software inventory.</p>
      )}
    </Card>
  );
}

function DomainSoftware({
  domainId,
  state,
}: {
  domainId: string;
  state: AsyncState<SoftwareListResponse | null>;
}) {
  if (state.status === 'loading') {
    return (
      <p className="text-sm text-fg-subtle" role="status">
        Loading software…
      </p>
    );
  }
  if (state.status === 'error') {
    return <LoadError error={state.error} title="Could not load software" />;
  }
  if (!state.data || state.data.items.length === 0) {
    return (
      <p className="text-sm text-fg-subtle">
        No software recorded. A Quick scan reads HTTP server headers; Standard and Deep scans also
        identify service versions on open ports.
      </p>
    );
  }
  return (
    <div className="space-y-3">
      <SoftwareTable items={state.data.items} compact />
      <p className="text-xs text-fg-subtle">
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
