import type { ChangesResponse } from '@exdomainvault/shared';
import { History } from 'lucide-react';
import { Link } from 'react-router';
import { api } from '../../lib/api.ts';
import { usePermission } from '../../lib/session.ts';
import { useAsync, type AsyncState } from '../../lib/use-async.ts';
import { Card } from '../ui/Card.tsx';
import { EmptyState } from '../ui/EmptyState.tsx';
import { LoadError } from '../ui/LoadError.tsx';
import { ChangeTimeline } from './ChangeTimeline.tsx';
import { changesSummary } from './format.ts';

const PAGE_SIZE = 20;

function summaryOf(state: AsyncState<ChangesResponse | null>): string | undefined {
  if (state.status === 'loading') return undefined;
  if (state.status === 'error') return 'Could not load';
  if (!state.data) return 'Not available to your role';
  return changesSummary(state.data);
}

/**
 * "What changed" on one domain or one asset over the last 30 days (collapsible; the newest 20
 * events, with a link to the full timeline). Pass exactly one of `domainId` / `assetId`.
 */
export function ChangesCard({
  domainId,
  assetId,
  className = '',
}: {
  domainId?: string;
  assetId?: string;
  className?: string;
}) {
  const canRead = usePermission('assets:read');
  const filter = assetId ? { assetId } : { domainId };
  const state = useAsync(
    (signal) =>
      canRead ? api.changes({ ...filter, pageSize: PAGE_SIZE }, { signal }) : Promise.resolve(null),
    [domainId, assetId, canRead],
  );
  const fullLink = `/changes?${assetId ? `assetId=${encodeURIComponent(assetId)}` : `domainId=${encodeURIComponent(domainId ?? '')}`}`;
  return (
    <Card
      title="Changes"
      className={className}
      collapsible={assetId ? 'asset.changes' : 'domain.changes'}
      defaultOpen={false}
      summary={summaryOf(state)}
    >
      {!canRead ? (
        <p className="text-sm text-fg-subtle">Your role cannot view the change timeline.</p>
      ) : state.status === 'loading' ? (
        <p className="text-sm text-fg-subtle" role="status">
          Loading changes…
        </p>
      ) : state.status === 'error' ? (
        <LoadError error={state.error} title="Could not load changes" />
      ) : !state.data || state.data.total === 0 ? (
        <EmptyState title="No changes in the last 30 days" icon={History}>
          Changes appear when a successful scan sees something different from the previous
          successful scan: DNS records, addresses, certificates, HTTP responses, ports, software and
          registration.
        </EmptyState>
      ) : (
        <div className="space-y-3">
          <ChangeTimeline items={state.data.items} showDomain={false} />
          <Link to={fullLink} className="text-xs text-sky-800 hover:underline">
            {state.data.total > state.data.items.length
              ? `View all ${state.data.total} changes`
              : 'Open the change timeline'}
          </Link>
        </div>
      )}
    </Card>
  );
}
