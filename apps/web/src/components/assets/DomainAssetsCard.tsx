import {
  ASSET_STATUSES,
  ASSET_STATUS_LABELS,
  type Asset,
  type AssetStatus,
  type DiscoveryRequestResponse,
  type Domain,
} from '@exdomainvault/shared';
import { useState } from 'react';
import { Link } from 'react-router';
import { api } from '../../lib/api.ts';
import { usePermission } from '../../lib/session.ts';
import { useAsync } from '../../lib/use-async.ts';
import { Button } from '../ui/Button.tsx';
import { buttonClass } from '../ui/button-styles.ts';
import { Card } from '../ui/Card.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';

const PAGE_SIZE = 100;
/** Upper bound on pages read for the counts (2 000 hostnames); beyond it counts are partial. */
const MAX_PAGES = 20;

/** Every asset of a domain, read page by page from `GET /domains/:id/assets`. */
async function loadAll(domainId: string, signal: AbortSignal) {
  const items: Asset[] = [];
  let total = 0;
  for (let page = 1; page <= MAX_PAGES; page++) {
    const res = await api.domains.assets(domainId, { page, pageSize: PAGE_SIZE }, { signal });
    items.push(...res.items);
    total = res.total;
    if (res.items.length === 0 || items.length >= total) break;
  }
  return { items, total };
}

/** Hostnames of this domain by review status, and a control to run passive discovery. */
export function DomainAssetsCard({ domain }: { domain: Domain }) {
  const canRead = usePermission('assets:read');
  const canRequest = usePermission('scans:request');
  const canImport = usePermission('domains:write');
  const state = useAsync(
    (signal) =>
      canRead ? loadAll(domain.id, signal) : Promise.resolve({ items: [] as Asset[], total: 0 }),
    [domain.id, canRead],
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [result, setResult] = useState<DiscoveryRequestResponse | null>(null);

  const runDiscovery = async () => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.domains.requestDiscovery(domain.id));
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setBusy(false);
    }
  };

  const counts = new Map<AssetStatus, number>();
  if (state.status === 'success') {
    for (const a of state.data.items) counts.set(a.status, (counts.get(a.status) ?? 0) + 1);
  }

  function assetsSummary(): string | undefined {
    if (!canRead) return 'Not available to your role';
    if (state.status === 'loading') return undefined;
    if (state.status === 'error') return 'Could not load';
    const { total } = state.data;
    const pending = counts.get('pending') ?? 0;
    const partial = state.data.items.length < total;
    return [
      `${total} asset${total === 1 ? '' : 's'}`,
      ...(pending > 0 ? [`${pending}${partial ? '+' : ''} pending`] : []),
    ].join(' · ');
  }

  return (
    <Card title="Assets" collapsible="domain.assets" summary={assetsSummary()}>
      <div className="space-y-4 text-sm">
        {!canRead && (
          <p className="text-fg-subtle">You do not have access to the asset inventory.</p>
        )}
        {state.status === 'error' && (
          <ErrorAlert error={state.error} title="Could not load assets" />
        )}
        {canRead && state.status === 'loading' && (
          <p className="text-fg-subtle" role="status">
            Loading assets…
          </p>
        )}
        {canRead && state.status === 'success' && (
          <>
            <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              {ASSET_STATUSES.map((s) => (
                <div key={s} className="rounded-md border border-line-soft px-3 py-2">
                  <dt className="text-xs text-fg-subtle">{ASSET_STATUS_LABELS[s]}</dt>
                  <dd
                    className="text-lg font-semibold tabular-nums text-fg"
                    data-testid={`asset-count-${s}`}
                  >
                    {counts.get(s) ?? 0}
                  </dd>
                </div>
              ))}
            </dl>
            {state.data.items.length < state.data.total && (
              <p className="text-xs text-fg-subtle">
                Counts cover the first {state.data.items.length} of {state.data.total} hostnames.
              </p>
            )}
            <div className="flex flex-wrap gap-x-4 gap-y-1">
              {(counts.get('pending') ?? 0) > 0 && (
                <Link to={`/assets?domainId=${domain.id}`} className="text-sky-800 hover:underline">
                  Review {counts.get('pending')} pending
                </Link>
              )}
              <Link
                to={`/assets?domainId=${domain.id}&status=all`}
                className="text-sky-800 hover:underline"
              >
                All assets of this domain
              </Link>
            </div>
          </>
        )}

        <div className="space-y-2 border-t border-line-soft pt-3">
          <p className="text-xs text-fg-subtle">
            Discovery looks up names in public Certificate Transparency logs. It never contacts your
            hosts, and new names wait as Pending review: nothing is scanned until approved. Hosts
            covered by a wildcard certificate are not found this way: import them from a DNS zone
            export or a list instead.
          </p>
          {(canRequest || canImport) && (
            <div className="flex flex-wrap gap-2">
              {canRequest && (
                <Button onClick={runDiscovery} disabled={busy}>
                  Run discovery
                </Button>
              )}
              {canImport && (
                <Link
                  to={`/domains/${domain.id}/import-hosts`}
                  className={buttonClass('secondary')}
                >
                  Import hosts
                </Link>
              )}
            </div>
          )}
          <div aria-live="polite">
            {result && (
              <p role="status" className="text-fg-2">
                {result.created
                  ? 'Discovery queued. New hostnames appear here when the job finishes.'
                  : 'Discovery is already queued or running for this domain.'}{' '}
                <Link to={`/scans/${result.scanJobId}`} className="text-sky-800 hover:underline">
                  View the discovery job
                </Link>
              </p>
            )}
          </div>
          {error && <ErrorAlert error={error} title="Discovery was not requested" />}
        </div>
      </div>
    </Card>
  );
}
