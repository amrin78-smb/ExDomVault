import type { DiscoveredNetwork, DiscoveredNetworksResponse } from '@exdomainvault/shared';
import { Network } from 'lucide-react';
import { Link } from 'react-router';
import { api } from '../../lib/api.ts';
import { formatDate } from '../../lib/format.ts';
import { usePermission } from '../../lib/session.ts';
import { useAsync } from '../../lib/use-async.ts';
import { Card } from '../ui/Card.tsx';
import { EmptyState } from '../ui/EmptyState.tsx';
import { ProportionBar } from '../ui/ProportionBar.tsx';

const plural = (n: number, word: string) => `${n.toLocaleString()} ${word}${n === 1 ? '' : 's'}`;

const REGISTRY_LABELS: Record<string, string> = {
  apnic: 'APNIC',
  arin: 'ARIN',
  ripe: 'RIPE NCC',
  lacnic: 'LACNIC',
  afrinic: 'AFRINIC',
};

/** Link into Settings → approved networks with the form pre-filled (nothing is approved here). */
function proposeNetworkHref(n: DiscoveredNetwork): string | null {
  if (!n.proposedCidr) return null;
  const label = `${n.orgName ?? n.networkName ?? 'Organisation network'}`.slice(0, 80);
  const params = new URLSearchParams({ proposeCidr: n.proposedCidr, proposeLabel: label });
  return `/settings?${params.toString()}`;
}

/**
 * Milestone 15 (wider discovery): IP ranges that RDAP registers to the organisation (matched
 * against Settings → Discovery organisation names) and the other networks hosting the assets.
 * Loaded separately from the rest of the page so a failure here never hides the attack surface.
 */
export function DiscoveredNetworksCards() {
  const state = useAsync((signal) => api.inventory.discoveredNetworks({ signal }), []);
  if (state.status === 'loading') {
    return (
      <p role="status" className="text-sm text-fg-subtle">
        Loading network ownership…
      </p>
    );
  }
  if (state.status === 'error') {
    return (
      <p className="text-sm text-fg-subtle">Network ownership (RDAP) is not available right now.</p>
    );
  }
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <OwnedNetworksCard data={state.data} />
      <HostingNetworksCard data={state.data} />
    </div>
  );
}

function OwnedNetworksCard({ data }: { data: DiscoveredNetworksResponse }) {
  const canPropose = usePermission('scan_policies:manage');
  const names = data.orgNames;
  return (
    <Card title="IP ranges registered to your organisation">
      <p className="mb-3 text-xs text-fg-subtle">
        From public registry (RDAP) records of the addresses your assets resolve to, matched against{' '}
        {names.length > 0 ? names.map((n) => `“${n}”`).join(', ') : 'no organisation names'}.
        Registration does not put a range in scan scope.
      </p>
      {data.matched.length === 0 ? (
        <EmptyState title="No ranges registered to your organisation found" icon={Network}>
          Ranges appear after the weekly discovery run looks up your assets’ addresses.
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line" aria-label="Organisation IP ranges">
          {data.matched.map((n) => {
            const href = canPropose ? proposeNetworkHref(n) : null;
            return (
              <li key={n.key} className="space-y-1 py-2 text-sm" aria-label={n.cidrs[0] ?? n.key}>
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <span className="font-mono text-fg">{n.cidrs.join(', ') || n.key}</span>
                  <span className="tabular-nums text-fg-muted">
                    {plural(n.assetCount, 'asset')}
                  </span>
                </div>
                <p className="text-fg-muted">
                  {n.orgName ?? n.networkName ?? 'Unnamed network'}
                  {n.registry && <> · {REGISTRY_LABELS[n.registry] ?? n.registry}</>}
                  {n.country && <> · {n.country}</>}
                  {n.handle && <> · {n.handle}</>}
                </p>
                {n.assets.length > 0 && (
                  <p className="text-xs text-fg-subtle">
                    {n.assets.map((a, i) => (
                      <span key={a.id}>
                        {i > 0 && ', '}
                        <Link to={`/assets/${a.id}`} className="text-sky-800 hover:underline">
                          {a.hostname}
                        </Link>
                      </span>
                    ))}
                    {n.assetCount > n.assets.length &&
                      ` and ${n.assetCount - n.assets.length} more`}
                  </p>
                )}
                <p className="flex flex-wrap items-center justify-between gap-2 text-xs text-fg-subtle">
                  <span>Last seen {formatDate(n.lastSeenAt)}</span>
                  {href && (
                    <Link to={href} className="font-medium text-sky-800 hover:underline">
                      Propose as approved network
                    </Link>
                  )}
                </p>
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}

function HostingNetworksCard({ data }: { data: DiscoveredNetworksResponse }) {
  const max = Math.max(0, ...data.hosting.map((h) => h.assetCount));
  return (
    <Card title="Other hosting networks">
      {data.hosting.length === 0 ? (
        <EmptyState title="No other networks observed" />
      ) : (
        <ul className="space-y-3" aria-label="Other hosting networks">
          {data.hosting.map((h) => (
            <li key={h.orgName}>
              <div className="flex items-center justify-between gap-2 text-sm">
                <span className="truncate text-fg-2">{h.orgName}</span>
                <span
                  className="shrink-0 tabular-nums text-fg"
                  aria-label={`${plural(h.assetCount, 'asset')} in ${plural(h.networks, 'network')}`}
                >
                  {h.assetCount.toLocaleString()}
                </span>
              </div>
              <ProportionBar
                percent={max > 0 ? (h.assetCount / max) * 100 : 0}
                className="mt-1 h-1.5 w-full rounded-full bg-line"
                fillClassName="fill-accent"
              />
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
