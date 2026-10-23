import { allowedAssetActions, type Asset } from '@exdomainvault/shared';
import { ArrowLeft } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { Link, useParams } from 'react-router';
import {
  AssetStatusBadge,
  HostingHintChip,
  WildcardOnlyMarker,
} from '../../components/assets/AssetBadges.tsx';
import {
  AssetDecisionForm,
  type AssetDecisionValues,
} from '../../components/assets/AssetDecisionForm.tsx';
import {
  ASSET_ACTION_DONE,
  ASSET_ACTION_LABELS,
  sourceLabel,
  type AssetAction,
} from '../../components/assets/labels.ts';
import { Button } from '../../components/ui/Button.tsx';
import { Card } from '../../components/ui/Card.tsx';
import { ErrorAlert } from '../../components/ui/ErrorAlert.tsx';
import { api, ApiClientError } from '../../lib/api.ts';
import { formatDateTime } from '../../lib/format.ts';
import { usePermission } from '../../lib/session.ts';
import { useAsync } from '../../lib/use-async.ts';

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-1 text-sm text-slate-800">{children}</dd>
    </div>
  );
}

const findingsLink = (asset: Asset) =>
  `/findings?q=${encodeURIComponent(asset.hostname)}&domainId=${asset.domain.id}`;

export function AssetDetailPage() {
  const { id = '' } = useParams();
  const [reloadKey, setReloadKey] = useState(0);
  const state = useAsync((signal) => api.assets.get(id, { signal }), [id, reloadKey]);
  // The asset returned by a decision, applied without refetching.
  const [override, setOverride] = useState<{ id: string; asset: Asset } | null>(null);

  if (state.status === 'loading') {
    return (
      <p className="py-8 text-center text-sm text-slate-500" role="status">
        Loading asset…
      </p>
    );
  }
  if (state.status === 'error') {
    return (
      <>
        <BackLink />
        <ErrorAlert error={state.error} title="Could not load this asset" />
      </>
    );
  }

  const asset = override?.id === id ? override.asset : state.data.asset;
  const { ips, discovery } = state.data;

  return (
    <>
      <BackLink />
      <div className="mb-6">
        <h1 className="break-all font-mono text-xl font-semibold tracking-tight text-slate-900">
          {asset.hostname}
        </h1>
        <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-slate-600">
          <AssetStatusBadge status={asset.status} />
          {asset.hostingHint && <HostingHintChip hint={asset.hostingHint} />}
          {asset.wildcardOnly && <WildcardOnlyMarker />}
          <span>
            {asset.assetType === 'apex' ? 'Apex of' : 'Subdomain of'}{' '}
            <Link
              to={`/domains/${asset.domain.id}`}
              className="font-mono text-sky-800 hover:underline"
            >
              {asset.domain.fqdn}
            </Link>
          </span>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <DecisionPanel
          key={asset.id}
          asset={asset}
          onDecided={(next) => setOverride({ id, asset: next })}
          onReload={() => {
            setOverride(null);
            setReloadKey((k) => k + 1);
          }}
        />

        <Card title="Overview">
          <dl className="grid gap-4 sm:grid-cols-2">
            <Field label="Discovery source">{sourceLabel(asset.source)}</Field>
            <Field label="Active findings">
              <Link to={findingsLink(asset)} className="text-sky-800 hover:underline">
                {asset.activeFindings === 1
                  ? '1 active finding'
                  : `${asset.activeFindings} active findings`}
              </Link>
            </Field>
            <Field label="First seen">{formatDateTime(asset.firstSeenAt)}</Field>
            <Field label="Last seen">{formatDateTime(asset.lastSeenAt)}</Field>
            <Field label="Hosting">
              {asset.hostingHint ? (
                <>
                  {asset.hostingHint.provider}
                  <span className="block text-xs text-slate-500">
                    Matched <span className="font-mono">{asset.hostingHint.matchedName}</span> in
                    the DNS records. Web checks reach the provider&apos;s addresses as a normal
                    visitor would; port and network checks need an approved network.
                  </span>
                </>
              ) : (
                <span className="text-slate-600">
                  No known provider detected
                  <span className="block text-xs text-slate-500">
                    This does not prove the host is self-hosted.
                  </span>
                </span>
              )}
            </Field>
          </dl>
        </Card>

        <Card title="IP addresses">
          {ips.length === 0 ? (
            <p className="text-sm text-slate-500">
              No addresses recorded yet. Addresses come from successful DNS observations.
            </p>
          ) : (
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
                  <th scope="col" className="py-2 pr-4">
                    Address
                  </th>
                  <th scope="col" className="py-2 pr-4">
                    State
                  </th>
                  <th scope="col" className="py-2 pr-4">
                    First seen
                  </th>
                  <th scope="col" className="py-2">
                    Last seen
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {[...ips]
                  .sort((a, b) => Number(b.isCurrent) - Number(a.isCurrent))
                  .map((ip) => (
                    <tr key={`${ip.ipAddress}:${ip.firstSeenAt}`}>
                      <th scope="row" className="py-2 pr-4 text-left font-mono text-xs font-normal">
                        {ip.ipAddress}
                      </th>
                      <td className="py-2 pr-4">
                        {ip.isCurrent ? (
                          <span className="font-medium text-slate-800">Current</span>
                        ) : (
                          <span className="text-slate-500">Past</span>
                        )}
                      </td>
                      <td className="py-2 pr-4 text-slate-600">{formatDateTime(ip.firstSeenAt)}</td>
                      <td className="py-2 text-slate-600">{formatDateTime(ip.lastSeenAt)}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          )}
        </Card>

        <Card title="Discovery sightings">
          {discovery.length === 0 ? (
            <p className="text-sm text-slate-500">
              No discovery sightings. This hostname was not found by passive discovery.
            </p>
          ) : (
            <>
              <table className="min-w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-200 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
                    <th scope="col" className="py-2 pr-4">
                      Source
                    </th>
                    <th scope="col" className="py-2 pr-4">
                      Observed
                    </th>
                    <th scope="col" className="py-2 pr-4">
                      Wildcard
                    </th>
                    <th scope="col" className="py-2">
                      Scan job
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {discovery.map((d) => (
                    <tr key={`${d.scanJobId}:${d.observedAt}:${d.source}`}>
                      <td className="py-2 pr-4">{sourceLabel(d.source)}</td>
                      <td className="py-2 pr-4 text-slate-600">{formatDateTime(d.observedAt)}</td>
                      <td className="py-2 pr-4">{d.wildcard ? 'Yes' : 'No'}</td>
                      <td className="py-2">
                        <Link
                          to={`/scans/${d.scanJobId}`}
                          className="text-sky-800 hover:underline"
                          aria-label={`Discovery job of ${formatDateTime(d.observedAt)}`}
                        >
                          View job
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="mt-3 text-xs text-slate-500">
                A sighting in a public certificate log proves neither ownership nor that the host is
                live.
              </p>
            </>
          )}
        </Card>
      </div>
    </>
  );
}

/** Review state and, for `assets:approve`, the decisions the current status allows. */
function DecisionPanel({
  asset,
  onDecided,
  onReload,
}: {
  asset: Asset;
  onDecided: (asset: Asset) => void;
  onReload: () => void;
}) {
  const canDecide = usePermission('assets:approve');
  const [pending, setPending] = useState<AssetAction | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const actions = allowedAssetActions(asset.status, asset.assetType);

  const decide = async (action: AssetAction, values: AssetDecisionValues) => {
    setError(null);
    try {
      const { asset: next } =
        action === 'approve'
          ? await api.assets.approve(asset.id, values)
          : action === 'reject'
            ? await api.assets.reject(asset.id, values.reason)
            : await api.assets.suspend(asset.id, values.reason);
      setPending(null);
      onDecided(next);
      setDone(`${asset.hostname} was ${ASSET_ACTION_DONE[action]}.`);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    }
  };

  return (
    <Card title="Review">
      <div className="space-y-4 text-sm">
        <div aria-live="polite">
          {done && (
            <p
              role="status"
              className="rounded-md border border-sky-200 bg-sky-50 px-3 py-2 text-sky-900"
            >
              {done}
            </p>
          )}
        </div>
        {asset.decidedAt ? (
          <dl className="grid gap-4 sm:grid-cols-2">
            <Field label="Decided by">{asset.decidedBy?.email ?? 'System'}</Field>
            <Field label="Decided at">{formatDateTime(asset.decidedAt)}</Field>
            {asset.decisionReason && (
              <div className="sm:col-span-2">
                <Field label="Reason">
                  <span className="whitespace-pre-wrap">{asset.decisionReason}</span>
                </Field>
              </div>
            )}
          </dl>
        ) : (
          <p className="text-slate-600">
            {asset.status === 'pending'
              ? 'Not reviewed yet. This hostname is not scanned until it is approved.'
              : 'No review decision recorded.'}
          </p>
        )}

        {canDecide && !pending && (
          <div className="flex flex-wrap gap-2">
            {actions.map((a) => (
              <Button
                key={a}
                variant={a === 'approve' ? 'primary' : 'secondary'}
                onClick={() => {
                  setPending(a);
                  setError(null);
                  setDone(null);
                }}
              >
                {ASSET_ACTION_LABELS[a]}
              </Button>
            ))}
          </div>
        )}
        {canDecide && asset.assetType === 'apex' && asset.status === 'pending' && !pending && (
          <p className="text-xs text-slate-500">
            The apex hostname of a registered domain can be suspended but never rejected.
          </p>
        )}
        {!canDecide && (
          <p className="text-xs text-slate-500">Only administrators approve or suspend assets.</p>
        )}
        {pending && (
          <AssetDecisionForm
            action={pending}
            title={`${ASSET_ACTION_LABELS[pending]} ${asset.hostname}`}
            confirmLabel={ASSET_ACTION_LABELS[pending]}
            providers={asset.hostingHint ? [asset.hostingHint.provider] : []}
            error={error}
            errorActions={
              error instanceof ApiClientError && error.status === 409 ? (
                <Button onClick={onReload}>Reload the asset</Button>
              ) : undefined
            }
            onSubmit={(values) => decide(pending, values)}
            onCancel={() => setPending(null)}
          />
        )}
      </div>
    </Card>
  );
}

function BackLink() {
  return (
    <Link
      to="/assets"
      className="mb-4 inline-flex items-center gap-1 text-sm text-slate-600 hover:text-slate-900"
    >
      <ArrowLeft className="size-4" aria-hidden />
      Assets
    </Link>
  );
}
