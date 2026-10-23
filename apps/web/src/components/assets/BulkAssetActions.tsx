import {
  ASSET_ACTIONS,
  ASSET_BULK_MAX,
  allowedAssetActions,
  type Asset,
  type AssetBulkDecisionResponse,
} from '@exdomainvault/shared';
import { useState } from 'react';
import { api } from '../../lib/api.ts';
import { Button } from '../ui/Button.tsx';
import { AssetDecisionForm, type AssetDecisionValues } from './AssetDecisionForm.tsx';
import { ASSET_ACTION_LABELS, type AssetAction } from './labels.ts';

/**
 * Decisions for the selected assets (requires `assets:approve`). The server checks each asset
 * individually: ones whose status does not allow the decision are skipped and reported.
 */
export function BulkAssetActions({
  assets,
  onDone,
  onClear,
}: {
  assets: Asset[];
  onDone: (result: AssetBulkDecisionResponse, action: AssetAction) => void;
  onClear: () => void;
}) {
  const [pending, setPending] = useState<AssetAction | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const tooMany = assets.length > ASSET_BULK_MAX;
  const n = `${assets.length} asset${assets.length === 1 ? '' : 's'}`;
  // Offer a decision when it applies to at least one selected asset.
  const offered = ASSET_ACTIONS.filter((a) =>
    assets.some((asset) => allowedAssetActions(asset.status, asset.assetType).includes(a)),
  );
  const providers = [
    ...new Set(assets.flatMap((a) => (a.hostingHint ? [a.hostingHint.provider] : []))),
  ];

  const send = async (action: AssetAction, values: AssetDecisionValues) => {
    setError(null);
    try {
      const result = await api.assets.bulkDecide({
        ids: assets.map((a) => a.id),
        action,
        reason: values.reason,
        acknowledgeThirdPartyHosting: values.acknowledgeThirdPartyHosting,
      });
      setPending(null);
      onDone(result, action);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    }
  };

  return (
    <div
      role="group"
      aria-label="Decisions for selected assets"
      className="mb-4 space-y-3 rounded-md border border-slate-200 bg-white px-3 py-2 text-sm shadow-sm"
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-slate-600">{assets.length} selected:</span>
        {offered.map((a) => (
          <Button
            key={a}
            onClick={() => {
              setPending(a);
              setError(null);
            }}
            disabled={tooMany}
            aria-expanded={pending === a}
          >
            {ASSET_ACTION_LABELS[a]}
          </Button>
        ))}
        <Button onClick={onClear}>Clear selection</Button>
      </div>
      {tooMany && (
        <p className="text-amber-900">Select at most {ASSET_BULK_MAX} assets for one decision.</p>
      )}
      {pending && (
        <AssetDecisionForm
          key={pending}
          action={pending}
          title={`${ASSET_ACTION_LABELS[pending]}: ${n}`}
          confirmLabel={`${ASSET_ACTION_LABELS[pending]} ${n}`}
          providers={providers}
          description="Assets whose current status does not allow this decision are skipped. The apex hostname of a domain can never be rejected."
          error={error}
          onSubmit={(values) => send(pending, values)}
          onCancel={() => setPending(null)}
        />
      )}
    </div>
  );
}
