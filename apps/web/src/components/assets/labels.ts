import type { AssetBulkDecisionResponse, HostingHint } from '@exdomainvault/shared';
import { ApiClientError } from '../../lib/api.ts';

export type AssetAction = 'approve' | 'reject' | 'suspend';

/** Where a hostname came from. */
export const ASSET_SOURCE_LABELS: Record<string, string> = {
  manual: 'Added manually',
  import: 'Imported',
  certificate_transparency: 'Certificate logs',
  dns: 'DNS',
};

export const sourceLabel = (source: string) => ASSET_SOURCE_LABELS[source] ?? source;

export const HOSTING_KIND_LABELS: Record<HostingHint['kind'], string> = {
  cdn: 'CDN',
  cloud: 'Cloud',
  paas: 'Platform',
  saas: 'SaaS',
  hosting: 'Hosting',
};

export const ASSET_ACTION_LABELS: Record<AssetAction, string> = {
  approve: 'Approve',
  reject: 'Reject',
  suspend: 'Suspend',
};

/** Past tense for result messages. */
export const ASSET_ACTION_DONE: Record<AssetAction, string> = {
  approve: 'approved',
  reject: 'rejected',
  suspend: 'suspended',
};

/** What each decision does, shown above the reason field. */
export const ASSET_ACTION_HELP: Record<AssetAction, string> = {
  approve:
    'Approval puts the hostname into scan scope: scans of its domain may then include it. It does not change what the domain itself is authorised for.',
  reject: 'Rejection keeps the hostname out of scan scope. It can still be approved later.',
  suspend: 'Suspension removes the hostname from scan scope until it is approved again.',
};

/** Why a bulk decision left an asset unchanged (server codes; unknown codes are shown as-is). */
export const ASSET_SKIP_LABELS: Record<string, string> = {
  not_found: 'not found or not visible to you',
  invalid_transition: 'decision not possible from their current status',
  third_party_not_acknowledged: 'third-party hosting not acknowledged',
  no_change: 'already in that state',
};

/** "Updated 3, skipped 2 (1 already in that state; 1 not found or not visible to you)." */
export function assetBulkResultText(result: AssetBulkDecisionResponse): string {
  const base = `Updated ${result.updated}, skipped ${result.skipped.length}`;
  if (result.skipped.length === 0) return `${base}.`;
  const counts = new Map<string, number>();
  for (const s of result.skipped) counts.set(s.code, (counts.get(s.code) ?? 0) + 1);
  const parts = [...counts].map(([code, n]) => `${n} ${ASSET_SKIP_LABELS[code] ?? code}`);
  return `${base} (${parts.join('; ')}).`;
}

/** The explicit acknowledgement required to approve hostnames served by a third-party provider. */
export function thirdPartyAcknowledgement(providers: readonly string[]): string {
  const names =
    providers.length === 0
      ? 'a third-party provider'
      : providers.length === 1
        ? providers[0]
        : `third-party providers (${providers.join(', ')})`;
  return `I understand that approval lets web checks reach addresses operated by ${names} as a normal visitor would (one TLS handshake and HTTP request per hop), and that port and network checks still need an approved network.`;
}

/** Plain-language explanation of a refused decision (shown above the API message). */
export function decisionErrorTitle(error: Error): string {
  if (error instanceof ApiClientError) {
    if (error.status === 409) return 'The asset changed since this page loaded';
    if (error.status === 403) return 'You do not have permission to make this decision';
    if (error.details?.some((d) => d.path === 'acknowledgeThirdPartyHosting')) {
      return 'Third-party hosting must be acknowledged';
    }
  }
  return 'The decision was not saved';
}
