import { z } from 'zod';
import { paginatedSchema } from './pagination.ts';

/**
 * Asset inventory (design §5.4–5.5, §7, §10 Assets). Assets are hostnames beneath a registered
 * domain. Passive discovery creates `pending` candidates; only an explicit, audited approval puts a
 * hostname into scan scope. Approval never authorises network checks against third-party hosting:
 * those still need an approved network (Milestone 6 tiered policy).
 */

const isoDateTime = z.iso.datetime();

export const ASSET_STATUSES = ['pending', 'approved', 'rejected', 'suspended'] as const;
export const assetStatusSchema = z.enum(ASSET_STATUSES);
export type AssetStatus = z.infer<typeof assetStatusSchema>;

export const ASSET_STATUS_LABELS: Record<AssetStatus, string> = {
  pending: 'Pending review',
  approved: 'Approved',
  rejected: 'Rejected',
  suspended: 'Suspended',
};

export const ASSET_SOURCES = ['manual', 'import', 'certificate_transparency', 'dns'] as const;
export const assetSourceSchema = z.enum(ASSET_SOURCES);

/**
 * Deterministic hosting classification from the asset's latest DNS (CNAME chain suffixes; see
 * `HOSTING_PROVIDER_SUFFIXES`). `null` = no known third-party provider matched (NOT proof the host is
 * self-hosted).
 */
export const hostingHintSchema = z.object({
  provider: z.string(),
  /** `cdn`, `cloud`, `paas`, `saas`, `hosting`. */
  kind: z.enum(['cdn', 'cloud', 'paas', 'saas', 'hosting']),
  /** The DNS name that matched (e.g. `d111.cloudfront.net`). */
  matchedName: z.string(),
});
export type HostingHint = z.infer<typeof hostingHintSchema>;

const userRefSchema = z.object({ id: z.uuid(), email: z.string() });

export const assetSchema = z.object({
  id: z.uuid(),
  domain: z.object({ id: z.uuid(), fqdn: z.string() }),
  hostname: z.string(),
  assetType: z.enum(['apex', 'subdomain']),
  status: assetStatusSchema,
  source: assetSourceSchema,
  firstSeenAt: isoDateTime,
  lastSeenAt: isoDateTime,
  /** Current addresses from the latest successful DNS observations (asset_ips.is_current). */
  currentIps: z.array(z.string()),
  hostingHint: hostingHintSchema.nullable(),
  /** The candidate came only from wildcard certificate names. */
  wildcardOnly: z.boolean(),
  /** Asset owner: users with the asset_owner role see only assets they own and their findings. */
  owner: userRefSchema.nullable(),
  decidedBy: userRefSchema.nullable(),
  decidedAt: isoDateTime.nullable(),
  decisionReason: z.string().nullable(),
  /** Active (non-resolved) findings on this hostname. */
  activeFindings: z.int(),
});
export type Asset = z.infer<typeof assetSchema>;

export const ASSET_SORTS = ['hostname', '-lastSeenAt', '-firstSeenAt'] as const;

export const assetListQuerySchema = z.object({
  page: z.coerce.number().int().min(1).max(10_000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
  status: assetStatusSchema.optional(),
  domainId: z.uuid().optional(),
  source: assetSourceSchema.optional(),
  /** `true` = only assets with a hosting hint; `false` = only without. */
  thirdParty: z.enum(['true', 'false']).optional(),
  q: z.string().trim().max(253).optional(),
  sort: z.enum(ASSET_SORTS).default('hostname'),
});
export type AssetListQuery = z.infer<typeof assetListQuerySchema>;

export const assetListResponseSchema = paginatedSchema(assetSchema);
export type AssetListResponse = z.infer<typeof assetListResponseSchema>;

export const assetIpSchema = z.object({
  ipAddress: z.string(),
  firstSeenAt: isoDateTime,
  lastSeenAt: isoDateTime,
  isCurrent: z.boolean(),
  source: z.string(),
});

export const assetDiscoveryEntrySchema = z.object({
  source: z.string(),
  observedAt: isoDateTime,
  wildcard: z.boolean(),
  scanJobId: z.uuid(),
  evidence: z.record(z.string(), z.unknown()),
});

export const assetDetailResponseSchema = z.object({
  asset: assetSchema,
  ips: z.array(assetIpSchema),
  /** Latest 50 discovery sightings, newest first. */
  discovery: z.array(assetDiscoveryEntrySchema),
});
export type AssetDetailResponse = z.infer<typeof assetDetailResponseSchema>;

const decisionReason = z.string().trim().min(3).max(1000);

/**
 * Approve a candidate (or a suspended asset) into scan scope. Requires `assets:approve`. When the
 * asset has a hosting hint, `acknowledgeThirdPartyHosting: true` is required (400 otherwise): the
 * approver confirms the organisation may have its web endpoints checked as a normal visitor would.
 */
export const assetApproveRequestSchema = z
  .object({
    reason: decisionReason,
    acknowledgeThirdPartyHosting: z.boolean().default(false),
  })
  .strict();

/** Reject a pending candidate, or suspend an approved asset (removes it from scope). */
export const assetDecisionRequestSchema = z.object({ reason: decisionReason }).strict();

export const ASSET_BULK_MAX = 500;
export const ASSET_ACTIONS = ['approve', 'reject', 'suspend'] as const;

export const assetBulkDecisionRequestSchema = z
  .object({
    ids: z.array(z.uuid()).min(1).max(ASSET_BULK_MAX),
    action: z.enum(ASSET_ACTIONS),
    reason: decisionReason,
    acknowledgeThirdPartyHosting: z.boolean().default(false),
  })
  .strict();
export type AssetBulkDecisionRequest = z.infer<typeof assetBulkDecisionRequestSchema>;

export const assetBulkDecisionResponseSchema = z.object({
  updated: z.int(),
  /** `not_found`, `invalid_transition`, `third_party_not_acknowledged`, `no_change`. */
  skipped: z.array(z.object({ id: z.uuid(), code: z.string() })),
});
export type AssetBulkDecisionResponse = z.infer<typeof assetBulkDecisionResponseSchema>;

export const assetResponseSchema = z.object({ asset: assetSchema });

/** Allowed decisions: pending → approved|rejected; approved → suspended; suspended → approved;
 * rejected → approved. The apex asset can be suspended but never rejected. */
export function allowedAssetActions(
  status: AssetStatus,
  assetType: 'apex' | 'subdomain',
): (typeof ASSET_ACTIONS)[number][] {
  switch (status) {
    case 'pending':
      return assetType === 'apex' ? ['approve'] : ['approve', 'reject'];
    case 'approved':
      return ['suspend'];
    case 'suspended':
    case 'rejected':
      return ['approve'];
  }
}

/**
 * `PATCH /assets/:id` (`assets:approve`): set or clear the asset owner. The owner must be an active
 * user (any role; asset_owner is the role it scopes). Audited `asset.owner_changed`.
 */
export const assetOwnerUpdateRequestSchema = z
  .object({ ownerUserId: z.uuid().nullable() })
  .strict();

/** `POST /domains/:id/discovery` response. */
export const discoveryRequestResponseSchema = z.object({
  scanJobId: z.uuid(),
  created: z.boolean(),
});
export type DiscoveryRequestResponse = z.infer<typeof discoveryRequestResponseSchema>;

/**
 * DNS-name suffixes of well-known third-party hosting, CDN, cloud and SaaS platforms, matched on a
 * label boundary against an asset's CNAME chain. Deterministic and versioned with the code; extend
 * as needed. Order matters: the first match wins.
 */
export const HOSTING_PROVIDER_SUFFIXES: readonly {
  suffix: string;
  provider: string;
  kind: HostingHint['kind'];
}[] = [
  { suffix: 'cloudfront.net', provider: 'Amazon CloudFront', kind: 'cdn' },
  { suffix: 'elb.amazonaws.com', provider: 'AWS Elastic Load Balancing', kind: 'cloud' },
  { suffix: 's3-website.amazonaws.com', provider: 'Amazon S3', kind: 'cloud' },
  { suffix: 'amazonaws.com', provider: 'Amazon Web Services', kind: 'cloud' },
  { suffix: 'awsglobalaccelerator.com', provider: 'AWS Global Accelerator', kind: 'cloud' },
  { suffix: 'azurewebsites.net', provider: 'Azure App Service', kind: 'paas' },
  { suffix: 'azureedge.net', provider: 'Azure CDN', kind: 'cdn' },
  { suffix: 'azurefd.net', provider: 'Azure Front Door', kind: 'cdn' },
  { suffix: 'trafficmanager.net', provider: 'Azure Traffic Manager', kind: 'cloud' },
  { suffix: 'cloudapp.azure.com', provider: 'Microsoft Azure', kind: 'cloud' },
  { suffix: 'cloudapp.net', provider: 'Microsoft Azure', kind: 'cloud' },
  { suffix: 'blob.core.windows.net', provider: 'Azure Blob Storage', kind: 'cloud' },
  { suffix: 'outlook.com', provider: 'Microsoft 365', kind: 'saas' },
  { suffix: 'sharepoint.com', provider: 'Microsoft SharePoint', kind: 'saas' },
  { suffix: 'googlehosted.com', provider: 'Google', kind: 'saas' },
  { suffix: 'googleusercontent.com', provider: 'Google Cloud', kind: 'cloud' },
  { suffix: 'appspot.com', provider: 'Google App Engine', kind: 'paas' },
  { suffix: 'run.app', provider: 'Google Cloud Run', kind: 'paas' },
  { suffix: 'akamaiedge.net', provider: 'Akamai', kind: 'cdn' },
  { suffix: 'edgekey.net', provider: 'Akamai', kind: 'cdn' },
  { suffix: 'edgesuite.net', provider: 'Akamai', kind: 'cdn' },
  { suffix: 'akamai.net', provider: 'Akamai', kind: 'cdn' },
  { suffix: 'fastly.net', provider: 'Fastly', kind: 'cdn' },
  { suffix: 'cdn.cloudflare.net', provider: 'Cloudflare', kind: 'cdn' },
  { suffix: 'incapdns.net', provider: 'Imperva', kind: 'cdn' },
  { suffix: 'herokuapp.com', provider: 'Heroku', kind: 'paas' },
  { suffix: 'herokudns.com', provider: 'Heroku', kind: 'paas' },
  { suffix: 'github.io', provider: 'GitHub Pages', kind: 'paas' },
  { suffix: 'netlify.app', provider: 'Netlify', kind: 'paas' },
  { suffix: 'vercel-dns.com', provider: 'Vercel', kind: 'paas' },
  { suffix: 'pages.dev', provider: 'Cloudflare Pages', kind: 'paas' },
  { suffix: 'myshopify.com', provider: 'Shopify', kind: 'saas' },
  { suffix: 'wpengine.com', provider: 'WP Engine', kind: 'hosting' },
  { suffix: 'squarespace.com', provider: 'Squarespace', kind: 'saas' },
  { suffix: 'wixdns.net', provider: 'Wix', kind: 'saas' },
  { suffix: 'zendesk.com', provider: 'Zendesk', kind: 'saas' },
  { suffix: 'hubspot.net', provider: 'HubSpot', kind: 'saas' },
  { suffix: 'salesforce.com', provider: 'Salesforce', kind: 'saas' },
  { suffix: 'force.com', provider: 'Salesforce', kind: 'saas' },
];

/** First provider whose suffix matches any name in the chain on a label boundary, else null. */
export function classifyHosting(names: readonly string[]): HostingHint | null {
  for (const entry of HOSTING_PROVIDER_SUFFIXES) {
    for (const raw of names) {
      const name = raw.toLowerCase().replace(/\.$/, '');
      if (name === entry.suffix || name.endsWith(`.${entry.suffix}`)) {
        return { provider: entry.provider, kind: entry.kind, matchedName: name };
      }
    }
  }
  return null;
}
