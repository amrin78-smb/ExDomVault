import { z } from 'zod';

/**
 * Milestone 15 — wider discovery: IP networks the domains' current addresses belong to (RDAP), and
 * the organisation names that mark a network as "ours".
 *
 * `GET /networks/discovered` (`assets:read`; asset owners: only networks containing their assets'
 * current addresses). `GET|PUT /settings/discovery` (`settings:manage`, audited
 * `settings.discovery_updated`). Matching is display/discovery only: a matched network is never
 * scanned unless an administrator approves it through the approved-networks flow.
 */

const isoDateTime = z.iso.datetime();

export const DISCOVERY_ORG_NAMES_SETTING_KEY = 'discovery_org_names';
export const MAX_DISCOVERY_ORG_NAMES = 20;

export const discoverySettingsSchema = z.strictObject({
  orgNames: z
    .array(z.string().trim().min(2, 'Use at least 2 characters.').max(100))
    .max(MAX_DISCOVERY_ORG_NAMES, `At most ${MAX_DISCOVERY_ORG_NAMES} names.`)
    .refine(
      (names) => new Set(names.map((n) => n.toLowerCase())).size === names.length,
      'Each name may appear only once.',
    ),
});
export type DiscoverySettings = z.infer<typeof discoverySettingsSchema>;

export const discoverySettingsResponseSchema = z.object({
  orgNames: z.array(z.string()),
  updatedAt: isoDateTime.nullable(),
});
export type DiscoverySettingsResponse = z.infer<typeof discoverySettingsResponseSchema>;

export const RDAP_REGISTRIES = ['apnic', 'arin', 'ripe', 'lacnic', 'afrinic'] as const;

/** Latest successful RDAP view of one network (grouped by registry + handle, else range). */
export const discoveredNetworkSchema = z.object({
  key: z.string(),
  registry: z.string().nullable(),
  handle: z.string().nullable(),
  networkName: z.string().nullable(),
  orgName: z.string().nullable(),
  country: z.string().nullable(),
  cidrs: z.array(z.string()),
  startAddress: z.string().nullable(),
  endAddress: z.string().nullable(),
  /** Matches a configured organisation name (re-evaluated against the current setting). */
  matched: z.boolean(),
  /** Current addresses of visible approved assets inside the network (at most 50). */
  addresses: z.array(z.string()),
  assetCount: z.int(),
  /** A few of those assets (at most 10), for the UI. */
  assets: z.array(z.object({ id: z.uuid(), hostname: z.string() })),
  /**
   * A CIDR the approved-networks form can be pre-filled with (the first registered prefix that is
   * public and no broader than the approval limit), or null when none qualifies.
   */
  proposedCidr: z.string().nullable(),
  firstSeenAt: isoDateTime,
  lastSeenAt: isoDateTime,
});
export type DiscoveredNetwork = z.infer<typeof discoveredNetworkSchema>;

export const hostingOrgSummarySchema = z.object({
  orgName: z.string(),
  networks: z.int(),
  assetCount: z.int(),
});
export type HostingOrgSummary = z.infer<typeof hostingOrgSummarySchema>;

export const discoveredNetworksResponseSchema = z.object({
  orgNames: z.array(z.string()),
  /** Networks registered to the organisation. */
  matched: z.array(discoveredNetworkSchema),
  /** Other networks hosting the assets, grouped by organisation (top 10 by assets). */
  hosting: z.array(hostingOrgSummarySchema),
  /** Total networks observed (matched + other). */
  total: z.int(),
});
export type DiscoveredNetworksResponse = z.infer<typeof discoveredNetworksResponseSchema>;

/** Sent with a claimed discovery job whose profile lists the `network` check. */
export const networkJobContextSchema = z.object({
  orgNames: z.array(z.string()),
  /** Distinct current public addresses of the domain's approved assets (at most 256). */
  addresses: z.array(z.string()),
});
export type NetworkJobContext = z.infer<typeof networkJobContextSchema>;
