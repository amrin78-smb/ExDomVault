import { z } from 'zod';
import { paginatedSchema } from './pagination.ts';

/**
 * Exposed-software inventory and vulnerability intelligence (Milestone 11). Software is what hosts
 * REPORT about themselves (HTTP `Server`/`X-Powered-By` headers, Nmap service identification); it is
 * evidence to verify, not proof. Intelligence comes from public feeds synchronised by the server:
 * endoflife.date (release cycles), CISA KEV (known exploited CVEs) and NVD (affected version ranges
 * of those CVEs for catalogue products).
 */

const isoDateTime = z.iso.datetime();

export const SOFTWARE_SOURCES = ['http_header', 'service_identification'] as const;
export const softwareSourceSchema = z.enum(SOFTWARE_SOURCES);

/** Distribution markers in a banner (`(Ubuntu)`, `deb`, `el8`…) mean fixes may be backported. */
export const backportHintSchema = z.object({ distribution: z.string() }).nullable();

export const softwareEolSchema = z.object({
  /** Release cycle the version belongs to (e.g. `7.4`). */
  cycle: z.string(),
  /** Upstream end of life; null when the feed has no date. */
  eolDate: z.iso.date().nullable(),
  isEol: z.boolean(),
  /** Latest release in that cycle per the feed. */
  latestInCycle: z.string().nullable(),
});

export const softwareItemSchema = z.object({
  id: z.uuid(),
  domain: z.object({ id: z.uuid(), fqdn: z.string() }),
  hostname: z.string().nullable(),
  ipAddress: z.string().nullable(),
  port: z.int().nullable(),
  source: softwareSourceSchema,
  product: z.string(),
  productLabel: z.string(),
  /** Null when the product was recognised but no version was disclosed. */
  version: z.string().nullable(),
  /** The banner the product was parsed from (truncated). */
  banner: z.string(),
  backportHint: backportHintSchema,
  firstSeenAt: isoDateTime,
  lastSeenAt: isoDateTime,
  eol: softwareEolSchema.nullable(),
  /** Known-exploited CVEs whose affected range includes the version (possible, verify). */
  knownExploited: z.array(
    z.object({ cveId: z.string(), cvss: z.number().nullable(), ransomware: z.boolean() }),
  ),
});
export type SoftwareItem = z.infer<typeof softwareItemSchema>;

export const softwareListQuerySchema = z.object({
  page: z.coerce.number().int().min(1).max(10_000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(50),
  domainId: z.uuid().optional(),
  product: z.string().max(40).optional(),
  /** `eol` = end-of-life versions only; `kev` = possibly affected by a known-exploited CVE. */
  status: z.enum(['eol', 'kev', 'all']).default('all'),
  q: z.string().trim().max(253).optional(),
});
export type SoftwareListQuery = z.infer<typeof softwareListQuerySchema>;

export const softwareListResponseSchema = paginatedSchema(softwareItemSchema);
export type SoftwareListResponse = z.infer<typeof softwareListResponseSchema>;

/** Portfolio rollup: per product, how many hosts and how many end-of-life / possibly KEV-affected. */
export const softwareSummaryResponseSchema = z.object({
  products: z.array(
    z.object({
      product: z.string(),
      productLabel: z.string(),
      hosts: z.int(),
      eol: z.int(),
      knownExploited: z.int(),
      versions: z.array(z.object({ version: z.string().nullable(), hosts: z.int() })),
    }),
  ),
});
export type SoftwareSummaryResponse = z.infer<typeof softwareSummaryResponseSchema>;

// --- Intelligence feeds -----------------------------------------------------------------------

export const INTEL_FEEDS = ['endoflife', 'cisa_kev', 'nvd'] as const;
export const intelFeedSchema = z.enum(INTEL_FEEDS);
export type IntelFeed = z.infer<typeof intelFeedSchema>;

export const intelFeedStatusSchema = z.object({
  feed: intelFeedSchema,
  /** Last time a sync completed successfully. */
  lastSuccessAt: isoDateTime.nullable(),
  lastAttemptAt: isoDateTime.nullable(),
  /** Short error class of the last failed attempt (no response bodies). */
  lastError: z.string().nullable(),
  /** Items held (cycles, KEV entries in scope, advisories). */
  items: z.int(),
  /** Feed's own version/date when it publishes one (KEV `catalogVersion`). */
  sourceVersion: z.string().nullable(),
  /** NVD only: KEV CVEs still waiting for their NVD record. */
  pending: z.int(),
});
export type IntelFeedStatus = z.infer<typeof intelFeedStatusSchema>;

export const intelFeedsResponseSchema = z.object({ feeds: z.array(intelFeedStatusSchema) });
export type IntelFeedsResponse = z.infer<typeof intelFeedsResponseSchema>;

/** One affected range in NVD terms (any bound may be absent). */
export const versionRangeSchema = z.object({
  startIncluding: z.string().optional(),
  startExcluding: z.string().optional(),
  endIncluding: z.string().optional(),
  endExcluding: z.string().optional(),
});
export type VersionRange = z.infer<typeof versionRangeSchema>;

export const vulnerabilityAdvisorySchema = z.object({
  cveId: z.string(),
  product: z.string(),
  ranges: z.array(versionRangeSchema),
  cvss: z.number().nullable(),
  kev: z.boolean(),
  kevDateAdded: z.iso.date().nullable(),
  ransomware: z.boolean(),
  title: z.string(),
  description: z.string(),
  publishedAt: isoDateTime.nullable(),
});
export type VulnerabilityAdvisoryDto = z.infer<typeof vulnerabilityAdvisorySchema>;
