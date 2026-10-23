import { sql } from 'drizzle-orm';
import {
  boolean,
  check,
  date,
  index,
  inet,
  integer,
  jsonb,
  pgTable,
  real,
  text,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import { assets } from './assets.ts';
import { createdAt, id, ts, updatedAt } from './common.ts';
import { domains } from './domains.ts';
import { scanJobs } from './scans.ts';

/**
 * Exposed-software inventory and public vulnerability intelligence (Milestone 11).
 *
 * `software_inventory` is maintained by rules evaluation from successful HTTP / port observations:
 * one row per (domain, location, source, product), where location is the hostname (HTTP headers) or
 * ip:port (service identification). `version` is the latest disclosed version (null = recognised but
 * hidden). Rows are evidence the host reported, not proof.
 */
export const softwareInventory = pgTable(
  'software_inventory',
  {
    id: id(),
    domainId: uuid('domain_id')
      .notNull()
      .references(() => domains.id, { onDelete: 'cascade' }),
    assetId: uuid('asset_id').references(() => assets.id, { onDelete: 'set null' }),
    hostname: text('hostname'),
    ipAddress: inet('ip_address'),
    port: integer('port'),
    /** `http_header` or `service_identification`. */
    source: text('source').notNull(),
    /** Catalogue key (`SOFTWARE_PRODUCTS`). */
    product: text('product').notNull(),
    version: text('version'),
    banner: text('banner').notNull(),
    /** Distribution marker found in the banner (fixes may be backported), else null. */
    backportDistribution: text('backport_distribution'),
    /** Stable identity: `${source}|${hostname ?? ''}|${ip ?? ''}|${port ?? ''}|${product}`. */
    locationKey: text('location_key').notNull(),
    firstSeenAt: ts('first_seen_at').notNull(),
    lastSeenAt: ts('last_seen_at').notNull(),
    lastScanJobId: uuid('last_scan_job_id').references(() => scanJobs.id, { onDelete: 'set null' }),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    uniqueIndex('software_inventory_location_key').on(t.domainId, t.locationKey),
    index('software_inventory_product_idx').on(t.product, t.version),
    check(
      'software_inventory_source_valid',
      sql`${t.source} IN ('http_header', 'service_identification')`,
    ),
  ],
);

/** Release cycles per product from endoflife.date. */
export const softwareEolCycles = pgTable(
  'software_eol_cycles',
  {
    id: id(),
    product: text('product').notNull(),
    cycle: text('cycle').notNull(),
    releaseDate: date('release_date'),
    /** Upstream end of life; null with `eolBoolean` when the feed gives true/false instead. */
    eolDate: date('eol_date'),
    eolBoolean: boolean('eol_boolean'),
    latest: text('latest'),
    fetchedAt: ts('fetched_at').notNull(),
  },
  (t) => [uniqueIndex('software_eol_cycles_key').on(t.product, t.cycle)],
);

/**
 * CVEs relevant to catalogue products. Rows exist for CISA KEV entries that pre-match a catalogue
 * product; `ranges` stays empty and `nvd_fetched_at` null until the NVD record has been read.
 * One row per (cve, product): a CVE can affect several products.
 */
export const vulnerabilityAdvisories = pgTable(
  'vulnerability_advisories',
  {
    id: id(),
    cveId: text('cve_id').notNull(),
    product: text('product').notNull(),
    /** NVD-style ranges: [{startIncluding?, startExcluding?, endIncluding?, endExcluding?}]. */
    ranges: jsonb('ranges').$type<Record<string, string>[]>().notNull().default([]),
    cvss: real('cvss'),
    kev: boolean('kev').notNull().default(false),
    kevDateAdded: date('kev_date_added'),
    ransomware: boolean('ransomware').notNull().default(false),
    title: text('title').notNull(),
    description: text('description').notNull().default(''),
    publishedAt: ts('published_at'),
    nvdFetchedAt: ts('nvd_fetched_at'),
    /** NVD lookup outcome: null (not yet), `ok`, `not_found`, `no_product_match`, `error`. */
    nvdStatus: text('nvd_status'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    uniqueIndex('vulnerability_advisories_key').on(t.cveId, t.product),
    index('vulnerability_advisories_pending_idx').on(t.nvdFetchedAt),
    check('vulnerability_advisories_cve_format', sql`${t.cveId} ~ '^CVE-[0-9]{4}-[0-9]{4,}$'`),
  ],
);

/** Sync state per intelligence feed (`endoflife`, `cisa_kev`, `nvd`). */
export const intelFeeds = pgTable('intel_feeds', {
  feed: text('feed').primaryKey(),
  lastSuccessAt: ts('last_success_at'),
  lastAttemptAt: ts('last_attempt_at'),
  lastError: text('last_error'),
  items: integer('items').notNull().default(0),
  sourceVersion: text('source_version'),
  /** Conditional-request validators (ETag / Last-Modified) to avoid refetching unchanged feeds. */
  etag: text('etag'),
  lastModified: text('last_modified'),
  updatedAt: updatedAt(),
});
