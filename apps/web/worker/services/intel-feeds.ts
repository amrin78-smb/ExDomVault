import { schema, type Database } from '@exdomainvault/database';
import {
  INTEL_FEEDS,
  SOFTWARE_PRODUCTS,
  type IntelFeed,
  type IntelFeedsResponse,
  type VersionRange,
} from '@exdomainvault/shared';
import { and, asc, count, eq, inArray, isNull, lt, max, notInArray, or, sql } from 'drizzle-orm';
import { z } from 'zod';
import { errorClassOf, fetchFeed, FeedError, type FetchLike } from '../lib/feed-fetch.ts';
import type { Logger } from '../lib/logger.ts';

const { intelFeeds, softwareEolCycles, vulnerabilityAdvisories } = schema;

/**
 * Public vulnerability intelligence (Milestone 11): endoflife.date release cycles, the CISA Known
 * Exploited Vulnerabilities catalogue and NVD affected version ranges for the KEV CVEs that concern
 * catalogue products. Run from the 5-minute Cron (each feed is its own failure-isolated maintenance
 * step) and on demand by an administrator (`POST /intel/feeds/sync`, endoflife + KEV only).
 *
 * Every response is untrusted input: fetched through `fetchFeed` (fixed HTTPS hosts, same-host
 * redirects only, timeout, size cap), validated with zod, and written set-based. Failures are
 * recorded as a short error class in `intel_feeds.last_error`, never the response body.
 */

export const ENDOFLIFE_BASE = 'https://endoflife.date/api/v1/products/';
export const KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
export const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

const DAY_MS = 24 * 3600_000;
/** endoflife.date and KEV are synced at most once a day… */
const DAILY_INTERVAL_MS = DAY_MS - 10 * 60_000;
/** …and after a failed attempt retried at most once an hour. */
const RETRY_GAP_MS = 3600_000;
/** Manual syncs: at most one per minute (also stops concurrent runs). */
const MANUAL_GAP_MS = 60_000;

const ENDOFLIFE_LIMITS = { timeoutMs: 10_000, maxBytes: 2 * 1024 * 1024 };
const KEV_LIMITS = { timeoutMs: 30_000, maxBytes: 16 * 1024 * 1024 };
const NVD_LIMITS = { timeoutMs: 15_000, maxBytes: 4 * 1024 * 1024 };

/** NVD public rate limits: 5 requests / 30 s without an API key, 50 / 30 s with one. */
export const NVD_WINDOW_MS = 30_000;
export const NVD_RATE_NO_KEY = 5;
export const NVD_RATE_WITH_KEY = 50;
/** CVEs looked up per cron run. */
export const NVD_BATCH_NO_KEY = 5;
export const NVD_BATCH_WITH_KEY = 20;
/** A lookup that failed is retried after this long (the row stays pending meanwhile). */
export const NVD_RETRY_BACKOFF_MS = 6 * 3600_000;

const KEV_CHUNK = 500;
const MAX_RANGES = 200;

export interface IntelDeps {
  fetch: FetchLike;
  /** `ExDomainVault/<version> (+https://exdomainvault.amrin78.workers.dev)`. */
  userAgent: string;
  /** Optional NVD API key (Worker secret `NVD_API_KEY`), sent as the `apiKey` header. */
  nvdApiKey?: string | null;
  /** Injectable for tests (rate limiter). */
  sleep?: (ms: number) => Promise<void>;
  clock?: () => number;
  /** Override the NVD batch size (tests). */
  nvdBatch?: number;
  logger?: Logger;
}

export const userAgentFor = (version: string) =>
  `ExDomainVault/${version} (+https://exdomainvault.amrin78.workers.dev)`;

type FeedRow = typeof intelFeeds.$inferSelect;

// --- Feed state ---------------------------------------------------------------------------------

async function ensureFeedRows(db: Database): Promise<void> {
  await db
    .insert(intelFeeds)
    .values(INTEL_FEEDS.map((feed) => ({ feed })))
    .onConflictDoNothing();
}

/**
 * Atomically claims a feed run: sets `last_attempt_at` only when no attempt happened in the last
 * `gapMs` and (unless `force`) the last success is older than `intervalMs`. Concurrent cron runs
 * and repeated manual requests therefore never fetch the same feed twice.
 */
async function claimFeed(
  db: Database,
  feed: IntelFeed,
  now: Date,
  opts: { gapMs: number; intervalMs?: number },
): Promise<FeedRow | null> {
  await ensureFeedRows(db);
  const gapCutoff = new Date(now.getTime() - opts.gapMs);
  const conditions = [
    eq(intelFeeds.feed, feed),
    or(isNull(intelFeeds.lastAttemptAt), lt(intelFeeds.lastAttemptAt, gapCutoff)),
  ];
  if (opts.intervalMs !== undefined) {
    const dueCutoff = new Date(now.getTime() - opts.intervalMs);
    conditions.push(or(isNull(intelFeeds.lastSuccessAt), lt(intelFeeds.lastSuccessAt, dueCutoff)));
  }
  const [row] = await db
    .update(intelFeeds)
    .set({ lastAttemptAt: now, updatedAt: now })
    .where(and(...conditions))
    .returning();
  return row ?? null;
}

async function recordSuccess(
  db: Database,
  feed: IntelFeed,
  now: Date,
  values: {
    items: number;
    sourceVersion?: string | null;
    etag?: string | null;
    lastModified?: string | null;
    lastError?: string | null;
  },
): Promise<void> {
  await db
    .update(intelFeeds)
    .set({ ...values, lastError: values.lastError ?? null, lastSuccessAt: now, updatedAt: now })
    .where(eq(intelFeeds.feed, feed));
}

async function recordFailure(
  db: Database,
  feed: IntelFeed,
  now: Date,
  errorClass: string,
): Promise<void> {
  await db
    .update(intelFeeds)
    .set({ lastError: errorClass.slice(0, 64), updatedAt: now })
    .where(eq(intelFeeds.feed, feed));
}

export type SyncOutcome = 'ok' | 'not_modified' | 'skipped' | `error:${string}`;

async function guarded(
  db: Database,
  feed: IntelFeed,
  now: Date,
  deps: IntelDeps,
  run: () => Promise<SyncOutcome>,
): Promise<SyncOutcome> {
  try {
    return await run();
  } catch (err) {
    const errorClass = errorClassOf(err);
    deps.logger?.warn('intel_feed_failed', {
      feed,
      errorClass,
      ...(errorClass === 'internal' && err instanceof Error ? { error: err.message } : {}),
    });
    await recordFailure(db, feed, now, errorClass);
    return `error:${errorClass}`;
  }
}

// --- endoflife.date -----------------------------------------------------------------------------

const shortText = (n: number) => z.string().min(1).max(n);

/** endoflife.date API v1 `GET /products/{product}` (only the fields used). */
export const endOfLifeResponseSchema = z.object({
  result: z.object({
    releases: z
      .array(
        z.object({
          name: shortText(64),
          releaseDate: z.iso.date().nullish(),
          isEol: z.boolean(),
          eolFrom: z.iso.date().nullish(),
          latest: z.object({ name: shortText(64) }).nullish(),
        }),
      )
      .max(1000),
  }),
});

/**
 * Fetches the release cycles of every catalogue product with an endoflife.date slug and upserts
 * them. One product failing does not stop the others (recorded as `partial_<class>`); the feed
 * fails only if every product failed. No conditional requests: validators are per URL and the
 * feed keeps one row (responses are small and fetched once a day).
 */
export async function syncEndOfLife(
  db: Database,
  now: Date,
  deps: IntelDeps,
  opts: { force?: boolean } = {},
): Promise<SyncOutcome> {
  const claimed = await claimFeed(
    db,
    'endoflife',
    now,
    opts.force ? { gapMs: MANUAL_GAP_MS } : { gapMs: RETRY_GAP_MS, intervalMs: DAILY_INTERVAL_MS },
  );
  if (!claimed) return 'skipped';
  return guarded(db, 'endoflife', now, deps, async () => {
    const products = SOFTWARE_PRODUCTS.flatMap((p) =>
      p.eolSlug ? [{ ...p, slug: p.eolSlug }] : [],
    );
    const rows: (typeof softwareEolCycles.$inferInsert)[] = [];
    let firstError: string | null = null;
    let succeeded = 0;
    for (const p of products) {
      try {
        const res = await fetchFeed(`${ENDOFLIFE_BASE}${encodeURIComponent(p.slug)}`, {
          fetch: deps.fetch,
          userAgent: deps.userAgent,
          ...ENDOFLIFE_LIMITS,
        });
        if (res.status === 'not_found') throw new FeedError('not_found');
        if (res.status !== 'ok') throw new FeedError('unexpected_not_modified');
        const parsed = endOfLifeResponseSchema.safeParse(res.body);
        if (!parsed.success) throw new FeedError('invalid_schema');
        const seen = new Set<string>();
        for (const r of parsed.data.result.releases) {
          if (seen.has(r.name)) continue;
          seen.add(r.name);
          rows.push({
            product: p.key,
            cycle: r.name,
            releaseDate: r.releaseDate ?? null,
            eolDate: r.eolFrom ?? null,
            // Without a date the feed's boolean is all there is.
            eolBoolean: r.eolFrom ? null : r.isEol,
            latest: r.latest?.name ?? null,
            fetchedAt: now,
          });
        }
        succeeded++;
      } catch (err) {
        const errorClass = errorClassOf(err);
        firstError ??= errorClass;
        deps.logger?.warn('intel_endoflife_product_failed', { product: p.key, errorClass });
      }
    }
    if (succeeded === 0) throw new FeedError(firstError ?? 'no_products');
    for (let i = 0; i < rows.length; i += KEV_CHUNK) {
      await db
        .insert(softwareEolCycles)
        .values(rows.slice(i, i + KEV_CHUNK))
        .onConflictDoUpdate({
          target: [softwareEolCycles.product, softwareEolCycles.cycle],
          set: {
            releaseDate: sql`excluded.release_date`,
            eolDate: sql`excluded.eol_date`,
            eolBoolean: sql`excluded.eol_boolean`,
            latest: sql`excluded.latest`,
            fetchedAt: sql`excluded.fetched_at`,
          },
        });
    }
    const [{ n } = { n: 0 }] = await db.select({ n: count() }).from(softwareEolCycles);
    await recordSuccess(db, 'endoflife', now, {
      items: n,
      lastError: firstError ? `partial_${firstError}` : null,
    });
    return 'ok';
  });
}

// --- CISA KEV -----------------------------------------------------------------------------------

const kevEnvelopeSchema = z.object({
  catalogVersion: shortText(64),
  vulnerabilities: z.array(z.unknown()).max(100_000),
});

export const kevEntrySchema = z.object({
  cveID: z.string().regex(/^CVE-\d{4}-\d{4,}$/),
  vendorProject: z.string().max(300),
  product: z.string().max(300),
  vulnerabilityName: z.string().max(1000),
  dateAdded: z.iso.date(),
  shortDescription: z.string().max(10_000),
  knownRansomwareCampaignUse: z.string().max(64).optional(),
});
export type KevEntry = z.infer<typeof kevEntrySchema>;

const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Alias matchers per catalogue product. An alias matches only as a whole word sequence in
 * `vendorProject + ' ' + product` (lowercase): `php` matches "PHP FastCGI Process Manager" but not
 * "phpMyAdmin"; `iis` matches "Microsoft Internet Information Services (IIS)" but not "Tiiscan".
 * This is a pre-selection only: remaining false positives (an unrelated product that happens to
 * contain an alias as a word) are dropped by the NVD step, which keeps only CPEs of the catalogue
 * product (`no_product_match`, empty ranges, never matched to a host).
 */
const KEV_MATCHERS = SOFTWARE_PRODUCTS.map((p) => ({
  key: p.key,
  patterns: p.kevAliases.map((a) => new RegExp(`(^|[^a-z0-9])${escapeRegExp(a)}($|[^a-z0-9])`)),
}));

export function kevProductsFor(vendorProject: string, product: string): string[] {
  const haystack = `${vendorProject} ${product}`.toLowerCase();
  return KEV_MATCHERS.filter((m) => m.patterns.some((re) => re.test(haystack))).map((m) => m.key);
}

/**
 * Downloads the KEV catalogue (conditional request) and upserts an advisory row per (CVE,
 * catalogue product) whose vendor/product pre-matches. New rows wait for NVD (`nvd_fetched_at`
 * null, empty ranges). CVEs that left the catalogue keep their row with `kev = false`. Malformed
 * entries are skipped (counted in the log); a malformed envelope fails the sync.
 */
export async function syncKev(
  db: Database,
  now: Date,
  deps: IntelDeps,
  opts: { force?: boolean } = {},
): Promise<SyncOutcome> {
  const claimed = await claimFeed(
    db,
    'cisa_kev',
    now,
    opts.force ? { gapMs: MANUAL_GAP_MS } : { gapMs: RETRY_GAP_MS, intervalMs: DAILY_INTERVAL_MS },
  );
  if (!claimed) return 'skipped';
  return guarded(db, 'cisa_kev', now, deps, async () => {
    const res = await fetchFeed(KEV_URL, {
      fetch: deps.fetch,
      userAgent: deps.userAgent,
      etag: claimed.etag,
      lastModified: claimed.lastModified,
      ...KEV_LIMITS,
    });
    if (res.status === 'not_found') throw new FeedError('not_found');
    if (res.status === 'not_modified') {
      await recordSuccess(db, 'cisa_kev', now, { items: claimed.items });
      return 'not_modified';
    }
    const envelope = kevEnvelopeSchema.safeParse(res.body);
    if (!envelope.success) throw new FeedError('invalid_schema');

    let invalid = 0;
    const byKey = new Map<string, typeof vulnerabilityAdvisories.$inferInsert>();
    for (const raw of envelope.data.vulnerabilities) {
      const parsed = kevEntrySchema.safeParse(raw);
      if (!parsed.success) {
        invalid++;
        continue;
      }
      const e = parsed.data;
      for (const product of kevProductsFor(e.vendorProject, e.product)) {
        byKey.set(`${e.cveID}|${product}`, {
          cveId: e.cveID,
          product,
          kev: true,
          kevDateAdded: e.dateAdded,
          ransomware: e.knownRansomwareCampaignUse === 'Known',
          title: e.vulnerabilityName.slice(0, 500) || e.cveID,
          description: e.shortDescription.slice(0, 2000),
          createdAt: now,
          updatedAt: now,
        });
      }
    }
    if (invalid > 0) deps.logger?.warn('intel_kev_entries_skipped', { invalid });

    const rows = [...byKey.values()];
    await db.transaction(async (tx) => {
      for (let i = 0; i < rows.length; i += KEV_CHUNK) {
        await tx
          .insert(vulnerabilityAdvisories)
          .values(rows.slice(i, i + KEV_CHUNK))
          .onConflictDoUpdate({
            target: [vulnerabilityAdvisories.cveId, vulnerabilityAdvisories.product],
            set: {
              kev: true,
              kevDateAdded: sql`excluded.kev_date_added`,
              ransomware: sql`excluded.ransomware`,
              title: sql`excluded.title`,
              description: sql`excluded.description`,
              updatedAt: now,
            },
            // Unchanged rows are not rewritten (`updated_at` also times NVD retry back-off).
            setWhere: sql`(${vulnerabilityAdvisories.kev}, ${vulnerabilityAdvisories.kevDateAdded}, ${vulnerabilityAdvisories.ransomware}, ${vulnerabilityAdvisories.title}, ${vulnerabilityAdvisories.description}) is distinct from (true, excluded.kev_date_added, excluded.ransomware, excluded.title, excluded.description)`,
          });
      }
      const keys = [...byKey.keys()];
      await tx
        .update(vulnerabilityAdvisories)
        .set({ kev: false, updatedAt: now })
        .where(
          and(
            eq(vulnerabilityAdvisories.kev, true),
            keys.length > 0
              ? notInArray(
                  sql`${vulnerabilityAdvisories.cveId} || '|' || ${vulnerabilityAdvisories.product}`,
                  keys,
                )
              : sql`true`,
          ),
        );
    });
    const [{ n } = { n: 0 }] = await db
      .select({ n: count() })
      .from(vulnerabilityAdvisories)
      .where(eq(vulnerabilityAdvisories.kev, true));
    await recordSuccess(db, 'cisa_kev', now, {
      items: n,
      sourceVersion: envelope.data.catalogVersion,
      etag: res.etag,
      lastModified: res.lastModified,
    });
    return 'ok';
  });
}

// --- NVD ----------------------------------------------------------------------------------------

const cvssMetrics = z
  .array(
    z.object({
      type: z.string().max(32).optional(),
      cvssData: z.object({ baseScore: z.number().min(0).max(10) }),
    }),
  )
  .max(50)
  .optional();

const versionText = z.string().max(100).optional();

export const nvdResponseSchema = z.object({
  totalResults: z.number().int().min(0),
  vulnerabilities: z
    .array(
      z.object({
        cve: z.object({
          id: z.string().regex(/^CVE-\d{4}-\d{4,}$/),
          published: z.string().max(40).optional(),
          metrics: z
            .object({
              cvssMetricV31: cvssMetrics,
              cvssMetricV40: cvssMetrics,
              cvssMetricV30: cvssMetrics,
            })
            .optional(),
          configurations: z
            .array(
              z.object({
                nodes: z
                  .array(
                    z.object({
                      negate: z.boolean().optional(),
                      cpeMatch: z
                        .array(
                          z.object({
                            vulnerable: z.boolean(),
                            criteria: z.string().max(1000),
                            versionStartIncluding: versionText,
                            versionStartExcluding: versionText,
                            versionEndIncluding: versionText,
                            versionEndExcluding: versionText,
                          }),
                        )
                        .max(20_000)
                        .optional(),
                    }),
                  )
                  .max(5_000),
              }),
            )
            .max(5_000)
            .optional(),
        }),
      }),
    )
    .max(10),
});
export type NvdCve = z.infer<typeof nvdResponseSchema>['vulnerabilities'][number]['cve'];

/** Splits a CPE 2.3 formatted string on unescaped colons and removes escapes from each part. */
function cpeParts(criteria: string): string[] {
  return criteria.split(/(?<!\\):/).map((p) => p.replace(/\\(.)/g, '$1'));
}

const concrete = (v: string | undefined) => v !== undefined && v !== '*' && v !== '-' && v !== '';

/**
 * Affected ranges of `cve` for one catalogue CPE (`vendor`/`product`): `vulnerable` cpeMatch
 * entries of part `a` for that product (negated nodes are ignored). A concrete version in the
 * criteria (`…:openssh:8.2:p1:…` → `8.2p1`) becomes an exact range; `*` uses the
 * versionStart…/versionEnd… bounds (none → every version). `-` (not applicable) is skipped.
 */
export function extractRanges(
  cve: NvdCve,
  cpe: { vendor: string; product: string },
): VersionRange[] {
  const out = new Map<string, VersionRange>();
  for (const config of cve.configurations ?? []) {
    for (const node of config.nodes) {
      if (node.negate) continue;
      for (const m of node.cpeMatch ?? []) {
        if (!m.vulnerable) continue;
        const parts = cpeParts(m.criteria);
        if (parts[0] !== 'cpe' || parts[1] !== '2.3' || parts[2] !== 'a') continue;
        if (parts[3]?.toLowerCase() !== cpe.vendor || parts[4]?.toLowerCase() !== cpe.product) {
          continue;
        }
        const version = parts[5];
        const update = parts[6];
        let range: VersionRange;
        if (version !== undefined && concrete(version)) {
          const exact = concrete(update) ? `${version}${update}` : version;
          range = { startIncluding: exact, endIncluding: exact };
        } else if (version === '*') {
          range = {};
          if (m.versionStartIncluding) range.startIncluding = m.versionStartIncluding;
          if (m.versionStartExcluding) range.startExcluding = m.versionStartExcluding;
          if (m.versionEndIncluding) range.endIncluding = m.versionEndIncluding;
          if (m.versionEndExcluding) range.endExcluding = m.versionEndExcluding;
        } else {
          continue;
        }
        out.set(JSON.stringify(range), range);
        if (out.size >= MAX_RANGES) return [...out.values()];
      }
    }
  }
  return [...out.values()];
}

/** CVSS base score: v3.1, then v4.0, then v3.0 (the NVD `Primary` metric first in each). */
export function selectCvss(cve: NvdCve): number | null {
  const m = cve.metrics;
  for (const list of [m?.cvssMetricV31, m?.cvssMetricV40, m?.cvssMetricV30]) {
    const primary = list?.find((x) => x.type === 'Primary') ?? list?.[0];
    if (primary) return primary.cvssData.baseScore;
  }
  return null;
}

/** NVD timestamps have no zone (`2021-12-10T10:15:09.143`) and are UTC. */
function nvdTime(v: string | undefined): Date | null {
  if (!v || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$/.test(v))
    return null;
  const d = new Date(/(Z|[+-]\d{2}:\d{2})$/.test(v) ? v : `${v}Z`);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Sliding-window limiter: at most `limit` acquisitions per `windowMs` (sleeps when exhausted). */
export class RateLimiter {
  private stamps: number[] = [];
  private readonly limit: number;
  private readonly windowMs: number;
  private readonly clock: () => number;
  private readonly sleep: (ms: number) => Promise<void>;
  constructor(
    limit: number,
    windowMs: number,
    clock: () => number,
    sleep: (ms: number) => Promise<void>,
  ) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.clock = clock;
    this.sleep = sleep;
  }

  async acquire(): Promise<void> {
    for (;;) {
      const now = this.clock();
      this.stamps = this.stamps.filter((t) => t > now - this.windowMs);
      if (this.stamps.length < this.limit) {
        this.stamps.push(now);
        return;
      }
      await this.sleep((this.stamps[0] ?? now) + this.windowMs - now + 1);
    }
  }
}

const realSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Looks up pending advisories in NVD (oldest first, a small batch per cron run). Pending = never
 * fetched (`nvd_fetched_at` null) and not in back-off: a failed lookup records `nvd_status =
 * 'error'` and its attempt time (`updated_at`) and is retried after `NVD_RETRY_BACKOFF_MS`.
 * Outcomes: `ok` (ranges for the catalogue CPE), `no_product_match` (CVE exists, no CPE of the
 * product: empty ranges, never matches a host), `not_found`. Rate limiting is respected twice:
 * an in-run sliding window (5 or 50 requests / 30 s) and a feed claim that keeps cron runs at
 * least one window apart. A `rate_limited` answer stops the batch without penalising the CVE.
 */
export async function syncNvd(db: Database, now: Date, deps: IntelDeps): Promise<SyncOutcome> {
  const backoffCutoff = new Date(now.getTime() - NVD_RETRY_BACKOFF_MS);
  const pendingWhere = and(
    isNull(vulnerabilityAdvisories.nvdFetchedAt),
    or(
      isNull(vulnerabilityAdvisories.nvdStatus),
      lt(vulnerabilityAdvisories.updatedAt, backoffCutoff),
    ),
  );
  const hasKey = Boolean(deps.nvdApiKey);
  const batch = deps.nvdBatch ?? (hasKey ? NVD_BATCH_WITH_KEY : NVD_BATCH_NO_KEY);
  const due = await db
    .select({ cveId: vulnerabilityAdvisories.cveId })
    .from(vulnerabilityAdvisories)
    .where(pendingWhere)
    .groupBy(vulnerabilityAdvisories.cveId)
    .orderBy(
      asc(sql`min(${vulnerabilityAdvisories.createdAt})`),
      asc(vulnerabilityAdvisories.cveId),
    )
    .limit(batch);
  if (due.length === 0) return 'skipped';
  const claimed = await claimFeed(db, 'nvd', now, { gapMs: NVD_WINDOW_MS });
  if (!claimed) return 'skipped';

  return guarded(db, 'nvd', now, deps, async () => {
    const limiter = new RateLimiter(
      hasKey ? NVD_RATE_WITH_KEY : NVD_RATE_NO_KEY,
      NVD_WINDOW_MS,
      deps.clock ?? Date.now,
      deps.sleep ?? realSleep,
    );
    const cveIds = due.map((d) => d.cveId);
    const rows = await db
      .select()
      .from(vulnerabilityAdvisories)
      .where(and(inArray(vulnerabilityAdvisories.cveId, cveIds), pendingWhere));
    let fetched = 0;
    let firstError: string | null = null;

    for (const cveId of cveIds) {
      const targets = rows.filter((r) => r.cveId === cveId);
      await limiter.acquire();
      let cve: NvdCve | null;
      try {
        const res = await fetchFeed(`${NVD_URL}?cveId=${encodeURIComponent(cveId)}`, {
          fetch: deps.fetch,
          userAgent: deps.userAgent,
          headers: deps.nvdApiKey ? { apiKey: deps.nvdApiKey } : {},
          ...NVD_LIMITS,
        });
        if (res.status === 'not_modified') throw new FeedError('unexpected_not_modified');
        if (res.status === 'not_found') {
          cve = null;
        } else {
          const parsed = nvdResponseSchema.safeParse(res.body);
          if (!parsed.success) throw new FeedError('invalid_schema');
          cve = parsed.data.vulnerabilities.find((v) => v.cve.id === cveId)?.cve ?? null;
        }
      } catch (err) {
        const errorClass = errorClassOf(err);
        firstError ??= errorClass;
        if (errorClass === 'rate_limited') break; // not the CVE's fault: no back-off recorded
        await db
          .update(vulnerabilityAdvisories)
          .set({ nvdStatus: 'error', updatedAt: now })
          .where(
            and(
              eq(vulnerabilityAdvisories.cveId, cveId),
              isNull(vulnerabilityAdvisories.nvdFetchedAt),
            ),
          );
        continue;
      }
      fetched++;
      for (const row of targets) {
        const cpe = SOFTWARE_PRODUCTS.find((p) => p.key === row.product)?.cpe ?? null;
        const ranges = cve && cpe ? extractRanges(cve, cpe) : [];
        await db
          .update(vulnerabilityAdvisories)
          .set({
            ranges: ranges as Record<string, string>[],
            cvss: cve ? selectCvss(cve) : null,
            publishedAt: cve ? nvdTime(cve.published) : null,
            nvdStatus: !cve ? 'not_found' : ranges.length > 0 ? 'ok' : 'no_product_match',
            nvdFetchedAt: now,
            updatedAt: now,
          })
          .where(eq(vulnerabilityAdvisories.id, row.id));
      }
    }

    const [stats] = await db
      .select({
        ok: sql<number>`count(*) filter (where ${vulnerabilityAdvisories.nvdStatus} = 'ok')::int`,
      })
      .from(vulnerabilityAdvisories);
    if (fetched === 0) throw new FeedError(firstError ?? 'no_results');
    await recordSuccess(db, 'nvd', now, { items: stats?.ok ?? 0, lastError: firstError });
    return 'ok';
  });
}

// --- Status / scheduling --------------------------------------------------------------------

/** GET /intel/feeds. */
export async function feedStatus(db: Database): Promise<IntelFeedsResponse> {
  const rows = await db.select().from(intelFeeds);
  const [pending] = await db
    .select({ n: count() })
    .from(vulnerabilityAdvisories)
    .where(isNull(vulnerabilityAdvisories.nvdFetchedAt));
  const iso = (d: Date | null) => (d ? d.toISOString() : null);
  return {
    feeds: INTEL_FEEDS.map((feed) => {
      const r = rows.find((x) => x.feed === feed);
      return {
        feed,
        lastSuccessAt: iso(r?.lastSuccessAt ?? null),
        lastAttemptAt: iso(r?.lastAttemptAt ?? null),
        lastError: r?.lastError ?? null,
        items: r?.items ?? 0,
        sourceVersion: r?.sourceVersion ?? null,
        pending: feed === 'nvd' ? (pending?.n ?? 0) : 0,
      };
    }),
  };
}

/** Newest successful sync of any feed (SoftwareIntel `asOf`); null if none ever succeeded. */
export async function intelAsOf(db: Database): Promise<Date | null> {
  const [row] = await db.select({ at: max(intelFeeds.lastSuccessAt) }).from(intelFeeds);
  const at = row?.at;
  if (!at) return null;
  return at instanceof Date ? at : new Date(at);
}

/** Maintenance steps, one per feed (each failure-isolated by `runMaintenance`). */
export function intelMaintenanceSteps(
  db: Database,
  now: Date,
  deps: IntelDeps,
): [string, () => Promise<number>][] {
  const n = (o: SyncOutcome) => (o === 'ok' || o === 'not_modified' ? 1 : 0);
  return [
    ['intel_endoflife', async () => n(await syncEndOfLife(db, now, deps))],
    ['intel_cisa_kev', async () => n(await syncKev(db, now, deps))],
    ['intel_nvd', async () => n(await syncNvd(db, now, deps))],
  ];
}
