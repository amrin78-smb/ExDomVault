import { schema, type Database } from '@exdomainvault/database';
import {
  eolStatus,
  matchAdvisories,
  type ObservationSet,
  type SoftwareIntel,
  type SoftwareSighting,
} from '@exdomainvault/rules';
import {
  softwareProduct,
  type CurrentUser,
  type SoftwareItem,
  type SoftwareListQuery,
  type SoftwareListResponse,
  type SoftwareSummaryResponse,
} from '@exdomainvault/shared';
import { canonicalIp } from '@exdomainvault/shared/net';
import {
  and,
  asc,
  count,
  desc,
  eq,
  ilike,
  inArray,
  isNotNull,
  or,
  sql,
  type SQL,
} from 'drizzle-orm';
import { intelAsOf } from './intel-feeds.ts';

const { assets, domains, softwareEolCycles, softwareInventory, vulnerabilityAdvisories } = schema;

/**
 * Exposed-software inventory (Milestone 11): maintained by rules evaluation from the sightings
 * `extractSoftware` finds in a succeeded job's observations, and read by `GET /software`,
 * `GET /software/summary` and `GET /domains/:id/software`. End-of-life and known-exploited status
 * are computed at read time from the stored intelligence with the rules package's pure functions,
 * so the inventory never stores a verdict that could go stale.
 */

type User = Pick<CurrentUser, 'id' | 'role'>;
type InventoryRow = typeof softwareInventory.$inferSelect;

// --- Intelligence loading ------------------------------------------------------------------------

/**
 * Intelligence rows for `products` only: their release cycles and the advisories whose NVD lookup
 * produced ranges (`nvd_status = 'ok'`; empty-range rows cannot match any version). Undefined when
 * no feed has ever synced, so software rules skip rather than report "no intelligence = fine".
 */
export async function loadSoftwareIntel(
  db: Database,
  products: readonly string[],
): Promise<SoftwareIntel | undefined> {
  const asOf = await intelAsOf(db);
  if (!asOf) return undefined;
  const keys = [...new Set(products)];
  if (keys.length === 0) return { asOf: asOf.toISOString(), eolCycles: [], advisories: [] };
  const [cycles, advisories] = await Promise.all([
    db
      .select({
        product: softwareEolCycles.product,
        cycle: softwareEolCycles.cycle,
        eolDate: softwareEolCycles.eolDate,
        eolBoolean: softwareEolCycles.eolBoolean,
        latest: softwareEolCycles.latest,
      })
      .from(softwareEolCycles)
      .where(inArray(softwareEolCycles.product, keys))
      .orderBy(asc(softwareEolCycles.product), asc(softwareEolCycles.cycle)),
    db
      .select({
        cveId: vulnerabilityAdvisories.cveId,
        product: vulnerabilityAdvisories.product,
        ranges: vulnerabilityAdvisories.ranges,
        cvss: vulnerabilityAdvisories.cvss,
        kev: vulnerabilityAdvisories.kev,
        kevDateAdded: vulnerabilityAdvisories.kevDateAdded,
        ransomware: vulnerabilityAdvisories.ransomware,
        title: vulnerabilityAdvisories.title,
      })
      .from(vulnerabilityAdvisories)
      .where(
        and(
          inArray(vulnerabilityAdvisories.product, keys),
          eq(vulnerabilityAdvisories.nvdStatus, 'ok'),
        ),
      )
      .orderBy(asc(vulnerabilityAdvisories.product), asc(vulnerabilityAdvisories.cveId)),
  ]);
  return { asOf: asOf.toISOString(), eolCycles: cycles, advisories };
}

// --- Inventory upsert (rules evaluation) ---------------------------------------------------------

export const locationKeyOf = (s: {
  source: string;
  hostname: string | null;
  ipAddress: string | null;
  port: number | null;
  product: string;
}) => `${s.source}|${s.hostname ?? ''}|${s.ipAddress ?? ''}|${s.port ?? ''}|${s.product}`;

/**
 * Upserts the job's sightings into `software_inventory` (one statement). Existing rows advance
 * `last_seen_at` and take the newest version/banner/backport hint — but only from evidence at
 * least as new as what they hold, so a backlog evaluated late never moves a row back in time.
 * Rows are never deleted: software not seen again simply stops advancing `last_seen_at`.
 *
 * Asset: the asset with the sighting's hostname; for service identification (ip:port, no
 * hostname) the asset whose name resolved to that address in this job, when exactly one did.
 */
export async function upsertSoftwareInventory(
  tx: Database,
  args: {
    domainId: string;
    jobId: string;
    sightings: readonly SoftwareSighting[];
    current: ObservationSet;
    assetOf: ReadonlyMap<string, string>;
    seenAt: Date;
    now: Date;
  },
): Promise<number> {
  if (args.sightings.length === 0) return 0;

  const assetsByIp = new Map<string, Set<string>>();
  for (const o of args.current.dns) {
    if (o.resultStatus !== 'success' || (o.recordType !== 'A' && o.recordType !== 'AAAA')) continue;
    const assetId = args.assetOf.get(o.hostname);
    if (!assetId) continue;
    for (const v of o.values) {
      const ip = canonicalIp(v) ?? v;
      const set = assetsByIp.get(ip) ?? new Set<string>();
      set.add(assetId);
      assetsByIp.set(ip, set);
    }
  }
  const assetFor = (s: SoftwareSighting): string | null => {
    if (s.hostname) return args.assetOf.get(s.hostname) ?? null;
    if (!s.ipAddress) return null;
    const set = assetsByIp.get(canonicalIp(s.ipAddress) ?? s.ipAddress);
    return set && set.size === 1 ? ([...set][0] ?? null) : null;
  };

  // One row per location key (ON CONFLICT cannot touch a row twice in one statement).
  const byKey = new Map<string, SoftwareSighting>();
  for (const s of args.sightings) {
    const key = locationKeyOf(s);
    const prev = byKey.get(key);
    if (!prev || prev.observedAt <= s.observedAt) byKey.set(key, s);
  }
  const values = [...byKey.entries()].map(([locationKey, s]) => ({
    domainId: args.domainId,
    assetId: assetFor(s),
    hostname: s.hostname,
    ipAddress: s.ipAddress,
    port: s.port,
    source: s.source,
    product: s.product,
    version: s.version,
    banner: s.banner.slice(0, 200),
    backportDistribution: s.backportDistribution,
    locationKey,
    firstSeenAt: args.seenAt,
    lastSeenAt: args.seenAt,
    lastScanJobId: args.jobId,
    createdAt: args.now,
    updatedAt: args.now,
  }));
  await tx
    .insert(softwareInventory)
    .values(values)
    .onConflictDoUpdate({
      target: [softwareInventory.domainId, softwareInventory.locationKey],
      set: {
        version: sql`excluded.version`,
        banner: sql`excluded.banner`,
        backportDistribution: sql`excluded.backport_distribution`,
        lastSeenAt: sql`excluded.last_seen_at`,
        lastScanJobId: sql`excluded.last_scan_job_id`,
        assetId: sql`coalesce(excluded.asset_id, ${softwareInventory.assetId})`,
        updatedAt: sql`excluded.updated_at`,
      },
      setWhere: sql`excluded.last_seen_at >= ${softwareInventory.lastSeenAt}`,
    });
  return values.length;
}

// --- Read API -----------------------------------------------------------------------------------

/** Rows whose status (eol / kev) is computed in memory for the `status` filter. */
export const STATUS_PRESCAN_LIMIT = 5000;
/** Distinct (product, version) pairs aggregated by the summary. */
export const SUMMARY_GROUP_LIMIT = 5000;

const escapeLike = (s: string) => s.replace(/[\\%_]/g, (m) => `\\${m}`);

/** Asset owners see only software on assets they own; everyone else with `findings:read` all. */
function visibility(db: Database, user: User): SQL | undefined {
  if (user.role !== 'asset_owner') return undefined;
  return inArray(
    softwareInventory.assetId,
    db.select({ id: assets.id }).from(assets).where(eq(assets.ownerUserId, user.id)),
  );
}

interface Status {
  eol: SoftwareItem['eol'];
  knownExploited: SoftwareItem['knownExploited'];
}

/** Computes eol / known-exploited for (product, version) pairs against the stored intelligence. */
async function statusComputer(db: Database, products: readonly string[], now: Date) {
  const intel = (await loadSoftwareIntel(db, products)) ?? {
    asOf: null,
    eolCycles: [],
    advisories: [],
  };
  const nowIso = now.toISOString();
  const cache = new Map<string, Status>();
  return (product: string, version: string | null): Status => {
    if (version === null) return { eol: null, knownExploited: [] };
    const key = `${product}|${version}`;
    const hit = cache.get(key);
    if (hit) return hit;
    const eol = eolStatus(product, version, intel.eolCycles, nowIso);
    const status: Status = {
      eol: eol
        ? {
            cycle: eol.cycle,
            eolDate: eol.eolDate,
            isEol: eol.isEol,
            latestInCycle: eol.latestInCycle,
          }
        : null,
      knownExploited: matchAdvisories(product, version, intel.advisories)
        .filter((a) => a.kev)
        .map((a) => ({ cveId: a.cveId, cvss: a.cvss, ransomware: a.ransomware })),
    };
    cache.set(key, status);
    return status;
  };
}

const rowSelect = {
  row: softwareInventory,
  fqdn: domains.fqdn,
};

function toItem(r: { row: InventoryRow; fqdn: string }, status: Status): SoftwareItem {
  const row = r.row;
  return {
    id: row.id,
    domain: { id: row.domainId, fqdn: r.fqdn },
    hostname: row.hostname,
    ipAddress: row.ipAddress,
    port: row.port,
    source: row.source as SoftwareItem['source'],
    product: row.product,
    productLabel: softwareProduct(row.product)?.label ?? row.product,
    version: row.version,
    banner: row.banner,
    backportHint: row.backportDistribution ? { distribution: row.backportDistribution } : null,
    firstSeenAt: row.firstSeenAt.toISOString(),
    lastSeenAt: row.lastSeenAt.toISOString(),
    eol: status.eol,
    knownExploited: status.knownExploited,
  };
}

/**
 * GET /software and GET /domains/:id/software. `status=all` pages in SQL and computes status for
 * the page's rows only. `status=eol|kev` needs the computed status to filter: the matching rows
 * (versions disclosed, products with intelligence) are pre-scanned up to `STATUS_PRESCAN_LIMIT`,
 * filtered in memory and paged; beyond that limit results (and `total`) are truncated.
 */
export async function listSoftware(
  db: Database,
  user: User,
  query: SoftwareListQuery,
  now: Date,
): Promise<SoftwareListResponse> {
  const conditions: (SQL | undefined)[] = [visibility(db, user)];
  if (query.domainId) conditions.push(eq(softwareInventory.domainId, query.domainId));
  if (query.product) conditions.push(eq(softwareInventory.product, query.product));
  if (query.q) {
    const like = `%${escapeLike(query.q)}%`;
    conditions.push(
      or(
        ilike(softwareInventory.hostname, like),
        ilike(sql`host(${softwareInventory.ipAddress})`, like),
        ilike(domains.fqdn, like),
        ilike(softwareInventory.product, like),
        ilike(softwareInventory.version, like),
        ilike(softwareInventory.banner, like),
      ),
    );
  }
  const order = [
    asc(domains.fqdn),
    asc(sql`coalesce(${softwareInventory.hostname}, '')`),
    asc(softwareInventory.ipAddress),
    asc(softwareInventory.port),
    asc(softwareInventory.product),
    asc(softwareInventory.id),
  ];
  const offset = (query.page - 1) * query.pageSize;

  if (query.status === 'all') {
    const where = and(...conditions);
    const [rows, [total]] = await Promise.all([
      db
        .select(rowSelect)
        .from(softwareInventory)
        .innerJoin(domains, eq(domains.id, softwareInventory.domainId))
        .where(where)
        .orderBy(...order)
        .limit(query.pageSize)
        .offset(offset),
      db
        .select({ n: count() })
        .from(softwareInventory)
        .innerJoin(domains, eq(domains.id, softwareInventory.domainId))
        .where(where),
    ]);
    const status = await statusComputer(
      db,
      rows.map((r) => r.row.product),
      now,
    );
    return {
      items: rows.map((r) => toItem(r, status(r.row.product, r.row.version))),
      page: query.page,
      pageSize: query.pageSize,
      total: total?.n ?? 0,
    };
  }

  // Only products that have the relevant intelligence can match.
  const intelProducts =
    query.status === 'eol'
      ? db.selectDistinct({ p: softwareEolCycles.product }).from(softwareEolCycles)
      : db
          .selectDistinct({ p: vulnerabilityAdvisories.product })
          .from(vulnerabilityAdvisories)
          .where(
            and(eq(vulnerabilityAdvisories.kev, true), eq(vulnerabilityAdvisories.nvdStatus, 'ok')),
          );
  conditions.push(isNotNull(softwareInventory.version));
  conditions.push(inArray(softwareInventory.product, intelProducts));
  const candidates = await db
    .select(rowSelect)
    .from(softwareInventory)
    .innerJoin(domains, eq(domains.id, softwareInventory.domainId))
    .where(and(...conditions))
    .orderBy(...order)
    .limit(STATUS_PRESCAN_LIMIT);
  const status = await statusComputer(
    db,
    candidates.map((r) => r.row.product),
    now,
  );
  const matching = candidates
    .map((r) => ({ r, s: status(r.row.product, r.row.version) }))
    .filter(({ s }) =>
      query.status === 'eol' ? s.eol?.isEol === true : s.knownExploited.length > 0,
    );
  return {
    items: matching.slice(offset, offset + query.pageSize).map(({ r, s }) => toItem(r, s)),
    page: query.page,
    pageSize: query.pageSize,
    total: matching.length,
  };
}

/**
 * GET /software/summary: per product, the number of inventory locations ("hosts"), how many are
 * end-of-life or possibly affected by a known-exploited CVE, and the version distribution. One
 * GROUP BY over (product, version) — status is computed once per distinct pair.
 */
export async function softwareSummary(
  db: Database,
  user: User,
  now: Date,
): Promise<SoftwareSummaryResponse> {
  const groups = await db
    .select({
      product: softwareInventory.product,
      version: softwareInventory.version,
      hosts: count(),
    })
    .from(softwareInventory)
    .where(visibility(db, user))
    .groupBy(softwareInventory.product, softwareInventory.version)
    .orderBy(asc(softwareInventory.product), desc(count()), asc(softwareInventory.version))
    .limit(SUMMARY_GROUP_LIMIT);
  const status = await statusComputer(
    db,
    groups.map((g) => g.product),
    now,
  );
  const byProduct = new Map<string, SoftwareSummaryResponse['products'][number]>();
  for (const g of groups) {
    let p = byProduct.get(g.product);
    if (!p) {
      p = {
        product: g.product,
        productLabel: softwareProduct(g.product)?.label ?? g.product,
        hosts: 0,
        eol: 0,
        knownExploited: 0,
        versions: [],
      };
      byProduct.set(g.product, p);
    }
    const s = status(g.product, g.version);
    p.hosts += g.hosts;
    if (s.eol?.isEol) p.eol += g.hosts;
    if (s.knownExploited.length > 0) p.knownExploited += g.hosts;
    p.versions.push({ version: g.version, hosts: g.hosts });
  }
  return {
    products: [...byProduct.values()].sort(
      (a, b) => b.hosts - a.hosts || a.product.localeCompare(b.product),
    ),
  };
}
