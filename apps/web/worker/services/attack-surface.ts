import type { Database } from '@exdomainvault/database';
import {
  ASSET_ROLES,
  CONTINENTS,
  DBIP_ATTRIBUTION,
  continentOf,
  type AssetRole,
  type AttackSurfaceResponse,
  type Continent,
  type CurrentUser,
} from '@exdomainvault/shared';
import { sql, type SQL } from 'drizzle-orm';
import { assetRolesFor } from './asset-roles.ts';

/**
 * GET /attack-surface (Milestone 13): what the approved estate looks like from outside — asset
 * roles, hosting providers, address geography and the most exposed services. Scope: APPROVED assets
 * visible to the user (asset owners: their own) and their CURRENT addresses. Four set-based
 * statements plus one `assetRolesFor` call, regardless of portfolio size.
 */

type User = Pick<CurrentUser, 'id' | 'role'>;
type HostingKind = AttackSurfaceResponse['hostingProviders'][number]['kind'];

/** Maximum entries in `exposedServices`. */
export const EXPOSED_SERVICES_LIMIT = 10;

async function rowsOf<T>(db: Database, query: SQL): Promise<T[]> {
  const res = (await db.execute(query)) as unknown as { rows: T[] };
  return res.rows;
}

const HOSTING_KINDS = new Set(['cdn', 'cloud', 'paas', 'saas', 'hosting']);

export async function attackSurface(
  db: Database,
  user: User,
  now: Date,
): Promise<AttackSurfaceResponse> {
  const scope =
    user.role === 'asset_owner'
      ? sql`a.verification_status = 'approved' and a.owner_user_id = ${user.id}`
      : sql`a.verification_status = 'approved'`;

  const [assetRows, ipRows, portRows] = await Promise.all([
    rowsOf<{ id: string; provider: string | null; kind: string | null }>(
      db,
      sql`select a.id, a.hosting_hint->>'provider' as provider, a.hosting_hint->>'kind' as kind
          from assets a where ${scope} order by a.id`,
    ),
    rowsOf<{ asset_id: string; ip: string; country: string | null }>(
      db,
      sql`select ai.asset_id, host(ai.ip_address) as ip, ai.country_code as country
          from asset_ips ai join assets a on a.id = ai.asset_id
          where ai.is_current and ${scope}`,
    ),
    // Latest successful TCP observation per (address, port) on the current addresses; open ones
    // grouped by port. `mode()` = the most common service name reported for the port.
    rowsOf<{ port: number; ips: number; service: string | null }>(
      db,
      sql`with cur as (
            select distinct ai.ip_address from asset_ips ai join assets a on a.id = ai.asset_id
            where ai.is_current and ${scope}
          ),
          latest as (
            select distinct on (p.ip_address, p.port) p.ip_address, p.port, p.state, p.service
            from port_observations p
            where p.result_status = 'success' and p.protocol = 'tcp'
              and p.ip_address in (select ip_address from cur)
            order by p.ip_address, p.port, p.observed_at desc, p.id desc
          )
          select port, count(*)::int as ips, mode() within group (order by service) as service
          from latest where state = 'open'
          group by port
          order by count(*) desc, port`,
    ),
  ]);

  // Roles: every approved visible asset, all roles present.
  const roles = await assetRolesFor(
    db,
    assetRows.map((a) => a.id),
    now,
  );
  const roleCounts = Object.fromEntries(ASSET_ROLES.map((r) => [r, 0])) as Record<
    AssetRole,
    number
  >;
  for (const role of roles.values()) roleCounts[role] += 1;

  // Hosting providers (null provider = no known third party matched).
  const providers = new Map<
    string,
    { provider: string | null; kind: HostingKind; assets: number }
  >();
  let thirdParty = 0;
  for (const a of assetRows) {
    const kind = a.kind && HOSTING_KINDS.has(a.kind) ? (a.kind as HostingKind) : null;
    const provider = a.provider && kind ? a.provider : null;
    if (provider) thirdParty += 1;
    const key = provider ? `${provider}|${kind}` : '';
    const entry = providers.get(key) ?? { provider, kind: provider ? kind : null, assets: 0 };
    entry.assets += 1;
    providers.set(key, entry);
  }

  // Geography: an address's country is the one recorded on its current rows (lowest code if two
  // assets' rows disagree, for determinism).
  const countryOfIp = new Map<string, string | null>();
  for (const r of ipRows) {
    const prev = countryOfIp.get(r.ip) ?? null;
    const next = r.country && (!prev || r.country < prev) ? r.country : prev;
    countryOfIp.set(r.ip, next);
  }
  const byCountry = new Map<string, { assets: Set<string>; ips: Set<string> }>();
  const byContinent = new Map<Continent, { assets: Set<string>; ips: Set<string> }>();
  for (const r of ipRows) {
    const country = countryOfIp.get(r.ip);
    if (!country) continue;
    const c = byCountry.get(country) ?? { assets: new Set(), ips: new Set() };
    c.assets.add(r.asset_id);
    c.ips.add(r.ip);
    byCountry.set(country, c);
    const continent = continentOf(country);
    if (!continent) continue;
    const k = byContinent.get(continent) ?? { assets: new Set(), ips: new Set() };
    k.assets.add(r.asset_id);
    k.ips.add(r.ip);
    byContinent.set(continent, k);
  }
  const unknownCountryIps = [...countryOfIp.values()].filter((c) => c === null).length;

  return {
    totals: {
      approvedAssets: assetRows.length,
      currentIps: countryOfIp.size,
      openPorts: portRows.reduce((sum, p) => sum + Number(p.ips), 0),
      thirdPartyHosted: thirdParty,
    },
    assetRoles: ASSET_ROLES.map((role) => ({ role, assets: roleCounts[role] })),
    hostingProviders: [...providers.values()].sort(
      (a, b) =>
        b.assets - a.assets ||
        (a.provider === null ? 1 : 0) - (b.provider === null ? 1 : 0) ||
        (a.provider ?? '').localeCompare(b.provider ?? ''),
    ),
    countries: [...byCountry]
      .map(([country, c]) => ({ country, assets: c.assets.size, ips: c.ips.size }))
      .sort((a, b) => b.ips - a.ips || b.assets - a.assets || a.country.localeCompare(b.country)),
    continents: CONTINENTS.flatMap((continent) => {
      const c = byContinent.get(continent);
      return c ? [{ continent, assets: c.assets.size, ips: c.ips.size }] : [];
    }).sort((a, b) => b.ips - a.ips || a.continent.localeCompare(b.continent)),
    unknownCountryIps,
    geoAttribution: byCountry.size > 0 ? DBIP_ATTRIBUTION : null,
    exposedServices: portRows.slice(0, EXPOSED_SERVICES_LIMIT).map((p) => ({
      port: Number(p.port),
      service: p.service,
      ips: Number(p.ips),
    })),
  };
}
