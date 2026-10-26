import type { Database } from '@exdomainvault/database';
import { classifyAssetRole, type AssetRole, type AssetRoleEvidence } from '@exdomainvault/shared';
import { sql } from 'drizzle-orm';

/** HTTP responses older than this no longer count as "responds to HTTP". */
const HTTP_WINDOW_MS = 30 * 86_400_000;

interface RoleRow {
  id: string;
  is_mx: boolean;
  is_ns: boolean;
  open_ports: number[] | null;
  http: boolean;
  hosting_kind: string | null;
}

/**
 * Primary roles for assets (Milestone 13), from collected evidence only (see `classifyAssetRole`):
 * - MX / NS targets: the latest successful MX/NS answer of every domain apex, values normalised
 *   (priority stripped, lowercased, trailing dot removed);
 * - open ports: the latest port observation per (address, port) on the asset's CURRENT addresses;
 * - HTTP: any successful HTTP observation of the asset within the last 30 days;
 * - hosting: `assets.hosting_hint.kind`.
 * One set-based statement; an asset without evidence is `unclassified`.
 */
export async function assetRolesFor(
  db: Database,
  assetIds: readonly string[],
  /** Reference time for the HTTP window (tests pass their clock). */
  now: Date = new Date(),
): Promise<Map<string, AssetRole>> {
  const out = new Map<string, AssetRole>();
  if (assetIds.length === 0) return out;
  const ids = sql.join(
    assetIds.map((id) => sql`${id}::uuid`),
    sql`, `,
  );
  const res = (await db.execute(sql`
    with target as (
      select a.id, a.hostname, a.hosting_hint->>'kind' as hosting_kind
      from assets a where a.id in (${ids})
    ),
    apex_answers as (
      select distinct on (o.hostname, o.record_type) o.record_type, o.record_values
      from dns_observations o
      join domains d on d.fqdn = o.hostname
      where o.record_type in ('MX', 'NS') and o.result_status = 'success'
      order by o.hostname, o.record_type, o.observed_at desc
    ),
    named as (
      select record_type,
             rtrim(lower(regexp_replace(v, '^\\s*\\d+\\s+', '')), '.') as name
      from apex_answers, unnest(record_values) as v
    ),
    ports as (
      select distinct on (p.ip_address, p.port, p.protocol) p.ip_address, p.port, p.protocol, p.state
      from port_observations p
      where p.result_status = 'success'
        and p.ip_address in (
          select ai.ip_address from asset_ips ai join target t on t.id = ai.asset_id
          where ai.is_current
        )
      order by p.ip_address, p.port, p.protocol, p.observed_at desc
    )
    select t.id,
      exists (select 1 from named n where n.record_type = 'MX' and n.name = t.hostname) as is_mx,
      exists (select 1 from named n where n.record_type = 'NS' and n.name = t.hostname) as is_ns,
      (select array_agg(distinct p.port) from ports p
         join asset_ips ai on ai.ip_address = p.ip_address and ai.is_current and ai.asset_id = t.id
        where p.state = 'open' and p.protocol = 'tcp') as open_ports,
      exists (select 1 from http_observations h
               where h.asset_id = t.id and h.result_status = 'success'
                 and h.observed_at > ${new Date(now.getTime() - HTTP_WINDOW_MS).toISOString()}::timestamptz) as http,
      t.hosting_kind
    from target t
  `)) as unknown as { rows: RoleRow[] };
  for (const r of res.rows) {
    const kind = r.hosting_kind as AssetRoleEvidence['hostingKind'];
    out.set(
      r.id,
      classifyAssetRole({
        isMxTarget: r.is_mx,
        isNsTarget: r.is_ns,
        openPorts: (r.open_ports ?? []).map(Number),
        respondsToHttp: r.http,
        hostingKind: kind ?? null,
      }),
    );
  }
  for (const id of assetIds) if (!out.has(id)) out.set(id, 'unclassified');
  return out;
}
