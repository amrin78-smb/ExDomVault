import type { Database } from '@exdomainvault/database';
import {
  CHANGE_IMPORTANCE,
  CHANGE_KINDS,
  CHANGES_DEFAULT_DAYS,
  CHANGES_MAX_DAYS,
  type ChangeEvent,
  type ChangeImportance,
  type ChangeKind,
  type ChangesQuery,
  type ChangesResponse,
  type CurrentUser,
} from '@exdomainvault/shared';
import { canonicalIp } from '@exdomainvault/shared/net';
import { sql, type SQL } from 'drizzle-orm';
import { rowsOf } from '../lib/db.ts';

/**
 * Change timeline (Milestone 14): GET /changes. Read-only and derived at request time from the
 * observations already stored, so it never disagrees with them and needs no backfill.
 *
 * For every observation kind the statement (1) folds the rows of one succeeded job into one
 * snapshot per key (e.g. hostname + record type), keeping it only when every row of that key in
 * the job was `success` — failed, partial and timed-out results are skipped, never compared; (2)
 * pairs each snapshot with the previous kept one for the same key (`lag` over the key, ordered by
 * time); (3) emits an event where the value differs. The first snapshot of a key emits nothing
 * (the asset-discovered event covers "new"). Snapshots are read from `since - LOOKBACK_DAYS`, so a
 * key last observed longer ago than that before the window has no predecessor and its first
 * in-window change is not reported (scans run daily or weekly; documented limitation).
 *
 * Asset owners see only events tied to assets they own; events with no asset (e.g. `_dmarc.`
 * names) are hidden from them.
 */

type User = Pick<CurrentUser, 'id' | 'role'>;

const DAY_MS = 86_400_000;
/** How far before `since` predecessors are looked for. */
export const LOOKBACK_DAYS = 8;
/** DNS record types whose churn is not a meaningful change (SOA serials, signatures). */
const IGNORED_RECORD_TYPES = ['SOA', 'RRSIG', 'NSEC', 'NSEC3'];
/** Values compared case-sensitively (TXT content is case-sensitive). */
const CASE_SENSITIVE_TYPES = ['TXT'];

const ts = (d: Date) => sql`${d.toISOString()}::timestamptz`;

interface Bounds {
  lo: Date;
  since: Date;
  until: Date;
}

interface Scope {
  domainId?: string;
}

/** `and j.domain_id = …` for job-based kinds. */
const jobDomain = (s: Scope) => (s.domainId ? sql`and j.domain_id = ${s.domainId}::uuid` : sql``);

// --- Per-kind statements ------------------------------------------------------------------------
// Each returns the columns: id, at, kind, domain_id, asset_id, hostname, subject, before, after,
// hint. `asset_id` may be null; it is resolved from (domain, hostname) afterwards.

function dnsEvents(b: Bounds, s: Scope): SQL {
  const ignored = sql.join(
    IGNORED_RECORD_TYPES.map((t) => sql`${t}`),
    sql`, `,
  );
  const cs = sql.join(
    CASE_SENSITIVE_TYPES.map((t) => sql`${t}`),
    sql`, `,
  );
  return sql`
    dns_seq as (
      select j.domain_id, o.hostname, o.record_type, o.scan_job_id as job_id, o.asset_id,
             o.observed_at as at, o.record_values as raw,
             lag(o.record_values) over w as raw_prev
      from dns_observations o
      join scan_jobs j on j.id = o.scan_job_id and j.status = 'succeeded' and j.domain_id is not null
      where o.result_status = 'success'
        and o.observed_at >= ${ts(b.lo)} and o.observed_at < ${ts(b.until)}
        and o.record_type not in (${ignored}) ${jobDomain(s)}
      window w as (partition by j.domain_id, o.hostname, o.record_type
                   order by o.observed_at, o.scan_job_id)
    ),
    -- Raw arrays differ also when only the answer order rotated: normalise just those candidates.
    dns_norm as (
      select q.*,
             array(select distinct case when q.record_type in (${cs}) then x else lower(x) end
                   from unnest(q.raw_prev) x order by 1) as prev,
             array(select distinct case when q.record_type in (${cs}) then x else lower(x) end
                   from unnest(q.raw) x order by 1) as val
      from dns_seq q
      where q.raw_prev is not null and q.raw_prev <> q.raw and q.at >= ${ts(b.since)}
    ),
    dns_ev as (
      select 'dns:' || job_id || ':' || hostname || ':' || record_type as id, at,
             'dns'::text as kind, domain_id, asset_id, hostname,
             record_type || ' record' as subject, to_jsonb(prev) as before, to_jsonb(val) as after,
             case when record_type = 'NS' then 'important'
                  when record_type in ('A', 'AAAA', 'CNAME', 'MX', 'DS') then 'notable'
                  else 'info' end as hint
      from dns_norm
      where prev <> val
    )`;
}

function ipEvents(b: Bounds, s: Scope): SQL {
  const dom = s.domainId ? sql`and a.domain_id = ${s.domainId}::uuid` : sql``;
  // "Added" excludes the asset's initial address set (first seen within an hour of its first).
  return sql`
    ip_ev as (
      select 'ip:' || ai.id || ':added' as id, ai.first_seen_at as at, 'ip'::text as kind,
             a.domain_id, a.id as asset_id, a.hostname, 'address' as subject,
             null::jsonb as before, jsonb_build_object('address', host(ai.ip_address)) as after,
             'notable' as hint
      from asset_ips ai join assets a on a.id = ai.asset_id
      where ai.first_seen_at >= ${ts(b.since)} and ai.first_seen_at < ${ts(b.until)} ${dom}
        and exists (select 1 from asset_ips p where p.asset_id = ai.asset_id
                    and p.first_seen_at < ai.first_seen_at - interval '1 hour')
      union all
      select 'ip:' || ai.id || ':removed', ai.last_seen_at, 'ip', a.domain_id, a.id, a.hostname,
             'address', jsonb_build_object('address', host(ai.ip_address)), null::jsonb, 'notable'
      from asset_ips ai join assets a on a.id = ai.asset_id
      where not ai.is_current
        and ai.last_seen_at >= ${ts(b.since)} and ai.last_seen_at < ${ts(b.until)} ${dom}
    )`;
}

function tlsEvents(b: Bounds, s: Scope): SQL {
  return sql`
    tls_snap as (
      select j.domain_id, o.hostname, o.port, o.scan_job_id as job_id,
             max(o.observed_at) as at,
             bool_and(o.result_status = 'success') and count(o.fingerprint_sha256) > 0 as ok,
             (array_agg(o.asset_id) filter (where o.asset_id is not null))[1] as asset_id,
             jsonb_build_object(
               'certificates', jsonb_agg(distinct c.cert order by c.cert)
                                 filter (where o.fingerprint_sha256 is not null),
               'protocols', coalesce(jsonb_agg(distinct o.protocol_version order by o.protocol_version)
                                 filter (where o.protocol_version is not null), '[]'::jsonb)
             ) as val,
             coalesce(jsonb_agg(distinct c.issuer_org order by c.issuer_org)
                        filter (where o.issuer is not null), '[]'::jsonb) as issuers
      from tls_observations o
      join scan_jobs j on j.id = o.scan_job_id and j.status = 'succeeded' and j.domain_id is not null
      cross join lateral (select jsonb_build_object(
        'fingerprint', o.fingerprint_sha256, 'issuer', o.issuer, 'subject', o.subject,
        'notAfter', o.not_after) as cert,
        coalesce(substring(o.issuer from '(?:^|,) *O=([^,]+)'), o.issuer) as issuer_org) c
      where o.observed_at >= ${ts(b.lo)} and o.observed_at < ${ts(b.until)} ${jobDomain(s)}
      group by j.domain_id, o.hostname, o.port, o.scan_job_id
    ),
    tls_seq as (
      select s.*, lag(s.val) over w as prev, lag(s.issuers) over w as prev_issuers
      from tls_snap s where s.ok
      window w as (partition by s.domain_id, s.hostname, s.port order by s.at, s.job_id)
    ),
    tls_ev as (
      select 'tls:' || job_id || ':' || hostname || ':' || port as id, at, 'tls'::text as kind,
             domain_id, asset_id, hostname,
             case when prev->'certificates' = val->'certificates' then 'TLS protocol ' || port || '/tcp'
                  else 'certificate ' || port || '/tcp' end as subject,
             prev as before, val as after,
             case when prev_issuers <> issuers then 'important' else 'info' end as hint
      from tls_seq
      where prev is not null and prev <> val and at >= ${ts(b.since)}
    )`;
}

const HOST_OF_URL = sql`lower(substring(o.url from '^[A-Za-z][A-Za-z0-9+.-]*://([^/:?#]+)'))`;

function httpEvents(b: Bounds, s: Scope): SQL {
  return sql`
    http_snap as (
      select j.domain_id, o.url, ${HOST_OF_URL} as hostname, o.scan_job_id as job_id,
             max(o.observed_at) as at,
             bool_and(o.result_status = 'success') as ok,
             (array_agg(o.asset_id) filter (where o.asset_id is not null))[1] as asset_id,
             jsonb_agg(distinct jsonb_build_object('statusCode', o.status_code,
                         'finalUrl', o.final_url, 'hsts', o.hsts_enabled)
                       order by jsonb_build_object('statusCode', o.status_code,
                         'finalUrl', o.final_url, 'hsts', o.hsts_enabled)) as val
      from http_observations o
      join scan_jobs j on j.id = o.scan_job_id and j.status = 'succeeded' and j.domain_id is not null
      where o.observed_at >= ${ts(b.lo)} and o.observed_at < ${ts(b.until)} ${jobDomain(s)}
      group by j.domain_id, o.url, o.scan_job_id
    ),
    http_seq as (
      select s.*, lag(s.val) over w as prev
      from http_snap s where s.ok
      window w as (partition by s.domain_id, s.url order by s.at, s.job_id)
    ),
    http_ev as (
      select 'http:' || job_id || ':' || url as id, at, 'http'::text as kind,
             domain_id, asset_id, hostname, url as subject, prev as before, val as after,
             case when prev @> '[{"hsts": true}]' and not val @> '[{"hsts": true}]' then 'notable'
                  else 'info' end as hint
      from http_seq
      where prev is not null and prev <> val and at >= ${ts(b.since)}
    )`;
}

function portEvents(b: Bounds, s: Scope): SQL {
  return sql`
    port_snap as (
      select j.domain_id, o.ip_address, o.port, o.protocol, o.scan_job_id as job_id,
             max(o.observed_at) as at,
             bool_and(o.result_status = 'success') as ok,
             (array_agg(o.asset_id) filter (where o.asset_id is not null))[1] as asset_id,
             string_agg(distinct o.state, ',' order by o.state) as state
      from port_observations o
      join scan_jobs j on j.id = o.scan_job_id and j.status = 'succeeded' and j.domain_id is not null
      where o.observed_at >= ${ts(b.lo)} and o.observed_at < ${ts(b.until)} ${jobDomain(s)}
      group by j.domain_id, o.ip_address, o.port, o.protocol, o.scan_job_id
    ),
    port_seq as (
      select s.*, lag(s.state) over w as prev
      from port_snap s where s.ok
      window w as (partition by s.domain_id, s.ip_address, s.port, s.protocol
                   order by s.at, s.job_id)
    ),
    port_ev as (
      select 'port:' || job_id || ':' || host(ip_address) || ':' || port || '/' || protocol as id,
             at, 'port'::text as kind, domain_id, asset_id, null::text as hostname,
             host(ip_address) || ' ' || port || '/' || protocol as subject,
             jsonb_build_object('state', prev) as before, jsonb_build_object('state', state) as after,
             case when state = 'open' then 'important' else 'info' end as hint
      from port_seq
      where prev is not null and prev <> state and at >= ${ts(b.since)}
    )`;
}

function softwareEvents(b: Bounds, s: Scope): SQL {
  // Web server banners per hostname (only from runs that recorded headers: `evidence ? 'server'`)
  // and service identification per address/port (only open ports that reported a product, so a
  // later run without identification is not mistaken for the product disappearing).
  return sql`
    sw_http_snap as (
      select j.domain_id, o.url, ${HOST_OF_URL} as hostname, o.scan_job_id as job_id,
             max(o.observed_at) as at,
             bool_and(o.result_status = 'success') as ok,
             (array_agg(o.asset_id) filter (where o.asset_id is not null))[1] as asset_id,
             jsonb_build_object(
               'server', coalesce(jsonb_agg(distinct o.evidence->>'server' order by o.evidence->>'server')
                           filter (where o.evidence->>'server' is not null), '[]'::jsonb),
               'xPoweredBy', coalesce(jsonb_agg(distinct o.evidence->>'xPoweredBy'
                                                order by o.evidence->>'xPoweredBy')
                           filter (where o.evidence->>'xPoweredBy' is not null), '[]'::jsonb)
             ) as val
      from http_observations o
      join scan_jobs j on j.id = o.scan_job_id and j.status = 'succeeded' and j.domain_id is not null
      where o.observed_at >= ${ts(b.lo)} and o.observed_at < ${ts(b.until)}
        and o.evidence ? 'server' ${jobDomain(s)}
      group by j.domain_id, o.url, o.scan_job_id
    ),
    sw_http_seq as (
      select s.*, lag(s.val) over w as prev
      from sw_http_snap s where s.ok
      window w as (partition by s.domain_id, s.url order by s.at, s.job_id)
    ),
    sw_port_snap as (
      select j.domain_id, o.ip_address, o.port, o.protocol, o.scan_job_id as job_id,
             max(o.observed_at) as at,
             bool_and(o.result_status = 'success') as ok,
             (array_agg(o.asset_id) filter (where o.asset_id is not null))[1] as asset_id,
             jsonb_agg(distinct jsonb_build_object('product', o.evidence->>'product',
                                                   'version', o.evidence->>'version')
                       order by jsonb_build_object('product', o.evidence->>'product',
                                                   'version', o.evidence->>'version')) as val
      from port_observations o
      join scan_jobs j on j.id = o.scan_job_id and j.status = 'succeeded' and j.domain_id is not null
      where o.observed_at >= ${ts(b.lo)} and o.observed_at < ${ts(b.until)}
        and o.state = 'open' and o.evidence ? 'product' ${jobDomain(s)}
      group by j.domain_id, o.ip_address, o.port, o.protocol, o.scan_job_id
    ),
    sw_port_seq as (
      select s.*, lag(s.val) over w as prev
      from sw_port_snap s where s.ok
      window w as (partition by s.domain_id, s.ip_address, s.port, s.protocol
                   order by s.at, s.job_id)
    ),
    sw_ev as (
      select 'software:' || job_id || ':' || url as id, at, 'software'::text as kind,
             domain_id, asset_id, hostname, url as subject,
             prev as before, val as after,
             case when val = '{"server": [], "xPoweredBy": []}'::jsonb then 'info'
                  else 'notable' end as hint
      from sw_http_seq
      where prev is not null and prev <> val and at >= ${ts(b.since)}
      union all
      select 'software:' || job_id || ':' || host(ip_address) || ':' || port || '/' || protocol,
             at, 'software', domain_id, asset_id, null::text,
             'service on ' || host(ip_address) || ' ' || port || '/' || protocol,
             prev, val, 'notable'
      from sw_port_seq
      where prev is not null and prev <> val and at >= ${ts(b.since)}
    )`;
}

function registrationEvents(b: Bounds, s: Scope): SQL {
  const dom = s.domainId ? sql`and o.domain_id = ${s.domainId}::uuid` : sql``;
  // Each field is compared with the previous observation that HAS a value for it: redacted or
  // unavailable registry data in between must not read as "registrar removed" or hide a change.
  return sql`
    reg_base as (
      select o.id, o.domain_id, o.asset_id, o.observed_at as at, o.registrar, o.expires_at,
             o.nameservers
      from registration_observations o
      join scan_jobs j on j.id = o.scan_job_id and j.status = 'succeeded'
      where o.result_status = 'success'
        and o.observed_at >= ${ts(b.lo)} and o.observed_at < ${ts(b.until)} ${dom}
    ),
    reg_registrar as (
      select r.*, lag(r.registrar) over w as prev
      from reg_base r where r.registrar is not null
      window w as (partition by r.domain_id order by r.at, r.id)
    ),
    reg_expiry as (
      select r.*, lag(r.expires_at) over w as prev
      from reg_base r where r.expires_at is not null
      window w as (partition by r.domain_id order by r.at, r.id)
    ),
    reg_ns_seq as (
      select r.*, lag(r.nameservers) over w as raw_prev
      from reg_base r where cardinality(r.nameservers) > 0
      window w as (partition by r.domain_id order by r.at, r.id)
    ),
    reg_ns as (
      select r.*,
             array(select distinct lower(rtrim(n, '.')) from unnest(r.nameservers) n order by 1)
               as ns,
             array(select distinct lower(rtrim(n, '.')) from unnest(r.raw_prev) n order by 1)
               as prev_ns
      from reg_ns_seq r
      where r.at >= ${ts(b.since)} and r.raw_prev is not null and r.raw_prev <> r.nameservers
    ),
    reg_ev as (
      select 'registration:' || id || ':registrar' as id, at, 'registration'::text as kind,
             domain_id, asset_id, null::text as hostname, 'registrar' as subject,
             to_jsonb(prev) as before, to_jsonb(registrar) as after, 'important' as hint
      from reg_registrar
      where at >= ${ts(b.since)} and prev is not null and lower(registrar) <> lower(prev)
      union all
      select 'registration:' || id || ':nameservers', at, 'registration', domain_id, asset_id,
             null, 'nameservers', to_jsonb(prev_ns), to_jsonb(ns), 'important'
      from reg_ns
      where ns <> prev_ns
      union all
      select 'registration:' || id || ':expiry', at, 'registration', domain_id, asset_id,
             null, 'expiry date', to_jsonb(prev), to_jsonb(expires_at),
             case when expires_at < prev then 'notable' else 'info' end
      from reg_expiry
      where at >= ${ts(b.since)} and prev is not null and expires_at <> prev
    )`;
}

function assetEvents(b: Bounds, s: Scope): SQL {
  const dom = s.domainId ? sql`and a.domain_id = ${s.domainId}::uuid` : sql``;
  return sql`
    asset_ev as (
      select 'asset:' || a.id || ':discovered' as id, a.first_seen_at as at, 'asset'::text as kind,
             a.domain_id, a.id as asset_id, a.hostname, 'asset' as subject, null::jsonb as before,
             jsonb_build_object('source', a.discovery_source) as after,
             case when a.discovery_source in ('certificate_transparency', 'dns') then 'notable'
                  else 'info' end as hint
      from assets a
      where a.first_seen_at >= ${ts(b.since)} and a.first_seen_at < ${ts(b.until)} ${dom}
      union all
      select 'asset:' || l.id || ':decision', l.created_at, 'asset', a.domain_id, a.id, a.hostname,
             'approval status', null::jsonb,
             jsonb_build_object('status', replace(l.action, 'asset.', ''),
                                'reason', l.metadata->>'reason'),
             'info'
      from audit_logs l join assets a on a.id::text = l.resource_id
      where l.resource_type = 'asset'
        and l.action in ('asset.approved', 'asset.rejected', 'asset.suspended')
        and l.created_at >= ${ts(b.since)} and l.created_at < ${ts(b.until)} ${dom}
    )`;
}

const KIND_SQL: Record<ChangeKind, { cte: (b: Bounds, s: Scope) => SQL; name: string }> = {
  dns: { cte: dnsEvents, name: 'dns_ev' },
  ip: { cte: ipEvents, name: 'ip_ev' },
  tls: { cte: tlsEvents, name: 'tls_ev' },
  http: { cte: httpEvents, name: 'http_ev' },
  port: { cte: portEvents, name: 'port_ev' },
  software: { cte: softwareEvents, name: 'sw_ev' },
  registration: { cte: registrationEvents, name: 'reg_ev' },
  asset: { cte: assetEvents, name: 'asset_ev' },
};

// --- Query --------------------------------------------------------------------------------------

interface EventRow {
  id: string;
  at: Date | string;
  kind: ChangeKind;
  domain_id: string;
  fqdn: string;
  asset_id: string | null;
  hostname: string | null;
  subject: string;
  before: unknown;
  after: unknown;
  hint: ChangeImportance;
  total: number;
  n_info: number;
  n_notable: number;
  n_important: number;
}

/** The effective window: `until` defaults to now, `since` to 30 days before, at most 366 days. */
export function changeWindow(q: Pick<ChangesQuery, 'since' | 'until'>, now: Date) {
  const until = q.until ? new Date(q.until) : now;
  const floor = new Date(until.getTime() - CHANGES_MAX_DAYS * DAY_MS);
  let since = q.since
    ? new Date(q.since)
    : new Date(until.getTime() - CHANGES_DEFAULT_DAYS * DAY_MS);
  if (since < floor) since = floor;
  return { since, until, lo: new Date(since.getTime() - LOOKBACK_DAYS * DAY_MS) };
}

/** The full statement (exported for EXPLAIN in development; not used elsewhere). */
export function changesStatement(
  user: User,
  q: ChangesQuery,
  bounds: Bounds,
  scope: Scope,
  paging: { limit: number; offset: number } | null,
): SQL {
  const kinds = q.kind && q.kind.length > 0 ? [...new Set(q.kind)] : [...CHANGE_KINDS];
  const parts = kinds.map((k) => KIND_SQL[k]);
  const ctes = sql.join(
    parts.map((p) => p.cte(bounds, scope)),
    sql`,`,
  );
  const union = sql.join(
    parts.map((p) => sql.raw(`select * from ${p.name}`)),
    sql` union all `,
  );
  const filters: SQL[] = [];
  if (q.domainId) filters.push(sql`e.domain_id = ${q.domainId}::uuid`);
  if (q.assetId) filters.push(sql`e.rid = ${q.assetId}::uuid`);
  if (q.importance) {
    const allowed = CHANGE_IMPORTANCE.slice(CHANGE_IMPORTANCE.indexOf(q.importance));
    filters.push(
      sql`e.hint in (${sql.join(
        allowed.map((v) => sql`${v}`),
        sql`, `,
      )})`,
    );
  }
  if (user.role === 'asset_owner') {
    filters.push(sql`e.rid in (select id from assets where owner_user_id = ${user.id}::uuid)`);
  }
  const where = filters.length > 0 ? sql.join(filters, sql` and `) : sql`true`;
  const page = paging ? sql`limit ${paging.limit} offset ${paging.offset}` : sql`limit 0`;
  return sql`
    with ${ctes},
    ev as (${union}),
    e as (
      select ev.*, coalesce(ev.asset_id, ra.id) as rid
      from ev
      left join assets ra on ev.asset_id is null and ev.hostname is not null
        and ra.domain_id = ev.domain_id and ra.hostname = ev.hostname
    )
    select e.id, e.at, e.kind, e.domain_id, d.fqdn, e.rid as asset_id, e.hostname, e.subject,
           e.before, e.after, e.hint,
           count(*) over ()::int as total,
           (count(*) filter (where e.hint = 'info') over ())::int as n_info,
           (count(*) filter (where e.hint = 'notable') over ())::int as n_notable,
           (count(*) filter (where e.hint = 'important') over ())::int as n_important
    from e join domains d on d.id = e.domain_id
    where ${where}
    order by e.at desc, e.id desc
    ${page}`;
}

/** Scope narrowing for performance: an asset filter implies its domain. */
async function scopeOf(db: Database, q: ChangesQuery): Promise<Scope | null> {
  if (!q.assetId) return { domainId: q.domainId };
  const [a] = await rowsOf<{ domain_id: string }>(
    db,
    sql`select domain_id from assets where id = ${q.assetId}::uuid`,
  );
  if (!a) return null;
  if (q.domainId && q.domainId !== a.domain_id) return null;
  return { domainId: a.domain_id };
}

export async function listChanges(
  db: Database,
  user: User,
  q: ChangesQuery,
  now: Date,
): Promise<ChangesResponse> {
  const bounds = changeWindow(q, now);
  const base = {
    page: q.page,
    pageSize: q.pageSize,
    since: bounds.since.toISOString(),
    until: bounds.until.toISOString(),
  };
  const empty: ChangesResponse = {
    ...base,
    items: [],
    total: 0,
    counts: { info: 0, notable: 0, important: 0 },
  };
  const scope = await scopeOf(db, q);
  if (!scope) return empty;

  const offset = (q.page - 1) * q.pageSize;
  let rows = await rowsOf<EventRow>(
    db,
    changesStatement(user, q, bounds, scope, { limit: q.pageSize, offset }),
  );
  let head = rows[0];
  if (!head && offset > 0) {
    // Past the last page: still report the totals.
    rows = await rowsOf<EventRow>(
      db,
      changesStatement(user, q, bounds, scope, { limit: 1, offset: 0 }),
    );
    head = rows[0];
    rows = [];
  }
  if (!head) return empty;
  return {
    ...base,
    items: rows.map(toEvent),
    total: head.total,
    counts: { info: head.n_info, notable: head.n_notable, important: head.n_important },
  };
}

// --- Presentation -------------------------------------------------------------------------------

const isoOf = (v: Date | string) => (v instanceof Date ? v : new Date(v)).toISOString();

type Json = Record<string, unknown>;
const asObj = (v: unknown): Json => (v && typeof v === 'object' ? (v as Json) : {});
const asStrings = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];

/** Values shown in a summary: at most three, then "+N more". */
function listOf(values: readonly string[]): string {
  if (values.length <= 3) return values.join(', ');
  return `${values.slice(0, 3).join(', ')} +${values.length - 3} more`;
}

function setDiff(before: readonly string[], after: readonly string[]) {
  const b = new Set(before);
  const a = new Set(after);
  return { added: after.filter((v) => !b.has(v)), removed: before.filter((v) => !a.has(v)) };
}

function diffSentence(before: readonly string[], after: readonly string[]): string {
  const { added, removed } = setDiff(before, after);
  const parts: string[] = [];
  if (added.length > 0) parts.push(`added ${listOf(added)}`);
  if (removed.length > 0) parts.push(`removed ${listOf(removed)}`);
  return parts.join('; ');
}

const dateOnly = (v: unknown) =>
  typeof v === 'string' && !Number.isNaN(Date.parse(v))
    ? new Date(v).toISOString().slice(0, 10)
    : '?';

/** TLS snapshot → a flat, display-ready object. */
function tlsView(v: unknown) {
  const o = asObj(v);
  const certs = Array.isArray(o.certificates) ? o.certificates.map(asObj) : [];
  const uniq = (key: string, f: (x: unknown) => string = String) => [
    ...new Set(
      certs
        .map((c) => c[key])
        .filter((x) => x !== null && x !== undefined)
        .map(f),
    ),
  ];
  return {
    fingerprint: uniq('fingerprint'),
    issuer: uniq('issuer'),
    subject: uniq('subject'),
    notAfter: uniq('notAfter', dateOnly),
    protocols: asStrings(o.protocols),
  };
}

const unwrapOne = (v: unknown) => (Array.isArray(v) && v.length === 1 ? (v[0] as unknown) : v);

function presentTls(row: EventRow) {
  const before = tlsView(row.before);
  const after = tlsView(row.after);
  const where = `${row.hostname}:${row.subject.replace(/\D+/g, '')}`;
  let summary: string;
  if (before.fingerprint.join() === after.fingerprint.join()) {
    summary = `TLS protocol on ${where} changed from ${listOf(before.protocols) || 'none'} to ${listOf(after.protocols) || 'none'}`;
  } else if (before.issuer.join() !== after.issuer.join()) {
    summary = `Certificate on ${where} changed issuer from ${listOf(before.issuer) || 'unknown'} to ${listOf(after.issuer) || 'unknown'}`;
  } else {
    summary = `Certificate on ${where} replaced (expires ${listOf(after.notAfter) || 'unknown'}, previously ${listOf(before.notAfter) || 'unknown'})`;
  }
  return { summary, before, after };
}

function presentHttp(row: EventRow) {
  const before = asObj(unwrapOne(row.before));
  const after = asObj(unwrapOne(row.after));
  const parts: string[] = [];
  const show = (v: unknown) => (v === null || v === undefined ? 'none' : String(v));
  if (before.statusCode !== after.statusCode) {
    parts.push(`status ${show(before.statusCode)} → ${show(after.statusCode)}`);
  }
  if (before.finalUrl !== after.finalUrl) {
    parts.push(`final URL ${show(before.finalUrl)} → ${show(after.finalUrl)}`);
  }
  if (before.hsts !== after.hsts) {
    const hsts = (v: unknown) => (v === true ? 'on' : v === false ? 'off' : 'not recorded');
    parts.push(`HSTS ${hsts(before.hsts)} → ${hsts(after.hsts)}`);
  }
  const what = parts.length > 0 ? parts.join('; ') : 'response changed';
  return {
    summary: `${row.subject}: ${what}`,
    before: unwrapOne(row.before),
    after: unwrapOne(row.after),
  };
}

function presentSoftware(row: EventRow) {
  if (!row.subject.startsWith('service on ')) {
    const b = asObj(row.before);
    const a = asObj(row.after);
    const banners = (o: Json) => [...asStrings(o.server), ...asStrings(o.xPoweredBy)];
    const before = banners(b);
    const after = banners(a);
    let summary: string;
    if (after.length === 0) summary = `${row.subject} no longer reports ${listOf(before)}`;
    else if (before.length === 0) summary = `${row.subject} now reports ${listOf(after)}`;
    else summary = `${row.subject} now reports ${listOf(after)} (was ${listOf(before)})`;
    return {
      summary,
      before: { server: asStrings(b.server), xPoweredBy: asStrings(b.xPoweredBy) },
      after: { server: asStrings(a.server), xPoweredBy: asStrings(a.xPoweredBy) },
    };
  }
  const label = (v: unknown) =>
    (Array.isArray(v) ? v.map(asObj) : [])
      .map((o) => [o.product, o.version].filter((x) => typeof x === 'string').join(' '))
      .filter(Boolean);
  const before = label(row.before);
  const after = label(row.after);
  return {
    summary: `${row.subject.replace(/^service on/, 'Service on')} now reports ${listOf(after) || 'nothing'} (was ${listOf(before) || 'nothing'})`,
    before: { service: before },
    after: { service: after },
  };
}

function present(row: EventRow): Pick<ChangeEvent, 'summary' | 'before' | 'after' | 'subject'> {
  const host = row.hostname ?? '';
  switch (row.kind) {
    case 'dns': {
      const before = asStrings(row.before);
      const after = asStrings(row.after);
      const summary =
        before.length === 0
          ? `${row.subject} of ${host} created: ${listOf(after)}`
          : after.length === 0
            ? `${row.subject} of ${host} removed (was ${listOf(before)})`
            : `${row.subject} of ${host} changed: ${diffSentence(before, after)}`;
      return { subject: row.subject, summary, before, after };
    }
    case 'ip': {
      const added = row.after !== null;
      const raw = String(asObj(added ? row.after : row.before).address ?? '');
      const address = canonicalIp(raw) ?? raw;
      const summary = added
        ? `${host} started resolving to ${address}`
        : `${host} stopped resolving to ${address} (last seen)`;
      const v = { address };
      return {
        subject: row.subject,
        summary,
        before: added ? null : v,
        after: added ? v : null,
      };
    }
    case 'tls':
      return { subject: row.subject, ...presentTls(row) };
    case 'http':
      return { subject: row.subject, ...presentHttp(row) };
    case 'port': {
      const b = String(asObj(row.before).state);
      const a = String(asObj(row.after).state);
      const verb = a === 'open' ? 'opened' : a === 'closed' ? 'closed' : `became ${a}`;
      return {
        subject: row.subject,
        summary: `Port ${row.subject} ${verb} (was ${b})`,
        before: row.before,
        after: row.after,
      };
    }
    case 'software':
      return { subject: row.subject, ...presentSoftware(row) };
    case 'registration': {
      if (row.subject === 'nameservers') {
        const before = asStrings(row.before);
        const after = asStrings(row.after);
        return {
          subject: row.subject,
          summary: `Nameservers of ${row.fqdn} changed: ${diffSentence(before, after)}`,
          before,
          after,
        };
      }
      if (row.subject === 'expiry date') {
        const before = dateOnly(row.before);
        const after = dateOnly(row.after);
        return {
          subject: row.subject,
          summary: `Registration expiry of ${row.fqdn} changed from ${before} to ${after}`,
          before: { expires: before },
          after: { expires: after },
        };
      }
      return {
        subject: row.subject,
        summary: `Registrar of ${row.fqdn} changed from ${String(row.before)} to ${String(row.after)}`,
        before: { registrar: row.before },
        after: { registrar: row.after },
      };
    }
    case 'asset': {
      const a = asObj(row.after);
      if (row.subject === 'asset') {
        const source = String(a.source ?? 'unknown').replace(/_/g, ' ');
        return {
          subject: row.subject,
          summary: `New asset ${host} added (source: ${source})`,
          before: null,
          after: { source },
        };
      }
      const reason = typeof a.reason === 'string' && a.reason ? `: ${a.reason}` : '';
      return {
        subject: row.subject,
        summary: `Asset ${host} ${String(a.status)}${reason}`,
        before: null,
        after: { status: a.status, ...(reason ? { reason: a.reason } : {}) },
      };
    }
  }
}

function toEvent(row: EventRow): ChangeEvent {
  return {
    id: row.id,
    at: isoOf(row.at),
    kind: row.kind,
    domain: { id: row.domain_id, fqdn: row.fqdn },
    assetId: row.asset_id,
    hostname: row.hostname,
    ...present(row),
    severityHint: row.hint,
  };
}
