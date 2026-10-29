import { schema, type Database } from '@exdomainvault/database';
import {
  SCORE_TREND_DAYS,
  computeSecurityScore,
  gradeSchema,
  type DomainScoreResponse,
  type Grade,
  type ScoreFindingState,
  type ScoreInputGroup,
  type SecurityScore,
  type Severity,
} from '@exdomainvault/shared';
import { and, asc, eq, gte, sql, type SQL } from 'drizzle-orm';
import { ApiError } from '../lib/errors.ts';

const { domainScoreSnapshots, domains } = schema;

/**
 * Security score (Milestone 14; formula in packages/shared/src/domain/security-score.ts and
 * docs/security-score.md). Scores are computed from the domain's non-resolved findings with one
 * aggregate statement and stored once per domain per UTC day (`domain_score_snapshots`, upsert).
 * Only domains with at least one successfully completed, rules-evaluated job are scored.
 */

const DAY_MS = 86_400_000;
/** Today's snapshots are refreshed by the cron at most this often. */
export const SCORE_REFRESH_MS = 3600 * 1000;
const UPSERT_CHUNK = 500;

const utcDay = (d: Date) => d.toISOString().slice(0, 10);

/** Rows of a raw statement (node-postgres and PGlite both return `{ rows }`). */
async function rowsOf<T>(db: Database, query: SQL): Promise<T[]> {
  const res = (await db.execute(query)) as unknown as { rows: T[] };
  return res.rows;
}

/** SQL: the `domains` row in scope has been scanned successfully (and evaluated) at least once. */
export const domainIsScored = sql`exists (
  select 1 from scan_jobs j
  where j.domain_id = "domains"."id" and j.status = 'succeeded' and j.rules_evaluated_at is not null
)`;

/** SQL: latest snapshot score / grade of the `domains` row in scope (null when none). */
export const latestScoreSql = sql<number | null>`(
  select s.score from domain_score_snapshots s
  where s.domain_id = "domains"."id" order by s.day desc limit 1
)`;
export const latestGradeSql = sql<string | null>`(
  select s.grade from domain_score_snapshots s
  where s.domain_id = "domains"."id" order by s.day desc limit 1
)`;

/** A stored grade (text column) as a Grade, or null. */
export const asGrade = (g: unknown): Grade | null => gradeSchema.safeParse(g).data ?? null;

/**
 * Score inputs per domain, one statement: non-resolved findings grouped by category, severity and
 * state (accepted risk / overdue at `now` / open). `domainIds` undefined → every domain.
 */
async function scoreInputs(
  db: Database,
  now: Date,
  domainIds?: readonly string[],
): Promise<Map<string, ScoreInputGroup[]>> {
  if (domainIds && domainIds.length === 0) return new Map();
  const at = now.toISOString();
  const scope = domainIds
    ? sql`and f.domain_id in (${sql.join(
        domainIds.map((id) => sql`${id}::uuid`),
        sql`, `,
      )})`
    : sql``;
  const rows = await rowsOf<{
    domain_id: string;
    category: string;
    severity: Severity;
    state: ScoreFindingState;
    n: number;
  }>(
    db,
    sql`select f.domain_id, f.category, f.severity,
          case when f.status = 'accepted_risk' then 'accepted_risk'
               when f.due_at is not null and f.due_at < ${at}::timestamptz then 'overdue'
               else 'open' end as state,
          count(*)::int as n
        from findings f
        where f.status <> 'resolved' ${scope}
        group by 1, 2, 3, 4`,
  );
  const out = new Map<string, ScoreInputGroup[]>();
  for (const r of rows) {
    const list = out.get(r.domain_id) ?? [];
    list.push({ category: r.category, severity: r.severity, state: r.state, count: Number(r.n) });
    out.set(r.domain_id, list);
  }
  return out;
}

/** Current scores of the scored domains among `domainIds` (all scored domains when undefined). */
export async function computeDomainScores(
  db: Database,
  now: Date,
  domainIds?: readonly string[],
): Promise<Map<string, SecurityScore>> {
  const scored = await db
    .select({ id: domains.id })
    .from(domains)
    .where(
      and(
        domainIsScored,
        domainIds
          ? sql`"domains"."id" in (${sql.join(
              domainIds.map((id) => sql`${id}::uuid`),
              sql`, `,
            )})`
          : undefined,
      ),
    );
  if (scored.length === 0) return new Map();
  const inputs = await scoreInputs(db, now, domainIds ? scored.map((d) => d.id) : undefined);
  return new Map(
    scored.map((d) => [d.id, computeSecurityScore({ findings: inputs.get(d.id) ?? [] })]),
  );
}

/** Upserts today's snapshot (UTC day of `now`) for each scored domain given. */
async function upsertSnapshots(
  db: Database,
  scores: Map<string, SecurityScore>,
  now: Date,
): Promise<number> {
  const day = utcDay(now);
  const values = [...scores].map(([domainId, s]) => ({
    domainId,
    day,
    score: s.score,
    grade: s.grade,
    inputs: { version: s.version, findings: s.inputs } as Record<string, unknown>,
    createdAt: now,
  }));
  for (let i = 0; i < values.length; i += UPSERT_CHUNK) {
    await db
      .insert(domainScoreSnapshots)
      .values(values.slice(i, i + UPSERT_CHUNK))
      .onConflictDoUpdate({
        target: [domainScoreSnapshots.domainId, domainScoreSnapshots.day],
        set: {
          score: sql`excluded.score`,
          grade: sql`excluded.grade`,
          inputs: sql`excluded.inputs`,
          // `created_at` records when the day's value was last computed.
          createdAt: sql`excluded.created_at`,
        },
      });
  }
  return values.length;
}

/**
 * Cron step: writes today's snapshot for every scored domain. Runs the (set-based) computation only
 * when some scored domain has no snapshot for today or today's is older than SCORE_REFRESH_MS, so
 * the 5-minute cron recomputes at most hourly. Idempotent (upsert on domain + day).
 */
export async function snapshotSecurityScores(db: Database, now: Date): Promise<number> {
  const day = utcDay(now);
  const staleBefore = new Date(now.getTime() - SCORE_REFRESH_MS).toISOString();
  const [due] = await rowsOf<{ n: number }>(
    db,
    sql`select count(*)::int as n from domains
        where ${domainIsScored}
          and not exists (
            select 1 from domain_score_snapshots s
            where s.domain_id = "domains"."id" and s.day = ${day}::date
              and s.created_at >= ${staleBefore}::timestamptz
          )`,
  );
  if (!due || Number(due.n) === 0) return 0;
  return upsertSnapshots(db, await computeDomainScores(db, now), now);
}

/** Latest snapshot score and grade of one domain (null when it has none). */
export async function latestScoreOf(
  db: Database,
  domainId: string,
): Promise<{ score: number | null; grade: Grade | null }> {
  const [row] = await db
    .select({ score: domainScoreSnapshots.score, grade: domainScoreSnapshots.grade })
    .from(domainScoreSnapshots)
    .where(eq(domainScoreSnapshots.domainId, domainId))
    .orderBy(sql`${domainScoreSnapshots.day} desc`)
    .limit(1);
  return row ? { score: row.score, grade: asGrade(row.grade) } : { score: null, grade: null };
}

/**
 * GET /domains/:id/score: the live score with its deductions, and the 90-day daily trend. When the
 * domain is scored but today's snapshot is missing, it is written now (so the trend has today).
 */
export async function getDomainScore(
  db: Database,
  domainId: string,
  now: Date,
): Promise<DomainScoreResponse> {
  const [domain] = await db
    .select({ id: domains.id, fqdn: domains.fqdn })
    .from(domains)
    .where(eq(domains.id, domainId));
  if (!domain) throw new ApiError(404, 'not_found', 'The requested resource was not found.');

  const current = (await computeDomainScores(db, now, [domainId])).get(domainId) ?? null;
  const today = utcDay(now);
  if (current) {
    const [existing] = await db
      .select({ id: domainScoreSnapshots.id })
      .from(domainScoreSnapshots)
      .where(and(eq(domainScoreSnapshots.domainId, domainId), eq(domainScoreSnapshots.day, today)));
    if (!existing) await upsertSnapshots(db, new Map([[domainId, current]]), now);
  }

  const since = utcDay(new Date(now.getTime() - (SCORE_TREND_DAYS - 1) * DAY_MS));
  const rows = await db
    .select({
      day: domainScoreSnapshots.day,
      score: domainScoreSnapshots.score,
      grade: domainScoreSnapshots.grade,
    })
    .from(domainScoreSnapshots)
    .where(and(eq(domainScoreSnapshots.domainId, domainId), gte(domainScoreSnapshots.day, since)))
    .orderBy(asc(domainScoreSnapshots.day));
  const trend = rows.flatMap((r) => {
    const grade = asGrade(r.grade);
    return grade ? [{ day: String(r.day), score: r.score, grade }] : [];
  });
  // Today's point shows the live value (the stored one may be up to an hour old).
  if (current) {
    const last = trend[trend.length - 1];
    if (last?.day === today) {
      last.score = current.score;
      last.grade = current.grade;
    } else trend.push({ day: today, score: current.score, grade: current.grade });
  }
  return { domain, current, trend, trendDays: SCORE_TREND_DAYS };
}
