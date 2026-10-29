import { schema, type Database } from '@exdomainvault/database';
import {
  DEFAULT_SLA_POLICY,
  SEVERITIES,
  SLA_POLICY_SETTING_KEY,
  slaPolicySchema,
  type SlaPolicy,
  type SlaPolicyResponse,
} from '@exdomainvault/shared';
import { and, eq, inArray, isNull, ne, sql, type SQL } from 'drizzle-orm';
import { writeAudit } from './audit.ts';
import type { Actor } from './domains.ts';

const { applicationSettings, findings, users } = schema;

/**
 * Remediation SLAs (Milestone 14, contract in packages/shared/src/api/sla.ts).
 *
 * `findings.due_at` is stored (so lists can filter and sort on it) and maintained here:
 *  - set when a finding is created, reopened by a recurrence, or its severity changes on
 *    re-evaluation (evaluation.ts), and when it leaves accepted risk (finding-lifecycle.ts);
 *  - recomputed for every non-resolved finding when the policy changes;
 *  - backfilled by the cron for findings that predate the column (`backfillDueDates`).
 * Resolved findings keep their due date: SLA compliance compares it with `resolved_at`.
 *
 * The SLA clock starts at `first_seen_at`, or at the last status-history entry that took the
 * finding out of `resolved` (recurrence) or `accepted_risk` (lapsed or withdrawn acceptance) into a
 * working status, whichever is later — always derived from history, so recomputation is idempotent.
 */

/** The stored policy, or the default when missing or no longer valid. */
export async function readSlaPolicy(db: Database): Promise<{
  policy: SlaPolicy;
  row: typeof applicationSettings.$inferSelect | null;
}> {
  const [row] = await db
    .select()
    .from(applicationSettings)
    .where(eq(applicationSettings.key, SLA_POLICY_SETTING_KEY));
  if (!row) return { policy: { ...DEFAULT_SLA_POLICY }, row: null };
  const parsed = slaPolicySchema.safeParse(row.value);
  return { policy: parsed.success ? parsed.data : { ...DEFAULT_SLA_POLICY }, row };
}

/**
 * SQL: when the SLA clock of the `findings` row in scope started. Columns are written with the
 * explicit table name so the expression also works inside single-table UPDATE statements.
 */
export const slaClockStart = sql`greatest("findings"."first_seen_at", (
  select max(h.created_at) from finding_status_history h
  where h.finding_id = "findings"."id"
    and h.from_status in ('resolved', 'accepted_risk')
    and h.to_status not in ('resolved', 'accepted_risk')
))`;

/** SQL: the due date of the `findings` row in scope under `policy` (null: no SLA). */
export function dueAtExpression(policy: SlaPolicy): SQL {
  const branches = SEVERITIES.filter((s) => policy[s] !== null).map(
    (s) =>
      sql`when ${s} then ${slaClockStart} + make_interval(days => ${policy[s] as number}::int)`,
  );
  if (branches.length === 0) return sql`null::timestamptz`;
  return sql`(case "findings"."severity"::text ${sql.join(branches, sql` `)} else null::timestamptz end)`;
}

/** SQL predicate on the `findings` row in scope: overdue at `now`. */
export function overdueAt(now: Date): SQL {
  return sql`("findings"."status" not in ('resolved', 'accepted_risk') and "findings"."due_at" is not null and "findings"."due_at" < ${now.toISOString()}::timestamptz)`;
}

/**
 * Recomputes `due_at` for the findings matching `where` under `policy`; rows whose due date is
 * already right are not touched. Returns the number of rows changed.
 */
export async function recomputeDueAt(
  db: Database,
  policy: SlaPolicy,
  where: SQL | undefined,
): Promise<number> {
  const expr = dueAtExpression(policy);
  const rows = await db
    .update(findings)
    .set({ dueAt: expr })
    .where(and(where, sql`"findings"."due_at" is distinct from ${expr}`))
    .returning({ id: findings.id });
  return rows.length;
}

/** Recomputes the due date of the given findings with the stored policy (no-op for none). */
export async function refreshDueDates(db: Database, ids: readonly string[]): Promise<number> {
  if (ids.length === 0) return 0;
  const { policy } = await readSlaPolicy(db);
  return recomputeDueAt(db, policy, inArray(findings.id, [...new Set(ids)]));
}

/**
 * Cron step: findings without a due date whose severity has an SLA get one (findings created before
 * Milestone 14, or a severity that gained an SLA). Includes resolved findings, so compliance has a
 * due date to compare with. Idempotent: once set, a row no longer matches.
 */
export async function backfillDueDates(db: Database): Promise<number> {
  const { policy } = await readSlaPolicy(db);
  const withSla = SEVERITIES.filter((s) => policy[s] !== null);
  if (withSla.length === 0) return 0;
  return recomputeDueAt(
    db,
    policy,
    and(isNull(findings.dueAt), inArray(findings.severity, withSla)),
  );
}

export async function getSlaPolicyResponse(db: Database): Promise<SlaPolicyResponse> {
  const { policy, row } = await readSlaPolicy(db);
  const [updater] = row?.updatedBy
    ? await db
        .select({ id: users.id, email: users.email })
        .from(users)
        .where(eq(users.id, row.updatedBy))
    : [];
  return {
    policy,
    updatedAt: row ? row.updatedAt.toISOString() : null,
    updatedBy: updater ?? null,
  };
}

/**
 * PUT /settings/sla: saves the policy and recomputes the due date of every non-resolved finding in
 * the same transaction (one set-based statement), audited `settings.sla_updated` with before/after.
 */
export async function updateSlaPolicy(
  db: Database,
  input: SlaPolicy,
  actor: Actor,
  now: Date,
): Promise<{ recomputed: number }> {
  return db.transaction(async (raw) => {
    const tx = raw as unknown as Database;
    const [existing] = await tx
      .select()
      .from(applicationSettings)
      .where(eq(applicationSettings.key, SLA_POLICY_SETTING_KEY))
      .for('update');
    const before = existing
      ? (slaPolicySchema.safeParse(existing.value).data ?? existing.value)
      : null;
    await tx
      .insert(applicationSettings)
      .values({
        key: SLA_POLICY_SETTING_KEY,
        value: input,
        updatedBy: actor.userId,
        updatedAt: now,
      })
      .onConflictDoUpdate({
        target: applicationSettings.key,
        set: { value: input, updatedBy: actor.userId, updatedAt: now },
      });
    const recomputed = await recomputeDueAt(tx, input, ne(findings.status, 'resolved'));
    await writeAudit(tx, {
      actorType: 'user',
      actorUserId: actor.userId,
      action: 'settings.sla_updated',
      resourceType: 'application_setting',
      resourceId: SLA_POLICY_SETTING_KEY,
      requestId: actor.requestId,
      metadata: { key: SLA_POLICY_SETTING_KEY, before, after: input, recomputed },
    });
    return { recomputed };
  });
}
