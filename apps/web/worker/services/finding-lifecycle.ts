import { schema, type Database } from '@exdomainvault/database';
import type { Rule } from '@exdomainvault/rules';
import {
  ACCEPTED_RISK_MAX_DAYS,
  SCAN_PROFILE_KEYS,
  canTransition,
  hasPermission,
  transitionRequirements,
  type AssignableUsersResponse,
  type CurrentUser,
  type Finding,
  type FindingBulkUpdateRequest,
  type FindingBulkUpdateResponse,
  type FindingComment,
  type FindingReassessResponse,
  type FindingStatus,
  type FindingUpdateRequest,
  type Permission,
} from '@exdomainvault/shared';
import { and, asc, eq, inArray, lte } from 'drizzle-orm';
import { firstRow } from '../lib/db.ts';
import { ApiError } from '../lib/errors.ts';
import { writeAudit, writeAuditMany, type AuditEntry } from './audit.ts';
import type { Actor } from './domains.ts';
import {
  isManualResolution,
  loadFinding,
  toCommentDto,
  visibleTo,
  type FindingRow,
} from './findings.ts';
import { createScan, listProfiles, type ScanPolicy } from './scans.ts';

const { findingComments, findingStatusHistory, findings, scanJobs, users } = schema;

/**
 * Finding lifecycle (design §9, Milestone 8): user status changes, assignment, comments,
 * reassessment and accepted-risk expiry. The transition table in `@exdomainvault/shared`
 * (`canTransition`, `transitionRequirements`) is the only definition of what users may do; this
 * module enforces it server-side, row-locked, with history and audit in the same transaction.
 *
 * Error mapping (codes are the shared ERROR_CODES; the specific cause is in `details[0].path`):
 *  - 403 `forbidden`: the user lacks the permission for this change (or for any finding change);
 *  - 404 `not_found`: the finding does not exist or is not visible to the user;
 *  - 409 `conflict` + path `expectedStatus`: the finding changed since the client read it;
 *  - 409 `conflict` + path `status`: no user may make this transition (e.g. from `resolved`,
 *    or resolving a finding whose rule resolves only through a scan);
 *  - 400 `validation_failed`: reason/review date/assignee requirements not met.
 */

type User = Pick<CurrentUser, 'id' | 'role'>;

const LIFECYCLE_PERMISSIONS: readonly Permission[] = [
  'findings:triage',
  'findings:remediate',
  'findings:accept_risk',
  'findings:assign',
];

const forbidden = () =>
  new ApiError(403, 'forbidden', 'You do not have permission to perform this action.');
const notFound = () => new ApiError(404, 'not_found', 'The requested resource was not found.');
const invalid = (path: string, message: string) =>
  new ApiError(400, 'validation_failed', 'The request is invalid.', [{ path, message }]);

function requireAnyLifecyclePermission(user: User) {
  if (!LIFECYCLE_PERMISSIONS.some((p) => hasPermission(user.role, p))) throw forbidden();
}

const can = (user: User) => (p: Permission) => hasPermission(user.role, p);

type TransitionCheck = 'ok' | 'invalid_transition' | 'transition_not_allowed';

function checkTransition(
  from: FindingStatus,
  to: FindingStatus,
  user: User,
  manualResolution: boolean,
): TransitionCheck {
  if (!canTransition(from, to, { can: () => true, manualResolution })) return 'invalid_transition';
  if (!canTransition(from, to, { can: can(user), manualResolution }))
    return 'transition_not_allowed';
  return 'ok';
}

interface StatusChange {
  to: FindingStatus;
  reason: string | undefined;
  reviewAt: Date | undefined;
}

/**
 * Validates the reason and review date a change to `to` must carry (from any other status).
 * `transitionRequirements` only varies with `from` for moves to `open`, which always need a
 * reason when they are a change at all, so this check is the same for every finding.
 */
function validateStatusChange(
  to: FindingStatus,
  body: { reason?: string; acceptedRiskReviewAt?: string },
  now: Date,
): StatusChange {
  const req = transitionRequirements(to === 'open' ? 'acknowledged' : 'open', to);
  const reason = body.reason?.trim();
  if (req.reason === 'required' && !reason)
    throw invalid('reason', 'A reason is required for this change.');
  if (reason !== undefined && reason.length < req.reasonMin)
    throw invalid('reason', `The reason must be at least ${req.reasonMin} characters.`);

  let reviewAt: Date | undefined;
  if (req.reviewDate) {
    if (!body.acceptedRiskReviewAt)
      throw invalid('acceptedRiskReviewAt', 'A review date is required to accept a risk.');
    reviewAt = new Date(body.acceptedRiskReviewAt);
    if (!(reviewAt.getTime() > now.getTime()))
      throw invalid('acceptedRiskReviewAt', 'The review date must be in the future.');
    if (reviewAt.getTime() > now.getTime() + ACCEPTED_RISK_MAX_DAYS * 86_400_000)
      throw invalid(
        'acceptedRiskReviewAt',
        `The review date must be within ${ACCEPTED_RISK_MAX_DAYS} days.`,
      );
  } else if (body.acceptedRiskReviewAt !== undefined) {
    throw invalid('acceptedRiskReviewAt', 'A review date applies only when accepting a risk.');
  }
  return { to, reason, reviewAt };
}

/** The assignee must be an existing, active user. */
async function validateAssignee(db: Database, assigneeId: string | null): Promise<void> {
  if (assigneeId === null) return;
  const [u] = await db
    .select({ isActive: users.isActive })
    .from(users)
    .where(eq(users.id, assigneeId.toLowerCase()));
  if (!u || !u.isActive) throw invalid('assigneeId', 'The assignee must be an active user.');
}

/** Applies one status change to locked rows (all currently ≠ `to`): row, history, audit. */
async function applyStatus(
  tx: Database,
  rows: FindingRow[],
  change: StatusChange,
  actor: Actor,
  now: Date,
  bulk: boolean,
): Promise<void> {
  if (rows.length === 0) return;
  const accepting = change.to === 'accepted_risk';
  await tx
    .update(findings)
    .set({
      status: change.to,
      resolvedAt: change.to === 'resolved' ? now : null,
      // Acceptance details exist only while the status is accepted_risk.
      acceptedRiskReason: accepting ? (change.reason ?? null) : null,
      acceptedRiskApprovedBy: accepting ? actor.userId : null,
      acceptedRiskReviewAt: accepting ? (change.reviewAt ?? null) : null,
      updatedAt: now,
    })
    .where(
      inArray(
        findings.id,
        rows.map((r) => r.id),
      ),
    );
  await tx.insert(findingStatusHistory).values(
    rows.map((r) => ({
      findingId: r.id,
      fromStatus: r.status,
      toStatus: change.to,
      changedBy: actor.userId,
      reason: 'manual',
      note: change.reason ?? null,
      createdAt: now,
    })),
  );
  await writeAuditMany(
    tx,
    rows.map((r): AuditEntry => ({
      actorType: 'user',
      actorUserId: actor.userId,
      action: accepting ? 'finding.risk_accepted' : 'finding.status_changed',
      resourceType: 'finding',
      resourceId: r.id,
      requestId: actor.requestId,
      metadata: {
        from: r.status,
        to: change.to,
        reason: change.reason ?? null,
        ruleId: r.ruleId,
        ...(accepting ? { reviewAt: change.reviewAt?.toISOString() } : {}),
        ...(bulk ? { bulk: true } : {}),
      },
    })),
  );
}

/** Assigns (or unassigns, `null`) locked rows whose assignee differs. */
async function applyAssignee(
  tx: Database,
  rows: FindingRow[],
  assigneeId: string | null,
  actor: Actor,
  now: Date,
  bulk: boolean,
): Promise<void> {
  if (rows.length === 0) return;
  await tx
    .update(findings)
    .set({ assignedTo: assigneeId, updatedAt: now })
    .where(
      inArray(
        findings.id,
        rows.map((r) => r.id),
      ),
    );
  await writeAuditMany(
    tx,
    rows.map((r): AuditEntry => ({
      actorType: 'user',
      actorUserId: actor.userId,
      action: assigneeId ? 'finding.assigned' : 'finding.unassigned',
      resourceType: 'finding',
      resourceId: r.id,
      requestId: actor.requestId,
      metadata: {
        assigneeId,
        previousAssigneeId: r.assignedTo,
        ...(bulk ? { bulk: true } : {}),
      },
    })),
  );
}

/** PATCH /findings/:id — status change and/or assignment, optimistic on `expectedStatus`. */
export async function updateFinding(
  db: Database,
  user: User,
  id: string,
  body: FindingUpdateRequest,
  rules: readonly Rule[],
  actor: Actor,
  now: Date,
): Promise<Finding> {
  requireAnyLifecyclePermission(user);
  if (body.assigneeId !== undefined && !hasPermission(user.role, 'findings:assign'))
    throw forbidden();
  if (body.status === undefined && body.reason !== undefined)
    throw invalid('reason', 'A reason applies only to a status change.');
  if (body.status !== 'accepted_risk' && body.acceptedRiskReviewAt !== undefined)
    throw invalid('acceptedRiskReviewAt', 'A review date applies only when accepting a risk.');
  if (body.assigneeId !== undefined) await validateAssignee(db, body.assigneeId);
  const assigneeId = body.assigneeId?.toLowerCase() ?? body.assigneeId;

  await db.transaction(async (raw) => {
    const tx = raw as unknown as Database;
    const [row] = await tx
      .select()
      .from(findings)
      .where(and(eq(findings.id, id), visibleTo(tx, user)))
      .for('update', { of: findings });
    if (!row) throw notFound();
    if (row.status !== body.expectedStatus) {
      throw new ApiError(409, 'conflict', 'The finding has changed since you loaded it.', [
        { path: 'expectedStatus', message: `The finding is now ${row.status}.` },
      ]);
    }

    // Re-sending the current status is not a change (and needs no reason). For a change: first
    // whether it exists and is permitted, then what it must carry.
    let statusChange: StatusChange | undefined;
    if (body.status !== undefined && body.status !== row.status) {
      const to = body.status;
      const check = checkTransition(row.status, to, user, isManualResolution(rules, row.ruleId));
      if (check === 'invalid_transition') {
        throw new ApiError(409, 'conflict', 'This status change is not possible.', [
          {
            path: 'status',
            message: `A finding cannot be moved from ${row.status} to ${to} by hand.`,
          },
        ]);
      }
      if (check === 'transition_not_allowed') throw forbidden();
      statusChange = validateStatusChange(to, body, now);
    }
    const assigneeRows = assigneeId !== undefined && assigneeId !== row.assignedTo ? [row] : [];

    if (statusChange) await applyStatus(tx, [row], statusChange, actor, now, false);
    await applyAssignee(tx, assigneeRows, assigneeId ?? null, actor, now, false);
  });
  return loadFinding(db, id, rules);
}

/** POST /findings/bulk — the same change applied to each finding individually. */
export async function bulkUpdateFindings(
  db: Database,
  user: User,
  body: FindingBulkUpdateRequest,
  rules: readonly Rule[],
  actor: Actor,
  now: Date,
): Promise<FindingBulkUpdateResponse> {
  requireAnyLifecyclePermission(user);
  if (body.assigneeId !== undefined && !hasPermission(user.role, 'findings:assign'))
    throw forbidden();
  const statusChange =
    body.status !== undefined ? validateStatusChange(body.status, body, now) : undefined;
  if (body.status === undefined && body.reason !== undefined)
    throw invalid('reason', 'A reason applies only to a status change.');
  if (body.assigneeId !== undefined) await validateAssignee(db, body.assigneeId);
  const assigneeId = body.assigneeId?.toLowerCase() ?? body.assigneeId;
  const ids = [...new Set(body.ids.map((i) => i.toLowerCase()))];

  return db.transaction(async (raw) => {
    const tx = raw as unknown as Database;
    // Locked in id order (as evaluation does) so concurrent multi-row lockers cannot deadlock.
    const rows = await tx
      .select()
      .from(findings)
      .where(and(inArray(findings.id, ids), visibleTo(tx, user)))
      .orderBy(asc(findings.id))
      .for('update', { of: findings });
    const byId = new Map(rows.map((r) => [r.id, r]));

    const skipped: FindingBulkUpdateResponse['skipped'] = [];
    const statusRows: FindingRow[] = [];
    const assigneeRows: FindingRow[] = [];
    for (const id of ids) {
      const row = byId.get(id);
      if (!row) {
        skipped.push({ id, code: 'not_found' });
        continue;
      }
      let statusChanges = false;
      if (statusChange && statusChange.to !== row.status) {
        const check = checkTransition(
          row.status,
          statusChange.to,
          user,
          isManualResolution(rules, row.ruleId),
        );
        if (check !== 'ok') {
          // All or nothing per finding: a refused status change also skips the assignment.
          skipped.push({ id, code: check });
          continue;
        }
        statusChanges = true;
      }
      const assigneeChanges = assigneeId !== undefined && assigneeId !== row.assignedTo;
      if (!statusChanges && !assigneeChanges) {
        skipped.push({ id, code: 'no_change' });
        continue;
      }
      if (statusChanges) statusRows.push(row);
      if (assigneeChanges) assigneeRows.push(row);
    }

    if (statusChange) await applyStatus(tx, statusRows, statusChange, actor, now, true);
    await applyAssignee(tx, assigneeRows, assigneeId ?? null, actor, now, true);
    const updated = new Set([...statusRows, ...assigneeRows].map((r) => r.id)).size;
    return { updated, skipped };
  });
}

/** Finds a finding the user can see (no lock). */
async function visibleFinding(db: Database, user: User, id: string): Promise<FindingRow> {
  const [row] = await db
    .select()
    .from(findings)
    .where(and(eq(findings.id, id), visibleTo(db, user)));
  if (!row) throw notFound();
  return row;
}

/** POST /findings/:id/comments — remediation notes (triage or remediate permission). */
export async function addComment(
  db: Database,
  user: User,
  id: string,
  body: string,
  actor: Actor,
  now: Date,
): Promise<FindingComment> {
  if (
    !hasPermission(user.role, 'findings:triage') &&
    !hasPermission(user.role, 'findings:remediate')
  )
    throw forbidden();
  await visibleFinding(db, user, id);
  return db.transaction(async (raw) => {
    const tx = raw as unknown as Database;
    const c = firstRow(
      await tx
        .insert(findingComments)
        .values({ findingId: id, authorUserId: actor.userId, body, createdAt: now })
        .returning(),
    );
    await writeAudit(tx, {
      actorType: 'user',
      actorUserId: actor.userId,
      action: 'finding.commented',
      resourceType: 'finding',
      resourceId: id,
      requestId: actor.requestId,
      // Never the body itself: comments may hold operational detail not meant for the audit log.
      metadata: { commentId: c.id, length: body.length },
    });
    const [author] = await tx
      .select({ id: users.id, email: users.email, displayName: users.displayName })
      .from(users)
      .where(eq(users.id, actor.userId));
    return toCommentDto(c, author ?? null);
  });
}

async function activeJobFor(db: Database, domainId: string, profile: string) {
  const [job] = await db
    .select({ id: scanJobs.id })
    .from(scanJobs)
    .where(
      and(
        eq(scanJobs.domainId, domainId),
        eq(scanJobs.profile, profile),
        inArray(scanJobs.status, ['queued', 'claimed', 'running']),
      ),
    )
    .limit(1);
  return job;
}

/**
 * POST /findings/:id/reassess — queues a scan of the finding's domain with the cheapest enabled
 * profile (passive < quick < standard < deep) that runs one of the rule's checks. Scan creation
 * rules (active scanning switch, domain authorisation, approved targets, audit) are createScan's.
 * An identical queued/running job is returned instead of a new one (`created: false`).
 */
export async function reassessFinding(
  db: Database,
  user: User,
  id: string,
  rules: readonly Rule[],
  actor: Actor,
  now: Date,
  policy: ScanPolicy,
): Promise<FindingReassessResponse> {
  const finding = await visibleFinding(db, user, id);
  const rule = rules.find((r) => r.id === finding.ruleId);
  const profiles = (await listProfiles(db)).filter((p) => p.enabled);
  const profile = rule
    ? SCAN_PROFILE_KEYS.map((k) => profiles.find((p) => p.key === k)).find(
        (p) =>
          p !== undefined &&
          rule.requiresChecks.some((c) => (p.config.checks as readonly string[]).includes(c)),
      )
    : undefined;
  if (!profile) {
    throw new ApiError(409, 'conflict', 'No scan profile re-checks this finding.', [
      { path: 'ruleId', message: `No enabled scan profile runs the checks of ${finding.ruleId}.` },
    ]);
  }

  const existing = await activeJobFor(db, finding.domainId, profile.key);
  if (existing) return { scanJobId: existing.id, profile: profile.key, created: false };
  try {
    const jobId = await createScan(
      db,
      finding.domainId,
      { profile: profile.key, reason: `Reassess finding ${finding.id} (${finding.ruleId})` },
      actor,
      now,
      policy,
    );
    return { scanJobId: jobId, profile: profile.key, created: true };
  } catch (err) {
    // Lost a race with another request creating the same job: return that job.
    if (err instanceof ApiError && err.status === 409) {
      const raced = await activeJobFor(db, finding.domainId, profile.key);
      if (raced) return { scanJobId: raced.id, profile: profile.key, created: false };
    }
    throw err;
  }
}

/** GET /users/assignable — active users, by email. */
export async function listAssignableUsers(db: Database): Promise<AssignableUsersResponse> {
  const rows = await db
    .select({ id: users.id, email: users.email, displayName: users.displayName, role: users.role })
    .from(users)
    .where(eq(users.isActive, true))
    .orderBy(asc(users.email));
  return { items: rows };
}

// Raw timestamps from a subquery may come back as strings, depending on the driver.
const toIso = (v: Date | string | null): string | null =>
  v === null ? null : new Date(v).toISOString();

/** Findings returned to `open` per maintenance run (oldest review date first). */
const EXPIRY_BATCH = 500;

/**
 * Maintenance: accepted risks whose review date has passed return to `open` (history reason
 * `accepted_risk_expired`, the lapsed reason kept in the note; system audit). Rows locked by a
 * concurrent user change are skipped and picked up by the next run.
 */
export async function expireAcceptedRisks(db: Database, now: Date): Promise<number> {
  return db.transaction(async (raw) => {
    const tx = raw as unknown as Database;
    // One statement: lock the lapsed rows (skipping rows a user is changing right now), reopen
    // them and return their previous acceptance for history and audit.
    const lapsed = tx
      .select({
        id: findings.id,
        reason: findings.acceptedRiskReason,
        approvedBy: findings.acceptedRiskApprovedBy,
        reviewAt: findings.acceptedRiskReviewAt,
        ruleId: findings.ruleId,
      })
      .from(findings)
      .where(and(eq(findings.status, 'accepted_risk'), lte(findings.acceptedRiskReviewAt, now)))
      .orderBy(asc(findings.id))
      .limit(EXPIRY_BATCH)
      .for('update', { skipLocked: true })
      .as('lapsed');
    const due = await tx
      .update(findings)
      .set({
        status: 'open',
        acceptedRiskReason: null,
        acceptedRiskApprovedBy: null,
        acceptedRiskReviewAt: null,
        updatedAt: now,
      })
      .from(lapsed)
      .where(eq(findings.id, lapsed.id))
      .returning({
        id: findings.id,
        acceptedRiskReason: lapsed.reason,
        acceptedRiskApprovedBy: lapsed.approvedBy,
        acceptedRiskReviewAt: lapsed.reviewAt,
        ruleId: lapsed.ruleId,
      });
    if (due.length === 0) return 0;
    await tx.insert(findingStatusHistory).values(
      due.map((f) => ({
        findingId: f.id,
        fromStatus: 'accepted_risk' as const,
        toStatus: 'open' as const,
        changedBy: null,
        reason: 'accepted_risk_expired',
        note: f.acceptedRiskReason,
        createdAt: now,
      })),
    );
    await writeAuditMany(
      tx,
      due.map((f): AuditEntry => ({
        actorType: 'system',
        action: 'finding.risk_acceptance_expired',
        resourceType: 'finding',
        resourceId: f.id,
        metadata: {
          reviewAt: toIso(f.acceptedRiskReviewAt),
          approvedBy: f.acceptedRiskApprovedBy,
          ruleId: f.ruleId,
        },
      })),
    );
    return due.length;
  });
}
