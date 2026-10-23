// @vitest-environment node
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import type { Rule } from '@exdomainvault/rules';
import {
  ACCEPTED_RISK_MAX_DAYS,
  FINDING_STATUSES,
  assignableUsersResponseSchema,
  errorResponseSchema,
  findingBulkUpdateResponseSchema,
  findingCommentResponseSchema,
  findingDetailResponseSchema,
  findingListResponseSchema,
  findingReassessResponseSchema,
  findingUpdateResponseSchema,
  type FindingStatus,
  type Role,
} from '@exdomainvault/shared';
import { and, asc, eq, inArray } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createLogger } from '../lib/logger.ts';
import { evaluateJob } from '../services/evaluation.ts';
import { expireAcceptedRisks } from '../services/finding-lifecycle.ts';
import { runMaintenance } from '../services/maintenance.ts';
import {
  FAKE_RULES,
  dnsFor,
  seedDomain,
  seedJob,
  type Seed,
} from '../testing/findings-fixtures.ts';
import { ensureUser, harness, userCall } from '../testing/harness.ts';

const { auditLogs, domains, findingStatusHistory, findings, scanJobs, users } = schema;

/** Rules that only exist so reassessment can pick a profile per check (never evaluated here). */
const checkRule = (id: string, category: Rule['category'], checks: string[]): Rule => ({
  ...FAKE_RULES[0]!,
  id,
  category,
  requiresChecks: checks,
});
const EXTRA_RULES: Rule[] = [
  checkRule('TST-TLS', 'tls', ['tls_certificate', 'tls_configuration']),
  checkRule('TST-HDR', 'http', ['http_headers']),
  checkRule('TST-PORT', 'exposure', ['tcp_ports']),
  checkRule('TST-TLSCFG', 'tls', ['tls_configuration']),
  checkRule('TST-DISC', 'asset', ['discovery']),
];

let t: TestDatabase;
let clock: Date;
const h = harness(
  () => t,
  () => clock,
  { rules: [...FAKE_RULES, ...EXTRA_RULES] },
);

beforeAll(async () => {
  t = await createTestDatabase();
}, 30_000);
afterAll(async () => {
  await t?.close();
});

beforeEach(async () => {
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
  clock = new Date('2026-10-22T10:00:00.000Z');
  await t.db.delete(findings);
  await t.db.delete(scanJobs);
  await t.db.delete(schema.assets);
  await t.db.delete(domains);
  await t.db.delete(auditLogs);
});
afterEach(() => vi.restoreAllMocks());

const ROLES: readonly Role[] = ['admin', 'analyst', 'asset_owner', 'viewer'];

const call = (
  role: Role,
  method: string,
  path: string,
  body?: unknown,
  env: Record<string, string> = {},
) => userCall(h, t, role, method, path, body, env);

async function expectError(res: Response, status: number, code: string, path?: string) {
  expect(res.status).toBe(status);
  const body = errorResponseSchema.parse(await res.json());
  expect(body.error.code).toBe(code);
  if (path) expect(body.error.details?.[0]?.path).toBe(path);
  return body;
}

const at = (hours: number) => new Date(Date.parse('2026-10-20T00:00:00.000Z') + hours * 3600_000);
const days = (n: number) => new Date(clock.getTime() + n * 86_400_000).toISOString();
const REASON = 'Reviewed with the service owner';

interface World {
  a: Seed;
  /** TST-HOST on www (asset owned by the asset owner; scan-resolved only). */
  hostWww: string;
  /** TST-ACHANGE on www (owned; manual resolution). */
  changeWww: string;
  /** TST-DMARC, domain level (invisible to the asset owner). */
  dmarc: string;
  hostApex: string;
  changeApex: string;
}

async function findingId(ruleId: string, hostname: string): Promise<string> {
  const [row] = await t.db
    .select({ id: findings.id })
    .from(findings)
    .where(and(eq(findings.ruleId, ruleId), eq(findings.hostname, hostname)));
  if (!row) throw new Error(`no finding ${ruleId} ${hostname}`);
  return row.id;
}

/** a.example: DMARC missing, both hosts resolve, then both A record sets change. */
async function seedWorld(): Promise<World> {
  const a = await seedDomain(t, 'a.example', { owned: true });
  const fqdn = a.fqdn;
  await evaluateJob(
    t.db,
    await seedJob(
      t,
      a.domainId,
      at(1),
      dnsFor(fqdn, { apexA: ['192.0.2.1'], wwwA: ['192.0.2.2'] }),
    ),
    clock,
    FAKE_RULES,
  );
  await evaluateJob(
    t.db,
    await seedJob(
      t,
      a.domainId,
      at(2),
      dnsFor(fqdn, { apexA: ['192.0.2.9'], wwwA: ['192.0.2.8'] }),
    ),
    clock,
    FAKE_RULES,
  );
  return {
    a,
    hostWww: await findingId('TST-HOST', `www.${fqdn}`),
    changeWww: await findingId('TST-ACHANGE', `www.${fqdn}`),
    dmarc: await findingId('TST-DMARC', fqdn),
    hostApex: await findingId('TST-HOST', fqdn),
    changeApex: await findingId('TST-ACHANGE', fqdn),
  };
}

/** Puts a finding directly into a status (test setup, bypassing the API). */
async function forceStatus(id: string, status: FindingStatus) {
  const admin = await ensureUser(t, 'admin');
  const accepted = status === 'accepted_risk';
  await t.db
    .update(findings)
    .set({
      status,
      resolvedAt: status === 'resolved' ? at(3) : null,
      acceptedRiskReason: accepted ? 'Accepted in test setup' : null,
      acceptedRiskApprovedBy: accepted ? admin : null,
      acceptedRiskReviewAt: accepted ? new Date(days(30)) : null,
    })
    .where(eq(findings.id, id));
}

const row = async (id: string) =>
  (await t.db.select().from(findings).where(eq(findings.id, id)))[0]!;
const historyOf = (id: string) =>
  t.db
    .select()
    .from(findingStatusHistory)
    .where(eq(findingStatusHistory.findingId, id))
    .orderBy(asc(findingStatusHistory.createdAt), asc(findingStatusHistory.id));
const auditFor = (id: string, action?: string) =>
  t.db
    .select()
    .from(auditLogs)
    .where(and(eq(auditLogs.resourceId, id), action ? eq(auditLogs.action, action) : undefined))
    .orderBy(asc(auditLogs.createdAt));

const patch = (role: Role, id: string, body: Record<string, unknown>) =>
  call(role, 'PATCH', `/findings/${id}`, body);

/**
 * The transition table, written out independently of `allowedTransitions` so the API is checked
 * against the specification rather than against itself. `resolved` by hand: manual-resolution
 * rules only.
 */
const FULL: Record<FindingStatus, FindingStatus[]> = {
  open: ['acknowledged', 'remediation_in_progress', 'accepted_risk', 'resolved'],
  acknowledged: ['remediation_in_progress', 'open', 'accepted_risk', 'resolved'],
  remediation_in_progress: ['acknowledged', 'open', 'accepted_risk', 'resolved'],
  accepted_risk: ['open', 'resolved'],
  resolved: [],
};
const OWNER: Record<FindingStatus, FindingStatus[]> = {
  open: ['remediation_in_progress'],
  acknowledged: ['remediation_in_progress'],
  remediation_in_progress: ['acknowledged'],
  accepted_risk: [],
  resolved: [],
};
const allowedFor = (role: Role): Record<FindingStatus, FindingStatus[]> | null =>
  role === 'viewer' ? null : role === 'asset_owner' ? OWNER : FULL;

describe('PATCH /findings/:id — transition matrix', () => {
  it.each(ROLES)('enforces every transition for %s', async (role) => {
    const w = await seedWorld();
    const userId = await ensureUser(t, role);
    let successes = 0;
    for (const manual of [false, true]) {
      // Both owned by the asset owner, so visibility is not what is being tested here.
      const id = manual ? w.changeWww : w.hostWww;
      for (const from of FINDING_STATUSES) {
        for (const to of FINDING_STATUSES) {
          if (to === from) continue;
          await forceStatus(id, from);
          clock = new Date(clock.getTime() + 1000); // history entries ordered by time
          const res = await patch(role, id, {
            expectedStatus: from,
            status: to,
            reason: REASON,
            ...(to === 'accepted_risk' ? { acceptedRiskReviewAt: days(90) } : {}),
          });
          const possible = FULL[from].includes(to) && (to !== 'resolved' || manual);
          const allowed = allowedFor(role)?.[from].includes(to) === true && possible;
          const label = `${role} ${from}→${to} manual=${manual}`;
          if (allowed) {
            expect(res.status, label).toBe(200);
            const body = findingUpdateResponseSchema.parse(await res.json());
            expect(body.finding.status, label).toBe(to);
            const r = await row(id);
            expect(r.status, label).toBe(to);
            expect(r.resolvedAt !== null, label).toBe(to === 'resolved');
            expect(r.acceptedRiskReason !== null, label).toBe(to === 'accepted_risk');
            const last = (await historyOf(id)).at(-1)!;
            expect(last, label).toMatchObject({
              fromStatus: from,
              toStatus: to,
              changedBy: userId,
              reason: 'manual',
              note: REASON,
            });
            successes++;
          } else {
            const status = role === 'viewer' || possible ? 403 : 409;
            const code = status === 403 ? 'forbidden' : 'conflict';
            await expectError(res, status, code);
            expect((await row(id)).status, label).toBe(from);
          }
        }
      }
    }
    const audits = await t.db
      .select()
      .from(auditLogs)
      .where(inArray(auditLogs.action, ['finding.status_changed', 'finding.risk_accepted']));
    expect(audits).toHaveLength(successes);
    expect(audits.every((x) => x.actorUserId === userId)).toBe(true);
    expect(successes).toBe({ admin: 24, analyst: 24, asset_owner: 6, viewer: 0 }[role]);
  });

  it('hides findings outside the asset owner’s assets (404), even for valid transitions', async () => {
    const w = await seedWorld();
    for (const id of [w.dmarc, w.hostApex]) {
      await expectError(
        await patch('asset_owner', id, {
          expectedStatus: 'open',
          status: 'remediation_in_progress',
        }),
        404,
        'not_found',
      );
      expect((await row(id)).status).toBe('open');
    }
    await expectError(
      await patch('admin', '00000000-0000-4000-8000-000000000000', {
        expectedStatus: 'open',
        status: 'acknowledged',
      }),
      404,
      'not_found',
    );
  });

  it('keeps resolved terminal by hand and reports it as a conflict on status', async () => {
    const w = await seedWorld();
    await forceStatus(w.changeApex, 'resolved');
    await expectError(
      await patch('admin', w.changeApex, {
        expectedStatus: 'resolved',
        status: 'open',
        reason: REASON,
      }),
      409,
      'conflict',
      'status',
    );
    // Scan-resolved rules cannot be resolved by hand, even by an admin.
    await expectError(
      await patch('admin', w.hostApex, {
        expectedStatus: 'open',
        status: 'resolved',
        reason: REASON,
      }),
      409,
      'conflict',
      'status',
    );
  });
});

describe('PATCH /findings/:id — details', () => {
  it('accepts a risk with reason, approver and review date, and clears them when it is reopened', async () => {
    const w = await seedWorld();
    const analyst = await ensureUser(t, 'analyst');
    const res = await patch('analyst', w.dmarc, {
      expectedStatus: 'open',
      status: 'accepted_risk',
      reason: 'Mail is not sent from this domain',
      acceptedRiskReviewAt: days(90),
    });
    expect(res.status).toBe(200);
    const { finding } = findingUpdateResponseSchema.parse(await res.json());
    expect(finding.acceptedRisk).toEqual({
      reason: 'Mail is not sent from this domain',
      approvedBy: { id: analyst, email: 'analyst@example.com', displayName: null },
      reviewAt: days(90),
    });
    const [audit] = await auditFor(w.dmarc, 'finding.risk_accepted');
    expect(audit).toMatchObject({ actorType: 'user', actorUserId: analyst });
    expect(audit!.metadata).toMatchObject({
      from: 'open',
      to: 'accepted_risk',
      reason: 'Mail is not sent from this domain',
      reviewAt: days(90),
    });
    expect(await auditFor(w.dmarc, 'finding.status_changed')).toHaveLength(0);

    const back = await patch('admin', w.dmarc, {
      expectedStatus: 'accepted_risk',
      status: 'open',
      reason: 'Mail now sent from here',
    });
    const reopened = findingUpdateResponseSchema.parse(await back.json()).finding;
    expect(reopened).toMatchObject({ status: 'open', acceptedRisk: null });
    expect(await row(w.dmarc)).toMatchObject({
      acceptedRiskReason: null,
      acceptedRiskApprovedBy: null,
      acceptedRiskReviewAt: null,
    });
    const [changed] = await auditFor(w.dmarc, 'finding.status_changed');
    expect(changed!.metadata).toMatchObject({ from: 'accepted_risk', to: 'open' });
  });

  it('resolves a manual-resolution finding with resolved_at and a manual history entry', async () => {
    const w = await seedWorld();
    const res = await patch('analyst', w.changeApex, {
      expectedStatus: 'open',
      status: 'resolved',
      reason: 'Planned migration to new hosting',
    });
    const { finding } = findingUpdateResponseSchema.parse(await res.json());
    expect(finding).toMatchObject({
      status: 'resolved',
      resolvedAt: clock.toISOString(),
      manualResolution: true,
    });
    const detail = findingDetailResponseSchema.parse(
      await (await call('viewer', 'GET', `/findings/${w.changeApex}`)).json(),
    );
    expect(detail.history.at(-1)).toMatchObject({
      fromStatus: 'open',
      toStatus: 'resolved',
      reason: 'manual',
      note: 'Planned migration to new hosting',
      changedBy: { email: 'analyst@example.com' },
    });
  });

  it('enforces reason and review-date requirements', async () => {
    const w = await seedWorld();
    const cases: [Record<string, unknown>, string][] = [
      [{ status: 'accepted_risk', acceptedRiskReviewAt: days(30) }, 'reason'],
      [{ status: 'accepted_risk', reason: 'too short', acceptedRiskReviewAt: days(30) }, 'reason'],
      [{ status: 'accepted_risk', reason: REASON }, 'acceptedRiskReviewAt'],
      [
        { status: 'accepted_risk', reason: REASON, acceptedRiskReviewAt: days(-1) },
        'acceptedRiskReviewAt',
      ],
      [
        { status: 'accepted_risk', reason: REASON, acceptedRiskReviewAt: clock.toISOString() },
        'acceptedRiskReviewAt',
      ],
      [
        {
          status: 'accepted_risk',
          reason: REASON,
          acceptedRiskReviewAt: days(ACCEPTED_RISK_MAX_DAYS + 1),
        },
        'acceptedRiskReviewAt',
      ],
      [{ status: 'acknowledged', acceptedRiskReviewAt: days(30) }, 'acceptedRiskReviewAt'],
      [{ status: 'resolved' }, 'reason'],
      [{ status: 'resolved', reason: 'ok' }, 'reason'], // schema minimum (3)
      [{ reason: REASON, assigneeId: null }, 'reason'], // reason without a status change
      [{}, '(body)'],
    ];
    for (const [body, path] of cases) {
      const res = await patch('admin', w.changeApex, { expectedStatus: 'open', ...body });
      const err = await expectError(res, 400, 'validation_failed');
      expect(err.error.details?.[0]?.path, JSON.stringify(body)).toBe(path);
    }
    // Moving back to open needs a reason too.
    await forceStatus(w.changeApex, 'acknowledged');
    await expectError(
      await patch('admin', w.changeApex, { expectedStatus: 'acknowledged', status: 'open' }),
      400,
      'validation_failed',
      'reason',
    );
    // The maximum itself is accepted; acknowledging needs no reason.
    expect(
      (
        await patch('admin', w.changeApex, {
          expectedStatus: 'acknowledged',
          status: 'accepted_risk',
          reason: REASON,
          acceptedRiskReviewAt: days(ACCEPTED_RISK_MAX_DAYS),
        })
      ).status,
    ).toBe(200);
    expect(
      (await patch('admin', w.hostApex, { expectedStatus: 'open', status: 'acknowledged' })).status,
    ).toBe(200);
  });

  it('answers 409 when the finding changed since the client read it', async () => {
    const w = await seedWorld();
    await forceStatus(w.hostApex, 'acknowledged');
    await expectError(
      await patch('analyst', w.hostApex, {
        expectedStatus: 'open',
        status: 'remediation_in_progress',
      }),
      409,
      'conflict',
      'expectedStatus',
    );
    expect((await row(w.hostApex)).status).toBe('acknowledged');
    expect(await auditFor(w.hostApex)).toHaveLength(0);
  });

  it('lets exactly one of two concurrent changes from the same state win', async () => {
    const w = await seedWorld();
    const [r1, r2] = await Promise.all([
      patch('analyst', w.hostApex, { expectedStatus: 'open', status: 'acknowledged' }),
      patch('admin', w.hostApex, { expectedStatus: 'open', status: 'remediation_in_progress' }),
    ]);
    expect([r1.status, r2.status].sort()).toEqual([200, 409]);
    const manual = (await historyOf(w.hostApex)).filter((x) => x.reason === 'manual');
    expect(manual).toHaveLength(1);
    expect((await row(w.hostApex)).status).toBe(manual[0]!.toStatus);
    expect(await auditFor(w.hostApex, 'finding.status_changed')).toHaveLength(1);
  });

  it('keeps history consistent when a user change races a resolving scan', async () => {
    const w = await seedWorld();
    const fixed = await seedJob(
      t,
      w.a.domainId,
      new Date(clock.getTime() + 60_000),
      dnsFor(w.a.fqdn, { dmarc: true, apexA: ['192.0.2.9'], wwwA: ['192.0.2.8'] }),
    );
    const [res] = await Promise.all([
      patch('analyst', w.dmarc, { expectedStatus: 'open', status: 'acknowledged' }),
      evaluateJob(t.db, fixed, clock, FAKE_RULES),
    ]);
    expect([200, 409]).toContain(res.status);
    const history = await historyOf(w.dmarc);
    // Every entry starts where the previous one ended: no stale `from_status`.
    for (let i = 1; i < history.length; i++) {
      expect(history[i]!.fromStatus).toBe(history[i - 1]!.toStatus);
    }
    expect(history.at(-1)).toMatchObject({ toStatus: 'resolved', reason: 'condition_absent' });
    expect((await row(w.dmarc)).status).toBe('resolved');
  });

  it('returns the finding unchanged when nothing changes', async () => {
    const w = await seedWorld();
    const res = await patch('analyst', w.hostApex, { expectedStatus: 'open', status: 'open' });
    expect(res.status).toBe(200);
    expect(await auditFor(w.hostApex)).toHaveLength(0);
    expect((await historyOf(w.hostApex)).filter((x) => x.reason === 'manual')).toHaveLength(0);
  });
});

describe('PATCH /findings/:id — assignment', () => {
  it('assigns and unassigns active users with audit, and filters by assignee', async () => {
    const w = await seedWorld();
    const owner = await ensureUser(t, 'asset_owner');
    const analyst = await ensureUser(t, 'analyst');
    const res = await patch('analyst', w.hostWww, { expectedStatus: 'open', assigneeId: owner });
    const { finding } = findingUpdateResponseSchema.parse(await res.json());
    expect(finding.assignee).toEqual({
      id: owner,
      email: 'asset_owner@example.com',
      displayName: null,
    });
    const [assigned] = await auditFor(w.hostWww, 'finding.assigned');
    expect(assigned).toMatchObject({ actorUserId: analyst });
    expect(assigned!.metadata).toMatchObject({ assigneeId: owner, previousAssigneeId: null });

    // Unchanged assignment: no audit.
    await patch('analyst', w.hostWww, { expectedStatus: 'open', assigneeId: owner });
    expect(await auditFor(w.hostWww, 'finding.assigned')).toHaveLength(1);

    const mine = findingListResponseSchema.parse(
      await (await call('asset_owner', 'GET', '/findings?assignee=me')).json(),
    );
    expect(mine.items.map((f) => f.id)).toEqual([w.hostWww]);
    const byId = findingListResponseSchema.parse(
      await (await call('viewer', 'GET', `/findings?assignee=${owner}`)).json(),
    );
    expect(byId.items.map((f) => f.id)).toEqual([w.hostWww]);
    const unassigned = findingListResponseSchema.parse(
      await (await call('viewer', 'GET', '/findings?assignee=unassigned')).json(),
    );
    expect(unassigned.total).toBe(4);

    // Status and assignment together, then unassign.
    await patch('analyst', w.hostWww, {
      expectedStatus: 'open',
      status: 'acknowledged',
      assigneeId: analyst,
    });
    expect(await row(w.hostWww)).toMatchObject({ status: 'acknowledged', assignedTo: analyst });
    await patch('analyst', w.hostWww, { expectedStatus: 'acknowledged', assigneeId: null });
    expect((await row(w.hostWww)).assignedTo).toBeNull();
    const [un] = await auditFor(w.hostWww, 'finding.unassigned');
    expect(un!.metadata).toMatchObject({ assigneeId: null, previousAssigneeId: analyst });
  });

  it('rejects inactive or unknown assignees and users without findings:assign', async () => {
    const w = await seedWorld();
    const [inactive] = await t.db
      .insert(users)
      .values({ email: 'gone@example.com', role: 'analyst', authProvider: 'dev', isActive: false })
      .onConflictDoUpdate({ target: users.email, set: { isActive: false } })
      .returning({ id: users.id });
    for (const assigneeId of [inactive!.id, '00000000-0000-4000-8000-000000000000']) {
      await expectError(
        await patch('admin', w.hostWww, { expectedStatus: 'open', assigneeId }),
        400,
        'validation_failed',
        'assigneeId',
      );
    }
    const analyst = await ensureUser(t, 'analyst');
    for (const role of ['asset_owner', 'viewer'] as const) {
      await expectError(
        await patch(role, w.hostWww, { expectedStatus: 'open', assigneeId: analyst }),
        403,
        'forbidden',
      );
    }
    // An asset owner's permitted status change is refused as a whole if it also assigns.
    await expectError(
      await patch('asset_owner', w.hostWww, {
        expectedStatus: 'open',
        status: 'remediation_in_progress',
        assigneeId: analyst,
      }),
      403,
      'forbidden',
    );
    expect(await row(w.hostWww)).toMatchObject({ status: 'open', assignedTo: null });
  });
});

describe('POST /findings/bulk', () => {
  it('applies a status change per finding and reports what it skipped', async () => {
    const w = await seedWorld();
    await forceStatus(w.dmarc, 'acknowledged');
    await forceStatus(w.changeApex, 'resolved');
    const unknown = '00000000-0000-4000-8000-000000000000';
    const res = await call('analyst', 'POST', '/findings/bulk', {
      ids: [w.hostApex, w.hostWww, w.dmarc, w.changeApex, unknown, w.hostApex],
      status: 'acknowledged',
    });
    expect(res.status).toBe(200);
    const body = findingBulkUpdateResponseSchema.parse(await res.json());
    expect(body.updated).toBe(2);
    expect(body.skipped).toEqual([
      { id: w.dmarc, code: 'no_change' },
      { id: w.changeApex, code: 'invalid_transition' },
      { id: unknown, code: 'not_found' },
    ]);
    const audits = await t.db
      .select()
      .from(auditLogs)
      .where(eq(auditLogs.action, 'finding.status_changed'));
    expect(audits.map((a) => a.resourceId).sort()).toEqual([w.hostApex, w.hostWww].sort());
    expect(audits[0]!.metadata).toMatchObject({ bulk: true, to: 'acknowledged' });
  });

  it('checks visibility and permission per finding for asset owners', async () => {
    const w = await seedWorld();
    await forceStatus(w.hostWww, 'remediation_in_progress');
    const res = await call('asset_owner', 'POST', '/findings/bulk', {
      ids: [w.hostWww, w.changeWww, w.dmarc],
      status: 'acknowledged',
    });
    const body = findingBulkUpdateResponseSchema.parse(await res.json());
    expect(body).toEqual({
      updated: 1,
      skipped: [
        { id: w.changeWww, code: 'transition_not_allowed' },
        { id: w.dmarc, code: 'not_found' },
      ],
    });
    expect((await row(w.hostWww)).status).toBe('acknowledged');
  });

  it('assigns in bulk and validates the request', async () => {
    const w = await seedWorld();
    const analyst = await ensureUser(t, 'analyst');
    await t.db.update(findings).set({ assignedTo: analyst }).where(eq(findings.id, w.dmarc));
    const res = await call('admin', 'POST', '/findings/bulk', {
      ids: [w.dmarc, w.hostApex, w.hostWww],
      assigneeId: analyst,
    });
    expect(findingBulkUpdateResponseSchema.parse(await res.json())).toEqual({
      updated: 2,
      skipped: [{ id: w.dmarc, code: 'no_change' }],
    });
    expect(
      await t.db.select().from(auditLogs).where(eq(auditLogs.action, 'finding.assigned')),
    ).toHaveLength(2);

    await expectError(
      await call('viewer', 'POST', '/findings/bulk', { ids: [w.dmarc], status: 'acknowledged' }),
      403,
      'forbidden',
    );
    await expectError(
      await call('asset_owner', 'POST', '/findings/bulk', { ids: [w.hostWww], assigneeId: null }),
      403,
      'forbidden',
    );
    for (const body of [
      { ids: [w.dmarc], status: 'accepted_risk', reason: REASON },
      { ids: [w.dmarc] },
      { ids: [] },
      { ids: Array.from({ length: 501 }, () => w.dmarc), status: 'acknowledged' },
    ]) {
      await expectError(
        await call('admin', 'POST', '/findings/bulk', body),
        400,
        'validation_failed',
      );
    }
  });
});

describe('POST /findings/:id/comments', () => {
  it('lets asset owners comment on their own findings only, audited without the body', async () => {
    const w = await seedWorld();
    const owner = await ensureUser(t, 'asset_owner');
    const res = await call('asset_owner', 'POST', `/findings/${w.hostWww}/comments`, {
      body: '  Patched the web server config.  ',
    });
    expect(res.status).toBe(201);
    const { comment } = findingCommentResponseSchema.parse(await res.json());
    expect(comment).toMatchObject({
      body: 'Patched the web server config.',
      author: { id: owner, email: 'asset_owner@example.com' },
    });
    clock = new Date(clock.getTime() + 60_000);
    await call('analyst', 'POST', `/findings/${w.hostWww}/comments`, {
      body: 'Thanks, will verify.',
    });

    const detail = findingDetailResponseSchema.parse(
      await (await call('viewer', 'GET', `/findings/${w.hostWww}`)).json(),
    );
    expect(detail.comments.map((c) => [c.author?.email, c.body])).toEqual([
      ['asset_owner@example.com', 'Patched the web server config.'],
      ['analyst@example.com', 'Thanks, will verify.'],
    ]);
    const audits = await auditFor(w.hostWww, 'finding.commented');
    expect(audits).toHaveLength(2);
    expect(audits[0]!.metadata).toEqual({ commentId: comment.id, length: 30 });

    await expectError(
      await call('asset_owner', 'POST', `/findings/${w.dmarc}/comments`, { body: 'Hello' }),
      404,
      'not_found',
    );
    await expectError(
      await call('viewer', 'POST', `/findings/${w.hostWww}/comments`, { body: 'Hello' }),
      403,
      'forbidden',
    );
    for (const body of [{ body: '   ' }, { body: 'x'.repeat(4001) }, { text: 'x' }]) {
      await expectError(
        await call('analyst', 'POST', `/findings/${w.hostWww}/comments`, body),
        400,
        'validation_failed',
      );
    }
  });
});

describe('POST /findings/:id/reassess', () => {
  async function insertFinding(domainId: string, ruleId: string, category: string) {
    const [r] = await t.db
      .insert(findings)
      .values({
        domainId,
        hostname: 'a.example',
        component: 'c',
        category,
        ruleId,
        ruleVersion: 1,
        fingerprint: `fp-${ruleId}`,
        title: 'Synthetic',
        description: 'Synthetic',
        severity: 'low',
        confidence: 'high',
        riskScore: 10,
        riskInputs: {},
        evidence: {},
        firstSeenAt: at(1),
        lastSeenAt: at(1),
      })
      .returning({ id: findings.id });
    return r!.id;
  }
  const ACTIVE_ON = { ACTIVE_SCANNING_ENABLED: 'true' };
  const reassess = (role: Role, id: string, env: Record<string, string> = {}) =>
    call(role, 'POST', `/findings/${id}/reassess`, undefined, env);

  it('queues the passive profile for DNS rules and reuses a queued job', async () => {
    const w = await seedWorld();
    const res = await reassess('analyst', w.dmarc);
    expect(res.status).toBe(201);
    const first = findingReassessResponseSchema.parse(await res.json());
    expect(first).toMatchObject({ profile: 'passive', created: true });
    const [job] = await t.db.select().from(scanJobs).where(eq(scanJobs.id, first.scanJobId));
    expect(job).toMatchObject({ status: 'queued', domainId: w.a.domainId });
    expect(job!.reason).toContain(w.dmarc);
    const [audit] = await t.db
      .select()
      .from(auditLogs)
      .where(
        and(eq(auditLogs.action, 'scan.requested'), eq(auditLogs.resourceId, first.scanJobId)),
      );
    expect((audit!.metadata as { reason: string }).reason).toContain(`Reassess finding ${w.dmarc}`);

    const again = await reassess('admin', w.hostApex);
    expect(again.status).toBe(200);
    expect(findingReassessResponseSchema.parse(await again.json())).toEqual({
      scanJobId: first.scanJobId,
      profile: 'passive',
      created: false,
    });
    expect(await t.db.select().from(scanJobs).where(eq(scanJobs.status, 'queued'))).toHaveLength(1);
  });

  it('picks the cheapest profile running the rule’s checks, subject to active scanning rules', async () => {
    const w = await seedWorld();
    const tls = await insertFinding(w.a.domainId, 'TST-TLS', 'tls');
    const hdr = await insertFinding(w.a.domainId, 'TST-HDR', 'http');
    const port = await insertFinding(w.a.domainId, 'TST-PORT', 'exposure');
    const tlsCfg = await insertFinding(w.a.domainId, 'TST-TLSCFG', 'tls');
    const disc = await insertFinding(w.a.domainId, 'TST-DISC', 'asset');

    // Active scanning disabled: refused, nothing queued.
    await expectError(await reassess('analyst', tls), 409, 'conflict');
    // Enabled but the domain is not verified: refused by scan creation.
    await expectError(await reassess('analyst', tls, ACTIVE_ON), 409, 'conflict');
    expect(await t.db.select().from(scanJobs).where(eq(scanJobs.status, 'queued'))).toHaveLength(0);

    await t.db
      .update(domains)
      .set({ verificationStatus: 'verified', verifiedAt: clock, verificationMethod: 'dns_txt' })
      .where(eq(domains.id, w.a.domainId));
    const profileOf = async (id: string) =>
      findingReassessResponseSchema.parse(await (await reassess('analyst', id, ACTIVE_ON)).json())
        .profile;
    expect(await profileOf(tls)).toBe('quick');
    expect(await profileOf(hdr)).toBe('standard');
    expect(await profileOf(port)).toBe('standard'); // reuses the standard job
    expect(await profileOf(tlsCfg)).toBe('deep');
    // Asset-inventory rules are re-checked by passive discovery (no verification needed).
    const discRes = await reassess('analyst', disc);
    expect(discRes.status).toBe(201);
    const discBody = findingReassessResponseSchema.parse(await discRes.json());
    expect(discBody).toMatchObject({ profile: 'discovery', created: true });
    const [discJob] = await t.db.select().from(scanJobs).where(eq(scanJobs.id, discBody.scanJobId));
    expect(discJob).toMatchObject({ jobType: 'discovery', status: 'queued' });
    // Asked again while queued: the same job.
    expect(
      findingReassessResponseSchema.parse(await (await reassess('analyst', disc)).json()),
    ).toMatchObject({ scanJobId: discBody.scanJobId, created: false });
  });

  it('requires scans:request and a visible finding', async () => {
    const w = await seedWorld();
    for (const role of ['asset_owner', 'viewer'] as const) {
      await expectError(await reassess(role, w.hostWww), 403, 'forbidden');
    }
    await expectError(
      await reassess('admin', '00000000-0000-4000-8000-000000000000'),
      404,
      'not_found',
    );
  });
});

describe('GET /users/assignable', () => {
  it('lists active users by email for users who can assign', async () => {
    for (const role of ROLES) await ensureUser(t, role);
    await t.db
      .insert(users)
      .values({ email: 'gone@example.com', role: 'analyst', authProvider: 'dev', isActive: false })
      .onConflictDoNothing();
    const res = await call('analyst', 'GET', '/users/assignable');
    expect(res.status).toBe(200);
    const body = assignableUsersResponseSchema.parse(await res.json());
    const emails = body.items.map((u) => u.email);
    expect(emails).toEqual([...emails].sort());
    expect(emails).toContain('asset_owner@example.com');
    expect(emails).not.toContain('gone@example.com');
    expect(body.items.find((u) => u.email === 'viewer@example.com')?.role).toBe('viewer');
    for (const role of ['asset_owner', 'viewer'] as const) {
      await expectError(await call(role, 'GET', '/users/assignable'), 403, 'forbidden');
    }
  });
});

describe('accepted-risk expiry (cron)', () => {
  it('reopens lapsed acceptances with history and system audit', async () => {
    const w = await seedWorld();
    await patch('analyst', w.dmarc, {
      expectedStatus: 'open',
      status: 'accepted_risk',
      reason: 'No mail sent from here',
      acceptedRiskReviewAt: days(10),
    });
    await patch('analyst', w.hostApex, {
      expectedStatus: 'open',
      status: 'accepted_risk',
      reason: 'Public by design for now',
      acceptedRiskReviewAt: days(40),
    });
    clock = new Date(days(10)); // exactly the review time of the first
    expect(await expireAcceptedRisks(t.db, clock)).toBe(1);
    expect(await expireAcceptedRisks(t.db, clock)).toBe(0); // idempotent

    expect(await row(w.dmarc)).toMatchObject({
      status: 'open',
      acceptedRiskReason: null,
      acceptedRiskApprovedBy: null,
      acceptedRiskReviewAt: null,
    });
    expect((await row(w.hostApex)).status).toBe('accepted_risk');
    expect((await historyOf(w.dmarc)).at(-1)).toMatchObject({
      fromStatus: 'accepted_risk',
      toStatus: 'open',
      reason: 'accepted_risk_expired',
      note: 'No mail sent from here',
      changedBy: null,
    });
    const [audit] = await auditFor(w.dmarc, 'finding.risk_acceptance_expired');
    expect(audit).toMatchObject({ actorType: 'system', actorUserId: null });

    // Wired into the maintenance run.
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((l: string) => void lines.push(l));
    clock = new Date(days(31));
    await runMaintenance(t.db, clock, createLogger({}));
    expect((await row(w.hostApex)).status).toBe('open');
    expect(lines.some((l) => l.includes('accepted_risks_expired') && l.includes('"count":1'))).toBe(
      true,
    );
  });
});

describe('lifecycle and scan evaluation', () => {
  it('reopens a manually resolved finding on recurrence with recurrence_count + 1', async () => {
    const w = await seedWorld();
    await patch('analyst', w.changeApex, {
      expectedStatus: 'open',
      status: 'resolved',
      reason: 'Planned hosting move',
    });
    // Unchanged A records later: no recurrence.
    const later = new Date(clock.getTime() + 3600_000);
    await evaluateJob(
      t.db,
      await seedJob(
        t,
        w.a.domainId,
        later,
        dnsFor(w.a.fqdn, { apexA: ['192.0.2.9'], wwwA: ['192.0.2.8'] }),
      ),
      clock,
      FAKE_RULES,
    );
    expect((await row(w.changeApex)).status).toBe('resolved');
    // Changed again: the same finding reopens.
    await evaluateJob(
      t.db,
      await seedJob(
        t,
        w.a.domainId,
        new Date(later.getTime() + 3600_000),
        dnsFor(w.a.fqdn, { apexA: ['203.0.113.5'], wwwA: ['192.0.2.8'] }),
      ),
      clock,
      FAKE_RULES,
    );
    expect(await row(w.changeApex)).toMatchObject({
      status: 'open',
      recurrenceCount: 1,
      resolvedAt: null,
    });
    expect(
      (await historyOf(w.changeApex)).map((x) => [x.fromStatus, x.toStatus, x.reason]),
    ).toEqual([
      [null, 'open', 'detected'],
      ['open', 'resolved', 'manual'],
      ['resolved', 'open', 'recurrence'],
    ]);
    const active = await t.db
      .select()
      .from(findings)
      .where(and(eq(findings.ruleId, 'TST-ACHANGE'), eq(findings.hostname, w.a.fqdn)));
    expect(active).toHaveLength(1);
  });

  it('clears acceptance when a successful scan resolves an accepted risk', async () => {
    const w = await seedWorld();
    await patch('analyst', w.dmarc, {
      expectedStatus: 'open',
      status: 'accepted_risk',
      reason: 'No mail sent from here',
      acceptedRiskReviewAt: days(30),
    });
    await evaluateJob(
      t.db,
      await seedJob(
        t,
        w.a.domainId,
        new Date(clock.getTime() + 60_000),
        dnsFor(w.a.fqdn, { dmarc: true, apexA: ['192.0.2.9'] }),
      ),
      clock,
      FAKE_RULES,
    );
    expect(await row(w.dmarc)).toMatchObject({
      status: 'resolved',
      acceptedRiskReason: null,
      acceptedRiskApprovedBy: null,
      acceptedRiskReviewAt: null,
    });
    expect((await historyOf(w.dmarc)).at(-1)).toMatchObject({
      fromStatus: 'accepted_risk',
      toStatus: 'resolved',
      reason: 'condition_absent',
    });
  });

  it('never resolves a triaged finding from a failed scan', async () => {
    const w = await seedWorld();
    await patch('analyst', w.dmarc, { expectedStatus: 'open', status: 'acknowledged' });
    const failed = await seedJob(
      t,
      w.a.domainId,
      at(3),
      dnsFor(w.a.fqdn, { dmarc: true }),
      'failed',
    );
    expect((await evaluateJob(t.db, failed, clock, FAKE_RULES)).status).toBe('not_eligible');
    expect((await row(w.dmarc)).status).toBe('acknowledged');
  });

  it('produces one active finding per fingerprint under duplicate and concurrent ingestion', async () => {
    const s = await seedDomain(t, 'c.example');
    const jobs = await Promise.all(
      [1, 2, 3].map((n) => seedJob(t, s.domainId, at(n), dnsFor(s.fqdn, { apexA: ['192.0.2.1'] }))),
    );
    // Every job evaluated concurrently, twice each (duplicate delivery).
    await Promise.all([...jobs, ...jobs].map((j) => evaluateJob(t.db, j, clock, FAKE_RULES)));
    // Deferred jobs are picked up by later runs, oldest first.
    for (const j of jobs) await evaluateJob(t.db, j, clock, FAKE_RULES);
    const rows = await t.db.select().from(findings).where(eq(findings.domainId, s.domainId));
    const fps = rows.map((r) => r.fingerprint);
    expect(new Set(fps).size).toBe(fps.length);
    expect(rows.map((r) => r.ruleId).sort()).toEqual(['TST-DMARC', 'TST-HOST']);
    const evaluated = await t.db
      .select()
      .from(scanJobs)
      .where(and(inArray(scanJobs.id, jobs), eq(scanJobs.status, 'succeeded')));
    expect(evaluated.every((j) => j.rulesEvaluatedAt !== null)).toBe(true);
    // The partial unique index refuses a second active row outright.
    await expect(
      t.db.insert(findings).values({ ...rows[0]!, id: undefined, status: 'open' }),
    ).rejects.toThrow();
  });
});
