import type { FindingDetailResponse, Role } from '@exdomainvault/shared';
import { fireEvent, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { reviewDateBounds } from '../../components/findings/lifecycle.ts';
import { ok, renderAt, stubApi, type Handler } from '../../testing/stub-api.tsx';
import { ANALYST, FINDING_ID, OWNER, assignable, detailOf, finding, page } from './test-data.ts';

afterEach(() => vi.unstubAllGlobals());

const DETAIL = `GET /api/v1/findings/${FINDING_ID}`;
const PATCH = `PATCH /api/v1/findings/${FINDING_ID}`;
const SCAN_ID = '9f8e7d6c-5b4a-4c3d-8e2f-1a0b9c8d7e6f';

const error =
  (status: number, code: string, message: string, details?: { path: string; message: string }[]) =>
  () => ({ status, body: { error: { code, message, requestId: 'r-1', details } } });

/** Serves `first` for the initial load and `next` (when given) for every reload. */
function detailHandler(first: FindingDetailResponse, next?: FindingDetailResponse): Handler {
  let calls = 0;
  return () => ({ status: 200, body: calls++ === 0 || !next ? first : next });
}

async function openDetail(role: Role, detail = detailOf(), handlers: Record<string, Handler> = {}) {
  const calls = stubApi(role, {
    [DETAIL]: ok(detail),
    'GET /api/v1/users/assignable': ok(assignable),
    ...handlers,
  });
  renderAt(`/findings/${FINDING_ID}`);
  const workflow = await screen.findByRole('region', { name: 'Workflow' });
  return { calls, workflow };
}

const actionNames = (workflow: HTMLElement) =>
  within(workflow)
    .queryAllByRole('button')
    .map((b) => b.textContent.trim());

describe('Finding detail: actions offered per role', () => {
  it('offers analysts triage, remediation, accepted risk, assignment and re-check', async () => {
    const { workflow } = await openDetail('analyst');
    expect(actionNames(workflow)).toEqual([
      'Acknowledge',
      'Start remediation',
      'Accept risk',
      'Save assignee',
      'Re-check now',
    ]);
    expect(within(workflow).getByLabelText('Assignee')).toBeInTheDocument();
    expect(within(workflow).getByText(/resolves automatically when a later successful scan/));
    expect(screen.getByLabelText('Add a comment')).toBeInTheDocument();
  });

  it('offers admins the same actions on an acknowledged finding, including reopen', async () => {
    const { workflow } = await openDetail(
      'admin',
      detailOf({ finding: finding({ status: 'acknowledged' }) }),
    );
    expect(actionNames(workflow)).toEqual([
      'Start remediation',
      'Reopen',
      'Accept risk',
      'Save assignee',
      'Re-check now',
    ]);
  });

  it('lets asset owners only start or pause remediation and comment', async () => {
    const { workflow } = await openDetail('asset_owner');
    expect(actionNames(workflow)).toEqual(['Start remediation']);
    expect(within(workflow).queryByLabelText('Assignee')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Add a comment')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Re-check/ })).not.toBeInTheDocument();
  });

  it('lets asset owners pause remediation in progress', async () => {
    const { workflow } = await openDetail(
      'asset_owner',
      detailOf({ finding: finding({ status: 'remediation_in_progress' }) }),
    );
    expect(actionNames(workflow)).toEqual(['Pause remediation']);
  });

  it('gives viewers a read-only view', async () => {
    const { workflow } = await openDetail(
      'viewer',
      detailOf({ finding: finding({ assignee: ANALYST }) }),
    );
    expect(actionNames(workflow)).toEqual([]);
    expect(within(workflow).getByText(/your role cannot change it/)).toBeInTheDocument();
    expect(within(workflow).getByTestId('assignee')).toHaveTextContent('Ana Lyst');
    expect(screen.queryByLabelText('Add a comment')).not.toBeInTheDocument();
  });

  it('offers manual resolution only for change-detection rules and only with triage', async () => {
    const manual = detailOf({ finding: finding({ manualResolution: true }) });
    const { workflow } = await openDetail('analyst', manual);
    expect(
      within(workflow).getByRole('button', { name: 'Mark as reviewed (resolve)' }),
    ).toBeInTheDocument();
    expect(within(workflow).getByText(/does not\s+clear by itself/)).toBeInTheDocument();
  });

  it('does not offer manual resolution to asset owners', async () => {
    const manual = detailOf({ finding: finding({ manualResolution: true }) });
    const { workflow } = await openDetail('asset_owner', manual);
    expect(
      within(workflow).queryByRole('button', { name: 'Mark as reviewed (resolve)' }),
    ).not.toBeInTheDocument();
  });

  it('offers no status changes on a resolved finding', async () => {
    const { workflow } = await openDetail(
      'admin',
      detailOf({ finding: finding({ status: 'resolved', manualResolution: true }) }),
    );
    expect(actionNames(workflow)).toEqual(['Save assignee', 'Re-check now']);
  });

  it('resolves a change-detection finding with a required reason', async () => {
    const manual = detailOf({ finding: finding({ manualResolution: true }) });
    const resolved = detailOf({ finding: finding({ manualResolution: true, status: 'resolved' }) });
    const { calls, workflow } = await openDetail('analyst', manual, {
      [DETAIL]: detailHandler(manual, resolved),
      [PATCH]: ok({ finding: resolved.finding }),
    });
    await userEvent.click(
      within(workflow).getByRole('button', { name: 'Mark as reviewed (resolve)' }),
    );
    await userEvent.click(
      within(workflow).getByRole('button', { name: 'Confirm: Mark as reviewed (resolve)' }),
    );
    expect(within(workflow).getByText('A reason is required.')).toBeInTheDocument();
    await userEvent.type(within(workflow).getByLabelText(/^Reason/), 'Expected new MX record');
    await userEvent.click(
      within(workflow).getByRole('button', { name: 'Confirm: Mark as reviewed (resolve)' }),
    );
    expect(await within(workflow).findByText('Status changed to Resolved.')).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'PATCH')?.body).toEqual({
      expectedStatus: 'open',
      status: 'resolved',
      reason: 'Expected new MX record',
    });
  });
});

describe('Finding detail: status changes', () => {
  it('acknowledges with an optional reason and shows the result', async () => {
    const acked = detailOf({ finding: finding({ status: 'acknowledged' }) });
    const { calls, workflow } = await openDetail('analyst', detailOf(), {
      [DETAIL]: detailHandler(detailOf(), acked),
      [PATCH]: ok({ finding: acked.finding }),
    });
    await userEvent.click(within(workflow).getByRole('button', { name: 'Acknowledge' }));
    expect(within(workflow).getByText('(optional)')).toBeInTheDocument();
    await userEvent.click(within(workflow).getByRole('button', { name: 'Confirm: Acknowledge' }));
    expect(await within(workflow).findByText('Status changed to Acknowledged.')).toBeVisible();
    expect(calls.find((c) => c.method === 'PATCH')?.body).toEqual({
      expectedStatus: 'open',
      status: 'acknowledged',
    });
    expect(within(workflow).getByRole('button', { name: 'Reopen' })).toBeInTheDocument();
  });

  it('validates accepted risk: reason length and a review date within the allowed window', async () => {
    const accepted = detailOf({
      finding: finding({
        status: 'accepted_risk',
        acceptedRisk: {
          reason: 'Legacy host, decommissioned next quarter',
          approvedBy: ANALYST,
          reviewAt: '2027-01-20T00:00:00.000Z',
        },
      }),
    });
    const { calls, workflow } = await openDetail('analyst', detailOf(), {
      [DETAIL]: detailHandler(detailOf(), accepted),
      [PATCH]: ok({ finding: accepted.finding }),
    });
    await userEvent.click(within(workflow).getByRole('button', { name: 'Accept risk' }));
    const form = within(workflow).getByRole('form', { name: 'Accept risk' });
    const date = within(form).getByLabelText(/^Review date/);
    const bounds = reviewDateBounds();
    expect(date).toHaveValue(bounds.default);
    expect(date).toHaveAttribute('max', bounds.max);
    expect(within(form).getByText('(required, at least 10 characters)')).toBeInTheDocument();

    const confirm = within(form).getByRole('button', { name: 'Confirm: Accept risk' });
    await userEvent.type(within(form).getByLabelText(/^Reason/), 'Too short');
    fireEvent.change(date, { target: { value: '2099-01-01' } });
    await userEvent.click(confirm);
    expect(within(form).getByText('Enter at least 10 characters.')).toBeInTheDocument();
    expect(within(form).getByText('The review date must be within 366 days.')).toBeInTheDocument();
    expect(within(form).getByLabelText(/^Reason/)).toHaveAttribute('aria-invalid', 'true');
    expect(calls.some((c) => c.method === 'PATCH')).toBe(false);

    await userEvent.clear(within(form).getByLabelText(/^Reason/));
    await userEvent.type(
      within(form).getByLabelText(/^Reason/),
      'Legacy host, decommissioned next quarter',
    );
    fireEvent.change(date, { target: { value: bounds.default } });
    await userEvent.click(confirm);
    expect(
      await within(workflow).findByText('Status changed to Accepted risk.'),
    ).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'PATCH')?.body).toEqual({
      expectedStatus: 'open',
      status: 'accepted_risk',
      reason: 'Legacy host, decommissioned next quarter',
      acceptedRiskReviewAt: `${bounds.default}T00:00:00.000Z`,
    });
    const block = within(workflow).getByRole('region', { name: 'Accepted risk' });
    expect(within(block).getByText('Ana Lyst')).toBeInTheDocument();
    expect(within(block).getByText('Jan 20, 2027')).toBeInTheDocument();
    expect(
      within(workflow).getByRole('button', { name: 'Withdraw risk acceptance' }),
    ).toBeVisible();
  });

  it('warns when the accepted-risk review date is within 14 days', async () => {
    const soon = new Date(Date.now() + 5 * 24 * 60 * 60 * 1000).toISOString();
    const { workflow } = await openDetail(
      'viewer',
      detailOf({
        finding: finding({
          status: 'accepted_risk',
          acceptedRisk: { reason: 'Compensating control', approvedBy: null, reviewAt: soon },
        }),
      }),
    );
    expect(within(workflow).getByText(/review date is within 14 days/)).toBeInTheDocument();
  });

  it('explains a conflict and reloads the latest version', async () => {
    const changed = detailOf({ finding: finding({ status: 'remediation_in_progress' }) });
    const { calls, workflow } = await openDetail('analyst', detailOf(), {
      [DETAIL]: detailHandler(detailOf(), changed),
      [PATCH]: error(409, 'conflict', 'The finding has changed since you loaded it.', [
        { path: 'expectedStatus', message: 'The finding is now remediation_in_progress.' },
      ]),
    });
    await userEvent.click(within(workflow).getByRole('button', { name: 'Acknowledge' }));
    await userEvent.click(within(workflow).getByRole('button', { name: 'Confirm: Acknowledge' }));
    expect(
      await within(workflow).findByText(/This finding changed since you opened it/),
    ).toBeVisible();
    expect(await within(workflow).findByText('Remediation in progress')).toBeInTheDocument();
    expect(
      calls.filter((c) => c.method === 'GET' && c.path === `/api/v1/findings/${FINDING_ID}`),
    ).toHaveLength(2);
    expect(within(workflow).queryByRole('form')).not.toBeInTheDocument();
  });

  it('shows other errors inside the form without closing it', async () => {
    const { workflow } = await openDetail('analyst', detailOf(), {
      [PATCH]: error(409, 'conflict', 'This status change is not possible.', [
        { path: 'status', message: 'Not by hand.' },
      ]),
    });
    await userEvent.click(within(workflow).getByRole('button', { name: 'Start remediation' }));
    await userEvent.click(
      within(workflow).getByRole('button', { name: 'Confirm: Start remediation' }),
    );
    expect(await within(workflow).findByRole('alert')).toHaveTextContent(
      'This status change is not possible.',
    );
    expect(within(workflow).getByRole('form')).toBeInTheDocument();
  });
});

describe('Finding detail: server refusals', () => {
  it('does not treat a status conflict as a stale finding', async () => {
    const { calls, workflow } = await openDetail('analyst', detailOf(), {
      [PATCH]: error(409, 'conflict', 'This status change is not possible.', [
        { path: 'status', message: 'A finding cannot be moved from resolved by hand.' },
      ]),
    });
    await userEvent.click(within(workflow).getByRole('button', { name: 'Acknowledge' }));
    await userEvent.click(within(workflow).getByRole('button', { name: 'Confirm: Acknowledge' }));
    const alert = await within(workflow).findByRole('alert');
    expect(alert).toHaveTextContent('A finding cannot be moved from resolved by hand.');
    expect(within(workflow).queryByText(/changed since you opened it/)).toBeNull();
    expect(calls.filter((c) => c.method === 'GET' && c.path.includes(FINDING_ID))).toHaveLength(1);
  });

  it('shows permission and validation errors from the server', async () => {
    let n = 0;
    const { workflow } = await openDetail('analyst', detailOf(), {
      [PATCH]: () =>
        n++ === 0
          ? error(403, 'forbidden', 'You do not have permission to perform this action.')()
          : error(400, 'validation_failed', 'The request is invalid.', [
              { path: 'acceptedRiskReviewAt', message: 'The review date must be in the future.' },
            ])(),
    });
    await userEvent.click(within(workflow).getByRole('button', { name: 'Start remediation' }));
    const confirm = within(workflow).getByRole('button', { name: 'Confirm: Start remediation' });
    await userEvent.click(confirm);
    expect(await within(workflow).findByRole('alert')).toHaveTextContent(
      'You do not have permission to perform this action.',
    );
    await userEvent.click(confirm);
    expect(
      await within(workflow).findByText('The review date must be in the future.'),
    ).toBeInTheDocument();
  });
});

describe('Finding detail: assignment', () => {
  it('assigns a user picked from the assignable list', async () => {
    const assigned = detailOf({ finding: finding({ assignee: ANALYST }) });
    const { calls, workflow } = await openDetail('analyst', detailOf(), {
      [DETAIL]: detailHandler(detailOf(), assigned),
      [PATCH]: ok({ finding: assigned.finding }),
    });
    expect(within(workflow).getByTestId('assignee')).toHaveTextContent('Unassigned');
    const select = within(workflow).getByLabelText('Assignee');
    await within(workflow).findByRole('option', { name: 'Ana Lyst (analyst)' });
    expect(within(workflow).getByRole('option', { name: 'owner@example.com (asset owner)' }));
    expect(within(workflow).getByRole('button', { name: 'Save assignee' })).toBeDisabled();
    await userEvent.selectOptions(select, ANALYST.id);
    await userEvent.click(within(workflow).getByRole('button', { name: 'Save assignee' }));
    expect(await within(workflow).findByText('Assigned to Ana Lyst.')).toBeInTheDocument();
    expect(within(workflow).getByTestId('assignee')).toHaveTextContent('Ana Lyst');
    expect(calls.find((c) => c.method === 'PATCH')?.body).toEqual({
      expectedStatus: 'open',
      assigneeId: ANALYST.id,
    });
  });

  it('unassigns', async () => {
    const assigned = detailOf({ finding: finding({ assignee: OWNER }) });
    const { calls, workflow } = await openDetail('admin', assigned, {
      [DETAIL]: detailHandler(assigned, detailOf()),
      [PATCH]: ok({ finding: finding() }),
    });
    await within(workflow).findByRole('option', { name: 'Ana Lyst (analyst)' });
    await userEvent.selectOptions(within(workflow).getByLabelText('Assignee'), '');
    await userEvent.click(within(workflow).getByRole('button', { name: 'Save assignee' }));
    expect(await within(workflow).findByText('The finding is now unassigned.')).toBeVisible();
    expect(calls.find((c) => c.method === 'PATCH')?.body).toEqual({
      expectedStatus: 'open',
      assigneeId: null,
    });
  });
});

describe('Finding detail: re-check', () => {
  it('queues a re-check and links to the scan', async () => {
    const { workflow } = await openDetail('analyst', detailOf(), {
      [`POST /api/v1/findings/${FINDING_ID}/reassess`]: () => ({
        status: 201,
        body: { scanJobId: SCAN_ID, profile: 'standard', created: true },
      }),
    });
    await userEvent.click(within(workflow).getByRole('button', { name: 'Re-check now' }));
    const status = await within(workflow).findByRole('status');
    await within(status).findByText(/Re-check queued using the standard profile/);
    expect(within(status).getByRole('link', { name: 'View scan' })).toHaveAttribute(
      'href',
      `/scans/${SCAN_ID}`,
    );
  });

  it('reports an existing queued re-check', async () => {
    const { workflow } = await openDetail('analyst', detailOf(), {
      [`POST /api/v1/findings/${FINDING_ID}/reassess`]: ok({
        scanJobId: SCAN_ID,
        profile: 'quick',
        created: false,
      }),
    });
    await userEvent.click(within(workflow).getByRole('button', { name: 'Re-check now' }));
    expect(await within(workflow).findByText(/already queued/)).toBeInTheDocument();
  });

  it('explains when no scan profile runs the rule', async () => {
    const { workflow } = await openDetail('analyst', detailOf(), {
      [`POST /api/v1/findings/${FINDING_ID}/reassess`]: error(
        409,
        'conflict',
        'No scan profile re-checks this finding.',
        [{ path: 'ruleId', message: 'No enabled scan profile runs the checks of TLS-003.' }],
      ),
    });
    await userEvent.click(within(workflow).getByRole('button', { name: 'Re-check now' }));
    const alert = await within(workflow).findByRole('alert');
    expect(alert).toHaveTextContent('No scan profile re-checks this finding.');
    expect(alert).toHaveTextContent('No enabled scan profile runs the checks of TLS-003.');
  });

  it('shows why a re-check was refused', async () => {
    const { workflow } = await openDetail('analyst', detailOf(), {
      [`POST /api/v1/findings/${FINDING_ID}/reassess`]: error(
        409,
        'conflict',
        'Active checks need a verified or authorised domain.',
      ),
    });
    await userEvent.click(within(workflow).getByRole('button', { name: 'Re-check now' }));
    expect(await within(workflow).findByRole('alert')).toHaveTextContent(
      'Active checks need a verified or authorised domain.',
    );
  });
});

describe('Finding detail: comments and history', () => {
  const comment = {
    id: crypto.randomUUID(),
    author: OWNER,
    body: 'Renewal ticket raised',
    createdAt: '2026-10-21T09:00:00.000Z',
  };

  it('lists comments and adds one', async () => {
    const withTwo = detailOf({
      comments: [comment, { ...comment, id: crypto.randomUUID(), author: ANALYST, body: 'Thanks' }],
    });
    const { calls } = await openDetail('asset_owner', detailOf({ comments: [comment] }), {
      [DETAIL]: detailHandler(detailOf({ comments: [comment] }), withTwo),
      [`POST /api/v1/findings/${FINDING_ID}/comments`]: () => ({
        status: 201,
        body: { comment: withTwo.comments[1] },
      }),
    });
    const card = screen.getByRole('region', { name: 'Comments' });
    expect(within(card).getByText('owner@example.com')).toBeInTheDocument();
    expect(within(card).getByText('Renewal ticket raised')).toBeInTheDocument();
    expect(within(card).getByText(/Oct 21, 2026/)).toBeInTheDocument();
    const box = within(card).getByLabelText('Add a comment');
    expect(box).toHaveAttribute('maxLength', '4000');
    expect(within(card).getByRole('button', { name: 'Add comment' })).toBeDisabled();
    await userEvent.type(box, '  Thanks  ');
    await userEvent.click(within(card).getByRole('button', { name: 'Add comment' }));
    expect(await within(card).findByText('Thanks')).toBeInTheDocument();
    expect(box).toHaveValue('');
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({ body: 'Thanks' });
    expect(within(card).getByText('Comment added.')).toBeInTheDocument();
  });

  it('shows friendly history reasons', async () => {
    const entry = {
      id: '',
      fromStatus: null,
      toStatus: 'open' as const,
      changedBy: null,
      reason: 'detected',
      note: null,
      scanJobId: null,
      createdAt: '2026-10-20T03:00:00.000Z',
    };
    await openDetail(
      'viewer',
      detailOf({
        history: [
          { ...entry, id: crypto.randomUUID() },
          {
            ...entry,
            id: crypto.randomUUID(),
            fromStatus: 'open',
            toStatus: 'accepted_risk',
            reason: 'manual',
            changedBy: { id: ANALYST.id, email: ANALYST.email },
            note: 'Compensating control in place',
          },
          {
            ...entry,
            id: crypto.randomUUID(),
            fromStatus: 'accepted_risk',
            toStatus: 'open',
            reason: 'accepted_risk_expired',
          },
          {
            ...entry,
            id: crypto.randomUUID(),
            fromStatus: 'open',
            toStatus: 'resolved',
            reason: 'condition_absent',
            scanJobId: SCAN_ID,
          },
        ],
      }),
    );
    const history = screen.getByRole('region', { name: 'Status history' });
    expect(within(history).getByText('First detected by a scan')).toBeInTheDocument();
    expect(within(history).getByText('Changed by analyst@example.com')).toBeInTheDocument();
    expect(within(history).getByText('Compensating control in place')).toBeInTheDocument();
    expect(within(history).getByText('Risk acceptance expired')).toBeInTheDocument();
    expect(within(history).getByText('Resolved by scan')).toBeInTheDocument();
    expect(within(history).getByRole('link', { name: 'scan' })).toHaveAttribute(
      'href',
      `/scans/${SCAN_ID}`,
    );
  });
});

describe('Findings list: assignment and bulk actions', () => {
  const second = finding({
    id: '6d7e8f9a-0b1c-4d2e-9f3a-4b5c6d7e8f9a',
    title: 'Missing DMARC record',
    hostname: 'example.com',
    assignee: ANALYST,
  });

  it('shows the assignee column and filters by assignee through the URL', async () => {
    const calls = stubApi('viewer', {
      'GET /api/v1/findings': ok(page([finding(), second])),
      'GET /api/v1/findings?assignee=unassigned': ok(page([finding()])),
    });
    renderAt('/findings');
    const row = (await screen.findByRole('link', { name: 'Missing DMARC record' })).closest('tr');
    if (!row) throw new Error('row missing');
    expect(within(row).getByText('Ana Lyst')).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: 'Assignee' })).toBeInTheDocument();
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText('Assignee'), 'unassigned');
    await screen.findByRole('link', { name: 'Certificate expires within 14 days' });
    expect(calls.map((c) => c.path)).toContain('/api/v1/findings?assignee=unassigned');
    expect(screen.getByLabelText('Assignee')).toHaveValue('unassigned');
  });

  it('offers asset owners only "Start remediation" for selected findings', async () => {
    stubApi('asset_owner', { 'GET /api/v1/findings': ok(page([finding(), second])) });
    renderAt('/findings');
    await userEvent.click(
      await screen.findByRole('checkbox', { name: /Select Missing DMARC record/ }),
    );
    const bar = screen.getByRole('group', { name: 'Actions for selected findings' });
    expect(within(bar).getByText('1 selected:')).toBeInTheDocument();
    expect(
      within(bar)
        .getAllByRole('button')
        .map((b) => b.textContent),
    ).toEqual(['Start remediation', 'Clear selection']);
  });

  it('acknowledges selected findings and summarises skipped ones', async () => {
    let listCalls = 0;
    const calls = stubApi('analyst', {
      'GET /api/v1/findings': () => ({
        status: 200,
        body: listCalls++ === 0 ? page([finding(), second]) : page([]),
      }),
      'POST /api/v1/findings/bulk': ok({
        updated: 1,
        skipped: [{ id: second.id, code: 'no_change' }],
      }),
    });
    renderAt('/findings');
    await userEvent.click(
      await screen.findByRole('checkbox', { name: 'Select all findings on this page' }),
    );
    const bar = screen.getByRole('group', { name: 'Actions for selected findings' });
    expect(
      within(bar)
        .getAllByRole('button')
        .map((b) => b.textContent),
    ).toEqual(['Acknowledge', 'Start remediation', 'Accept risk', 'Assign to…', 'Clear selection']);
    await userEvent.click(within(bar).getByRole('button', { name: 'Acknowledge' }));
    await userEvent.click(within(bar).getByRole('button', { name: 'Acknowledge for 2 findings' }));
    expect(
      await screen.findByText('Updated 1, skipped 1 (1 already in that state).'),
    ).toBeVisible();
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({
      ids: [finding().id, second.id],
      status: 'acknowledged',
    });
    expect(screen.queryByRole('group', { name: 'Actions for selected findings' })).toBeNull();
    expect(listCalls).toBe(2);
  });

  it('accepts risk for selected findings with a reason and review date', async () => {
    const calls = stubApi('analyst', {
      'GET /api/v1/findings': ok(page([finding()])),
      'POST /api/v1/findings/bulk': ok({ updated: 1, skipped: [] }),
    });
    renderAt('/findings');
    await userEvent.click(await screen.findByRole('checkbox', { name: /Select Certificate/ }));
    const bar = screen.getByRole('group', { name: 'Actions for selected findings' });
    await userEvent.click(within(bar).getByRole('button', { name: 'Accept risk' }));
    const confirm = within(bar).getByRole('button', { name: 'Accept risk for 1 finding' });
    await userEvent.click(confirm);
    expect(within(bar).getByText('A reason is required.')).toBeInTheDocument();
    await userEvent.type(within(bar).getByLabelText(/^Reason/), 'Accepted by the CISO in RISK-12');
    await userEvent.click(confirm);
    expect(await screen.findByText('Updated 1, skipped 0.')).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({
      ids: [finding().id],
      status: 'accepted_risk',
      reason: 'Accepted by the CISO in RISK-12',
      acceptedRiskReviewAt: `${reviewDateBounds().default}T00:00:00.000Z`,
    });
  });

  it('assigns selected findings', async () => {
    const calls = stubApi('admin', {
      'GET /api/v1/findings': ok(page([finding(), second])),
      'GET /api/v1/users/assignable': ok(assignable),
      'POST /api/v1/findings/bulk': ok({
        updated: 0,
        skipped: [
          { id: finding().id, code: 'invalid_transition' },
          { id: second.id, code: 'not_found' },
        ],
      }),
    });
    renderAt('/findings');
    await userEvent.click(
      await screen.findByRole('checkbox', { name: 'Select all findings on this page' }),
    );
    const bar = screen.getByRole('group', { name: 'Actions for selected findings' });
    await userEvent.click(within(bar).getByRole('button', { name: 'Assign to…' }));
    await within(bar).findByRole('option', { name: 'Ana Lyst (analyst)' });
    await userEvent.selectOptions(within(bar).getByLabelText('Assign 2 findings to'), OWNER.id);
    await userEvent.click(within(bar).getByRole('button', { name: 'Assign 2 findings' }));
    expect(
      await screen.findByText(
        'Updated 0, skipped 2 (1 change not possible from their current status; 1 not found or not visible to you).',
      ),
    ).toBeVisible();
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({
      ids: [finding().id, second.id],
      assigneeId: OWNER.id,
    });
  });
});
