// Key operator workflows end to end through the UI (Milestone 10): each test drives real pages and
// navigation against a small stateful stub of the API, so a later read sees the earlier change.
import type { Asset, Domain, Finding, ScanJob, ScanProfile } from '@exdomainvault/shared';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { openDomainCards } from '../testing/domain-cards.ts';
import { ok, renderAt, stubApi } from '../testing/stub-api.tsx';
import { asset as assetOf, detailOf as assetDetailOf } from './assets/test-data.ts';
import {
  assignable,
  detailOf as findingDetailOf,
  finding as findingOf,
  page,
} from './findings/test-data.ts';

beforeEach(openDomainCards);
afterEach(() => vi.unstubAllGlobals());

const DOMAIN_ID = '0b8e3f9a-4c1d-4e5f-8a7b-1c2d3e4f5a6b';
const JOB_ID = '7d1f8c2e-3b4a-4c5d-9e6f-0a1b2c3d4e5f';
const NOW = '2026-10-22T10:00:00.000Z';

const nav = () => within(screen.getByRole('navigation', { name: 'Primary' }));

const domainOf = (overrides: Partial<Domain> = {}): Domain => ({
  id: DOMAIN_ID,
  fqdn: 'example.com',
  unicodeFqdn: 'example.com',
  warnings: [],
  registrar: null,
  registeredAt: null,
  expiresAt: null,
  registrationDataStatus: 'unknown',
  criticality: 'medium',
  businessOwner: null,
  verificationStatus: 'unverified',
  verifiedAt: null,
  verificationMethod: null,
  verificationExpiresAt: null,
  monitoringEnabled: false,
  brandMonitoring: false,
  score: null,
  grade: null,
  createdAt: NOW,
  updatedAt: NOW,
  ...overrides,
});

const challenge = (overrides: Record<string, unknown> = {}) => ({
  id: '1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d',
  method: 'dns_txt',
  status: 'pending',
  recordName: '_exdomainvault-challenge.example.com',
  reason: null,
  reference: null,
  createdAt: NOW,
  expiresAt: '2026-10-25T10:00:00.000Z',
  lastCheckedAt: null,
  verifiedAt: null,
  failureReason: null,
  ...overrides,
});

const passiveConfig = {
  active: false,
  checks: ['dns', 'rdap'],
  tcpPorts: [],
  timeouts: { connectMs: 3000, readMs: 5000, targetSeconds: 60 },
  concurrency: 4,
  ratePerSecond: 5,
  maxTargets: 50,
} satisfies ScanProfile['config'];

const profiles = {
  activeScanningEnabled: false,
  items: [
    {
      key: 'passive',
      name: 'Passive',
      description: 'DNS and RDAP only.',
      version: 1,
      defaultSchedule: 'daily',
      enabled: true,
      config: passiveConfig,
    },
  ],
};

const jobOf = (overrides: Partial<ScanJob> = {}): ScanJob => ({
  id: JOB_ID,
  jobType: 'scan',
  profile: 'passive',
  domain: { id: DOMAIN_ID, fqdn: 'example.com' },
  status: 'queued',
  priority: 100,
  reason: null,
  trigger: 'manual',
  requestedBy: { id: crypto.randomUUID(), email: 'analyst@example.com' },
  createdAt: NOW,
  scheduledAt: NOW,
  startedAt: null,
  completedAt: null,
  leaseExpiresAt: null,
  attempts: 0,
  maxAttempts: 3,
  worker: null,
  progress: null,
  cancelRequestedAt: null,
  errorCode: null,
  errorSummary: null,
  targetCounts: { pending: 1, running: 0, succeeded: 0, failed: 0, skipped: 0 },
  ...overrides,
});

const jobDetail = (j: ScanJob) => ({
  job: j,
  targets: [
    {
      id: crypto.randomUUID(),
      assetId: null,
      hostname: 'example.com',
      ip: null,
      status: 'pending',
      startedAt: null,
      completedAt: null,
      errorCode: null,
    },
  ],
  scopeSnapshot: {
    version: 1,
    createdAt: j.createdAt,
    requestedBy: null,
    trigger: 'manual',
    domain: {
      id: DOMAIN_ID,
      fqdn: 'example.com',
      verificationStatus: 'verified',
      verificationMethod: 'dns_txt',
      verificationExpiresAt: null,
    },
    profile: { key: 'passive', version: 1, config: passiveConfig },
    targets: [{ assetId: null, hostname: 'example.com' }],
  },
});

describe('Workflow: add a domain and verify it by DNS TXT', () => {
  it('adds the domain, issues the TXT record, verifies, and lists it as verified', async () => {
    let domain: Domain | null = null;
    let verification: ReturnType<typeof challenge> | null = null;
    const calls = stubApi('admin', {
      'GET /api/v1/domains': () => ok(page(domain ? [domain] : []))(),
      'POST /api/v1/domains': () => {
        domain = domainOf();
        return { status: 201, body: { domain, verification: null } };
      },
      [`GET /api/v1/domains/${DOMAIN_ID}`]: () => ok({ domain, verification })(),
      [`POST /api/v1/domains/${DOMAIN_ID}/verification`]: () => {
        verification = challenge();
        domain = domainOf({ verificationStatus: 'pending' });
        return {
          status: 201,
          body: {
            challenge: verification,
            record: {
              type: 'TXT',
              name: '_exdomainvault-challenge.example.com',
              value: 'exdomainvault-verification=synthetic-token',
            },
          },
        };
      },
      [`POST /api/v1/domains/${DOMAIN_ID}/verify`]: () => {
        verification = challenge({
          status: 'verified',
          lastCheckedAt: '2026-10-22T10:05:00.000Z',
          verifiedAt: '2026-10-22T10:05:00.000Z',
        });
        domain = domainOf({
          verificationStatus: 'verified',
          verificationMethod: 'dns_txt',
          verifiedAt: '2026-10-22T10:05:00.000Z',
        });
        return ok({
          outcome: 'verified',
          message: 'The verification record was found. The domain is verified.',
          domain,
          verification,
        })();
      },
    });

    const router = renderAt('/domains');
    expect(await screen.findByText('No domains yet')).toBeInTheDocument();

    // Add.
    await userEvent.click(screen.getByRole('button', { name: 'Add domain' }));
    await userEvent.type(screen.getByLabelText('Domain'), 'example.com');
    await userEvent.click(
      within(screen.getByRole('region', { name: 'Add a domain' })).getByRole('button', {
        name: 'Add domain',
      }),
    );
    expect(
      await screen.findByRole('heading', { level: 1, name: 'example.com' }),
    ).toBeInTheDocument();
    expect(router.state.location.pathname).toBe(`/domains/${DOMAIN_ID}`);

    // Issue the TXT challenge: the value is shown once, to publish in DNS.
    await userEvent.click(screen.getByRole('button', { name: 'Verify with DNS TXT record' }));
    expect(
      await screen.findByText('exdomainvault-verification=synthetic-token'),
    ).toBeInTheDocument();
    expect(screen.getByText('_exdomainvault-challenge.example.com')).toBeInTheDocument();

    // Check now: the server looks the record up and verifies.
    await userEvent.click(screen.getByRole('button', { name: 'Check now' }));
    expect(await screen.findByText(/Verified by DNS TXT record/)).toBeInTheDocument();
    expect(
      screen.getByText('The verification record was found. The domain is verified.'),
    ).toBeInTheDocument();
    expect(calls.filter((c) => c.method === 'POST').map((c) => c.path)).toEqual([
      '/api/v1/domains',
      `/api/v1/domains/${DOMAIN_ID}/verification`,
      `/api/v1/domains/${DOMAIN_ID}/verify`,
    ]);

    // The list now shows it as verified.
    await userEvent.click(nav().getByRole('link', { name: 'Domains' }));
    const table = await screen.findByRole('table');
    expect(within(table).getByRole('link', { name: 'example.com' })).toBeInTheDocument();
    expect(within(table).getByText('Verified (DNS)')).toBeInTheDocument();
  });
});

describe('Workflow: approve a discovered asset', () => {
  it('reviews the pending asset, approves it with a reason, and empties the review queue', async () => {
    let current: Asset = assetOf();
    const calls = stubApi('admin', {
      'GET /api/v1/assets?status=pending': () =>
        ok(page(current.status === 'pending' ? [current] : []))(),
      'GET /api/v1/assets?status=approved': () =>
        ok(page(current.status === 'approved' ? [current] : []))(),
      [`GET /api/v1/assets/${current.id}`]: () => ok(assetDetailOf(current))(),
      [`POST /api/v1/assets/${current.id}/approve`]: (body) => {
        current = assetOf({
          status: 'approved',
          decidedBy: { id: crypto.randomUUID(), email: 'admin@example.com' },
          decidedAt: '2026-10-22T10:10:00.000Z',
          decisionReason: (body as { reason: string }).reason,
        });
        return ok({ asset: current })();
      },
    });

    renderAt('/assets');
    const queue = await screen.findByRole('table');
    expect(within(queue).getByText('Pending review')).toBeInTheDocument();
    await userEvent.click(within(queue).getByRole('link', { name: 'shop.example.com' }));

    const panel = await screen.findByRole('region', { name: 'Review' });
    await userEvent.click(within(panel).getByRole('button', { name: 'Approve' }));
    const form = within(panel).getByRole('form', { name: 'Approve shop.example.com' });
    await userEvent.type(within(form).getByLabelText(/Reason/), 'Customer storefront');
    await userEvent.click(within(form).getByRole('button', { name: 'Approve' }));
    expect(await within(panel).findByRole('status')).toHaveTextContent(
      'shop.example.com was approved.',
    );
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({
      reason: 'Customer storefront',
      acknowledgeThirdPartyHosting: false,
    });

    await userEvent.click(nav().getByRole('link', { name: 'Assets' }));
    expect(await screen.findByText('Nothing waiting for review')).toBeInTheDocument();
  });
});

describe('Workflow: launch a scan', () => {
  it('requests a passive scan from the domain page, follows it, and finds it in scan history', async () => {
    const jobs: ScanJob[] = [];
    const domain = domainOf({
      verificationStatus: 'verified',
      verificationMethod: 'dns_txt',
      verifiedAt: NOW,
      monitoringEnabled: true,
    });
    const calls = stubApi('analyst', {
      'GET /api/v1/domains': ok(page([domain])),
      [`GET /api/v1/domains/${DOMAIN_ID}`]: ok({ domain, verification: null }),
      'GET /api/v1/scan-profiles': ok(profiles),
      [`GET /api/v1/scans?domainId=${DOMAIN_ID}&pageSize=5`]: () => ok(page(jobs))(),
      'GET /api/v1/scans': () => ok(page(jobs))(),
      [`POST /api/v1/domains/${DOMAIN_ID}/scans`]: () => {
        jobs.unshift(jobOf());
        return { status: 202, body: jobDetail(jobs[0]!) };
      },
      [`GET /api/v1/scans/${JOB_ID}`]: () => ok(jobDetail(jobs[0]!))(),
    });

    const router = renderAt('/domains');
    await userEvent.click(await screen.findByRole('link', { name: 'example.com' }));
    const scansCard = await screen.findByRole('region', { name: 'Scans' });
    expect(await within(scansCard).findByText('No scans yet.')).toBeInTheDocument();
    await userEvent.click(await within(scansCard).findByRole('button', { name: 'Request scan' }));

    expect(await screen.findByText('dns, rdap')).toBeInTheDocument();
    expect(router.state.location.pathname).toBe(`/scans/${JOB_ID}`);
    expect(calls.find((c) => c.method === 'POST')).toMatchObject({
      path: `/api/v1/domains/${DOMAIN_ID}/scans`,
      body: { profile: 'passive' },
    });

    await userEvent.click(nav().getByRole('link', { name: 'Scans' }));
    const history = await screen.findByRole('table');
    expect(within(history).getByRole('link', { name: 'example.com' })).toHaveAttribute(
      'href',
      `/scans/${JOB_ID}`,
    );
    expect(within(history).getByText('Queued')).toBeInTheDocument();
  });
});

describe('Workflow: update a finding', () => {
  it('opens a finding from the list, acknowledges it, and sees the new status in the list', async () => {
    let current: Finding = findingOf();
    const calls = stubApi('analyst', {
      'GET /api/v1/findings': () => ok(page([current]))(),
      [`GET /api/v1/findings/${current.id}`]: () => ok(findingDetailOf({ finding: current }))(),
      'GET /api/v1/users/assignable': ok(assignable),
      [`PATCH /api/v1/findings/${current.id}`]: (body) => {
        current = findingOf({ status: (body as { status: Finding['status'] }).status });
        return ok({ finding: current })();
      },
    });

    renderAt('/findings');
    const list = await screen.findByRole('table');
    expect(within(list).getByText('Open')).toBeInTheDocument();
    await userEvent.click(
      within(list).getByRole('link', { name: 'Certificate expires within 14 days' }),
    );

    const workflow = await screen.findByRole('region', { name: 'Workflow' });
    await userEvent.click(within(workflow).getByRole('button', { name: 'Acknowledge' }));
    await userEvent.click(within(workflow).getByRole('button', { name: 'Confirm: Acknowledge' }));
    expect(await within(workflow).findByText('Status changed to Acknowledged.')).toBeVisible();
    expect(calls.find((c) => c.method === 'PATCH')?.body).toEqual({
      expectedStatus: 'open',
      status: 'acknowledged',
    });

    await userEvent.click(nav().getByRole('link', { name: 'Findings' }));
    const updated = await screen.findByRole('table');
    expect(await within(updated).findByText('Acknowledged')).toBeInTheDocument();
  });
});
