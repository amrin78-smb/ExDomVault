import type { Domain, ScanJob, ScanProfile } from '@exdomainvault/shared';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ok, renderAt, stubApi } from '../../testing/stub-api.tsx';

const DOMAIN_ID = '0b8e3f9a-4c1d-4e5f-8a7b-1c2d3e4f5a6b';
const JOB_ID = '7d1f8c2e-3b4a-4c5d-9e6f-0a1b2c3d4e5f';

const job = (overrides: Partial<ScanJob> = {}): ScanJob => ({
  id: JOB_ID,
  jobType: 'scan',
  profile: 'passive',
  domain: { id: DOMAIN_ID, fqdn: 'example.com' },
  status: 'queued',
  priority: 100,
  reason: null,
  trigger: 'manual',
  requestedBy: { id: crypto.randomUUID(), email: 'analyst@example.com' },
  createdAt: '2026-10-22T10:00:00.000Z',
  scheduledAt: '2026-10-22T10:00:00.000Z',
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

const passiveConfig = {
  active: false,
  checks: ['dns', 'rdap'],
  tcpPorts: [],
  timeouts: { connectMs: 3000, readMs: 5000, targetSeconds: 60 },
  concurrency: 4,
  ratePerSecond: 5,
  maxTargets: 50,
} satisfies ScanProfile['config'];

const detail = (j: ScanJob) => ({
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
      verificationStatus: 'unverified',
      verificationMethod: null,
      verificationExpiresAt: null,
    },
    profile: { key: 'passive', version: 1, config: passiveConfig },
    targets: [{ assetId: null, hostname: 'example.com' }],
  },
});

const profiles = (activeScanningEnabled: boolean) => ({
  activeScanningEnabled,
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
    {
      key: 'quick',
      name: 'Quick',
      description: 'TLS and HTTP too.',
      version: 1,
      defaultSchedule: 'daily',
      enabled: true,
      config: { ...passiveConfig, active: true, checks: ['dns', 'rdap', 'tls_certificate'] },
    },
  ],
});

const domain: Domain = {
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
  monitoringEnabled: true,
  createdAt: '2026-10-22T10:00:00.000Z',
  updatedAt: '2026-10-22T10:00:00.000Z',
};

afterEach(() => vi.unstubAllGlobals());

describe('Scans', () => {
  it('lists scans with status, profile and trigger', async () => {
    stubApi('viewer', {
      'GET /api/v1/scans': ok({
        items: [job(), job({ id: crypto.randomUUID(), status: 'succeeded', trigger: 'schedule' })],
        page: 1,
        pageSize: 25,
        total: 2,
      }),
    });
    renderAt('/scans');
    const table = await screen.findByRole('table');
    expect(within(table).getByText('Queued')).toBeInTheDocument();
    expect(within(table).getByText('Succeeded')).toBeInTheDocument();
    expect(within(table).getByText('Scheduled')).toBeInTheDocument();
    expect(within(table).getAllByRole('link', { name: 'example.com' })[0]).toHaveAttribute(
      'href',
      `/scans/${JOB_ID}`,
    );
  });

  it('shows a scan with its fixed scope and lets an analyst cancel it', async () => {
    let cancelled = false;
    const done = () =>
      detail(job({ status: 'cancelled', completedAt: '2026-10-22T10:01:00.000Z' }));
    const calls = stubApi('analyst', {
      [`GET /api/v1/scans/${JOB_ID}`]: () => ok(cancelled ? done() : detail(job()))(),
      [`POST /api/v1/scans/${JOB_ID}/cancel`]: () => {
        cancelled = true;
        return ok(done())();
      },
    });
    renderAt(`/scans/${JOB_ID}`);
    expect(await screen.findByText('dns, rdap')).toBeInTheDocument();
    expect(screen.getByText(/Waiting for the scanning worker/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Cancel scan' }));
    expect(await screen.findByText('Cancelled')).toBeInTheDocument();
    expect(calls.some((c) => c.method === 'POST' && c.path.endsWith('/cancel'))).toBe(true);
    expect(screen.queryByRole('button', { name: 'Cancel scan' })).not.toBeInTheDocument();
  });

  it('hides cancel from viewers', async () => {
    stubApi('viewer', { [`GET /api/v1/scans/${JOB_ID}`]: ok(detail(job())) });
    renderAt(`/scans/${JOB_ID}`);
    await screen.findByText('dns, rdap');
    expect(screen.queryByRole('button', { name: 'Cancel scan' })).not.toBeInTheDocument();
  });
});

describe('Domain scans card', () => {
  it('requests a passive scan and offers active profiles only when allowed', async () => {
    const calls = stubApi('analyst', {
      [`GET /api/v1/domains/${DOMAIN_ID}`]: ok({ domain, verification: null }),
      'GET /api/v1/scan-profiles': ok(profiles(false)),
      [`GET /api/v1/scans?domainId=${DOMAIN_ID}&pageSize=5`]: ok({
        items: [],
        page: 1,
        pageSize: 5,
        total: 0,
      }),
      [`POST /api/v1/domains/${DOMAIN_ID}/scans`]: () => ({ status: 202, body: detail(job()) }),
      [`GET /api/v1/scans/${JOB_ID}`]: ok(detail(job())),
    });
    const router = renderAt(`/domains/${DOMAIN_ID}`);
    const quick = await screen.findByRole('option', {
      name: /Quick \(active scanning not enabled yet\)/,
    });
    expect(quick).toBeDisabled();
    expect(
      screen.getByRole('option', { name: /Passive \(no contact with your hosts\)/ }),
    ).toBeEnabled();

    await userEvent.click(screen.getByRole('button', { name: 'Request scan' }));
    expect(await screen.findByText('dns, rdap')).toBeInTheDocument();
    expect(router.state.location.pathname).toBe(`/scans/${JOB_ID}`);
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({ profile: 'passive' });
  });
});

describe('Discovery jobs', () => {
  const discoveryJob = () =>
    job({ id: crypto.randomUUID(), jobType: 'discovery', profile: 'discovery' });

  it('shows the job type in the scan list', async () => {
    stubApi('viewer', {
      'GET /api/v1/scans': ok({ items: [job(), discoveryJob()], page: 1, pageSize: 25, total: 2 }),
    });
    renderAt('/scans');
    const table = await screen.findByRole('table');
    expect(within(table).getByRole('columnheader', { name: 'Type' })).toBeInTheDocument();
    const rows = within(table).getAllByRole('row').slice(1);
    expect(within(rows[0]!).getByText('Scan')).toBeInTheDocument();
    expect(within(rows[1]!).getByText('Discovery')).toBeInTheDocument();
  });

  it('titles a discovery job and explains that nothing is contacted or scanned', async () => {
    const d = job({ jobType: 'discovery', profile: 'discovery' });
    stubApi('viewer', { [`GET /api/v1/scans/${JOB_ID}`]: ok(detail(d)) });
    renderAt(`/scans/${JOB_ID}`);
    expect(
      await screen.findByRole('heading', { level: 1, name: 'Discovery for example.com' }),
    ).toBeInTheDocument();
    expect(screen.getByText('Discovery job')).toBeInTheDocument();
    const note = screen.getByTestId('discovery-note');
    expect(note).toHaveTextContent(/never contacts the domain's hosts/);
    expect(within(note).getByRole('link', { name: 'Assets' })).toHaveAttribute(
      'href',
      `/assets?domainId=${DOMAIN_ID}`,
    );
  });

  it('never offers the discovery profile in the scan picker', async () => {
    const withDiscovery = profiles(false);
    withDiscovery.items.push({
      key: 'discovery',
      name: 'Discovery',
      description: 'Certificate Transparency.',
      version: 1,
      defaultSchedule: 'weekly',
      enabled: true,
      config: { ...passiveConfig, checks: ['discovery'] },
    });
    stubApi('analyst', {
      [`GET /api/v1/domains/${DOMAIN_ID}`]: ok({ domain, verification: null }),
      'GET /api/v1/scan-profiles': ok(withDiscovery),
      [`GET /api/v1/scans?domainId=${DOMAIN_ID}&pageSize=5`]: ok({
        items: [discoveryJob()],
        page: 1,
        pageSize: 5,
        total: 1,
      }),
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    const scans = await screen.findByRole('region', { name: 'Scans' });
    await within(scans).findByRole('option', { name: /Passive/ });
    expect(
      within(scans)
        .getAllByRole('option')
        .map((o) => o.getAttribute('value')),
    ).toEqual(['passive', 'quick']);
    expect(await within(scans).findByRole('link', { name: /^Discovery ·/ })).toBeInTheDocument();
  });
});

describe('Settings: workers', () => {
  it('registers a worker by public key and shows its key id', async () => {
    const worker = {
      id: crypto.randomUUID(),
      name: 'home-1',
      status: 'active',
      version: null,
      lastSeenAt: null,
      createdAt: '2026-10-22T10:00:00.000Z',
      credentials: [
        {
          id: '11111111-2222-4333-8444-555555555555',
          fingerprint: 'aa:bb:cc:dd:ee:ff:00:11',
          createdAt: '2026-10-22T10:00:00.000Z',
          expiresAt: '2027-10-22T10:00:00.000Z',
          revokedAt: null,
          lastUsedAt: null,
        },
      ],
    };
    let registered = false;
    const calls = stubApi('admin', {
      'GET /api/v1/workers': () => ok({ items: registered ? [worker] : [] })(),
      'POST /api/v1/workers': () => {
        registered = true;
        return { status: 201, body: { worker, credentialId: worker.credentials[0]!.id } };
      },
    });
    renderAt('/settings');
    expect(await screen.findByText('No workers registered')).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('Public key (base64)'), 'A'.repeat(43) + '=');
    await userEvent.click(screen.getByRole('button', { name: 'Register worker' }));
    expect(await screen.findByText(/Configure the worker with key id/)).toHaveTextContent(
      worker.credentials[0]!.id,
    );
    expect(await screen.findByText('aa:bb:cc:dd:ee:ff:00:11')).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({
      name: 'home-1',
      publicKey: 'A'.repeat(43) + '=',
    });
  });

  it('is limited to administrators', async () => {
    stubApi('analyst', {});
    renderAt('/settings');
    expect(await screen.findByText('Administrators only')).toBeInTheDocument();
  });
});
