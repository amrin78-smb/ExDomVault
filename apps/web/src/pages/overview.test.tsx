import type { ScanJob, Worker } from '@exdomainvault/shared';
import { screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ok, renderAt, stubApi, type Handler } from '../testing/stub-api.tsx';
import { DOMAIN_ID, NO_CATEGORIES, finding, page } from './findings/test-data.ts';

afterEach(() => vi.unstubAllGlobals());

const job = (overrides: Partial<ScanJob> = {}): ScanJob => ({
  id: crypto.randomUUID(),
  jobType: 'scan',
  profile: 'passive',
  domain: { id: DOMAIN_ID, fqdn: 'example.com' },
  status: 'succeeded',
  priority: 100,
  reason: null,
  trigger: 'schedule',
  requestedBy: null,
  createdAt: '2026-10-22T02:00:00.000Z',
  scheduledAt: '2026-10-22T02:00:00.000Z',
  startedAt: '2026-10-22T02:00:05.000Z',
  completedAt: '2026-10-22T02:01:00.000Z',
  leaseExpiresAt: null,
  attempts: 1,
  maxAttempts: 3,
  worker: null,
  progress: null,
  cancelRequestedAt: null,
  errorCode: null,
  errorSummary: null,
  targetCounts: { pending: 0, running: 0, succeeded: 1, failed: 0, skipped: 0 },
  ...overrides,
});

const worker = (overrides: Partial<Worker> = {}): Worker => ({
  id: crypto.randomUUID(),
  name: 'home-worker-01',
  status: 'active',
  version: '0.1.0',
  lastSeenAt: new Date().toISOString(),
  createdAt: '2026-10-01T00:00:00.000Z',
  credentials: [],
  ...overrides,
});

const total = (n: number) => ok(page([], n));
const summary = {
  bySeverity: { critical: 1, high: 2, medium: 3, low: 0, informational: 4 },
  total: 10,
  byCategory: NO_CATEGORIES,
};
const empty = ok(page([]));

const ALL: Record<string, Handler> = {
  'GET /api/v1/domains?pageSize=1': total(12),
  'GET /api/v1/domains?monitoring=true&pageSize=1': total(9),
  'GET /api/v1/domains?verificationStatus=verified&pageSize=1': total(4),
  'GET /api/v1/findings/summary': ok(summary),
  'GET /api/v1/scans?pageSize=5': ok(
    page([job(), job({ status: 'failed', domain: { id: DOMAIN_ID, fqdn: 'example.org' } })]),
  ),
  'GET /api/v1/workers': ok({ items: [worker()] }),
  'GET /api/v1/findings?pageSize=5&sort=-riskScore': ok(
    page([finding({ title: 'Potential dangling CNAME requiring validation', ruleId: 'DNS-002' })]),
  ),
  'GET /api/v1/findings?ruleId=TLS-001&pageSize=5': empty,
  'GET /api/v1/findings?ruleId=TLS-003&pageSize=5': ok(page([finding()])),
  'GET /api/v1/findings?ruleId=DNS-001&pageSize=5': ok(
    page([
      finding({
        id: crypto.randomUUID(),
        ruleId: 'DNS-001',
        title: 'Unexpected authoritative DNS change',
        hostname: 'example.com',
      }),
    ]),
  ),
  'GET /api/v1/findings?ruleId=REG-002&pageSize=5': empty,
};

const card = (name: string) => screen.findByRole('region', { name });

describe('Overview', () => {
  it('renders live counts, findings, scans, workers and priorities', async () => {
    stubApi('admin', ALL);
    renderAt('/');
    expect(await screen.findByText('of 12 domains')).toBeInTheDocument();
    const stat = (label: string) => screen.getByText(label).parentElement!;
    expect(stat('Domains monitored')).toHaveTextContent('9');
    expect(stat('Verified domains')).toHaveTextContent('4');
    expect(await screen.findByText('Not yet resolved')).toBeInTheDocument();
    expect(stat('Open findings')).toHaveTextContent('10');
    expect(stat('Critical and high')).toHaveTextContent('3');

    const sev = await card('Open findings by severity');
    expect(await within(sev).findByTestId('count-informational')).toHaveTextContent('4');
    expect(within(sev).getByRole('link', { name: 'View all 10 open findings' })).toBeVisible();

    const scans = await card('Latest scans');
    expect(await within(scans).findByText('example.org')).toBeInTheDocument();
    expect(within(scans).getByText('Failed')).toBeInTheDocument();
    expect(within(scans).getByText('Succeeded')).toBeInTheDocument();

    const workers = await card('Worker health');
    expect(await within(workers).findByText('home-worker-01')).toBeInTheDocument();
    expect(within(workers).getByText('Polling')).toBeInTheDocument();

    const top = await card('Top remediation priorities');
    expect(
      await within(top).findByRole('link', {
        name: 'Potential dangling CNAME requiring validation',
      }),
    ).toBeInTheDocument();

    const certs = await card('Certificates approaching expiry');
    expect(
      await within(certs).findByRole('link', { name: 'Certificate expires within 14 days' }),
    ).toBeInTheDocument();

    const dns = await card('Recently changed DNS records');
    expect(
      await within(dns).findByRole('link', { name: 'Unexpected authoritative DNS change' }),
    ).toBeInTheDocument();
    expect(screen.queryByText(/Development data/)).not.toBeInTheDocument();
  });

  it('shows honest empty states when there is no data', async () => {
    stubApi('admin', {
      ...ALL,
      'GET /api/v1/findings/summary': ok({
        bySeverity: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
        total: 0,
        byCategory: NO_CATEGORIES,
      }),
      'GET /api/v1/scans?pageSize=5': empty,
      'GET /api/v1/workers': ok({ items: [] }),
      'GET /api/v1/findings?pageSize=5&sort=-riskScore': empty,
      'GET /api/v1/findings?ruleId=TLS-003&pageSize=5': empty,
      'GET /api/v1/findings?ruleId=DNS-001&pageSize=5': empty,
    });
    renderAt('/');
    expect(await screen.findByText('No open findings')).toBeInTheDocument();
    expect(await screen.findByText('No scans have run')).toBeInTheDocument();
    expect(await screen.findByText('No worker registered')).toBeInTheDocument();
    expect(await screen.findByText('Nothing to prioritise')).toBeInTheDocument();
    expect(await screen.findByText('No certificate expiry findings')).toBeInTheDocument();
    expect(
      await screen.findByText('No unexpected DNS or registration changes'),
    ).toBeInTheDocument();
  });

  it('shows an error per card without hiding the others', async () => {
    const fail = () => ({
      status: 500,
      body: { error: { code: 'internal_error', message: 'Boom.', requestId: 'r6' } },
    });
    stubApi('admin', {
      ...ALL,
      'GET /api/v1/scans?pageSize=5': fail,
      'GET /api/v1/findings?ruleId=TLS-001&pageSize=5': fail,
    });
    renderAt('/');
    const scans = await card('Latest scans');
    expect(await within(scans).findByRole('alert')).toHaveTextContent('Could not load scans');
    const certs = await card('Certificates approaching expiry');
    expect(await within(certs).findByRole('alert')).toHaveTextContent('Could not load findings');
    const top = await card('Top remediation priorities');
    expect(
      await within(top).findByRole('link', {
        name: 'Potential dangling CNAME requiring validation',
      }),
    ).toBeInTheDocument();
  });

  it('hides worker health from non-administrators and never requests it', async () => {
    const calls = stubApi('viewer', ALL);
    renderAt('/');
    const workers = await card('Worker health');
    expect(
      await within(workers).findByText('Worker health is visible to administrators.'),
    ).toBeInTheDocument();
    await screen.findByText('of 12 domains');
    expect(calls.some((c) => c.path === '/api/v1/workers')).toBe(false);
  });

  it('flags a worker that has not polled recently', async () => {
    stubApi('admin', {
      ...ALL,
      'GET /api/v1/workers': ok({
        items: [
          worker({ lastSeenAt: '2026-01-01T00:00:00.000Z' }),
          worker({ name: 'w2', lastSeenAt: null }),
        ],
      }),
    });
    renderAt('/');
    const workers = await card('Worker health');
    expect(await within(workers).findAllByText('Not seen recently')).toHaveLength(2);
    expect(within(workers).getByText('Last seen never')).toBeInTheDocument();
  });
});
