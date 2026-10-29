import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {
  DEFAULT_SLA_POLICY,
  computeSecurityScore,
  type DomainScoreResponse,
  type MonthlyReport,
} from '@exdomainvault/shared';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DueBadge } from '../../components/findings/DueBadge.tsx';
import { SecurityScoreCard } from '../../components/domains/SecurityScoreCard.tsx';
import { GradeBadge } from '../../components/ui/GradeBadge.tsx';
import { ok, renderAt, stubApi } from '../../testing/stub-api.tsx';
import { DOMAIN_ID, FINDING_ID, domain, finding, page } from '../findings/test-data.ts';
import { REPORT_PATHS, reportSummary } from './test-data.ts';

beforeEach(() => localStorage.clear());
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const NOW = new Date('2026-10-22T12:00:00.000Z');

describe('DueBadge', () => {
  it('shows overdue in red text with the number of days', () => {
    render(
      <DueBadge
        finding={{ status: 'open', overdue: true, dueAt: '2026-10-17T12:00:00.000Z' }}
        now={NOW}
      />,
    );
    const pill = screen.getByText('Overdue 5d');
    expect(pill.className).toMatch(/text-red-800/);
  });

  it('warns in amber when due within a week', () => {
    render(
      <DueBadge
        finding={{ status: 'acknowledged', overdue: false, dueAt: '2026-10-25T11:00:00.000Z' }}
        now={NOW}
      />,
    );
    expect(screen.getByText('Due in 3d').className).toMatch(/text-amber-800/);
  });

  it('shows the date when due later, and no SLA when there is no due date', () => {
    const { unmount } = render(
      <DueBadge
        finding={{ status: 'open', overdue: false, dueAt: '2026-12-01T00:00:00.000Z' }}
        now={NOW}
      />,
    );
    expect(screen.getByText(/Dec 1, 2026/)).toBeInTheDocument();
    unmount();
    render(<DueBadge finding={{ status: 'open', overdue: false, dueAt: null }} now={NOW} />);
    expect(screen.getByText('No SLA')).toBeInTheDocument();
  });

  it('never shows accepted risk as overdue', () => {
    render(
      <DueBadge
        finding={{ status: 'accepted_risk', overdue: false, dueAt: '2026-10-01T00:00:00.000Z' }}
        now={NOW}
      />,
    );
    expect(screen.queryByText(/Overdue/)).toBeNull();
  });
});

describe('GradeBadge', () => {
  it('labels the grade and score and uses grade (not severity) colours', () => {
    render(<GradeBadge grade="A" score={95} />);
    const a = screen.getByRole('img', { name: 'Grade A, score 95 of 100' });
    expect(a).toHaveTextContent('A');
    expect(a.className).toMatch(/emerald/);
  });
  it('shows F in red and a dash when not scored', () => {
    const { unmount } = render(<GradeBadge grade="F" />);
    expect(screen.getByRole('img', { name: 'Grade F' }).className).toMatch(/red/);
    unmount();
    render(<GradeBadge grade={null} />);
    expect(screen.getByTitle(/Not scored yet/)).toHaveTextContent('—');
  });
});

describe('Findings list due dates', () => {
  it('shows a Due column and filters overdue findings', async () => {
    const overdue = finding({ overdue: true, dueAt: '2026-10-01T00:00:00.000Z' });
    const calls = stubApi('viewer', {
      'GET /api/v1/findings': ok(page([overdue])),
      'GET /api/v1/findings?overdue=true': ok(page([overdue])),
    });
    renderAt('/findings');
    const row = (
      await screen.findByRole('link', { name: 'Certificate expires within 14 days' })
    ).closest('tr');
    expect(within(row!).getByText(/^Overdue \d+d$/)).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText('Remediation SLA'), 'true');
    await screen.findByRole('link', { name: 'Certificate expires within 14 days' });
    expect(calls.map((c) => c.path)).toContain('/api/v1/findings?overdue=true');
  });
});

describe('Settings → Remediation SLAs', () => {
  const policyResponse = {
    policy: DEFAULT_SLA_POLICY,
    updatedAt: null,
    updatedBy: null,
  };

  it('lets administrators edit the days per severity', async () => {
    const calls = stubApi('admin', {
      'GET /api/v1/settings/sla': ok(policyResponse),
      'PUT /api/v1/settings/sla': (body) => ({
        status: 200,
        body: {
          policy: body,
          updatedAt: '2026-10-22T12:00:00.000Z',
          updatedBy: { id: crypto.randomUUID(), email: 'admin@example.com' },
          recomputed: 12,
        },
      }),
    });
    renderAt('/settings?tab=sla');
    const high = await screen.findByLabelText('High days to remediate');
    expect(high).toHaveValue('30');
    await userEvent.clear(high);
    await userEvent.type(high, '14');
    await userEvent.click(screen.getByLabelText('Medium has an SLA'));
    await userEvent.click(screen.getByRole('button', { name: 'Save SLA policy' }));
    expect(await screen.findByText(/Due dates of 12 findings were recalculated/)).toBeVisible();
    expect(calls.find((c) => c.method === 'PUT')?.body).toEqual({
      critical: 7,
      high: 14,
      medium: null,
      low: 180,
      informational: null,
    });
  });

  it('refuses out-of-range values before sending', async () => {
    const calls = stubApi('admin', { 'GET /api/v1/settings/sla': ok(policyResponse) });
    renderAt('/settings?tab=sla');
    const critical = await screen.findByLabelText('Critical days to remediate');
    await userEvent.clear(critical);
    await userEvent.type(critical, '0');
    await userEvent.click(screen.getByRole('button', { name: 'Save SLA policy' }));
    expect(await screen.findByText('Enter 1–3650 days.')).toBeInTheDocument();
    expect(calls.some((c) => c.method === 'PUT')).toBe(false);
  });

  it('is read-only for other roles', async () => {
    stubApi('viewer', { 'GET /api/v1/settings/sla': ok(policyResponse) });
    renderAt('/settings?tab=sla');
    expect(await screen.findByText(/Only administrators can change the policy/)).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Save SLA policy' })).toBeNull();
    expect(screen.getByText('7 days')).toBeInTheDocument();
  });
});

describe('Reports page SLA, owners and monthly reports', () => {
  it('shows the SLA card, owner grades and the monthly report list', async () => {
    stubApi('admin', {
      [REPORT_PATHS.summary]: ok(reportSummary()),
      'GET /api/v1/reports/monthly': ok({
        items: [
          {
            period: '2026-09',
            generatedAt: '2026-10-01T00:05:00.000Z',
            openAtEndTotal: 42,
            overdueAtEnd: 5,
            averageScore: 81.5,
          },
        ],
      }),
    });
    renderAt('/reports');
    const sla = await screen.findByRole('region', { name: 'Remediation SLAs' });
    expect(within(sla).getByTestId('sla-overdue')).toHaveTextContent('3');
    expect(within(sla).getByTestId('sla-overdue')).toHaveAttribute(
      'href',
      '/findings?overdue=true',
    );
    expect(within(sla).getByTestId('sla-compliance')).toHaveTextContent('85%');
    expect(within(sla).getByText('17 of 20 resolved on time, last 90 days')).toBeInTheDocument();

    const monthly = await screen.findByRole('region', { name: 'Monthly reports' });
    expect(await within(monthly).findByRole('link', { name: 'September 2026' })).toHaveAttribute(
      'href',
      '/reports/monthly/2026-09',
    );
    expect(within(monthly).getByRole('button', { name: /^Generate / })).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Expand all' }));
    const owners = await screen.findByRole('region', { name: 'Open findings by business owner' });
    expect(within(owners).getByRole('img', { name: 'Grade B, score 82.4 of 100' })).toBeVisible();
  });
});

const report: MonthlyReport = {
  version: 1,
  period: '2026-09',
  periodStart: '2026-09-01T00:00:00.000Z',
  periodEnd: '2026-10-01T00:00:00.000Z',
  generatedAt: '2026-10-01T00:05:00.000Z',
  totals: { domains: 339, monitoredDomains: 320, assets: 900, approvedAssets: 700, newAssets: 12 },
  findings: {
    opened: { critical: 1, high: 4, medium: 10, low: 3, informational: 0 },
    openedTotal: 18,
    reopened: 2,
    resolved: { critical: 1, high: 2, medium: 5, low: 0, informational: 0 },
    resolvedTotal: 8,
    openAtEnd: { critical: 0, high: 6, medium: 30, low: 6, informational: 0 },
    openAtEndTotal: 42,
    acceptedRiskAtEnd: 3,
    overdueAtEnd: 5,
    overdueAtEndBySeverity: { critical: 0, high: 2, medium: 3, low: 0, informational: 0 },
  },
  sla: {
    policy: DEFAULT_SLA_POLICY,
    resolvedWithSla: 8,
    resolvedWithinSla: 6,
    compliancePercent: 75,
    meanDaysToResolve: 12.5,
    meanDaysToResolveBySeverity: {
      critical: 3,
      high: 10,
      medium: 15,
      low: null,
      informational: null,
    },
  },
  topFindings: [
    {
      id: FINDING_ID,
      ruleId: 'TLS-003',
      title: 'Certificate expires within 14 days',
      severity: 'high',
      riskScore: 80,
      domain: { id: DOMAIN_ID, fqdn: 'example.com' },
      hostname: 'shop.example.com',
      firstSeenAt: '2026-08-01T00:00:00.000Z',
      dueAt: '2026-08-31T00:00:00.000Z',
      overdue: true,
    },
  ],
  topDomains: [
    {
      domain: { id: DOMAIN_ID, fqdn: 'example.com' },
      criticality: 'high',
      businessOwner: 'Retail',
      openFindings: 7,
      riskTotal: 300,
      highestSeverity: 'high',
      grade: 'D',
    },
  ],
  securityScore: {
    scoredDomains: 2,
    averageScore: 81.5,
    grades: { A: 1, B: 0, C: 0, D: 1, F: 0 },
    previousAverageScore: 79,
    change: 2.5,
    best: [{ domain: { id: crypto.randomUUID(), fqdn: 'example.org' }, score: 99, grade: 'A' }],
    worst: [{ domain: { id: DOMAIN_ID, fqdn: 'example.com' }, score: 64, grade: 'D' }],
  },
  exposure: { certificatesExpiring30d: 4, endOfLifeSoftware: 2, knownExploitedSoftware: 1 },
};

describe('Monthly report page', () => {
  it('renders the executive summary and prints', async () => {
    stubApi('viewer', { 'GET /api/v1/reports/monthly/2026-09': ok({ report }) });
    const print = vi.spyOn(window, 'print').mockImplementation(() => {});
    renderAt('/reports/monthly/2026-09');
    expect(
      await screen.findByRole('heading', { name: 'Security report — September 2026' }),
    ).toBeInTheDocument();
    const summary = screen.getByRole('region', { name: 'Summary' });
    expect(within(summary).getByText('81.5')).toBeInTheDocument();
    expect(within(summary).getByText('+2.5 points vs the previous month')).toBeInTheDocument();
    expect(within(summary).getByText('75%')).toBeInTheDocument();
    expect(screen.getByText('(overdue)')).toBeInTheDocument();
    expect(screen.getByRole('img', { name: 'Grade D' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Print / Save as PDF' }));
    expect(print).toHaveBeenCalledTimes(1);
  });

  it('prints in the light theme and restores the dark one', async () => {
    stubApi('viewer', { 'GET /api/v1/reports/monthly/2026-09': ok({ report }) });
    document.documentElement.classList.add('dark');
    renderAt('/reports/monthly/2026-09');
    await screen.findByRole('heading', { name: 'Security report — September 2026' });
    window.dispatchEvent(new Event('beforeprint'));
    expect(document.documentElement.classList.contains('dark')).toBe(false);
    window.dispatchEvent(new Event('afterprint'));
    expect(document.documentElement.classList.contains('dark')).toBe(true);
    document.documentElement.classList.remove('dark');
  });

  it('explains when the report is not available to the role', async () => {
    stubApi('asset_owner', {
      'GET /api/v1/reports/monthly/2026-09': () => ({
        status: 403,
        body: { error: { code: 'forbidden', message: 'No.', requestId: 'r' } },
      }),
    });
    renderAt('/reports/monthly/2026-09');
    expect(await screen.findByText(/not available to your role/)).toBeInTheDocument();
  });
});

describe('Security score in the domain views', () => {
  it('shows a sortable, filterable grade column in the domains list', async () => {
    const calls = stubApi('viewer', {
      'GET /api/v1/domains': ok(page([domain({ score: 76, grade: 'C' })])),
      'GET /api/v1/domains?grade=C': ok(page([domain({ score: 76, grade: 'C' })])),
      'GET /api/v1/domains?grade=C&sort=score': ok(page([domain({ score: 76, grade: 'C' })])),
    });
    renderAt('/domains');
    expect(await screen.findByRole('img', { name: 'Grade C, score 76 of 100' })).toBeVisible();
    await userEvent.selectOptions(screen.getByLabelText('Security grade'), 'C');
    await userEvent.selectOptions(screen.getByLabelText('Sort'), 'score');
    await screen.findByRole('img', { name: 'Grade C, score 76 of 100' });
    expect(calls.map((c) => c.path)).toContain('/api/v1/domains?grade=C&sort=score');
  });

  it('explains the score with deductions and the trend', async () => {
    const current = computeSecurityScore({
      findings: [
        { category: 'email', severity: 'medium', state: 'overdue', count: 1 },
        { category: 'tls', severity: 'high', state: 'open', count: 5 },
      ],
    });
    const res: DomainScoreResponse = {
      domain: { id: DOMAIN_ID, fqdn: 'example.com' },
      current,
      trend: [
        { day: '2026-09-01', score: 60, grade: 'D' },
        { day: '2026-10-22', score: current.score, grade: current.grade },
      ],
      trendDays: 90,
    };
    stubApi('viewer', { [`GET /api/v1/domains/${DOMAIN_ID}/score`]: ok(res) });
    render(<SecurityScoreCard domainId={DOMAIN_ID} />);
    expect(await screen.findByTestId('score-value')).toHaveTextContent('54');
    expect(screen.getByRole('img', { name: 'Grade F, score 54 of 100' })).toBeVisible();
    const why = screen.getByRole('list', { name: 'Why the score is lower' });
    expect(within(why).getByText('TLS / certificates')).toBeInTheDocument();
    expect(within(why).getByText('−40')).toBeInTheDocument();
    expect(within(why).getByText('(capped from 50)')).toBeInTheDocument();
    expect(within(why).getByText(/1 medium overdue \(×1.5\) × 6 = 6/)).toBeInTheDocument();
    expect(screen.getByTestId('sparkline')).toBeInTheDocument();
    expect(screen.getByText(/60 on Sep 1, 2026 → 54 today/)).toBeInTheDocument();
  });

  it('says when a domain has not been scored yet', async () => {
    stubApi('viewer', {
      [`GET /api/v1/domains/${DOMAIN_ID}/score`]: ok({
        domain: { id: DOMAIN_ID, fqdn: 'example.com' },
        current: null,
        trend: [],
        trendDays: 90,
      }),
    });
    render(<SecurityScoreCard domainId={DOMAIN_ID} />);
    expect(await screen.findByText(/Not scored yet/)).toBeInTheDocument();
  });
});
