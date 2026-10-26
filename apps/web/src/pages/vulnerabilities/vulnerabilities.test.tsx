// Vulnerabilities (KEV CVE) inventory page (Milestone 13).
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { CvssChip } from '../../components/inventory/CvssChip.tsx';
import { cvssBand } from '../../components/inventory/format.ts';
import {
  INVENTORY_PATHS,
  vulnerabilitiesPage,
  vulnerabilityItem,
} from '../../components/inventory/test-data.ts';
import { apiError, ok, renderAt, stubApi } from '../../testing/stub-api.tsx';

afterEach(() => vi.unstubAllGlobals());

const log4j = () =>
  vulnerabilityItem({
    cve: 'CVE-2021-44228',
    title: 'Apache Log4j2 Remote Code Execution',
    cvss: 10,
    knownRansomwareUse: false,
    products: [{ product: 'log4j', productLabel: 'Log4j' }],
    affectedHosts: 1,
    affectedDomains: 1,
    openFindings: 0,
    kevDateAdded: null,
  });

function stubVulns(handlers: Parameters<typeof stubApi>[1] = {}) {
  return stubApi('viewer', {
    [INVENTORY_PATHS.vulnerabilities()]: ok(vulnerabilitiesPage([vulnerabilityItem(), log4j()])),
    ...handlers,
  });
}

const rowOf = (text: string) => {
  const row = screen.getByText(text).closest('tr');
  if (!row) throw new Error(`row for ${text} missing`);
  return within(row);
};

describe('CVSS chip', () => {
  it.each([
    [0, 'None'],
    [0.1, 'Low'],
    [3.9, 'Low'],
    [4, 'Medium'],
    [6.9, 'Medium'],
    [7, 'High'],
    [8.9, 'High'],
    [9, 'Critical'],
    [10, 'Critical'],
  ] as const)('%s → %s (CVSS v3 bands)', (score, band) => {
    expect(cvssBand(score)).toBe(band);
  });

  it('shows the score and band as text, and nothing coloured like a severity badge', () => {
    render(<CvssChip score={9.8} />);
    const chip = screen.getByTitle('CVSS base score 9.8 (Critical)');
    expect(chip).toHaveTextContent('9.8Critical');
    expect(chip.className).not.toMatch(/sev-|red-|orange-/);
  });
});

describe('Vulnerabilities page', () => {
  it('is reachable from the navigation (no longer a placeholder)', async () => {
    stubVulns();
    renderAt('/');
    const nav = screen.getByRole('navigation', { name: 'Primary' });
    await userEvent.click(within(nav).getByRole('link', { name: 'Vulnerabilities' }));
    expect(screen.getByRole('heading', { level: 1, name: 'Vulnerabilities' })).toBeInTheDocument();
    expect(screen.queryByText(/Milestone 13/)).not.toBeInTheDocument();
  });

  it('explains that matches are possible, not proof', async () => {
    stubVulns();
    renderAt('/vulnerabilities');
    const note = screen.getByRole('note', { name: 'How to read these matches' });
    expect(note).toHaveTextContent('Possibly affected — verify before acting.');
    expect(note).toHaveTextContent(
      'Versions come from banners; distributions often backport fixes.',
    );
  });

  it('renders CVE links to NVD, KEV and ransomware badges, CVSS, products, counts and dates', async () => {
    stubVulns();
    renderAt('/vulnerabilities');
    await screen.findByText('Apache HTTP Server Path Traversal');

    const apache = rowOf('Apache HTTP Server Path Traversal');
    const link = apache.getByRole('link', { name: /^CVE-2021-41773/ });
    expect(link).toHaveAttribute('href', 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773');
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
    expect(apache.getByText('CISA KEV')).toBeInTheDocument();
    expect(apache.getByText('Ransomware use')).toBeInTheDocument();
    expect(apache.getByTitle('CVSS base score 7.5 (High)')).toBeInTheDocument();
    expect(apache.getByRole('link', { name: 'Apache HTTP Server' })).toHaveAttribute(
      'href',
      '/software?product=apache_httpd&status=kev',
    );
    expect(apache.getByText('3 hosts')).toBeInTheDocument();
    expect(
      apache.getByRole('link', { name: '2 open findings for CVE-2021-41773' }),
    ).toHaveAttribute('href', '/findings?ruleId=SOFT-002&q=CVE-2021-41773');
    expect(apache.getByText('Nov 3, 2021')).toBeInTheDocument();

    const log = rowOf('Apache Log4j2 Remote Code Execution');
    expect(log.queryByText('Ransomware use')).not.toBeInTheDocument();
    expect(log.getByTitle('CVSS base score 10.0 (Critical)')).toBeInTheDocument();
    expect(log.queryByRole('link', { name: /open finding/ })).not.toBeInTheDocument();
    expect(log.getByText('1 host')).toBeInTheDocument();
    expect(log.getByText('1 domain')).toBeInTheDocument();
  });

  it('keeps search and sort in the URL and sends them to the API', async () => {
    const calls = stubVulns({
      [INVENTORY_PATHS.vulnerabilities('?q=log4j')]: ok(vulnerabilitiesPage([log4j()])),
      [INVENTORY_PATHS.vulnerabilities('?q=log4j&sort=cvss')]: ok(vulnerabilitiesPage([])),
    });
    const router = renderAt('/vulnerabilities');
    await screen.findByText('Apache HTTP Server Path Traversal');
    await userEvent.type(screen.getByLabelText('Search vulnerabilities'), 'log4j');
    await userEvent.click(screen.getByRole('button', { name: 'Search' }));
    await userEvent.selectOptions(screen.getByLabelText('Sort by'), 'cvss');
    expect(router.state.location.search).toBe('?q=log4j&sort=cvss');
    expect(await screen.findByText('No vulnerabilities match this search')).toBeInTheDocument();
    expect(calls.map((c) => c.path)).toContain('/api/v1/vulnerabilities?q=log4j&sort=cvss');
  });

  it('paginates through the URL', async () => {
    const calls = stubVulns({
      [INVENTORY_PATHS.vulnerabilities()]: ok(vulnerabilitiesPage([vulnerabilityItem()], 26)),
      [INVENTORY_PATHS.vulnerabilities('?page=2')]: ok({
        ...vulnerabilitiesPage([log4j()], 26),
        page: 2,
      }),
    });
    const router = renderAt('/vulnerabilities');
    expect(await screen.findByText('1–25 of 26')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(router.state.location.search).toBe('?page=2');
    expect(await screen.findByText('Apache Log4j2 Remote Code Execution')).toBeInTheDocument();
    expect(calls.map((c) => c.path)).toContain('/api/v1/vulnerabilities?page=2');
  });

  it('explains why the list can be empty without implying safety', async () => {
    stubVulns({ [INVENTORY_PATHS.vulnerabilities()]: ok(vulnerabilitiesPage([])) });
    renderAt('/vulnerabilities');
    expect(
      await screen.findByText('No known-exploited CVEs match your software'),
    ).toBeInTheDocument();
    expect(screen.getByText(/not proof of/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Settings → Intelligence feeds' })).toHaveAttribute(
      'href',
      '/settings?tab=intel',
    );
  });

  it('shows the error with a Retry button', async () => {
    stubVulns({
      [INVENTORY_PATHS.vulnerabilities()]: apiError(500, 'internal_error', 'Something went wrong'),
    });
    renderAt('/vulnerabilities');
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load vulnerabilities');
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
  });
});
