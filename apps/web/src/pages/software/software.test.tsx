// Software inventory page, domain Software card, SOFT-002 evidence and the software category label.
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { CATEGORY_LABELS } from '../../components/findings/labels.ts';
import { SOFTWARE_PATHS, apiError, ok, renderAt, stubApi } from '../../testing/stub-api.tsx';
import { attackSurface, dashboard } from '../overview/test-data.ts';
import { FINDING_ID, detailOf, domain, finding, page } from '../findings/test-data.ts';
import { DOMAIN_ID, eolPhp, hiddenSsh, softwareItem, softwarePage, summary } from './test-data.ts';

afterEach(() => vi.unstubAllGlobals());

const NVD = 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773';

function stubSoftware(
  handlers: Parameters<typeof stubApi>[1] = {},
  role: 'viewer' | 'asset_owner' = 'viewer',
) {
  return stubApi(role, {
    [SOFTWARE_PATHS.list()]: ok(softwarePage([softwareItem(), eolPhp(), hiddenSsh()])),
    [SOFTWARE_PATHS.summary]: ok(summary()),
    ...handlers,
  });
}

const rowOf = (text: string) => {
  const row = screen.getByText(text).closest('tr');
  if (!row) throw new Error(`row for ${text} missing`);
  return within(row);
};

describe('Software page', () => {
  it('is in the primary navigation after Certificates (Milestone 13 order)', async () => {
    stubSoftware();
    renderAt('/software');
    const nav = screen.getByRole('navigation', { name: 'Primary' });
    const labels = within(nav)
      .getAllByRole('link')
      .map((l) => l.textContent);
    expect(labels.indexOf('Software')).toBe(labels.indexOf('Certificates') + 1);
    expect(screen.getByRole('heading', { level: 1, name: 'Software' })).toBeInTheDocument();
  });

  it('explains self-reported versions, backports, hidden versions, verification and scan tiers', async () => {
    stubSoftware();
    renderAt('/software');
    const note = screen.getByRole('note', { name: 'How to read this inventory' });
    expect(note).toHaveTextContent(/self-reported/);
    expect(note).toHaveTextContent(/backport security fixes without changing the version number/);
    expect(note).toHaveTextContent(/hidden version means unknown, not safe/);
    expect(note).toHaveTextContent(/possibly affected — verify/);
    expect(note).toHaveTextContent(/Quick scan or higher/);
    expect(note).toHaveTextContent(/Standard or Deep scan/);
  });

  it('renders location, version, source, EOL badge, KEV chips with NVD links and backport hints', async () => {
    stubSoftware();
    renderAt('/software');
    await screen.findByText('shop.example.com:443');

    const apache = rowOf('shop.example.com:443');
    expect(apache.getByText('Apache HTTP Server')).toBeInTheDocument();
    expect(apache.getByText('2.4.49')).toBeInTheDocument();
    expect(apache.getByText('HTTP header')).toBeInTheDocument();
    expect(apache.getByText('Ubuntu build: fixes may be backported')).toBeInTheDocument();
    expect(apache.getByText(/Supported/)).toBeInTheDocument();
    const cve = apache.getByRole('link', { name: /CVE-2021-41773/ });
    expect(cve).toHaveAttribute('href', NVD);
    expect(cve).toHaveAttribute('target', '_blank');
    expect(cve).toHaveAttribute('rel', 'noopener noreferrer');
    expect(apache.getByText('CVSS 7.5')).toBeInTheDocument();
    // Ransomware use is stated in text, never by colour alone.
    expect(apache.getByText('Ransomware')).toBeInTheDocument();
    expect(apache.getByRole('link', { name: 'example.com' })).toHaveAttribute(
      'href',
      `/domains/${DOMAIN_ID}`,
    );

    const php = rowOf('legacy.example.com:443');
    expect(php.getByText(/End of life since Nov 28, 2022/)).toBeInTheDocument();
    expect(php.getByText(/Cycle 7.4 · latest 7.4.33/)).toBeInTheDocument();
    expect(php.getByText('None matched')).toBeInTheDocument();

    const ssh = rowOf('[2001:db8::5]:22');
    expect(ssh.getByText('hidden')).toBeInTheDocument();
    expect(ssh.getByText('Service identification')).toBeInTheDocument();
    expect(ssh.getByText('No end-of-life data')).toBeInTheDocument();
  });

  it('shows the portfolio rollup with host counts, version distribution, EOL and KEV counts', async () => {
    stubSoftware();
    renderAt('/software');
    const card = within(await screen.findByRole('region', { name: 'Portfolio by product' }));
    const phpLink = await card.findByRole('link', { name: 'PHP' });
    const php = within(phpLink.closest('tr') as HTMLElement);
    const cells = php.getAllByRole('cell').map((c) => c.textContent);
    expect(cells[1]).toBe('4');
    expect(cells[2]).toContain('7.4.3 × 2');
    expect(cells[2]).toContain('hidden × 1');
    expect(cells[3]).toBe('3');
    expect(cells[4]).toBe('0');
    expect(phpLink).toHaveAttribute('href', '/software?product=php');
    // Possibly-KEV products sort first.
    const products = card
      .getAllByRole('row')
      .slice(1)
      .map((r) => within(r).getAllByRole('cell')[0]?.textContent);
    expect(products).toEqual(['Apache HTTP Server', 'PHP']);
  });

  it('keeps filters in the URL and sends them to the API', async () => {
    const calls = stubSoftware({
      [SOFTWARE_PATHS.list('?product=php')]: ok(softwarePage([eolPhp()])),
      [SOFTWARE_PATHS.list('?product=php&status=eol')]: ok(softwarePage([eolPhp()])),
      [SOFTWARE_PATHS.list('?product=php&status=eol&q=legacy')]: ok(softwarePage([])),
    });
    const router = renderAt('/software');
    await screen.findByText('shop.example.com:443');
    await userEvent.selectOptions(screen.getByLabelText('Product'), 'php');
    await userEvent.selectOptions(screen.getByLabelText('Show'), 'eol');
    await userEvent.type(screen.getByLabelText('Search software'), 'legacy');
    await userEvent.click(screen.getByRole('button', { name: 'Search' }));
    expect(await screen.findByText('No software matches these filters')).toBeInTheDocument();
    expect(router.state.location.search).toBe('?product=php&status=eol&q=legacy');
    expect(calls.map((c) => c.path)).toContain('/api/v1/software?product=php&status=eol&q=legacy');

    await userEvent.selectOptions(screen.getByLabelText('Show'), 'all');
    expect(router.state.location.search).toBe('?product=php&q=legacy');
  });

  it('reads a domain filter from the URL and lets it be cleared', async () => {
    stubSoftware({
      [SOFTWARE_PATHS.list(`?domainId=${DOMAIN_ID}`)]: ok(softwarePage([softwareItem()])),
    });
    const router = renderAt(`/software?domainId=${DOMAIN_ID}`);
    await userEvent.click(
      await screen.findByRole('button', { name: 'Clear filter Domain: example.com' }),
    );
    expect(router.state.location.search).toBe('');
    expect(await screen.findByText('[2001:db8::5]:22')).toBeInTheDocument();
  });

  it('guides the user to run Quick or Standard scans when nothing is recorded', async () => {
    stubSoftware({
      [SOFTWARE_PATHS.list()]: ok(softwarePage([])),
      [SOFTWARE_PATHS.summary]: ok({ products: [] }),
    });
    renderAt('/software');
    expect(await screen.findByText('No software recorded yet')).toBeInTheDocument();
    expect(screen.getByText(/Run a/).textContent).toMatch(/Quick scan.*Standard scan/);
    expect(screen.getByRole('link', { name: 'domain page' })).toHaveAttribute('href', '/domains');
    expect(screen.getByRole('link', { name: 'Settings → Scan profiles' })).toHaveAttribute(
      'href',
      '/settings?tab=profiles',
    );
  });

  it('shows the permission-denied state on 403, not the raw error', async () => {
    stubSoftware({
      [SOFTWARE_PATHS.list()]: apiError(403, 'forbidden', 'Forbidden'),
      [SOFTWARE_PATHS.summary]: apiError(403, 'forbidden', 'Forbidden'),
    });
    renderAt('/software');
    expect((await screen.findAllByText('You do not have access to this information')).length).toBe(
      2,
    );
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
});

describe('Domain software card', () => {
  const stubDomain = (handlers: Parameters<typeof stubApi>[1] = {}) =>
    stubApi('viewer', {
      [`GET /api/v1/domains/${DOMAIN_ID}`]: ok({ domain: domain(), verification: null }),
      [SOFTWARE_PATHS.domain(DOMAIN_ID, '?pageSize=10')]: ok(
        softwarePage([softwareItem(), eolPhp()], 14, 10),
      ),
      ...handlers,
    });

  it('lists the compact columns and links to the filtered inventory', async () => {
    stubDomain();
    renderAt(`/domains/${DOMAIN_ID}`);
    const card = within(await screen.findByRole('region', { name: 'Software' }));
    expect(await card.findByText('shop.example.com:443')).toBeInTheDocument();
    expect(card.getByRole('link', { name: /CVE-2021-41773/ })).toHaveAttribute('href', NVD);
    expect(card.getByText(/End of life since/)).toBeInTheDocument();
    expect(card.queryByText('Source')).not.toBeInTheDocument();
    expect(card.getByText(/possibly affected — verify/)).toBeInTheDocument();
    expect(card.getByRole('link', { name: 'View all 14 software entries' })).toHaveAttribute(
      'href',
      `/software?domainId=${DOMAIN_ID}`,
    );
  });

  it('explains how software gets recorded when there is none', async () => {
    stubDomain({ [SOFTWARE_PATHS.domain(DOMAIN_ID, '?pageSize=10')]: ok(softwarePage([])) });
    renderAt(`/domains/${DOMAIN_ID}`);
    const card = within(await screen.findByRole('region', { name: 'Software' }));
    expect(await card.findByText(/No software recorded. A Quick scan/)).toBeInTheDocument();
  });
});

describe('SOFT-002 evidence', () => {
  const soft002 = finding({
    ruleId: 'SOFT-002',
    category: 'software',
    title: 'Version possibly affected by a known-exploited vulnerability (CISA KEV)',
    component: 'software:apache_httpd:443',
    evidence: {
      product: 'apache_httpd',
      version: '2.4.49',
      banner: 'Apache/2.4.49 (Ubuntu)',
      backportDistribution: 'Ubuntu',
      cveId: 'CVE-2021-41773',
      ranges: [{ startIncluding: '2.4.49', endExcluding: '2.4.50' }],
      advisories: [
        {
          cveId: 'CVE-2021-42013',
          title: 'Apache HTTP Server path traversal',
          cvss: 9.8,
          kevDateAdded: '2021-11-03',
          ransomware: true,
          ranges: [{ startIncluding: '2.4.49', endIncluding: '2.4.50' }],
        },
      ],
      note: '<img src=x onerror=alert(1)>',
    },
  });

  it('links CVEs to NVD, states ranges, CVSS, KEV date and backport note as text', async () => {
    stubApi('viewer', {
      [`GET /api/v1/findings/${FINDING_ID}`]: ok(detailOf({ finding: soft002 })),
    });
    renderAt(`/findings/${FINDING_ID}`);
    const evidence = within(await screen.findByTestId('evidence'));
    expect(evidence.getByRole('link', { name: /CVE-2021-41773/ })).toHaveAttribute('href', NVD);
    expect(evidence.getByRole('link', { name: /CVE-2021-42013/ })).toHaveAttribute(
      'href',
      'https://nvd.nist.gov/vuln/detail/CVE-2021-42013',
    );
    expect(evidence.getByText('from 2.4.49 up to (not including) 2.4.50')).toBeInTheDocument();
    expect(evidence.getByText('from 2.4.49 up to and including 2.4.50')).toBeInTheDocument();
    expect(evidence.getByText('CVSS 9.8')).toBeInTheDocument();
    expect(evidence.getByText(/Added to CISA KEV Nov 3, 2021/)).toBeInTheDocument();
    expect(evidence.getByText('Known ransomware use')).toBeInTheDocument();
    expect(evidence.getByText('Apache HTTP Server path traversal')).toBeInTheDocument();
    // Evidence text is never interpreted as HTML.
    expect(evidence.getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument();
    expect(document.querySelector('img[src="x"]')).toBeNull();

    expect(
      screen.getByText(/names a Ubuntu build\. Distributions often backport security fixes/),
    ).toBeInTheDocument();
    expect(screen.getByText(/treat this as possibly affected and verify/)).toBeInTheDocument();
    expect(screen.getByText('Exposed software')).toBeInTheDocument();
  });

  it('never links strings that are not well-formed CVE identifiers', async () => {
    stubApi('viewer', {
      [`GET /api/v1/findings/${FINDING_ID}`]: ok(
        detailOf({
          finding: finding({
            evidence: { cveId: 'CVE-2021-41773"><script>', other: 'javascript:alert(1)' },
          }),
        }),
      ),
    });
    renderAt(`/findings/${FINDING_ID}`);
    const evidence = within(await screen.findByTestId('evidence'));
    expect(evidence.queryByRole('link')).not.toBeInTheDocument();
    expect(evidence.getByText('CVE-2021-41773"><script>')).toBeInTheDocument();
  });
});

describe('Software category label', () => {
  it('has a display label and appears in the findings category filter', async () => {
    expect(CATEGORY_LABELS.software).toBe('Exposed software');
    stubApi('viewer', {
      'GET /api/v1/findings': ok(page([])),
      'GET /api/v1/findings?category=software': ok(page([])),
    });
    const router = renderAt('/findings');
    await userEvent.selectOptions(await screen.findByLabelText('Category'), 'software');
    expect(router.state.location.search).toBe('?category=software');
    expect(screen.getByRole('option', { name: 'Exposed software' })).toBeInTheDocument();
  });

  it('shows EOL and possibly-KEV counts on the Overview', async () => {
    stubApi('viewer', {
      'GET /api/v1/dashboard?range=30': ok(dashboard()),
      'GET /api/v1/attack-surface': ok(attackSurface()),
    });
    renderAt('/');
    const tile = within(await screen.findByTestId('stat-eolSoftware'));
    expect(tile.getByTestId('stat-value')).toHaveTextContent('4');
    expect(tile.getByText('1 possibly KEV-affected')).toBeInTheDocument();
    const card = within(await screen.findByRole('region', { name: 'Exposed software (top 5)' }));
    expect(card.getByText('3 EOL')).toBeInTheDocument();
    expect(card.getByRole('link', { name: /View all/ })).toHaveAttribute('href', '/software');
  });
});
