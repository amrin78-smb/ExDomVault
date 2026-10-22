import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { RouterProvider, createMemoryRouter } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DataModeProvider } from './lib/DataModeProvider.tsx';
import { routes } from './routes.tsx';

const healthBody = {
  status: 'degraded',
  service: 'exdomainvault-api',
  version: '0.1.0',
  environment: 'development',
  time: '2026-10-22T00:00:00.000Z',
  components: { database: 'not_configured', auth: 'not_configured' },
};

function renderApp(path = '/', fixtures = false) {
  const router = createMemoryRouter(routes, { initialEntries: [path] });
  return render(
    <DataModeProvider fixtures={fixtures}>
      <RouterProvider router={router} />
    </DataModeProvider>,
  );
}

describe('App shell', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify(healthBody), { status: 200 })),
    );
  });
  afterEach(() => vi.unstubAllGlobals());

  it('renders every primary navigation section', () => {
    renderApp();
    const nav = screen.getByRole('navigation', { name: 'Primary' });
    for (const label of [
      'Overview',
      'Domains',
      'Assets',
      'Scans',
      'Findings',
      'Advisories',
      'Reports',
      'Settings',
    ]) {
      expect(within(nav).getByRole('link', { name: label })).toBeInTheDocument();
    }
  });

  it('shows honest empty states and no dev banner when fixtures are off', () => {
    renderApp();
    expect(screen.getByRole('heading', { level: 1, name: 'Overview' })).toBeInTheDocument();
    expect(screen.queryByText(/Development data/)).not.toBeInTheDocument();
    expect(screen.getByText('No findings recorded')).toBeInTheDocument();
    expect(screen.queryByText('shop.example.com')).not.toBeInTheDocument();
  });

  it('labels fixture data with the development banner', () => {
    renderApp('/', true);
    expect(screen.getByRole('note')).toHaveTextContent('not real scan results');
    expect(screen.getAllByText('shop.example.com').length).toBeGreaterThan(0);
  });

  it('navigates to a section placeholder', async () => {
    renderApp();
    await userEvent.click(screen.getByRole('link', { name: 'Domains' }));
    expect(screen.getByRole('heading', { level: 1, name: 'Domains' })).toBeInTheDocument();
    expect(screen.getByText(/implemented in Milestone 3/)).toBeInTheDocument();
  });

  it('reports API health from the typed health endpoint', async () => {
    renderApp();
    expect(await screen.findByText('API degraded')).toBeInTheDocument();
  });

  it('reports an unreachable API without crashing', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('network down');
      }),
    );
    renderApp();
    expect(await screen.findByText('API unreachable')).toBeInTheDocument();
  });
});
