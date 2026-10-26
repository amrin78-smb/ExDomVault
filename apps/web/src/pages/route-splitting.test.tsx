import { render, screen } from '@testing-library/react';
import { RouterProvider, createMemoryRouter } from 'react-router';
import { describe, expect, it } from 'vitest';
import { routes } from '../routes.tsx';
import { RouteErrorPage } from './RouteErrorPage.tsx';

describe('route code splitting', () => {
  it('loads every implemented page lazily, keeping only the shell eager', () => {
    const children = routes[0]?.children ?? [];
    const lazy = children.filter((r) => typeof r.lazy === 'function');
    expect(lazy.length).toBeGreaterThanOrEqual(20);
    expect(children.find((r) => r.index)?.lazy).toBeTypeOf('function');
  });

  it('asks for a reload when a page chunk from an older deploy is gone', async () => {
    const router = createMemoryRouter(
      [
        {
          path: '/',
          errorElement: <RouteErrorPage />,
          lazy: () =>
            Promise.reject(
              new TypeError('Failed to fetch dynamically imported module: /assets/Old-abc.js'),
            ),
        },
      ],
      { initialEntries: ['/'] },
    );
    render(<RouterProvider router={router} />);
    expect(
      await screen.findByText(/A new version of ExDomainVault was deployed/),
    ).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Reload the application' })).toBeInTheDocument();
  });
});
