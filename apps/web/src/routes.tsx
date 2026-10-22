import type { RouteObject } from 'react-router';
import { AppShell } from './components/layout/AppShell.tsx';
import { NAV_ITEMS } from './components/layout/nav.ts';
import { DomainDetailPage } from './pages/domains/DomainDetailPage.tsx';
import { DomainImportPage } from './pages/domains/DomainImportPage.tsx';
import { DomainsPage } from './pages/domains/DomainsPage.tsx';
import { NotFoundPage } from './pages/NotFoundPage.tsx';
import { OverviewPage } from './pages/OverviewPage.tsx';
import { PlaceholderPage } from './pages/PlaceholderPage.tsx';
import { RouteErrorPage } from './pages/RouteErrorPage.tsx';

/** Sections with real pages; the rest render a placeholder naming their milestone. */
const IMPLEMENTED = new Set(['/', '/domains']);

export const routes: RouteObject[] = [
  {
    path: '/',
    element: <AppShell />,
    errorElement: <RouteErrorPage />,
    children: [
      { index: true, element: <OverviewPage /> },
      { path: 'domains', element: <DomainsPage /> },
      { path: 'domains/import', element: <DomainImportPage /> },
      { path: 'domains/:id', element: <DomainDetailPage /> },
      ...NAV_ITEMS.filter((item) => !IMPLEMENTED.has(item.path)).map((item) => ({
        path: item.path.slice(1),
        element: <PlaceholderPage item={item} />,
      })),
      { path: '*', element: <NotFoundPage /> },
    ],
  },
];
