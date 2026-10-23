import type { RouteObject } from 'react-router';
import { AppShell } from './components/layout/AppShell.tsx';
import { NAV_ITEMS } from './components/layout/nav.ts';
import { AssetDetailPage } from './pages/assets/AssetDetailPage.tsx';
import { AssetsPage } from './pages/assets/AssetsPage.tsx';
import { AdvisoriesPage } from './pages/advisories/AdvisoriesPage.tsx';
import { FindingDetailPage } from './pages/findings/FindingDetailPage.tsx';
import { FindingsPage } from './pages/findings/FindingsPage.tsx';
import { DomainDetailPage } from './pages/domains/DomainDetailPage.tsx';
import { DomainImportPage } from './pages/domains/DomainImportPage.tsx';
import { DomainsPage } from './pages/domains/DomainsPage.tsx';
import { NotFoundPage } from './pages/NotFoundPage.tsx';
import { ScanDetailPage } from './pages/scans/ScanDetailPage.tsx';
import { ScansPage } from './pages/scans/ScansPage.tsx';
import { SettingsPage } from './pages/settings/SettingsPage.tsx';
import { SoftwarePage } from './pages/software/SoftwarePage.tsx';
import { OverviewPage } from './pages/OverviewPage.tsx';
import { PlaceholderPage } from './pages/PlaceholderPage.tsx';
import { ReportsPage } from './pages/reports/ReportsPage.tsx';
import { RouteErrorPage } from './pages/RouteErrorPage.tsx';

/** Sections with real pages; the rest render a placeholder naming their milestone. */
const IMPLEMENTED = new Set([
  '/',
  '/domains',
  '/assets',
  '/software',
  '/scans',
  '/findings',
  '/advisories',
  '/reports',
  '/settings',
]);

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
      { path: 'assets', element: <AssetsPage /> },
      { path: 'assets/:id', element: <AssetDetailPage /> },
      { path: 'software', element: <SoftwarePage /> },
      { path: 'scans', element: <ScansPage /> },
      { path: 'scans/:id', element: <ScanDetailPage /> },
      { path: 'findings', element: <FindingsPage /> },
      { path: 'findings/:id', element: <FindingDetailPage /> },
      { path: 'advisories', element: <AdvisoriesPage /> },
      { path: 'reports', element: <ReportsPage /> },
      { path: 'settings', element: <SettingsPage /> },
      ...NAV_ITEMS.filter((item) => !IMPLEMENTED.has(item.path)).map((item) => ({
        path: item.path.slice(1),
        element: <PlaceholderPage item={item} />,
      })),
      { path: '*', element: <NotFoundPage /> },
    ],
  },
];
