import type { RouteObject } from 'react-router';
import { AppShell } from './components/layout/AppShell.tsx';
import { NAV_ITEMS } from './components/layout/nav.ts';
import { NotFoundPage } from './pages/NotFoundPage.tsx';
import { PlaceholderPage } from './pages/PlaceholderPage.tsx';
import { RouteErrorPage } from './pages/RouteErrorPage.tsx';
import { PageLoading } from './components/ui/PageLoading.tsx';

/** Sections with real pages; the rest render a placeholder naming their milestone. */
const IMPLEMENTED = new Set([
  '/',
  '/domains',
  '/subdomains',
  '/assets',
  '/attack-surface',
  '/lookalikes',
  '/changes',
  '/ports',
  '/certificates',
  '/software',
  '/vulnerabilities',
  '/scans',
  '/findings',
  '/advisories',
  '/reports',
  '/settings',
]);

/*
 * Pages are code-split: each route loads its own chunk on first visit (react-router `lazy`), so the
 * initial download holds only the shell. Charts (Recharts) and the map ship with the pages that use
 * them. The router keeps the current page on screen while the next chunk loads.
 */
export const routes: RouteObject[] = [
  {
    path: '/',
    element: <AppShell />,
    errorElement: <RouteErrorPage />,
    hydrateFallbackElement: <PageLoading />,
    children: [
      {
        index: true,
        lazy: () => import('./pages/OverviewPage.tsx').then((m) => ({ Component: m.OverviewPage })),
      },
      {
        path: 'domains',
        lazy: () =>
          import('./pages/domains/DomainsPage.tsx').then((m) => ({ Component: m.DomainsPage })),
      },
      {
        path: 'domains/import',
        lazy: () =>
          import('./pages/domains/DomainImportPage.tsx').then((m) => ({
            Component: m.DomainImportPage,
          })),
      },
      {
        path: 'domains/:id',
        lazy: () =>
          import('./pages/domains/DomainDetailPage.tsx').then((m) => ({
            Component: m.DomainDetailPage,
          })),
      },
      {
        path: 'domains/:id/import-hosts',
        lazy: () =>
          import('./pages/domains/AssetImportPage.tsx').then((m) => ({
            Component: m.AssetImportPage,
          })),
      },
      {
        path: 'subdomains',
        lazy: () =>
          import('./pages/subdomains/SubdomainsPage.tsx').then((m) => ({
            Component: m.SubdomainsPage,
          })),
      },
      {
        path: 'assets',
        lazy: () =>
          import('./pages/assets/AssetsPage.tsx').then((m) => ({ Component: m.AssetsPage })),
      },
      {
        path: 'assets/:id',
        lazy: () =>
          import('./pages/assets/AssetDetailPage.tsx').then((m) => ({
            Component: m.AssetDetailPage,
          })),
      },
      {
        path: 'attack-surface',
        lazy: () =>
          import('./pages/attack-surface/AttackSurfacePage.tsx').then((m) => ({
            Component: m.AttackSurfacePage,
          })),
      },
      {
        path: 'lookalikes',
        lazy: () =>
          import('./pages/lookalikes/LookalikesPage.tsx').then((m) => ({
            Component: m.LookalikesPage,
          })),
      },
      {
        path: 'changes',
        lazy: () =>
          import('./pages/changes/ChangesPage.tsx').then((m) => ({ Component: m.ChangesPage })),
      },
      {
        path: 'ports',
        lazy: () => import('./pages/ports/PortsPage.tsx').then((m) => ({ Component: m.PortsPage })),
      },
      {
        path: 'certificates',
        lazy: () =>
          import('./pages/certificates/CertificatesPage.tsx').then((m) => ({
            Component: m.CertificatesPage,
          })),
      },
      {
        path: 'software',
        lazy: () =>
          import('./pages/software/SoftwarePage.tsx').then((m) => ({ Component: m.SoftwarePage })),
      },
      {
        path: 'vulnerabilities',
        lazy: () =>
          import('./pages/vulnerabilities/VulnerabilitiesPage.tsx').then((m) => ({
            Component: m.VulnerabilitiesPage,
          })),
      },
      {
        path: 'scans',
        lazy: () => import('./pages/scans/ScansPage.tsx').then((m) => ({ Component: m.ScansPage })),
      },
      {
        path: 'scans/:id',
        lazy: () =>
          import('./pages/scans/ScanDetailPage.tsx').then((m) => ({ Component: m.ScanDetailPage })),
      },
      {
        path: 'findings',
        lazy: () =>
          import('./pages/findings/FindingsPage.tsx').then((m) => ({ Component: m.FindingsPage })),
      },
      {
        path: 'findings/:id',
        lazy: () =>
          import('./pages/findings/FindingDetailPage.tsx').then((m) => ({
            Component: m.FindingDetailPage,
          })),
      },
      {
        path: 'advisories',
        lazy: () =>
          import('./pages/advisories/AdvisoriesPage.tsx').then((m) => ({
            Component: m.AdvisoriesPage,
          })),
      },
      {
        path: 'reports',
        lazy: () =>
          import('./pages/reports/ReportsPage.tsx').then((m) => ({ Component: m.ReportsPage })),
      },
      {
        path: 'reports/monthly/:period',
        lazy: () =>
          import('./pages/reports/MonthlyReportPage.tsx').then((m) => ({
            Component: m.MonthlyReportPage,
          })),
      },
      {
        path: 'settings',
        lazy: () =>
          import('./pages/settings/SettingsPage.tsx').then((m) => ({ Component: m.SettingsPage })),
      },
      ...NAV_ITEMS.filter((item) => !IMPLEMENTED.has(item.path)).map((item) => ({
        path: item.path.slice(1),
        element: <PlaceholderPage item={item} />,
      })),
      { path: '*', element: <NotFoundPage /> },
    ],
  },
];
