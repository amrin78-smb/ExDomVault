import type { RouteObject } from 'react-router';
import { AppShell } from './components/layout/AppShell.tsx';
import { NAV_ITEMS } from './components/layout/nav.ts';
import { NotFoundPage } from './pages/NotFoundPage.tsx';
import { OverviewPage } from './pages/OverviewPage.tsx';
import { PlaceholderPage } from './pages/PlaceholderPage.tsx';
import { RouteErrorPage } from './pages/RouteErrorPage.tsx';

export const routes: RouteObject[] = [
  {
    path: '/',
    element: <AppShell />,
    errorElement: <RouteErrorPage />,
    children: [
      { index: true, element: <OverviewPage /> },
      ...NAV_ITEMS.filter((item) => item.path !== '/').map((item) => ({
        path: item.path.slice(1),
        element: <PlaceholderPage item={item} />,
      })),
      { path: '*', element: <NotFoundPage /> },
    ],
  },
];
