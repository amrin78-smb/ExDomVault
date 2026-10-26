import { Outlet } from 'react-router';
import { useDataMode } from '../../lib/data-mode.ts';
import { OpsAlertsProvider } from '../../lib/OpsAlertsProvider.tsx';
import { SessionProvider } from '../../lib/SessionProvider.tsx';
import { DevDataBanner } from '../ui/DevDataBanner.tsx';
import { OpsAlertBanner } from './OpsAlertBanner.tsx';
import { Sidebar } from './Sidebar.tsx';
import { TopBar } from './TopBar.tsx';

export function AppShell() {
  const { fixtures } = useDataMode();

  return (
    <SessionProvider>
      <OpsAlertsProvider>
        <div className="flex min-h-screen bg-canvas">
          <a
            href="#main"
            className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:rounded focus:bg-surface focus:px-3 focus:py-2"
          >
            Skip to content
          </a>
          <Sidebar />
          <div className="flex min-w-0 flex-1 flex-col">
            <TopBar />
            {fixtures && <DevDataBanner />}
            <OpsAlertBanner />
            <main id="main" className="flex-1 px-6 py-6 lg:px-8">
              <Outlet />
            </main>
          </div>
        </div>
      </OpsAlertsProvider>
    </SessionProvider>
  );
}
