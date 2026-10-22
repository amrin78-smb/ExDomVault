import { Outlet } from 'react-router';
import { useDataMode } from '../../lib/data-mode.ts';
import { DevDataBanner } from '../ui/DevDataBanner.tsx';
import { ApiStatus } from './ApiStatus.tsx';
import { Sidebar } from './Sidebar.tsx';

export function AppShell() {
  const { fixtures } = useDataMode();

  return (
    <div className="flex min-h-screen">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-white focus:px-3 focus:py-2"
      >
        Skip to content
      </a>
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 items-center justify-end gap-4 border-b border-slate-200 bg-white px-6">
          <ApiStatus />
        </header>
        {fixtures && <DevDataBanner />}
        <main id="main" className="flex-1 px-6 py-6 lg:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
