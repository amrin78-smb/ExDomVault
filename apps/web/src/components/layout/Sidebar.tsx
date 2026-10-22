import { NavLink } from 'react-router';
import { NAV_ITEMS } from './nav.ts';

export function Sidebar() {
  return (
    <aside className="sticky top-0 flex h-screen w-60 shrink-0 flex-col bg-slate-900 text-slate-300">
      <div className="flex h-14 items-center gap-2.5 border-b border-slate-800 px-5">
        <img src="/favicon.svg" alt="" className="size-7" />
        <div className="leading-tight">
          <div className="text-sm font-semibold text-white">ExDomainVault</div>
          <div className="text-[11px] text-slate-400">External exposure monitoring</div>
        </div>
      </div>
      <nav aria-label="Primary" className="flex-1 overflow-y-auto px-3 py-4">
        <ul className="space-y-0.5">
          {NAV_ITEMS.map(({ path, label, icon: Icon }) => (
            <li key={path}>
              <NavLink
                to={path}
                end={path === '/'}
                className={({ isActive }) =>
                  [
                    'flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors',
                    isActive
                      ? 'bg-slate-800 text-white'
                      : 'text-slate-300 hover:bg-slate-800/60 hover:text-white',
                  ].join(' ')
                }
              >
                <Icon className="size-4 shrink-0" aria-hidden />
                {label}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
      <div className="border-t border-slate-800 px-5 py-3 text-[11px] text-slate-500">v0.1.0</div>
    </aside>
  );
}
