import { Building2 } from 'lucide-react';
import { NavLink } from 'react-router';
import { useSession } from '../../lib/session.ts';
import { ApiStatus } from './ApiStatus.tsx';
import { NAV_ITEMS } from './nav.ts';

/** Primary navigation. Navy in both themes; colours come from the fixed `nav-*` tokens. */
export function Sidebar() {
  const session = useSession();
  const organisation = session.status === 'success' ? session.data.organisation : null;

  return (
    <aside className="sticky top-0 flex h-screen w-[17rem] shrink-0 flex-col border-r border-nav-line bg-nav text-nav-fg">
      <div className="flex h-16 items-center gap-3 px-5">
        <img
          src="/logo-icon.svg"
          alt=""
          className="size-9 drop-shadow-[0_0_8px_rgb(56_189_248/0.35)]"
        />
        <div className="leading-tight">
          <div className="text-[15px] font-bold tracking-tight text-white">
            ExDomain<span className="text-nav-accent">Vault</span>
          </div>
          <div className="text-[11px] text-nav-muted">External attack-surface monitoring</div>
        </div>
      </div>
      <nav aria-label="Primary" className="flex-1 overflow-y-auto px-3 py-3">
        <ul className="space-y-1">
          {NAV_ITEMS.map(({ path, label, icon: Icon }) => (
            <li key={path}>
              <NavLink
                to={path}
                end={path === '/'}
                className={({ isActive }) =>
                  [
                    'group flex items-center gap-3 rounded-lg border px-3 py-2 text-sm font-medium transition-colors',
                    isActive
                      ? 'border-[#3b82f6]/60 bg-linear-to-r from-[#2563eb]/35 to-[#2563eb]/5 text-white shadow-glow'
                      : 'border-transparent text-nav-fg hover:bg-white/5 hover:text-white',
                  ].join(' ')
                }
              >
                {({ isActive }) => (
                  <>
                    <Icon
                      className={`size-4 shrink-0 ${isActive ? 'text-nav-accent' : 'text-nav-muted group-hover:text-nav-fg'}`}
                      aria-hidden
                    />
                    {label}
                  </>
                )}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
      <div className="space-y-3 border-t border-nav-line px-4 py-4">
        {organisation && (
          <section
            aria-label="Organisation"
            className="flex items-center gap-3 rounded-lg border border-nav-line bg-nav-2 px-3 py-2.5"
          >
            <span className="grid size-8 shrink-0 place-items-center rounded-md bg-[#2563eb]/20 text-nav-accent">
              <Building2 className="size-4" aria-hidden />
            </span>
            <div className="min-w-0 leading-tight">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-nav-muted">
                Organisation
              </div>
              <div className="truncate text-sm font-medium text-white" title={organisation}>
                {organisation}
              </div>
            </div>
          </section>
        )}
        <ApiStatus />
      </div>
    </aside>
  );
}
