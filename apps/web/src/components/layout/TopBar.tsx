import { Search } from 'lucide-react';
import { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { CommandPalette, Kbd } from './CommandPalette.tsx';
import { NotificationBell } from './NotificationBell.tsx';
import { UserMenu } from './UserMenu.tsx';

/** Shell top bar: global search (also Ctrl/Cmd+K), notifications and the account menu. */
export function TopBar() {
  const [searchOpen, setSearchOpen] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setSearchOpen(true);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return (
    <header className="sticky top-0 z-30 flex h-16 items-center gap-4 border-b border-line bg-canvas/85 px-6 backdrop-blur lg:px-8">
      <button
        type="button"
        onClick={() => setSearchOpen(true)}
        aria-haspopup="dialog"
        aria-keyshortcuts="Control+K Meta+K"
        className="flex h-10 w-full max-w-2xl min-w-0 items-center gap-3 rounded-lg border border-line bg-surface px-3 text-left text-sm text-fg-subtle shadow-card transition-colors hover:border-line-strong"
      >
        <Search className="size-4 shrink-0" aria-hidden />
        <span className="min-w-0 flex-1 truncate">
          Search domains, subdomains, IPs, ports, software, CVEs…
        </span>
        <span className="hidden items-center gap-1 sm:flex" aria-hidden>
          <Kbd>Ctrl</Kbd>
          <Kbd>K</Kbd>
        </span>
      </button>
      <div className="ml-auto flex shrink-0 items-center gap-3">
        <NotificationBell />
        <div className="h-8 w-px bg-line" aria-hidden />
        <UserMenu />
      </div>
      {/* Portalled: the header's backdrop filter would otherwise contain the fixed overlay. */}
      {searchOpen &&
        createPortal(<CommandPalette onClose={() => setSearchOpen(false)} />, document.body)}
    </header>
  );
}
