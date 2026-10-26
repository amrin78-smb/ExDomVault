import { ROLE_LABELS } from '@exdomainvault/shared';
import { ChevronDown, LogOut, Moon, ShieldAlert, Sun } from 'lucide-react';
import { useCallback, useId, useRef, useState, type KeyboardEvent } from 'react';
import { ApiClientError } from '../../lib/api.ts';
import { useSession } from '../../lib/session.ts';
import { useTheme } from '../../lib/theme.ts';
import { useDismiss } from '../ui/use-dismiss.ts';

/** Cloudflare Access ends the session (and its cookie) at this path on the app's own origin. */
export const SIGN_OUT_PATH = '/cdn-cgi/access/logout';

/** Explains, in plain terms, why the API refused to identify the user. */
function deniedLabel(error: Error): string {
  if (!(error instanceof ApiClientError)) return 'Sign-in status unavailable';
  switch (error.status) {
    case 401:
      return 'Not signed in';
    case 403:
      return 'Access not granted';
    case 503:
      return 'Sign-in unavailable';
    default:
      return 'Sign-in status unavailable';
  }
}

const itemClass =
  'flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-left text-sm text-fg-2 hover:bg-surface-3 hover:text-fg focus-visible:bg-surface-3 focus-visible:outline-none';

/**
 * The signed-in user (avatar initial, name, role) with a menu holding the theme switch and, behind
 * Cloudflare Access, Sign out. The menu is available even when sign-in failed, for the theme.
 */
export function UserMenu() {
  const state = useSession();
  const [theme, setTheme] = useTheme();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const menuId = useId();
  const close = useCallback(() => setOpen(false), []);
  useDismiss(ref, open, close);

  const onMenuKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const items = Array.from(e.currentTarget.querySelectorAll<HTMLElement>('[role="menuitem"]'));
    const i = items.indexOf(document.activeElement as HTMLElement);
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const next =
        e.key === 'ArrowDown' ? (i + 1) % items.length : (i - 1 + items.length) % items.length;
      items[next]?.focus();
    } else if (e.key === 'Escape') {
      e.stopPropagation();
      setOpen(false);
      buttonRef.current?.focus();
    } else if (e.key === 'Tab') {
      setOpen(false);
    }
  };

  let trigger;
  if (state.status === 'loading') {
    trigger = <span className="text-xs text-fg-subtle">Signing in…</span>;
  } else if (state.status === 'error') {
    trigger = (
      <span
        className="flex items-center gap-1.5 text-xs font-medium text-amber-800"
        title={state.error.message}
      >
        <ShieldAlert className="size-4" aria-hidden />
        {deniedLabel(state.error)}
      </span>
    );
  } else {
    const { user, authProvider } = state.data;
    const name = user.displayName ?? user.email;
    trigger = (
      <>
        <span
          className="grid size-8 shrink-0 place-items-center rounded-full bg-linear-to-br from-[#2563eb] to-[#22d3ee] text-sm font-semibold text-white shadow-[0_0_12px_-2px_rgb(37_99_235/0.7)]"
          aria-hidden
        >
          {name.charAt(0).toUpperCase()}
        </span>
        <span className="hidden min-w-0 text-left leading-tight sm:block" title={user.email}>
          <span className="block max-w-48 truncate text-sm font-medium text-fg">{name}</span>
          <span className="block text-[11px] text-fg-subtle">
            {ROLE_LABELS[user.role]}
            {authProvider === 'dev' && ' · development sign-in'}
          </span>
        </span>
      </>
    );
  }

  const signedIn = state.status === 'success' ? state.data : null;

  return (
    <div ref={ref} className="relative">
      <button
        ref={buttonRef}
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-2.5 rounded-lg px-2 py-1.5 hover:bg-surface-3"
      >
        {trigger}
        <ChevronDown className="size-4 text-fg-faint" aria-hidden />
        <span className="sr-only">Account menu</span>
      </button>
      {open && (
        <div
          id={menuId}
          role="menu"
          aria-label="Account"
          onKeyDown={onMenuKey}
          className="absolute right-0 z-40 mt-2 w-64 rounded-xl border border-line bg-surface p-1.5 shadow-pop"
        >
          {signedIn && (
            <div className="border-b border-line-soft px-2.5 pt-1.5 pb-2.5">
              <p className="truncate text-sm font-medium text-fg">{signedIn.user.email}</p>
              <p className="text-xs text-fg-subtle">{ROLE_LABELS[signedIn.user.role]}</p>
            </div>
          )}
          <div className="pt-1">
            <button
              type="button"
              role="menuitem"
              autoFocus
              className={itemClass}
              onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            >
              {theme === 'dark' ? (
                <Moon className="size-4" aria-hidden />
              ) : (
                <Sun className="size-4" aria-hidden />
              )}
              Theme: {theme === 'dark' ? 'Dark' : 'Light'}
              <span className="ml-auto text-xs text-fg-subtle">
                Switch to {theme === 'dark' ? 'light' : 'dark'}
              </span>
            </button>
            {signedIn?.authProvider === 'cloudflare_access' && (
              <a role="menuitem" href={SIGN_OUT_PATH} className={itemClass}>
                <LogOut className="size-4" aria-hidden />
                Sign out
              </a>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
