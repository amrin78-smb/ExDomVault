import { ROLE_LABELS } from '@exdomainvault/shared';
import { CircleUserRound, ShieldAlert } from 'lucide-react';
import { ApiClientError } from '../../lib/api.ts';
import { useSession } from '../../lib/session.ts';

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

export function CurrentUser() {
  const state = useSession();

  if (state.status === 'loading') {
    return <span className="text-xs text-slate-400">Signing in…</span>;
  }

  if (state.status === 'error') {
    return (
      <span
        className="flex items-center gap-1.5 text-xs font-medium text-amber-800"
        title={state.error.message}
        role="status"
      >
        <ShieldAlert className="size-4" aria-hidden />
        {deniedLabel(state.error)}
      </span>
    );
  }

  const { user, authProvider } = state.data;
  return (
    <div className="flex items-center gap-2 text-sm" title={user.email}>
      <CircleUserRound className="size-5 text-slate-500" aria-hidden />
      <div className="leading-tight">
        <div className="font-medium text-slate-800">{user.displayName ?? user.email}</div>
        <div className="text-[11px] text-slate-500">
          {ROLE_LABELS[user.role]}
          {authProvider === 'dev' && ' · development sign-in'}
        </div>
      </div>
    </div>
  );
}
