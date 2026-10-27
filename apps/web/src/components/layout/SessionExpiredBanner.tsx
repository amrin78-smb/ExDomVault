import { LogIn } from 'lucide-react';
import { useSessionExpired } from '../../lib/session-expiry.ts';

/** Shown once any API call finds the Cloudflare Access session expired. */
export function SessionExpiredBanner() {
  const expired = useSessionExpired();
  if (!expired) return null;
  return (
    <div
      role="alert"
      className="flex flex-wrap items-center gap-3 border-b border-amber-200 bg-amber-50 px-6 py-3 text-sm text-amber-900"
    >
      <span className="flex-1">
        Your sign-in has expired, so new data can&rsquo;t be loaded. Sign in again to continue
        &mdash; you&rsquo;ll return to this page.
      </span>
      <button
        type="button"
        onClick={() => window.location.reload()}
        className="inline-flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-fg hover:bg-accent-hover"
      >
        <LogIn className="size-4" aria-hidden />
        Sign in again
      </button>
    </div>
  );
}
