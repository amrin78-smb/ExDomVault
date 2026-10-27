import { useSyncExternalStore } from 'react';

/**
 * Cloudflare Access session expiry. When the Access cookie expires, API requests are answered with
 * a redirect to the Access login page; fetch cannot follow that cross-origin redirect, so the API
 * client reports it here and the shell offers "Sign in again" (a full reload, which goes through
 * the Access login and returns to the same page).
 */
let expired = false;
const listeners = new Set<() => void>();

export function notifySessionExpired(): void {
  if (expired) return;
  expired = true;
  for (const l of listeners) l();
}

export function useSessionExpired(): boolean {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    () => expired,
    () => false,
  );
}

/** Tests only: start from a fresh session. */
export function resetSessionExpiredForTests(): void {
  expired = false;
}
