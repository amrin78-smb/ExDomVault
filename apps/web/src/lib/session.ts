import type { MeResponse, Permission } from '@exdomainvault/shared';
import { createContext, useContext } from 'react';
import type { AsyncState } from './use-async.ts';

/** The signed-in user, loaded once per page load by SessionProvider. */
export const SessionContext = createContext<AsyncState<MeResponse>>({ status: 'loading' });

export function useSession(): AsyncState<MeResponse> {
  return useContext(SessionContext);
}

/**
 * Whether the current user holds a permission. Only used to hide actions the API would refuse;
 * the API enforces every permission itself.
 */
export function usePermission(permission: Permission): boolean {
  const session = useSession();
  return session.status === 'success' && session.data.permissions.includes(permission);
}

/** A permission check for the current user (false for every permission until the session loads). */
export function usePermissions(): (permission: Permission) => boolean {
  const session = useSession();
  const granted = session.status === 'success' ? session.data.permissions : [];
  return (permission) => granted.includes(permission);
}
