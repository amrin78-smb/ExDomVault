import type { ReactNode } from 'react';
import { api } from './api.ts';
import { SessionContext } from './session.ts';
import { useAsync } from './use-async.ts';

export function SessionProvider({ children }: { children: ReactNode }) {
  const state = useAsync((signal) => api.me({ signal }), []);
  return <SessionContext value={state}>{children}</SessionContext>;
}
