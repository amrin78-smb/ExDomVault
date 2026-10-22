import type { ReactNode } from 'react';
import { DEV_FIXTURES_ENABLED, DataModeContext } from './data-mode.ts';

export function DataModeProvider({
  fixtures = DEV_FIXTURES_ENABLED,
  children,
}: {
  fixtures?: boolean;
  children: ReactNode;
}) {
  return <DataModeContext value={{ fixtures }}>{children}</DataModeContext>;
}
