import { createContext, useContext } from 'react';

/**
 * Development fixtures are only available in a Vite dev build with VITE_DEV_FIXTURES=true.
 * `import.meta.env.DEV` is statically false in production builds, so fixtures can never be
 * enabled there.
 */
export const DEV_FIXTURES_ENABLED =
  import.meta.env.DEV && import.meta.env.VITE_DEV_FIXTURES === 'true';

export interface DataMode {
  /** True when pages should render clearly labelled development fixtures instead of API data. */
  fixtures: boolean;
}

export const DataModeContext = createContext<DataMode>({ fixtures: false });

export function useDataMode(): DataMode {
  return useContext(DataModeContext);
}
