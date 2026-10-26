import type { OpsAlertsResponse } from '@exdomainvault/shared';
import { createContext, useContext } from 'react';

export type OpsAlert = OpsAlertsResponse['alerts'][number];

/** Poll interval for `/ops/alerts`; it is also re-read whenever the window regains focus. */
export const ALERTS_POLL_MS = 120_000;

/**
 * Operational alerts, polled once for the whole shell (the alert banner and the notification bell
 * share them). Empty until the first successful load; a failed poll keeps the last good list.
 */
export const OpsAlertsContext = createContext<readonly OpsAlert[]>([]);

export function useOpsAlerts(): readonly OpsAlert[] {
  return useContext(OpsAlertsContext);
}
