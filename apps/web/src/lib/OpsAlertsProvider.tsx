import { useEffect, useState, type ReactNode } from 'react';
import { api } from './api.ts';
import { ALERTS_POLL_MS, OpsAlertsContext, type OpsAlert } from './ops-alerts.ts';
import { usePollingKey } from './use-polling.ts';

/** Polls `/ops/alerts` every two minutes and on window focus. Failures are silent. */
export function OpsAlertsProvider({ children }: { children: ReactNode }) {
  const tick = usePollingKey(true, ALERTS_POLL_MS);
  const [focusTick, setFocusTick] = useState(0);
  const [alerts, setAlerts] = useState<readonly OpsAlert[]>([]);

  useEffect(() => {
    const onFocus = () => setFocusTick((t) => t + 1);
    window.addEventListener('focus', onFocus);
    return () => window.removeEventListener('focus', onFocus);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    api.ops.alerts({ signal: controller.signal }).then(
      (res) => {
        if (!controller.signal.aborted) setAlerts(res.alerts);
      },
      () => {
        // Fail silent: keep whatever was last shown (nothing, if this was the first load).
      },
    );
    return () => controller.abort();
  }, [tick, focusTick]);

  return <OpsAlertsContext value={alerts}>{children}</OpsAlertsContext>;
}
