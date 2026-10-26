import { formatDateTime } from '../../lib/format.ts';
import type { OpsAlert } from '../../lib/ops-alerts.ts';

/** An alert is identified by its kind and start time: a new occurrence is a new alert. */
export const alertKey = (a: OpsAlert) => `${a.kind}@${a.since ?? ''}`;

/** Plain-language text for an operational alert; the settings link only for administrators. */
export function describeAlert(
  alert: OpsAlert,
  canManage: boolean,
): { title: string; body: string | null; link: { to: string; label: string } | null } {
  switch (alert.kind) {
    case 'worker_outage':
      return {
        title: alert.since
          ? `Scanning is delayed: the scanning worker has not been seen since ${formatDateTime(alert.since)}.`
          : 'Scanning is delayed: the scanning worker is not responding.',
        body: 'Queued scans will run when it reconnects. Existing results and findings are unaffected.',
        link: canManage ? { to: '/settings?tab=health', label: 'Open System health' } : null,
      };
    case 'feeds_stale':
      return {
        title: 'Intelligence feeds are out of date',
        body: alert.message,
        link: canManage ? { to: '/settings?tab=intel', label: 'Open intelligence feeds' } : null,
      };
    case 'active_scanning_disabled':
      return { title: 'Active scanning is disabled', body: alert.message, link: null };
  }
}
