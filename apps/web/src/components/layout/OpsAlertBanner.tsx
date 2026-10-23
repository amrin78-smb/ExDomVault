import type { OpsAlertsResponse } from '@exdomainvault/shared';
import { Info, OctagonAlert, TriangleAlert, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { api } from '../../lib/api.ts';
import { formatDateTime } from '../../lib/format.ts';
import { usePermission } from '../../lib/session.ts';
import { usePollingKey } from '../../lib/use-polling.ts';

type Alert = OpsAlertsResponse['alerts'][number];

/** Poll interval for `/ops/alerts`; it is also re-read whenever the window regains focus. */
export const ALERTS_POLL_MS = 120_000;
const DISMISSED_KEY = 'exdomainvault.dismissedAlerts';

/** An alert is dismissed for its kind and start time: a new occurrence shows again. */
const alertKey = (a: Alert) => `${a.kind}@${a.since ?? ''}`;

function readDismissed(): string[] {
  try {
    const raw = sessionStorage.getItem(DISMISSED_KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

function writeDismissed(keys: string[]) {
  try {
    sessionStorage.setItem(DISMISSED_KEY, JSON.stringify(keys));
  } catch {
    // Storage unavailable (private mode, blocked): dismissal lasts until reload.
  }
}

const TONE = {
  critical: { className: 'border-red-300 bg-red-50 text-red-900', icon: OctagonAlert },
  warning: { className: 'border-amber-300 bg-amber-50 text-amber-900', icon: TriangleAlert },
  info: { className: 'border-sky-200 bg-sky-50 text-sky-900', icon: Info },
} as const;

/**
 * Operational alerts for everyone, polled from `/ops/alerts`. Non-blocking, announced politely,
 * dismissible for the browser session. Any failure (403, network, bad shape) shows nothing: the
 * banner must never break the page it sits on.
 */
export function OpsAlertBanner() {
  const canManage = usePermission('settings:manage');
  const tick = usePollingKey(true, ALERTS_POLL_MS);
  const [focusTick, setFocusTick] = useState(0);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [dismissed, setDismissed] = useState<string[]>(readDismissed);

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

  const visible = alerts.filter((a) => !dismissed.includes(alertKey(a)));

  const dismiss = (a: Alert) => {
    // Keep only keys of alerts still active so the stored list does not grow without bound.
    const active = new Set(alerts.map(alertKey));
    const next = [...dismissed.filter((k) => active.has(k)), alertKey(a)];
    setDismissed(next);
    writeDismissed(next);
  };

  return (
    <div aria-live="polite" aria-label="System alerts" role="status">
      {visible.length > 0 && (
        <ul className="space-y-2 border-b border-slate-200 bg-white px-6 py-3 lg:px-8">
          {visible.map((a) => (
            <AlertRow key={alertKey(a)} alert={a} canManage={canManage} onDismiss={dismiss} />
          ))}
        </ul>
      )}
    </div>
  );
}

function AlertRow({
  alert,
  canManage,
  onDismiss,
}: {
  alert: Alert;
  canManage: boolean;
  onDismiss: (a: Alert) => void;
}) {
  const tone = TONE[alert.severity];
  const Icon = tone.icon;
  const { title, body, link } = describe(alert, canManage);
  return (
    <li
      data-kind={alert.kind}
      className={`flex items-start gap-2 rounded-md border px-3 py-2 text-sm ${tone.className}`}
    >
      <Icon className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div className="min-w-0 flex-1">
        <p className="font-medium">{title}</p>
        {body && <p>{body}</p>}
        {link && (
          <Link to={link.to} className="font-medium underline underline-offset-2">
            {link.label}
          </Link>
        )}
      </div>
      <button
        type="button"
        onClick={() => onDismiss(alert)}
        className="rounded p-0.5 opacity-80 hover:bg-black/5 hover:opacity-100 focus-visible:outline-2"
        aria-label={`Dismiss: ${title}`}
      >
        <X className="size-4" aria-hidden />
      </button>
    </li>
  );
}

function describe(
  alert: Alert,
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
