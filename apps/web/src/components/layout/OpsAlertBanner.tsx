import { Info, OctagonAlert, TriangleAlert, X } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router';
import { useOpsAlerts, type OpsAlert } from '../../lib/ops-alerts.ts';
import { usePermission } from '../../lib/session.ts';
import { alertKey, describeAlert } from './ops-alert-text.ts';

const DISMISSED_KEY = 'exdomainvault.dismissedAlerts';

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
 * Operational alerts for everyone (polled by OpsAlertsProvider). Non-blocking, announced politely,
 * dismissible for the browser session. Any failure shows nothing: the banner must never break the
 * page it sits on. Dismissed alerts still count in the top bar's notification bell.
 */
export function OpsAlertBanner() {
  const canManage = usePermission('settings:manage');
  const alerts = useOpsAlerts();
  const [dismissed, setDismissed] = useState<string[]>(readDismissed);

  const visible = alerts.filter((a) => !dismissed.includes(alertKey(a)));

  const dismiss = (a: OpsAlert) => {
    // Keep only keys of alerts still active so the stored list does not grow without bound.
    const active = new Set(alerts.map(alertKey));
    const next = [...dismissed.filter((k) => active.has(k)), alertKey(a)];
    setDismissed(next);
    writeDismissed(next);
  };

  return (
    <div aria-live="polite" aria-label="System alerts" role="status">
      {visible.length > 0 && (
        <ul className="space-y-2 px-6 pt-4 lg:px-8">
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
  alert: OpsAlert;
  canManage: boolean;
  onDismiss: (a: OpsAlert) => void;
}) {
  const tone = TONE[alert.severity];
  const Icon = tone.icon;
  const { title, body, link } = describeAlert(alert, canManage);
  return (
    <li
      data-kind={alert.kind}
      className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-sm ${tone.className}`}
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
        className="rounded p-0.5 opacity-80 hover:bg-black/5 hover:opacity-100 focus-visible:outline-2 dark:hover:bg-white/10"
        aria-label={`Dismiss: ${title}`}
      >
        <X className="size-4" aria-hidden />
      </button>
    </li>
  );
}
