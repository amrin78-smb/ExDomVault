import { Bell, ChevronRight, Info, OctagonAlert, ShieldAlert, TriangleAlert } from 'lucide-react';
import { useCallback, useId, useRef, useState } from 'react';
import { Link } from 'react-router';
import { api } from '../../lib/api.ts';
import { useOpsAlerts } from '../../lib/ops-alerts.ts';
import { usePermission } from '../../lib/session.ts';
import { useAsync } from '../../lib/use-async.ts';
import { useDismiss } from '../ui/use-dismiss.ts';
import { alertKey, describeAlert } from './ops-alert-text.ts';

const ALERT_ICON = { critical: OctagonAlert, warning: TriangleAlert, info: Info } as const;
const ALERT_TONE = {
  critical: 'text-red-700',
  warning: 'text-amber-700',
  info: 'text-sky-700',
} as const;

/** Open (not resolved) critical findings the viewer can see; null when unknown or not permitted. */
function useOpenCriticalFindings(): number | null {
  const canRead = usePermission('findings:read');
  const state = useAsync(
    (signal) => (canRead ? api.findings.summary({}, { signal }) : Promise.resolve(null)),
    [canRead],
  );
  return state.status === 'success' && state.data ? state.data.bySeverity.critical : null;
}

/**
 * Top-bar notifications: active operational alerts plus the open critical findings count. Both
 * sources fail silently (the count shows only what loaded).
 */
export function NotificationBell() {
  const alerts = useOpsAlerts();
  const critical = useOpenCriticalFindings();
  const canManage = usePermission('settings:manage');
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const panelId = useId();
  const close = useCallback(() => setOpen(false), []);
  useDismiss(ref, open, close);

  const count = alerts.length + (critical ?? 0);
  const label = count === 0 ? 'Notifications' : `Notifications, ${count} active`;

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        aria-label={label}
        aria-expanded={open}
        aria-controls={open ? panelId : undefined}
        onClick={() => setOpen((o) => !o)}
        className="relative grid size-10 place-items-center rounded-lg border border-line bg-surface text-fg-muted hover:text-fg"
      >
        <Bell className="size-5" aria-hidden />
        {count > 0 && (
          <span
            data-testid="notification-count"
            aria-hidden
            className="absolute -top-1.5 -right-1.5 grid h-5 min-w-5 place-items-center rounded-full bg-[#dc2626] px-1 text-[11px] font-semibold tabular-nums text-white ring-2 ring-canvas"
          >
            {count > 99 ? '99+' : count}
          </span>
        )}
      </button>
      {open && (
        <div
          id={panelId}
          role="region"
          aria-label="Notifications"
          className="absolute right-0 z-40 mt-2 w-96 max-w-[calc(100vw-2rem)] rounded-xl border border-line bg-surface shadow-pop"
        >
          <div className="border-b border-line-soft px-4 py-3 text-sm font-semibold text-fg">
            Notifications
          </div>
          {count === 0 ? (
            <p className="px-4 py-6 text-center text-sm text-fg-subtle">
              No active alerts or open critical findings.
            </p>
          ) : (
            <ul className="max-h-96 divide-y divide-line-soft overflow-y-auto">
              {critical !== null && critical > 0 && (
                <li>
                  <Link
                    to="/findings?severity=critical"
                    onClick={close}
                    className="flex items-center gap-3 px-4 py-3 text-sm hover:bg-surface-2"
                  >
                    <ShieldAlert className="size-4 shrink-0 text-red-700" aria-hidden />
                    <span className="flex-1 text-fg">
                      {critical} open critical {critical === 1 ? 'finding' : 'findings'}
                    </span>
                    <ChevronRight className="size-4 text-fg-faint" aria-hidden />
                  </Link>
                </li>
              )}
              {alerts.map((a) => {
                const { title, link } = describeAlert(a, canManage);
                const Icon = ALERT_ICON[a.severity];
                return (
                  <li key={alertKey(a)} className="flex items-start gap-3 px-4 py-3 text-sm">
                    <Icon
                      className={`mt-0.5 size-4 shrink-0 ${ALERT_TONE[a.severity]}`}
                      aria-hidden
                    />
                    <div className="min-w-0 flex-1">
                      <p className="text-fg">{title}</p>
                      {link && (
                        <Link
                          to={link.to}
                          onClick={close}
                          className="text-xs font-medium text-sky-800 hover:underline"
                        >
                          {link.label}
                        </Link>
                      )}
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
