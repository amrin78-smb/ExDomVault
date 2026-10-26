import { DASHBOARD_RANGES, type DashboardRange } from '@exdomainvault/shared';
import { Ellipsis, Play, RefreshCw } from 'lucide-react';
import { useCallback, useId, useRef, useState } from 'react';
import { formatDateTime } from '../../lib/format.ts';
import { usePermission } from '../../lib/session.ts';
import { ExportCsvButton } from '../reports/ExportCsvButton.tsx';
import { Button } from '../ui/Button.tsx';
import { useDismiss } from '../ui/use-dismiss.ts';
import { RunScanDialog } from './RunScanDialog.tsx';

/** Last 7 / 30 / 90 days, as a segmented control (one pressed button). */
export function RangeSelector({
  value,
  onChange,
}: {
  value: DashboardRange;
  onChange: (range: DashboardRange) => void;
}) {
  return (
    <div
      role="group"
      aria-label="Time range"
      className="inline-flex rounded-lg border border-line bg-surface p-0.5 shadow-card"
    >
      {DASHBOARD_RANGES.map((r) => (
        <button
          key={r}
          type="button"
          aria-pressed={r === value}
          onClick={() => onChange(r)}
          className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
            r === value ? 'bg-accent-soft text-fg' : 'text-fg-subtle hover:text-fg'
          }`}
        >
          Last {r} days
        </button>
      ))}
    </div>
  );
}

function MoreMenu({ onRefresh }: { onRefresh: () => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const panelId = useId();
  const close = useCallback(() => setOpen(false), []);
  useDismiss(ref, open, close);
  return (
    <div ref={ref} className="relative">
      <Button
        aria-label="More actions"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((o) => !o)}
        className="px-2"
      >
        <Ellipsis className="size-4" aria-hidden />
      </Button>
      {open && (
        <div
          id={panelId}
          className="absolute right-0 z-20 mt-2 w-72 space-y-2 rounded-xl border border-line bg-surface p-3 shadow-pop"
        >
          <Button
            className="w-full justify-center"
            onClick={() => {
              setOpen(false);
              onRefresh();
            }}
          >
            <RefreshCw className="size-4" aria-hidden />
            Refresh
          </Button>
          <ExportCsvButton
            resource="findings"
            filters={{ status: 'active' }}
            label="Export findings (CSV)"
          />
        </div>
      )}
    </div>
  );
}

/**
 * Overview title row: last completed scan, Run scan (for users who may request scans), the range
 * selector and a menu with Refresh and the findings CSV export.
 */
export function OverviewHeader({
  lastScanAt,
  range,
  onRange,
  onRefresh,
}: {
  /** `undefined` while loading; `null` when no scan has completed. */
  lastScanAt: string | null | undefined;
  range: DashboardRange;
  onRange: (range: DashboardRange) => void;
  onRefresh: () => void;
}) {
  const canScan = usePermission('scans:request');
  const [dialog, setDialog] = useState(false);
  return (
    <div className="mb-6 space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-fg">Overview</h1>
          <p className="mt-1 text-sm text-fg-muted">
            External exposure across monitored domains, open findings and operational health.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {lastScanAt !== undefined && (
            <span
              className="flex items-center gap-1.5 text-xs text-fg-muted"
              data-testid="last-scan"
            >
              <span
                className={`size-2 rounded-full ${lastScanAt ? 'bg-emerald-500' : 'bg-fg-faint'}`}
                aria-hidden
              />
              {lastScanAt ? `Last scan: ${formatDateTime(lastScanAt)}` : 'No completed scans yet'}
            </span>
          )}
          {canScan && (
            <Button variant="primary" onClick={() => setDialog(true)} aria-haspopup="dialog">
              <Play className="size-4" aria-hidden />
              Run scan
            </Button>
          )}
          <MoreMenu onRefresh={onRefresh} />
        </div>
      </div>
      <RangeSelector value={range} onChange={onRange} />
      {dialog && <RunScanDialog onClose={() => setDialog(false)} />}
    </div>
  );
}
