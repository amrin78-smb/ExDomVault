import { DASHBOARD_RANGES, type DashboardRange, type Permission } from '@exdomainvault/shared';
import { useSearchParams } from 'react-router';
import { RecentChangesCard } from '../components/changes/RecentChangesCard.tsx';
import { AssetTypesCard, SeverityCard, TrendCard } from '../components/dashboard/ChartCards.tsx';
import {
  CertificateExpiryCard,
  ExposedSoftwareCard,
  LatestScansCard,
  RecentAssetsCard,
  TopRemediationCard,
} from '../components/dashboard/ListCards.tsx';
import { OverviewHeader } from '../components/dashboard/OverviewHeader.tsx';
import { RegionCard } from '../components/dashboard/RegionCard.tsx';
import { StatCards } from '../components/dashboard/StatCards.tsx';
import { WorkerHealthNotice } from '../components/dashboard/WorkerHealthNotice.tsx';
import { PermissionDenied } from '../components/ui/PermissionDenied.tsx';
import { StaleDataNotice } from '../components/ui/StaleDataNotice.tsx';
import { api } from '../lib/api.ts';
import { useSession } from '../lib/session.ts';
import type { AsyncState } from '../lib/use-async.ts';
import { useRefreshableAsync } from '../lib/use-refreshable-async.ts';

const DEFAULT_RANGE: DashboardRange = 30;
const parseRange = (v: string | null): DashboardRange => {
  const n = Number(v);
  return (DASHBOARD_RANGES as readonly number[]).includes(n)
    ? (n as DashboardRange)
    : DEFAULT_RANGE;
};

/** The dashboard needs any one of these (each section is scoped server-side by role). */
const DASHBOARD_PERMISSIONS: Permission[] = ['domains:read', 'assets:read', 'findings:read'];

const NEVER: AsyncState<never> = { status: 'loading' };

/**
 * Overview dashboard: one `GET /dashboard?range=` for the headline numbers, charts and lists, and
 * one `GET /attack-surface` for asset types and regions (not reloaded on range change). Each card
 * renders its own loading, error (with retry) and empty state; nothing is estimated or invented.
 * The range lives in the URL (`?range=7|30|90`).
 */
export function OverviewPage() {
  const session = useSession();
  const granted = session.status === 'success' ? session.data.permissions : null;
  const can = (p: Permission) => granted?.includes(p) ?? false;
  const canDashboard = granted !== null && DASHBOARD_PERMISSIONS.some(can);
  const canAssets = can('assets:read');

  const [params, setParams] = useSearchParams();
  const range = parseRange(params.get('range'));
  const setRange = (r: DashboardRange) => {
    const next = new URLSearchParams(params);
    if (r === DEFAULT_RANGE) next.delete('range');
    else next.set('range', String(r));
    setParams(next, { replace: true });
  };

  const dashboard = useRefreshableAsync(
    (signal) => (canDashboard ? api.dashboard(range, { signal }) : new Promise<never>(() => {})),
    [range, canDashboard],
  );
  const surface = useRefreshableAsync(
    (signal) =>
      canAssets ? api.inventory.attackSurface({ signal }) : new Promise<never>(() => {}),
    [canAssets],
  );
  const dash = canDashboard ? dashboard.state : NEVER;
  const surf = canAssets ? surface.state : NEVER;
  const refresh = () => {
    dashboard.retry();
    if (canAssets) surface.retry();
  };

  const header = (
    <OverviewHeader
      lastScanAt={dash.status === 'success' ? dash.data.lastScanAt : undefined}
      range={range}
      onRange={setRange}
      onRefresh={refresh}
    />
  );

  if (session.status === 'success' && !canDashboard) {
    return (
      <>
        {header}
        <PermissionDenied />
      </>
    );
  }

  return (
    <>
      {header}
      <WorkerHealthNotice />
      {dashboard.stale && (
        <StaleDataNotice
          loadedAt={dashboard.stale.loadedAt}
          error={dashboard.stale.error}
          onRetry={dashboard.retry}
          retrying={dashboard.refreshing}
        />
      )}

      <StatCards state={dash} canDomains={can('domains:read')} onRetry={dashboard.retry} />

      <div className="mt-6 grid items-start gap-4 lg:grid-cols-2 xl:grid-cols-3">
        <SeverityCard state={dash} onRetry={dashboard.retry} />
        <TrendCard state={dash} range={range} onRetry={dashboard.retry} />
        {canAssets && <AssetTypesCard state={surf} onRetry={surface.retry} />}
      </div>

      <div className="mt-6 grid items-start gap-4 lg:grid-cols-2 xl:grid-cols-3">
        <TopRemediationCard state={dash} onRetry={dashboard.retry} />
        <LatestScansCard state={dash} onRetry={dashboard.retry} canRead={can('scans:read')} />
        <CertificateExpiryCard state={dash} onRetry={dashboard.retry} />
      </div>

      <div className="mt-6 grid items-start gap-4 lg:grid-cols-2 xl:grid-cols-3">
        {canAssets && <RegionCard state={surf} onRetry={surface.retry} />}
        <RecentAssetsCard state={dash} onRetry={dashboard.retry} />
        <ExposedSoftwareCard state={dash} onRetry={dashboard.retry} />
      </div>

      {canAssets && (
        <div className="mt-6 grid items-start gap-4 lg:grid-cols-2 xl:grid-cols-3">
          <RecentChangesCard />
        </div>
      )}
    </>
  );
}
