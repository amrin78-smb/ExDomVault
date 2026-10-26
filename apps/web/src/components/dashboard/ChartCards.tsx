import {
  ASSET_ROLE_LABELS,
  ASSET_ROLES,
  SEVERITIES,
  SEVERITY_LABELS,
  type AttackSurfaceResponse,
  type DashboardResponse,
} from '@exdomainvault/shared';
import { ArrowRight } from 'lucide-react';
import { Link } from 'react-router';
import type { AsyncState } from '../../lib/use-async.ts';
import { DonutChart, type DonutSlice } from '../charts/DonutChart.tsx';
import {
  NEUTRAL_CHART_COLOR,
  SEVERITY_CHART_COLORS,
  useCategoricalPalette,
} from '../charts/palette.ts';
import { StackedAreaChart } from '../charts/StackedAreaChart.tsx';
import { Card } from '../ui/Card.tsx';
import { CardBody, CardEmpty, Skeleton, cardLinkClass } from './states.tsx';

function DonutSkeleton() {
  return (
    <div className="flex items-center gap-4" role="status" aria-label="Loading">
      <Skeleton className="size-36 shrink-0 rounded-full" />
      <div className="w-full space-y-2">
        {Array.from({ length: 5 }, (_, i) => (
          <Skeleton key={i} className="h-3.5 w-full" />
        ))}
      </div>
    </div>
  );
}

const FINDINGS_HINT =
  'Findings come from rules run on completed scans and appear within minutes of a scan finishing.';

export function SeverityCard({
  state,
  onRetry,
}: {
  state: AsyncState<DashboardResponse>;
  onRetry: () => void;
}) {
  return (
    <Card
      title="Findings by severity"
      actions={
        <Link to="/findings" className={cardLinkClass}>
          View all findings <ArrowRight className="size-3" aria-hidden />
        </Link>
      }
    >
      <CardBody state={state} onRetry={onRetry} skeleton={<DonutSkeleton />}>
        {(d) => {
          const slices: DonutSlice[] = [...SEVERITIES].reverse().map((s) => ({
            key: s,
            label: SEVERITY_LABELS[s],
            value: d.severity[s] ?? 0,
            color: SEVERITY_CHART_COLORS[s],
          }));
          const total = slices.reduce((n, s) => n + s.value, 0);
          if (total === 0) {
            return <CardEmpty title="No open findings">{FINDINGS_HINT}</CardEmpty>;
          }
          return (
            <DonutChart
              slices={slices}
              label="Open findings by severity"
              centerValue={total}
              centerLabel="Open"
              showZero
              legendItem={(s, content) => (
                <Link
                  to={`/findings?severity=${s.key}`}
                  className="flex w-full items-center justify-between gap-3 rounded px-1 hover:bg-surface-3"
                >
                  {content}
                </Link>
              )}
            />
          );
        }}
      </CardBody>
    </Card>
  );
}

/** Bottom → top: informational at the base, critical on top. */
const STACK = SEVERITIES.map((s) => ({
  key: s,
  label: SEVERITY_LABELS[s],
  color: SEVERITY_CHART_COLORS[s],
}));

export function TrendCard({
  state,
  range,
  onRetry,
}: {
  state: AsyncState<DashboardResponse>;
  range: number;
  onRetry: () => void;
}) {
  return (
    <Card title="Findings trend">
      <CardBody state={state} onRetry={onRetry} skeleton={<Skeleton className="h-56 w-full" />}>
        {(d) => {
          const created = d.trend.reduce(
            (n, t) => n + t.critical + t.high + t.medium + t.low + t.informational,
            0,
          );
          const resolved = d.trend.reduce((n, t) => n + t.resolved, 0);
          if (d.trend.length === 0 || (created === 0 && resolved === 0)) {
            return (
              <CardEmpty title={`No new findings in the last ${range} days`}>
                {FINDINGS_HINT}
              </CardEmpty>
            );
          }
          return (
            <div className="space-y-2">
              <StackedAreaChart
                data={d.trend}
                series={STACK}
                label={`New findings per day by severity, last ${d.range} days`}
              />
              <p className="text-xs text-fg-subtle">
                {created.toLocaleString()} first seen, {resolved.toLocaleString()} resolved in the
                last {d.range} days (UTC days).
              </p>
            </div>
          );
        }}
      </CardBody>
    </Card>
  );
}

export function AssetTypesCard({
  state,
  onRetry,
}: {
  state: AsyncState<AttackSurfaceResponse>;
  onRetry: () => void;
}) {
  const palette = useCategoricalPalette();
  return (
    <Card
      title="Asset types"
      actions={
        <Link to="/attack-surface" className={cardLinkClass}>
          Attack surface <ArrowRight className="size-3" aria-hidden />
        </Link>
      }
    >
      <CardBody state={state} onRetry={onRetry} skeleton={<DonutSkeleton />}>
        {(d) => {
          // Colour follows the role (a fixed slot per role), never its rank.
          const slices: DonutSlice[] = d.assetRoles.map((r) => ({
            key: r.role,
            label: ASSET_ROLE_LABELS[r.role],
            value: r.assets,
            color:
              r.role === 'unclassified'
                ? NEUTRAL_CHART_COLOR
                : (palette[ASSET_ROLES.indexOf(r.role)] ?? NEUTRAL_CHART_COLOR),
          }));
          if (d.totals.approvedAssets === 0) {
            return (
              <CardEmpty title="No approved assets yet">
                Approve discovered hostnames to classify them by role.
              </CardEmpty>
            );
          }
          return (
            <DonutChart
              slices={slices}
              label="Approved assets by type"
              centerValue={d.totals.approvedAssets}
              centerLabel="Assets"
            />
          );
        }}
      </CardBody>
    </Card>
  );
}
