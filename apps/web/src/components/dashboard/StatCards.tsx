import type { DashboardResponse, DashboardStat } from '@exdomainvault/shared';
import {
  CalendarClock,
  Globe,
  PackageX,
  Server,
  ShieldAlert,
  Siren,
  type LucideIcon,
} from 'lucide-react';
import { Link } from 'react-router';
import type { AsyncState } from '../../lib/use-async.ts';
import { Sparkline } from '../charts/Sparkline.tsx';
import { CardError, Skeleton } from './states.tsx';

/** Which direction of change is bad news (findings going up) or good news (coverage going up). */
type Good = 'up' | 'down';

interface Tile {
  key: string;
  label: string;
  icon: LucideIcon;
  /** Icon square colours (palette tints remap for the dark theme in index.css). */
  tone: string;
  /** Sparkline colour. */
  spark: string;
  good: Good;
  to: string | null;
  stat: DashboardStat | null;
  hint: string;
}

function tiles(d: DashboardResponse, canDomains: boolean): Tile[] {
  const s = d.stats;
  return [
    {
      key: 'domains',
      label: 'Domains monitored',
      icon: Globe,
      tone: 'bg-blue-50 text-blue-700',
      spark: 'text-blue-600',
      good: 'up',
      to: canDomains ? '/domains' : null,
      stat: canDomains ? s.domains : null,
      hint: canDomains ? `${s.domains.active.toLocaleString()} active` : 'Not visible to your role',
    },
    {
      key: 'assets',
      label: 'Total assets',
      icon: Server,
      tone: 'bg-cyan-50 text-cyan-700',
      spark: 'text-cyan-600',
      good: 'up',
      to: '/assets',
      stat: s.assets,
      hint: `Approved · ${s.assets.pending.toLocaleString()} pending review`,
    },
    {
      key: 'openFindings',
      label: 'Open findings',
      icon: ShieldAlert,
      tone: 'bg-violet-50 text-violet-700',
      spark: 'text-violet-600',
      good: 'down',
      to: '/findings',
      stat: s.openFindings,
      hint: 'Not yet resolved',
    },
    {
      key: 'criticalHigh',
      label: 'Critical & high',
      icon: Siren,
      tone: 'bg-red-50 text-red-700',
      spark: 'text-red-600',
      good: 'down',
      to: '/findings?sort=-severity',
      stat: s.criticalHigh,
      hint: 'Require attention',
    },
    {
      key: 'expiringCertificates',
      label: 'Expiring certificates',
      icon: CalendarClock,
      tone: 'bg-amber-50 text-amber-700',
      spark: 'text-amber-600',
      good: 'down',
      to: '/certificates?status=expiring',
      stat: s.expiringCertificates,
      hint: 'Within 30 days',
    },
    {
      key: 'eolSoftware',
      label: 'End-of-life software',
      icon: PackageX,
      tone: 'bg-orange-50 text-orange-700',
      spark: 'text-orange-600',
      good: 'down',
      to: '/software',
      stat: s.eolSoftware,
      hint: `${s.eolSoftware.kev.toLocaleString()} possibly KEV-affected`,
    },
  ];
}

/** ▲ +3 / ▼ −2 / ▬ 0, coloured by whether the change is good news; hidden when there is no history. */
function Delta({ delta, good, range }: { delta: number | null; good: Good; range: number }) {
  if (delta === null) return null;
  const period = `over the last ${range} days`;
  if (delta === 0) {
    return (
      <span className="text-xs font-medium text-fg-subtle" data-testid="delta">
        <span aria-hidden>▬ 0</span>
        <span className="sr-only">No change {period}</span>
      </span>
    );
  }
  const up = delta > 0;
  const isGood = (up && good === 'up') || (!up && good === 'down');
  return (
    <span
      className={`text-xs font-medium tabular-nums ${isGood ? 'text-emerald-700' : 'text-red-700'}`}
      data-testid="delta"
      data-tone={isGood ? 'good' : 'bad'}
    >
      <span aria-hidden>
        {up ? '▲ +' : '▼ −'}
        {Math.abs(delta).toLocaleString()}
      </span>
      <span className="sr-only">
        {up ? 'Up' : 'Down'} {Math.abs(delta)} {period}
      </span>
    </span>
  );
}

const tileClass =
  'group flex h-full flex-col rounded-xl border border-line bg-surface p-4 shadow-card transition-colors';

function StatTile({ tile, range }: { tile: Tile; range: number }) {
  const Icon = tile.icon;
  const body = (
    <>
      <div className="flex items-start justify-between gap-2">
        <span className="text-xs font-medium text-fg-muted">{tile.label}</span>
        <span className={`grid size-8 shrink-0 place-items-center rounded-lg ${tile.tone}`}>
          <Icon className="size-4" aria-hidden />
        </span>
      </div>
      <div className="mt-1 flex items-baseline gap-2">
        <span
          className="text-2xl font-semibold tracking-tight tabular-nums text-fg"
          data-testid="stat-value"
        >
          {tile.stat ? (
            tile.stat.value.toLocaleString()
          ) : (
            <span className="text-fg-faint" aria-label="No data">
              —
            </span>
          )}
        </span>
        {tile.stat && <Delta delta={tile.stat.delta} good={tile.good} range={range} />}
      </div>
      <div className="mt-auto flex items-end justify-between gap-2 pt-2">
        <span className="text-xs text-fg-subtle">{tile.hint}</span>
        {tile.stat && tile.stat.series.length > 0 && (
          <Sparkline series={tile.stat.series} className={`h-7 w-20 shrink-0 ${tile.spark}`} />
        )}
      </div>
    </>
  );
  return tile.to ? (
    <Link
      to={tile.to}
      className={`${tileClass} hover:border-line-strong`}
      data-testid={`stat-${tile.key}`}
    >
      {body}
    </Link>
  ) : (
    <div className={tileClass} data-testid={`stat-${tile.key}`}>
      {body}
    </div>
  );
}

const GRID = 'grid grid-cols-1 gap-4 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-6';

/** The six headline numbers, each linking to its list. */
export function StatCards({
  state,
  canDomains,
  onRetry,
}: {
  state: AsyncState<DashboardResponse>;
  canDomains: boolean;
  onRetry: () => void;
}) {
  if (state.status === 'error') {
    return (
      <div className={GRID}>
        <div className="col-span-full">
          <CardError error={state.error} onRetry={onRetry} />
        </div>
      </div>
    );
  }
  if (state.status === 'loading') {
    return (
      <div className={GRID} role="status" aria-label="Loading headline numbers">
        {Array.from({ length: 6 }, (_, i) => (
          <div key={i} className={`${tileClass} gap-3`}>
            <Skeleton className="h-3 w-24" />
            <Skeleton className="h-7 w-16" />
            <Skeleton className="h-3 w-28" />
          </div>
        ))}
      </div>
    );
  }
  return (
    <div className={GRID}>
      {tiles(state.data, canDomains).map((t) => (
        <StatTile key={t.key} tile={t} range={state.data.range} />
      ))}
    </div>
  );
}
