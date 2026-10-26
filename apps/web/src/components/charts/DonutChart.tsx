import { Pie, PieChart, Tooltip, type TooltipContentProps } from 'recharts';
import { percentOf } from './palette.ts';
import { prefersReducedMotion } from './motion.ts';

export interface DonutSlice {
  key: string;
  label: string;
  value: number;
  /** Any SVG paint, e.g. `var(--color-sev-high)` or a palette hex. */
  color: string;
}

function SliceTooltip({ active, payload, total }: TooltipContentProps & { total: number }) {
  const entry = payload[0];
  if (!active || !entry) return null;
  const slice = entry.payload as DonutSlice;
  return (
    <div className="rounded-md border border-line bg-surface px-2.5 py-1.5 text-xs shadow-pop">
      <span className="font-medium text-fg">{slice.label}</span>{' '}
      <span className="tabular-nums text-fg-muted">
        {slice.value.toLocaleString()} ({percentOf(slice.value, total)}%)
      </span>
    </div>
  );
}

/**
 * Donut with a centred total and a text legend (label, count, share), so colour is never the only
 * cue. The ring is one `role="img"` whose label lists every slice; the legend repeats the values as
 * text. Zero-value slices are left out of the ring but kept in the legend when `showZero` is set.
 * Fixed pixel size: no measuring, so it renders the same in tests.
 */
export function DonutChart({
  slices,
  label,
  centerValue,
  centerLabel,
  size = 152,
  showZero = false,
  legendItem,
}: {
  slices: readonly DonutSlice[];
  /** What the chart shows, e.g. "Open findings by severity". */
  label: string;
  centerValue: number;
  centerLabel: string;
  size?: number;
  showZero?: boolean;
  /** Optional wrapper for each legend row (e.g. a link to a filtered list). */
  legendItem?: (slice: DonutSlice, content: React.ReactNode) => React.ReactNode;
}) {
  const total = slices.reduce((n, s) => n + s.value, 0);
  const drawn = slices.filter((s) => s.value > 0).map((s) => ({ ...s, fill: s.color }));
  const listed = showZero ? slices : slices.filter((s) => s.value > 0);
  const summary = `${label}: ${slices
    .map((s) => `${s.label} ${s.value} (${percentOf(s.value, total)}%)`)
    .join(', ')}`;
  const outer = size / 2 - 2;

  return (
    <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-center">
      <div className="relative shrink-0" role="img" aria-label={summary}>
        <PieChart width={size} height={size} accessibilityLayer={false}>
          {/* Empty track behind the slices, so "nothing yet" still reads as a ring. */}
          <Pie
            data={[{ value: 1 }]}
            dataKey="value"
            innerRadius={outer - 16}
            outerRadius={outer}
            fill="var(--color-surface-3)"
            stroke="none"
            isAnimationActive={false}
          />
          <Pie
            data={drawn}
            dataKey="value"
            nameKey="label"
            innerRadius={outer - 16}
            outerRadius={outer}
            paddingAngle={drawn.length > 1 ? 2 : 0}
            cornerRadius={3}
            stroke="var(--color-surface)"
            strokeWidth={drawn.length > 1 ? 2 : 0}
            startAngle={90}
            endAngle={-270}
            isAnimationActive={!prefersReducedMotion()}
          />
          <Tooltip content={(props) => <SliceTooltip {...props} total={total} />} />
        </PieChart>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-semibold tabular-nums text-fg">
            {centerValue.toLocaleString()}
          </span>
          <span className="text-xs text-fg-subtle">{centerLabel}</span>
        </div>
      </div>
      <ul className="w-full min-w-0 flex-1 space-y-1.5 text-sm" aria-label={`${label} legend`}>
        {listed.map((s) => {
          const content = (
            <>
              <span className="flex min-w-0 items-center gap-2">
                <svg
                  viewBox="0 0 10 10"
                  className="size-2.5 shrink-0"
                  aria-hidden
                  focusable="false"
                >
                  <rect width="10" height="10" rx="2.5" fill={s.color} />
                </svg>
                <span className="truncate text-fg-2">{s.label}</span>
              </span>
              <span className="shrink-0 tabular-nums">
                <span className="font-medium text-fg" data-testid={`legend-count-${s.key}`}>
                  {s.value.toLocaleString()}
                </span>{' '}
                <span
                  className="inline-block w-10 text-right text-fg-subtle"
                  data-testid={`legend-pct-${s.key}`}
                >
                  {percentOf(s.value, total)}%
                </span>
              </span>
            </>
          );
          return (
            <li key={s.key} className="flex items-center justify-between gap-3">
              {legendItem ? legendItem(s, content) : content}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
