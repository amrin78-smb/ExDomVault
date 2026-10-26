import { useId } from 'react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  type TooltipContentProps,
} from 'recharts';
import { AXIS_TEXT_COLOR, GRID_COLOR } from './palette.ts';
import { formatDay, formatLongDay } from './format-day.ts';
import { prefersReducedMotion } from './motion.ts';

export interface AreaSeries {
  key: string;
  label: string;
  color: string;
}

type Row = { date: string } & Record<string, number | string>;

const num = (v: unknown) => (typeof v === 'number' ? v : 0);

function DayTooltip({
  active,
  payload,
  label,
  series,
}: TooltipContentProps & { series: readonly AreaSeries[] }) {
  if (!active || payload.length === 0 || typeof label !== 'string') return null;
  const row = payload[0]?.payload as Row | undefined;
  if (!row) return null;
  const total = series.reduce((n, s) => n + num(row[s.key]), 0);
  return (
    <div className="min-w-40 rounded-md border border-line bg-surface px-3 py-2 text-xs shadow-pop">
      <div className="mb-1 font-medium text-fg">{formatLongDay(label)}</div>
      <ul className="space-y-0.5">
        {[...series].reverse().map((s) => (
          <li key={s.key} className="flex items-center justify-between gap-4">
            <span className="flex items-center gap-1.5 text-fg-muted">
              <svg viewBox="0 0 10 10" className="size-2" aria-hidden focusable="false">
                <rect width="10" height="10" rx="2" fill={s.color} />
              </svg>
              {s.label}
            </span>
            <span className="tabular-nums text-fg">{num(row[s.key])}</span>
          </li>
        ))}
      </ul>
      <div className="mt-1 flex justify-between border-t border-line pt-1 text-fg-muted">
        <span>Total</span>
        <span className="tabular-nums text-fg">{total}</span>
      </div>
    </div>
  );
}

/**
 * Stacked areas over UTC days on one axis, with a crosshair tooltip, a text legend and a visually
 * hidden data table (exact values for screen readers). `series` is ordered bottom → top; the legend
 * lists it top → bottom so it matches the stack. Width follows the container; height is fixed.
 */
export function StackedAreaChart({
  data,
  series,
  label,
  height = 200,
}: {
  data: readonly Row[];
  series: readonly AreaSeries[];
  /** What the chart shows; also the table caption. */
  label: string;
  height?: number;
}) {
  const tableId = useId();
  const animate = !prefersReducedMotion();
  const topDown = [...series].reverse();
  return (
    <figure className="space-y-3">
      <ul
        className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-fg-muted"
        aria-label={`${label} legend`}
      >
        {topDown.map((s) => (
          <li key={s.key} className="flex items-center gap-1.5">
            <svg viewBox="0 0 10 10" className="size-2.5" aria-hidden focusable="false">
              <rect width="10" height="10" rx="2.5" fill={s.color} />
            </svg>
            {s.label}
          </li>
        ))}
      </ul>
      <div role="img" aria-label={label} aria-describedby={tableId}>
        <ResponsiveContainer width="100%" height={height} initialDimension={{ width: 560, height }}>
          <AreaChart
            data={[...data]}
            margin={{ top: 4, right: 8, bottom: 0, left: -12 }}
            accessibilityLayer={false}
          >
            <CartesianGrid vertical={false} stroke={GRID_COLOR} strokeDasharray="3 3" />
            <XAxis
              dataKey="date"
              tickFormatter={formatDay}
              tick={{ fill: AXIS_TEXT_COLOR, fontSize: 11 }}
              tickLine={false}
              axisLine={{ stroke: GRID_COLOR }}
              minTickGap={24}
            />
            <YAxis
              allowDecimals={false}
              tick={{ fill: AXIS_TEXT_COLOR, fontSize: 11 }}
              tickLine={false}
              axisLine={false}
              width={40}
            />
            <Tooltip
              content={(props) => <DayTooltip {...props} series={series} />}
              cursor={{ stroke: 'var(--color-line-strong)', strokeWidth: 1 }}
            />
            {series.map((s) => (
              <Area
                key={s.key}
                type="monotone"
                dataKey={s.key}
                name={s.label}
                stackId="stack"
                stroke={s.color}
                strokeWidth={2}
                fill={s.color}
                fillOpacity={0.22}
                activeDot={{ r: 4, stroke: 'var(--color-surface)', strokeWidth: 2 }}
                isAnimationActive={animate}
              />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <table id={tableId} className="sr-only">
        <caption>{label}</caption>
        <thead>
          <tr>
            <th scope="col">Day</th>
            {topDown.map((s) => (
              <th key={s.key} scope="col">
                {s.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row) => (
            <tr key={row.date}>
              <th scope="row">{formatLongDay(row.date)}</th>
              {topDown.map((s) => (
                <td key={s.key}>{num(row[s.key])}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </figure>
  );
}
