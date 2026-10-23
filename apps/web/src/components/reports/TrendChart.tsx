import type { ReportSummaryResponse } from '@exdomainvault/shared';
import { useId, useState, type PointerEvent } from 'react';
import { formatDate } from '../../lib/format.ts';

type Trend = ReportSummaryResponse['trend'];

/**
 * Categorical slots 1 and 3 of the data-viz reference palette (validated together: CVD ΔE 23).
 * Not severity or status colours. "Resolved" is also dashed and the data table is always
 * available, so colour is never the only cue.
 */
const SERIES = [
  { key: 'created', label: 'Created', color: '#2a78d6', dash: undefined },
  { key: 'resolved', label: 'Resolved', color: '#1baf7a', dash: '5 3' },
] as const;

const W = 600;
const PAD = { top: 8, right: 8, bottom: 20, left: 28 };

/**
 * Findings created vs resolved per UTC day: two lines on one axis, a hover crosshair with the
 * day's values, and a data table for screen readers and exact values.
 */
export function TrendChart({ trend, compact = false }: { trend: Trend; compact?: boolean }) {
  const [hover, setHover] = useState<number | null>(null);
  const tableId = useId();
  const H = compact ? 96 : 180;
  const totals = {
    created: trend.reduce((a, d) => a + d.created, 0),
    resolved: trend.reduce((a, d) => a + d.resolved, 0),
  };

  const first = trend[0];
  const lastDay = trend[trend.length - 1];
  if (!first || !lastDay) {
    return <p className="text-sm text-slate-500">No trend data yet.</p>;
  }

  const max = Math.max(1, ...trend.map((d) => Math.max(d.created, d.resolved)));
  const plotW = W - PAD.left - PAD.right;
  const plotH = H - PAD.top - PAD.bottom;
  const x = (i: number) =>
    PAD.left + (trend.length === 1 ? plotW / 2 : (i / (trend.length - 1)) * plotW);
  const y = (v: number) => PAD.top + plotH - (v / max) * plotH;
  const path = (key: 'created' | 'resolved') =>
    trend
      .map((d, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)},${y(d[key]).toFixed(1)}`)
      .join('');

  const onMove = (e: PointerEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    if (rect.width === 0) return;
    const px = ((e.clientX - rect.left) / rect.width) * W;
    const i = Math.round(((px - PAD.left) / plotW) * (trend.length - 1));
    setHover(Math.min(trend.length - 1, Math.max(0, i)));
  };
  const hovered = hover === null ? null : trend[hover];

  return (
    <figure className="space-y-2">
      <figcaption className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-600">
        {SERIES.map((s) => (
          <span key={s.key} className="inline-flex items-center gap-1.5">
            <svg width="18" height="6" aria-hidden>
              <line
                x1="0"
                y1="3"
                x2="18"
                y2="3"
                stroke={s.color}
                strokeWidth="2"
                strokeDasharray={s.dash}
              />
            </svg>
            {s.label}{' '}
            <span className="font-medium tabular-nums text-slate-800">{totals[s.key]}</span>
          </span>
        ))}
        <span className="text-slate-500">
          {trend.length} days to {formatDate(`${lastDay.date}T00:00:00Z`)} (UTC)
        </span>
      </figcaption>
      <div className="relative">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="h-auto w-full touch-none"
          role="img"
          aria-label={`Findings created (${totals.created}) and resolved (${totals.resolved}) per day over ${trend.length} days. Exact values are in the data table.`}
          aria-describedby={tableId}
          onPointerMove={onMove}
          onPointerLeave={() => setHover(null)}
        >
          <line
            x1={PAD.left}
            x2={W - PAD.right}
            y1={y(0)}
            y2={y(0)}
            stroke="#cbd5e1"
            strokeWidth="1"
          />
          <line
            x1={PAD.left}
            x2={W - PAD.right}
            y1={y(max)}
            y2={y(max)}
            stroke="#e2e8f0"
            strokeWidth="1"
            strokeDasharray="2 3"
          />
          <text
            x={PAD.left - 6}
            y={y(max) + 4}
            textAnchor="end"
            className="fill-slate-500 text-[10px]"
          >
            {max}
          </text>
          <text
            x={PAD.left - 6}
            y={y(0) + 4}
            textAnchor="end"
            className="fill-slate-500 text-[10px]"
          >
            0
          </text>
          <text x={x(0)} y={H - 4} className="fill-slate-500 text-[10px]">
            {formatDate(`${first.date}T00:00:00Z`)}
          </text>
          <text
            x={x(trend.length - 1)}
            y={H - 4}
            textAnchor="end"
            className="fill-slate-500 text-[10px]"
          >
            {formatDate(`${lastDay.date}T00:00:00Z`)}
          </text>
          {SERIES.map((s) => (
            <path
              key={s.key}
              d={path(s.key)}
              fill="none"
              stroke={s.color}
              strokeWidth="2"
              strokeDasharray={s.dash}
              strokeLinejoin="round"
              strokeLinecap="round"
            />
          ))}
          {hover !== null && hovered && (
            <g>
              <line
                x1={x(hover)}
                x2={x(hover)}
                y1={PAD.top}
                y2={y(0)}
                stroke="#94a3b8"
                strokeWidth="1"
              />
              {SERIES.map((s) => (
                <circle
                  key={s.key}
                  cx={x(hover)}
                  cy={y(hovered[s.key])}
                  r="4"
                  fill={s.color}
                  stroke="#ffffff"
                  strokeWidth="2"
                />
              ))}
            </g>
          )}
        </svg>
        {hover !== null && hovered && (
          <div
            className="pointer-events-none absolute top-0 rounded-md border border-slate-200 bg-white px-2 py-1 text-xs text-slate-700 shadow-sm"
            style={
              hover > trend.length / 2
                ? { right: `${100 - (x(hover) / W) * 100 + 1}%` }
                : { left: `${(x(hover) / W) * 100 + 1}%` }
            }
            aria-hidden
          >
            <div className="font-medium text-slate-900">
              {formatDate(`${hovered.date}T00:00:00Z`)}
            </div>
            <div>Created {hovered.created}</div>
            <div>Resolved {hovered.resolved}</div>
          </div>
        )}
      </div>
      <details className="text-xs text-slate-600">
        <summary className="cursor-pointer text-sky-800">Show data table</summary>
        <table id={tableId} className="mt-2 min-w-full text-xs">
          <caption className="sr-only">Findings created and resolved per UTC day</caption>
          <thead>
            <tr className="text-left text-slate-500">
              <th scope="col" className="py-1 pr-4 font-medium">
                Date (UTC)
              </th>
              <th scope="col" className="py-1 pr-4 text-right font-medium">
                Created
              </th>
              <th scope="col" className="py-1 text-right font-medium">
                Resolved
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 tabular-nums">
            {trend.map((d) => (
              <tr key={d.date}>
                <td className="py-1 pr-4">{d.date}</td>
                <td className="py-1 pr-4 text-right">{d.created}</td>
                <td className="py-1 text-right">{d.resolved}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </figure>
  );
}
