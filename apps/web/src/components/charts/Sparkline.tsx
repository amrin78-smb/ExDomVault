import { sampleSeries } from './series.ts';

/**
 * A decorative mini bar chart of a daily series (the value it summarises must be shown as text).
 * Bars are SVG geometry coloured with a Tailwind `fill-*` / `text-*` class via `currentColor`.
 */
export function Sparkline({
  series,
  className = 'h-8 w-24 text-accent',
}: {
  series: readonly number[];
  /** Size and colour (`text-*`), e.g. `h-8 w-24 text-sky-600`. */
  className?: string;
}) {
  const bars = sampleSeries(series);
  if (bars.length === 0) return null;
  const max = Math.max(1, ...bars);
  const step = 4;
  const H = 24;
  return (
    <svg
      viewBox={`0 0 ${bars.length * step} ${H}`}
      preserveAspectRatio="none"
      className={`block ${className}`}
      aria-hidden
      focusable="false"
      data-testid="sparkline"
    >
      {bars.map((v, i) => {
        // Zero still draws a 1-unit stub so the baseline reads as "none", not "missing".
        const h = Math.max(1, (v / max) * H);
        return (
          <rect
            key={i}
            x={i * step + 0.5}
            y={H - h}
            width={step - 1}
            height={h}
            rx={0.8}
            fill="currentColor"
            opacity={i === bars.length - 1 ? 1 : 0.55}
          />
        );
      })}
    </svg>
  );
}
