/**
 * A decorative horizontal bar filled to `percent` (0–100). Drawn as SVG geometry (a `width`
 * attribute, not a `style` attribute), so it needs no inline styles under a strict CSP. The value
 * must always be shown as text next to it.
 */
export function ProportionBar({
  percent,
  className,
  fillClassName,
}: {
  percent: number;
  /** Size, track colour and rounding, e.g. `h-1.5 w-12 rounded-full bg-line`. */
  className: string;
  /** Fill colour as a Tailwind `fill-*` class. */
  fillClassName: string;
}) {
  const width = Number.isFinite(percent) ? Math.min(100, Math.max(0, percent)) : 0;
  return (
    <svg
      viewBox="0 0 100 1"
      preserveAspectRatio="none"
      className={`block overflow-hidden ${className}`}
      aria-hidden
      focusable="false"
    >
      <rect x="0" y="0" width={width} height="1" className={fillClassName} />
    </svg>
  );
}
