import type { Severity } from '@exdomainvault/shared';
import { useTheme } from '../../lib/theme.ts';

/**
 * Chart colours. Severity uses the `--color-sev-*` tokens from index.css (the same hues as
 * SeverityBadge, flipped for the dark theme there), so a chart never invents its own severity
 * palette. Pass these strings straight to SVG `fill` / `stroke`.
 */
export const SEVERITY_CHART_COLORS: Record<Severity, string> = {
  critical: 'var(--color-sev-critical)',
  high: 'var(--color-sev-high)',
  medium: 'var(--color-sev-medium)',
  low: 'var(--color-sev-low)',
  informational: 'var(--color-sev-info)',
};

/** Neutral for "other" / "unclassified" slices and empty tracks. */
export const NEUTRAL_CHART_COLOR = 'var(--color-fg-faint)';
export const GRID_COLOR = 'var(--color-line)';
export const AXIS_TEXT_COLOR = 'var(--color-fg-subtle)';

/**
 * Categorical slots of the data-viz reference palette, each stepped separately for the light and
 * dark surfaces (adjacent pairs validated for colour-vision deficiency). Assign in this fixed order
 * by entity, never by rank, and always next to a text legend.
 */
const CATEGORICAL = {
  light: ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4', '#008300', '#6250d6', '#e34948'],
  dark: ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#008300', '#9085e9', '#e66767'],
} as const;

/** The categorical palette for the active theme (re-renders when the theme changes). */
export function useCategoricalPalette(): readonly string[] {
  const [theme] = useTheme();
  return CATEGORICAL[theme];
}

/** Whole-number percentage of `value` in `total` (0 when the total is 0). */
export const percentOf = (value: number, total: number) =>
  total > 0 ? Math.round((value / total) * 100) : 0;
