import { SEVERITY_LABELS, type Severity } from '@exdomainvault/shared';

// Light: tinted fill, dark text. Dark: the palettes are remapped (index.css) to a translucent wash,
// and the sev-* text tokens flip to light shades, so each pill reads as a glowing outline.
const STYLES: Record<Severity, string> = {
  critical: 'bg-red-50 text-sev-critical ring-red-600/25 dark:ring-red-400/55',
  high: 'bg-orange-50 text-sev-high ring-orange-600/25 dark:ring-orange-400/55',
  medium: 'bg-amber-50 text-sev-medium ring-amber-600/30 dark:ring-amber-400/55',
  low: 'bg-blue-50 text-sev-low ring-blue-600/25 dark:ring-blue-400/55',
  informational: 'bg-slate-100 text-sev-info ring-slate-500/25 dark:ring-slate-500/50',
};

/** The single source of severity styling. Label text is always shown; colour is never the only cue. */
export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${STYLES[severity]}`}
    >
      {SEVERITY_LABELS[severity]}
    </span>
  );
}
