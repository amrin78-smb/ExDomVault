import { cvssBand } from './format.ts';

/**
 * A CVSS base score with its CVSS v3 qualitative rating (None/Low/Medium/High/Critical).
 *
 * Deliberately NOT a SeverityBadge: CVSS is NVD's generic score for the vulnerability, while our
 * severity comes only from the deterministic rules for a specific finding on a specific asset.
 * Colouring the two the same way would suggest they are the same thing, so the chip is neutral:
 * a monospace score, the band as text and a four-step meter.
 */
export function CvssChip({ score }: { score: number | null }) {
  if (score === null) return <span className="text-xs text-fg-faint">No score</span>;
  const band = cvssBand(score);
  const steps = { None: 0, Low: 1, Medium: 2, High: 3, Critical: 4 }[band];
  return (
    <span
      className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border border-line-strong bg-surface-2 px-1.5 py-0.5 text-xs"
      title={`CVSS base score ${score.toFixed(1)} (${band})`}
    >
      <span className="font-mono font-semibold tabular-nums text-fg">{score.toFixed(1)}</span>
      <span className="text-fg-muted">{band}</span>
      <span aria-hidden className="flex gap-px">
        {[1, 2, 3, 4].map((i) => (
          <span
            key={i}
            className={`h-2.5 w-1 rounded-sm ${i <= steps ? 'bg-fg-muted' : 'bg-line'}`}
          />
        ))}
      </span>
    </span>
  );
}
