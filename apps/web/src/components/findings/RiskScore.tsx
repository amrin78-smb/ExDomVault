/** Risk score 0–100 as a number with a neutral bar. Severity colour is never reused here. */
export function RiskScore({ score }: { score: number }) {
  return (
    <span className="inline-flex items-center gap-2" title="Risk score (0–100)">
      <span
        className="h-1.5 w-12 overflow-hidden rounded-full bg-slate-200"
        aria-hidden
        data-testid="risk-bar"
      >
        <span className="block h-full bg-slate-600" style={{ width: `${score}%` }} />
      </span>
      <span className="tabular-nums font-medium text-slate-800">
        <span className="sr-only">Risk </span>
        {score}
      </span>
    </span>
  );
}
