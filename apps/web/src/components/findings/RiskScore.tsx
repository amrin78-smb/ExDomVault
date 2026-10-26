import { ProportionBar } from '../ui/ProportionBar.tsx';

/** Risk score 0–100 as a number with a neutral bar. Severity colour is never reused here. */
export function RiskScore({ score }: { score: number }) {
  return (
    <span className="inline-flex items-center gap-2" title="Risk score (0–100)">
      <span aria-hidden data-testid="risk-bar">
        <ProportionBar
          percent={score}
          className="h-1.5 w-12 rounded-full bg-line"
          fillClassName="fill-slate-600"
        />
      </span>
      <span className="tabular-nums font-medium text-fg">
        <span className="sr-only">Risk </span>
        {score}
      </span>
    </span>
  );
}
