import {
  ACCEPTED_RISK_MULTIPLIER,
  CATEGORY_CAP,
  OVERDUE_MULTIPLIER,
  SEVERITY_LABELS,
  type DomainScoreResponse,
  type ScoreDeduction,
} from '@exdomainvault/shared';
import { Sparkline } from '../charts/Sparkline.tsx';
import { CATEGORY_LABELS } from '../findings/labels.ts';
import { Card } from '../ui/Card.tsx';
import { GradeBadge } from '../ui/GradeBadge.tsx';
import { LoadError } from '../ui/LoadError.tsx';
import { api } from '../../lib/api.ts';
import { formatDate } from '../../lib/format.ts';
import { useAsync } from '../../lib/use-async.ts';

const STATE_TEXT = {
  open: 'open',
  overdue: `overdue (×${OVERDUE_MULTIPLIER})`,
  accepted_risk: `accepted risk (×${ACCEPTED_RISK_MULTIPLIER})`,
} as const;

const pts = (n: number) => `${Number.isInteger(n) ? n : n.toFixed(2)}`;

/**
 * Security score of a domain: grade, score, what lowered it (per category, with the cap), and the
 * daily trend. Deterministic: computed from the domain's open findings (docs/security-score.md).
 */
export function SecurityScoreCard({ domainId }: { domainId: string }) {
  const state = useAsync((signal) => api.domains.score(domainId, { signal }), [domainId]);
  const current = state.status === 'success' ? state.data.current : null;
  return (
    <Card
      title="Security score"
      collapsible="domain.score"
      summary={current ? `Grade ${current.grade} · ${current.score}/100` : undefined}
    >
      {state.status === 'loading' && (
        <p role="status" className="text-sm text-fg-subtle">
          Loading the security score…
        </p>
      )}
      {state.status === 'error' && (
        <LoadError error={state.error} title="Could not load the security score" />
      )}
      {state.status === 'success' && <ScoreBody data={state.data} />}
    </Card>
  );
}

function ScoreBody({ data }: { data: DomainScoreResponse }) {
  const { current, trend } = data;
  if (!current) {
    return (
      <p className="text-sm text-fg-muted">
        Not scored yet: the score is calculated once a scan of this domain has completed.
      </p>
    );
  }
  const first = trend[0];
  return (
    <div className="space-y-4 text-sm">
      <div className="flex flex-wrap items-center gap-4">
        <GradeBadge grade={current.grade} score={current.score} size="lg" />
        <div>
          <div className="text-2xl font-semibold tabular-nums text-fg" data-testid="score-value">
            {current.score}
            <span className="text-sm font-normal text-fg-subtle"> / 100</span>
          </div>
          <div className="text-xs text-fg-subtle">
            {current.deductions.length === 0
              ? 'No open findings lower the score.'
              : `${pts(100 - current.score)} points deducted for open findings`}
          </div>
        </div>
        {trend.length > 1 && first && (
          <div className="ml-auto text-right">
            <Sparkline
              series={trend.map((p) => p.score)}
              className="ml-auto h-8 w-32 text-sky-600"
            />
            <div className="mt-1 text-xs text-fg-subtle">
              {first.score} on {formatDate(first.day)} → {current.score} today
            </div>
          </div>
        )}
      </div>
      {current.deductions.length > 0 && <Deductions rows={current.deductions} />}
      <p className="text-xs text-fg-subtle">
        Starts at 100. Each open finding deducts points by severity (critical 25, high 10, medium 4,
        low 1); overdue findings count {OVERDUE_MULTIPLIER}×, accepted risks{' '}
        {ACCEPTED_RISK_MULTIPLIER}×. Each category deducts at most {CATEGORY_CAP} points. Grades: A
        ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, otherwise F.
      </p>
    </div>
  );
}

function Deductions({ rows }: { rows: ScoreDeduction[] }) {
  return (
    <ul className="divide-y divide-line-soft" aria-label="Why the score is lower">
      {rows.map((d) => (
        <li key={d.category} className="py-2">
          <div className="flex items-baseline justify-between gap-3">
            <span className="font-medium text-fg">{CATEGORY_LABELS[d.category] ?? d.category}</span>
            <span className="tabular-nums text-fg">
              −{pts(d.points)}
              {d.capped && (
                <span className="ml-1 text-xs text-fg-subtle">(capped from {pts(d.uncapped)})</span>
              )}
            </span>
          </div>
          <ul className="mt-1 space-y-0.5 text-xs text-fg-muted">
            {d.items.map((i) => (
              <li key={`${i.severity}|${i.state}`}>
                {i.count} {SEVERITY_LABELS[i.severity].toLowerCase()} {STATE_TEXT[i.state]} ×{' '}
                {pts(i.each)} = {pts(i.points)}
              </li>
            ))}
          </ul>
        </li>
      ))}
    </ul>
  );
}
