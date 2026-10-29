import type { Grade } from '@exdomainvault/shared';

// Security grade (A best … F worst). Deliberately separate from SeverityBadge: a grade summarises a
// domain's posture, it is not a finding severity.
const STYLES: Record<Grade, string> = {
  A: 'bg-emerald-50 text-emerald-800 ring-emerald-600/25 dark:ring-emerald-400/55',
  B: 'bg-green-50 text-green-800 ring-green-600/25 dark:ring-green-400/55',
  C: 'bg-amber-50 text-amber-800 ring-amber-600/30 dark:ring-amber-400/55',
  D: 'bg-orange-50 text-orange-800 ring-orange-600/25 dark:ring-orange-400/55',
  F: 'bg-red-50 text-red-800 ring-red-600/25 dark:ring-red-400/55',
};

const SIZES = { sm: 'size-6 text-xs', lg: 'size-12 text-2xl' } as const;

/** A–F security grade. The letter is always shown; `score` adds an accessible label. */
export function GradeBadge({
  grade,
  score,
  size = 'sm',
}: {
  grade: Grade | null;
  score?: number | null;
  size?: keyof typeof SIZES;
}) {
  if (!grade) {
    return (
      <span className="text-xs text-fg-faint" title="Not scored yet: no completed scan">
        —
      </span>
    );
  }
  const label =
    score === undefined || score === null
      ? `Grade ${grade}`
      : `Grade ${grade}, score ${score} of 100`;
  return (
    <span
      role="img"
      aria-label={label}
      title={label}
      className={`inline-flex shrink-0 items-center justify-center rounded-md font-semibold ring-1 ring-inset ${SIZES[size]} ${STYLES[grade]}`}
    >
      {grade}
    </span>
  );
}
