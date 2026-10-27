import { Link } from 'react-router';

export function StatCard({
  label,
  value,
  hint,
  to,
}: {
  label: string;
  value: number | string | null;
  hint?: string;
  /** Makes the whole card a link to the matching filtered list. */
  to?: string;
}) {
  const body = (
    <>
      <div className="text-xs font-medium uppercase tracking-wider text-fg-subtle">{label}</div>
      <div className="mt-2 text-3xl font-semibold tracking-tight tabular-nums text-fg">
        {value ?? (
          <span className="text-fg-faint" aria-label="No data">
            —
          </span>
        )}
      </div>
      {hint && <div className="mt-1 text-xs text-fg-subtle">{hint}</div>}
    </>
  );
  const box = 'block rounded-xl border border-line bg-surface p-4 shadow-card';
  return to ? (
    <Link to={to} className={`${box} transition-colors hover:border-accent/60 hover:bg-surface-2`}>
      {body}
    </Link>
  ) : (
    <div className={box}>{body}</div>
  );
}
