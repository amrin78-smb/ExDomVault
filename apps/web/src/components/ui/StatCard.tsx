export function StatCard({
  label,
  value,
  hint,
}: {
  label: string;
  value: number | string | null;
  hint?: string;
}) {
  return (
    <div className="rounded-xl border border-line bg-surface p-4 shadow-card">
      <div className="text-xs font-medium uppercase tracking-wider text-fg-subtle">{label}</div>
      <div className="mt-2 text-3xl font-semibold tracking-tight tabular-nums text-fg">
        {value ?? (
          <span className="text-fg-faint" aria-label="No data">
            —
          </span>
        )}
      </div>
      {hint && <div className="mt-1 text-xs text-fg-subtle">{hint}</div>}
    </div>
  );
}
