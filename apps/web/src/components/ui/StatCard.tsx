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
    <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
      <div className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-2 text-2xl font-semibold tabular-nums text-slate-900">
        {value ?? (
          <span className="text-slate-300" aria-label="No data">
            —
          </span>
        )}
      </div>
      {hint && <div className="mt-1 text-xs text-slate-500">{hint}</div>}
    </div>
  );
}
