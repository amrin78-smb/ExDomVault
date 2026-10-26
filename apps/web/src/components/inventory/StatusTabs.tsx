/**
 * Status/state filter shown as segmented tabs with counts. Each tab is a toggle button
 * (`aria-pressed`) rather than an ARIA tab, because it filters the one list below instead of
 * switching between panels.
 */
export interface StatusTab {
  value: string;
  label: string;
  count?: number;
}

export function StatusTabs({
  label,
  tabs,
  value,
  onChange,
}: {
  label: string;
  tabs: readonly StatusTab[];
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div
      role="group"
      aria-label={label}
      className="-mx-1 flex gap-1 overflow-x-auto border-b border-line px-1"
    >
      {tabs.map((t) => {
        const active = t.value === value;
        return (
          <button
            key={t.value}
            type="button"
            aria-pressed={active}
            aria-label={t.count === undefined ? t.label : `${t.label} (${t.count})`}
            onClick={() => onChange(t.value)}
            className={`-mb-px inline-flex shrink-0 items-center gap-2 border-b-2 px-3 py-2 text-sm font-medium transition-colors ${
              active
                ? 'border-accent text-fg'
                : 'border-transparent text-fg-muted hover:border-line-strong hover:text-fg'
            }`}
          >
            {t.label}
            {t.count !== undefined && (
              <span
                className={`rounded-full px-1.5 py-0.5 text-xs tabular-nums ${
                  active ? 'bg-accent-soft text-fg' : 'bg-surface-3 text-fg-subtle'
                }`}
              >
                {t.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}
