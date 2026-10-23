import type { ReactNode } from 'react';

export function Card({
  title,
  actions,
  children,
  className = '',
}: {
  title?: string;
  /** Controls shown at the right of the title bar (needs `title`). */
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-lg border border-slate-200 bg-white shadow-sm ${className}`}
      aria-label={title}
    >
      {title &&
        (actions ? (
          <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-100 px-4 py-3">
            <h2 className="text-sm font-semibold text-slate-800">{title}</h2>
            {actions}
          </div>
        ) : (
          <h2 className="border-b border-slate-100 px-4 py-3 text-sm font-semibold text-slate-800">
            {title}
          </h2>
        ))}
      <div className="p-4">{children}</div>
    </section>
  );
}
