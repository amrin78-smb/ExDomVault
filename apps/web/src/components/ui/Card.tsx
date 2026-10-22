import type { ReactNode } from 'react';

export function Card({
  title,
  children,
  className = '',
}: {
  title?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-lg border border-slate-200 bg-white shadow-sm ${className}`}
      aria-label={title}
    >
      {title && (
        <h2 className="border-b border-slate-100 px-4 py-3 text-sm font-semibold text-slate-800">
          {title}
        </h2>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}
