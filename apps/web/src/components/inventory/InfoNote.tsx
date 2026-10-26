import { Info, TriangleAlert } from 'lucide-react';
import type { ReactNode } from 'react';

/** A short explanatory banner above a list (role="note", named for screen readers). */
export function InfoNote({
  label,
  tone = 'info',
  children,
}: {
  label: string;
  tone?: 'info' | 'caution';
  children: ReactNode;
}) {
  const Icon = tone === 'caution' ? TriangleAlert : Info;
  const colours =
    tone === 'caution'
      ? 'border-amber-200 bg-amber-50 text-amber-900'
      : 'border-sky-200 bg-sky-50 text-sky-900';
  return (
    <div
      role="note"
      aria-label={label}
      className={`flex gap-2 rounded-lg border px-3 py-2 text-sm ${colours}`}
    >
      <Icon className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div>{children}</div>
    </div>
  );
}
