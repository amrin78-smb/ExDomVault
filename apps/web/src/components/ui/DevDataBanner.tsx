import { FlaskConical } from 'lucide-react';

export function DevDataBanner() {
  return (
    <div
      role="note"
      className="flex items-center gap-2 border-b border-amber-300 bg-amber-100 px-6 py-2 text-sm font-medium text-amber-900"
    >
      <FlaskConical className="size-4 shrink-0" aria-hidden />
      Development data — synthetic fixtures, not real scan results.
    </div>
  );
}
