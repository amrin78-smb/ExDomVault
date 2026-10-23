import { useEffect, useId, useRef, type ReactNode } from 'react';
import { Button } from '../ui/Button.tsx';

/**
 * An inline confirmation step (role `alertdialog`) for consequential changes. Focus moves into it
 * when it opens so screen readers announce the question, and Escape cancels.
 */
export function ConfirmPanel({
  title,
  children,
  confirmLabel,
  danger = false,
  busy = false,
  onConfirm,
  onCancel,
}: {
  title: string;
  children: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const bodyId = useId();

  useEffect(() => {
    ref.current?.focus();
  }, []);

  return (
    <div
      ref={ref}
      role="alertdialog"
      aria-labelledby={titleId}
      aria-describedby={bodyId}
      tabIndex={-1}
      onKeyDown={(e) => {
        if (e.key === 'Escape' && !busy) onCancel();
      }}
      className={`space-y-2 rounded-md border p-3 text-sm outline-none focus-visible:ring-2 focus-visible:ring-sky-500 ${
        danger ? 'border-red-200 bg-red-50' : 'border-amber-200 bg-amber-50'
      }`}
    >
      <p id={titleId} className="font-medium text-slate-900">
        {title}
      </p>
      <div id={bodyId} className="text-slate-700">
        {children}
      </div>
      <div className="flex gap-2">
        <Button variant={danger ? 'danger' : 'primary'} onClick={onConfirm} disabled={busy}>
          {confirmLabel}
        </Button>
        <Button onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
      </div>
    </div>
  );
}
