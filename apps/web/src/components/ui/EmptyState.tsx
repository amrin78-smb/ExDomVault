import { Inbox, type LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';

export function EmptyState({
  title,
  children,
  icon: Icon = Inbox,
}: {
  title: string;
  children?: ReactNode;
  icon?: LucideIcon;
}) {
  return (
    <div className="flex flex-col items-center justify-center px-4 py-8 text-center">
      <span className="grid size-11 place-items-center rounded-full border border-line bg-surface-2">
        <Icon className="size-5 text-fg-subtle" aria-hidden />
      </span>
      <p className="mt-3 text-sm font-medium text-fg-2">{title}</p>
      {children && <div className="mt-1 max-w-sm text-xs text-fg-subtle">{children}</div>}
    </div>
  );
}
