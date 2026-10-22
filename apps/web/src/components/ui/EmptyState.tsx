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
      <Icon className="size-6 text-slate-400" aria-hidden />
      <p className="mt-2 text-sm font-medium text-slate-700">{title}</p>
      {children && <div className="mt-1 max-w-sm text-xs text-slate-500">{children}</div>}
    </div>
  );
}
