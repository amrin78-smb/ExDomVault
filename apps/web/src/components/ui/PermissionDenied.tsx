import { Lock } from 'lucide-react';
import type { ReactNode } from 'react';
import { EmptyState } from './EmptyState.tsx';

/** The empty state for data the signed-in role may not see (an API 403, or a missing permission). */
export function PermissionDenied({
  title = 'You do not have access to this information',
  children = 'Your role does not include this. Ask an administrator if you need access.',
}: {
  title?: string;
  children?: ReactNode;
}) {
  return (
    <EmptyState title={title} icon={Lock}>
      {children}
    </EmptyState>
  );
}
