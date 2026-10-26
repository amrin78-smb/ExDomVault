import { RefreshCw, TriangleAlert } from 'lucide-react';
import type { ReactNode } from 'react';
import { ApiClientError } from '../../lib/api.ts';
import type { AsyncState } from '../../lib/use-async.ts';

/** A shimmering placeholder block while a card loads. */
export function Skeleton({ className = 'h-4 w-full' }: { className?: string }) {
  return <div className={`animate-pulse rounded-md bg-surface-3 ${className}`} aria-hidden />;
}

/** A few skeleton rows, announced once as "Loading…". */
export function SkeletonRows({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-3" role="status" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className={`h-4 ${i % 2 ? 'w-3/4' : 'w-full'}`} />
      ))}
    </div>
  );
}

const errorText = (error: Error) =>
  error instanceof ApiClientError && error.status === 403
    ? 'Your role cannot view this information.'
    : error instanceof ApiClientError
      ? error.message
      : 'The server could not be reached.';

/** A compact inline load error with Retry (forbidden loads get no Retry: it would fail again). */
export function CardError({ error, onRetry }: { error: Error; onRetry?: () => void }) {
  const forbidden = error instanceof ApiClientError && error.status === 403;
  return (
    <div
      role="alert"
      className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-900"
    >
      <span className="flex min-w-0 items-start gap-2">
        <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
        <span>
          <span className="font-medium">Could not load.</span> {errorText(error)}
        </span>
      </span>
      {onRetry && !forbidden && (
        <button
          type="button"
          onClick={onRetry}
          className="inline-flex items-center gap-1 rounded-md border border-red-300 px-2 py-1 text-xs font-medium hover:bg-red-100"
        >
          <RefreshCw className="size-3" aria-hidden />
          Retry
        </button>
      )}
    </div>
  );
}

/** Loading skeleton / inline error with retry / content, for every overview card. */
export function CardBody<T>({
  state,
  onRetry,
  skeleton = <SkeletonRows />,
  children,
}: {
  state: AsyncState<T>;
  onRetry?: () => void;
  skeleton?: ReactNode;
  children: (data: T) => ReactNode;
}) {
  if (state.status === 'loading') return skeleton;
  if (state.status === 'error') return <CardError error={state.error} onRetry={onRetry} />;
  return children(state.data);
}

/** A short empty-state line for a card with no data yet. */
export function CardEmpty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex min-h-28 flex-col items-center justify-center px-2 py-6 text-center">
      <p className="text-sm font-medium text-fg-2">{title}</p>
      {children && <p className="mt-1 max-w-xs text-xs text-fg-subtle">{children}</p>}
    </div>
  );
}

/** "View all →" style link classes for card headers. */
export const cardLinkClass =
  'inline-flex items-center gap-1 text-xs font-medium text-highlight hover:underline';
