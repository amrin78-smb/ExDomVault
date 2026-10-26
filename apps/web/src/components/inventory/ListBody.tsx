import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import type { RefreshableAsync } from '../../lib/use-refreshable-async.ts';
import { Pagination } from '../findings/Pagination.tsx';
import { EmptyState } from '../ui/EmptyState.tsx';
import { LoadError } from '../ui/LoadError.tsx';
import { StaleDataNotice } from '../ui/StaleDataNotice.tsx';

/** Placeholder rows while a list loads (announced once as a status, hidden from the table). */
export function TableSkeleton({
  label,
  columns,
  rows = 6,
}: {
  label: string;
  columns: number;
  rows?: number;
}) {
  return (
    <div role="status" aria-live="polite" className="py-2">
      <span className="sr-only">{label}</span>
      <div aria-hidden className="space-y-2">
        {Array.from({ length: rows }, (_, r) => (
          <div key={r} className="flex gap-4">
            {Array.from({ length: columns }, (_, c) => (
              <div
                key={c}
                className="h-4 flex-1 animate-pulse rounded bg-surface-3"
                style={{ opacity: 1 - r * 0.12 }}
              />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

interface Page {
  items: readonly unknown[];
  page: number;
  pageSize: number;
  total: number;
}

/**
 * Loading / error / empty / table+pagination states of a paginated inventory list. Data still
 * on screen after a failed refresh is marked stale.
 */
export function ListBody<T extends Page>({
  list,
  noun,
  columns,
  empty,
  onPage,
  children,
}: {
  list: RefreshableAsync<T>;
  /** Plural noun for messages, e.g. "ports". */
  noun: string;
  columns: number;
  empty: { title: string; icon: LucideIcon; body: ReactNode };
  onPage: (page: number) => void;
  children: (data: T) => ReactNode;
}) {
  const { state, stale, refreshing, retry } = list;
  return (
    <>
      {stale && (
        <StaleDataNotice
          loadedAt={stale.loadedAt}
          error={stale.error}
          onRetry={retry}
          retrying={refreshing}
        />
      )}
      {state.status === 'loading' && <TableSkeleton label={`Loading ${noun}…`} columns={columns} />}
      {state.status === 'error' && (
        <LoadError error={state.error} title={`Could not load ${noun}`} onRetry={retry} />
      )}
      {state.status === 'success' && state.data.items.length === 0 && (
        <EmptyState title={empty.title} icon={empty.icon}>
          {empty.body}
        </EmptyState>
      )}
      {state.status === 'success' && state.data.items.length > 0 && (
        <>
          {children(state.data)}
          <Pagination
            page={state.data.page}
            pageSize={state.data.pageSize}
            total={state.data.total}
            onPage={onPage}
          />
        </>
      )}
    </>
  );
}

/** Table classes shared by the inventory tables. */
export const tableClass = 'min-w-full text-sm';
export const theadRowClass =
  'border-b border-line text-left text-xs font-medium uppercase tracking-wide text-fg-subtle';
export const thClass = 'whitespace-nowrap py-2 pr-4 font-medium';
export const tdClass = 'py-2.5 pr-4 align-top';
export const linkClass = 'text-sky-800 hover:underline';

/** Horizontal scroll inside the card on narrow screens; the page itself never scrolls sideways. */
export function TableFrame({ caption, children }: { caption: string; children: ReactNode }) {
  return (
    <div className="-mx-4 overflow-x-auto px-4">
      <table className={tableClass}>
        <caption className="sr-only">{caption}</caption>
        {children}
      </table>
    </div>
  );
}
