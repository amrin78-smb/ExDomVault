import { RefreshCw, TriangleAlert } from 'lucide-react';
import { formatDateTime } from '../../lib/format.ts';
import { Button } from './Button.tsx';

/**
 * Shown above data that is still on screen after a refresh failed, so nobody mistakes it for
 * current data. The previous data stays visible; Retry loads it again.
 */
export function StaleDataNotice({
  loadedAt,
  error,
  onRetry,
  retrying = false,
}: {
  loadedAt: string;
  error: Error;
  onRetry: () => void;
  retrying?: boolean;
}) {
  return (
    <div
      role="status"
      className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900"
    >
      <p className="flex items-start gap-2">
        <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
        <span>
          Showing data from {formatDateTime(loadedAt)}; refresh failed — {error.message}
        </span>
      </p>
      <Button onClick={onRetry} disabled={retrying}>
        <RefreshCw className="size-3.5" aria-hidden />
        {retrying ? 'Retrying…' : 'Retry'}
      </Button>
    </div>
  );
}
