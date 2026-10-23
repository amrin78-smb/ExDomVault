import { useEffect, useState } from 'react';
import type { AsyncState } from './use-async.ts';

export interface StaleInfo {
  /** When the data still on screen was loaded (ISO). */
  loadedAt: string;
  /** Why the latest refresh failed. */
  error: Error;
}

export interface RefreshableAsync<T> {
  /**
   * What to render. After a successful load, a refresh of the same inputs keeps the previous data
   * on screen (no flash of "Loading…"), and a failed refresh keeps it too, with `stale` set.
   */
  state: AsyncState<T>;
  /** Set when the data shown is from an earlier load because the latest refresh failed. */
  stale: StaleInfo | null;
  /** A refresh of data already on screen is in flight. */
  refreshing: boolean;
  /** Loads again with the same inputs. */
  retry: () => void;
}

const LOADING = { status: 'loading' } as const;

/**
 * Like `useAsync`, for pages that reload the same data (after an action or on retry). `deps` are
 * the inputs (filters, ids): changing them shows a fresh loading state. `refreshKey` only forces
 * a reload of the same inputs, so the previous data stays visible while it runs or if it fails.
 */
export function useRefreshableAsync<T>(
  load: (signal: AbortSignal) => Promise<T>,
  deps: readonly unknown[],
  refreshKey: unknown = 0,
): RefreshableAsync<T> {
  const base = JSON.stringify(deps);
  const [attempt, setAttempt] = useState(0);
  const run = JSON.stringify([refreshKey, attempt]);
  const [result, setResult] = useState<{ base: string; run: string; state: AsyncState<T> } | null>(
    null,
  );
  const [last, setLast] = useState<{ base: string; data: T; at: string } | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal).then(
      (data) => {
        if (controller.signal.aborted) return;
        setResult({ base, run, state: { status: 'success', data } });
        setLast({ base, data, at: new Date().toISOString() });
      },
      (error: unknown) => {
        if (controller.signal.aborted) return;
        const err = error instanceof Error ? error : new Error(String(error));
        setResult({ base, run, state: { status: 'error', error: err } });
      },
    );
    return () => controller.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `base` and `run` capture the inputs
  }, [base, run]);

  const current: AsyncState<T> =
    result?.base === base && result.run === run ? result.state : LOADING;
  const previous = last?.base === base ? last : null;
  const retry = () => setAttempt((a) => a + 1);

  if (current.status !== 'success' && previous) {
    return {
      state: { status: 'success', data: previous.data },
      stale: current.status === 'error' ? { loadedAt: previous.at, error: current.error } : null,
      refreshing: current.status === 'loading',
      retry,
    };
  }
  return { state: current, stale: null, refreshing: false, retry };
}
