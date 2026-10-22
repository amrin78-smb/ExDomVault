import { useEffect, useState } from 'react';

export type AsyncState<T> =
  { status: 'loading' } | { status: 'success'; data: T } | { status: 'error'; error: Error };

const LOADING = { status: 'loading' } as const;

/**
 * Runs an abortable async loader on mount and whenever `deps` change. Results are keyed by the
 * serialised deps so a stale result is never shown for new inputs.
 */
export function useAsync<T>(
  load: (signal: AbortSignal) => Promise<T>,
  deps: readonly unknown[],
): AsyncState<T> {
  const key = JSON.stringify(deps);
  const [result, setResult] = useState<{ key: string; state: AsyncState<T> } | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal).then(
      (data) => {
        if (!controller.signal.aborted) setResult({ key, state: { status: 'success', data } });
      },
      (error: unknown) => {
        if (!controller.signal.aborted) {
          const err = error instanceof Error ? error : new Error(String(error));
          setResult({ key, state: { status: 'error', error: err } });
        }
      },
    );
    return () => controller.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `key` captures the caller's deps
  }, [key]);

  return result?.key === key ? result.state : LOADING;
}
