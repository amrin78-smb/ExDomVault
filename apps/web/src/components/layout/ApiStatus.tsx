import { api } from '../../lib/api.ts';
import { useAsync } from '../../lib/use-async.ts';

const DOT = {
  ok: 'bg-emerald-500',
  degraded: 'bg-amber-500',
  error: 'bg-red-500',
  loading: 'bg-slate-300',
} as const;

/** Compact API health indicator for the top bar. */
export function ApiStatus() {
  const state = useAsync((signal) => api.health({ signal }), []);

  let tone: keyof typeof DOT = 'loading';
  let label = 'Checking API…';
  if (state.status === 'success') {
    tone = state.data.status;
    label = state.data.status === 'ok' ? 'API healthy' : 'API degraded';
  } else if (state.status === 'error') {
    tone = 'error';
    label = 'API unreachable';
  }

  const title =
    state.status === 'success'
      ? `Environment: ${state.data.environment} · Database: ${state.data.components.database} · Auth: ${state.data.components.auth}`
      : state.status === 'error'
        ? state.error.message
        : undefined;

  return (
    <div className="flex items-center gap-2 text-xs text-slate-600" title={title} role="status">
      <span className={`size-2 rounded-full ${DOT[tone]}`} aria-hidden />
      {label}
      {state.status === 'success' && (
        <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] text-slate-500">
          {state.data.environment}
        </span>
      )}
    </div>
  );
}
