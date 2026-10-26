import { api } from '../../lib/api.ts';
import { useAsync } from '../../lib/use-async.ts';

const DOT = {
  ok: 'bg-emerald-500 shadow-[0_0_6px_rgb(16_185_129/0.8)]',
  degraded: 'bg-amber-500',
  error: 'bg-red-500',
  loading: 'bg-nav-muted',
} as const;

/** Compact API health indicator and app version for the sidebar footer (always on navy). */
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
    <div className="flex items-center justify-between gap-2 text-[11px] text-nav-muted">
      <div className="flex items-center gap-2" title={title} role="status">
        <span className={`size-2 rounded-full ${DOT[tone]}`} aria-hidden />
        {label}
        {state.status === 'success' && (
          <span className="rounded bg-white/5 px-1.5 py-0.5 font-mono text-[10px]">
            {state.data.environment}
          </span>
        )}
      </div>
      {state.status === 'success' && (
        <span className="font-mono tabular-nums">v{state.data.version}</span>
      )}
    </div>
  );
}
