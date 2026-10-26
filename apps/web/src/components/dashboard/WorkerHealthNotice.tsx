import { TriangleAlert } from 'lucide-react';
import { Link } from 'react-router';
import { api } from '../../lib/api.ts';
import { usePermission } from '../../lib/session.ts';
import { useAsync } from '../../lib/use-async.ts';
import { isStale } from './format.ts';

function Loader() {
  const state = useAsync((signal) => api.workers.list({ signal }), []);
  if (state.status !== 'success') return null;
  const workers = state.data.items.filter((w) => w.status !== 'disabled');
  const quiet = workers.filter((w) => isStale(w));
  let text: string | null = null;
  if (state.data.items.length === 0) {
    text = 'No scanning worker is registered, so no scans will run.';
  } else if (workers.length === 0) {
    text = 'Every scanning worker is disabled, so no scans will run.';
  } else if (quiet.length === workers.length) {
    text = `No scanning worker has polled in the last 10 minutes (${quiet.map((w) => w.name).join(', ')}). Scans stay queued until one does.`;
  } else if (quiet.length > 0) {
    text = `${quiet.length} of ${workers.length} scanning workers not seen recently: ${quiet.map((w) => w.name).join(', ')}.`;
  }
  if (!text) return null;
  return (
    <div
      role="status"
      className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900"
    >
      <p className="flex items-start gap-2">
        <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
        <span>{text}</span>
      </p>
      <Link to="/settings" className="text-xs font-medium underline-offset-2 hover:underline">
        Worker settings
      </Link>
    </div>
  );
}

/** Administrators only (workers need `settings:manage`): a warning when scans cannot run. */
export function WorkerHealthNotice() {
  const allowed = usePermission('settings:manage');
  return allowed ? <Loader /> : null;
}
