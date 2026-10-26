import { AlertTriangle } from 'lucide-react';
import { ApiClientError } from '../../lib/api.ts';

/** Shows an API error message (already safe for display) and its request ID for support. */
export function ErrorAlert({ error, title }: { error: Error; title?: string }) {
  const details = error instanceof ApiClientError ? error.details : undefined;
  const requestId = error instanceof ApiClientError ? error.requestId : undefined;
  return (
    <div
      role="alert"
      className="flex gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800"
    >
      <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div>
        {title && <p className="font-medium">{title}</p>}
        <p>{error.message}</p>
        {details && details.length > 0 && (
          <ul className="mt-1 list-disc pl-4">
            {details.map((d) => (
              <li key={`${d.path}:${d.message}`}>{d.message}</li>
            ))}
          </ul>
        )}
        {requestId && <p className="mt-1 text-xs text-red-700/80">Request ID: {requestId}</p>}
      </div>
    </div>
  );
}
