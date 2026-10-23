import { ApiClientError } from '../../lib/api.ts';
import { Button } from './Button.tsx';
import { ErrorAlert } from './ErrorAlert.tsx';
import { PermissionDenied } from './PermissionDenied.tsx';

const isForbidden = (error: Error) => error instanceof ApiClientError && error.status === 403;

/**
 * A failed load: the permission-denied state for 403 (never the raw error), otherwise the error
 * alert with an optional Retry.
 */
export function LoadError({
  error,
  title,
  onRetry,
  deniedTitle,
}: {
  error: Error;
  title: string;
  onRetry?: () => void;
  deniedTitle?: string;
}) {
  if (isForbidden(error)) return <PermissionDenied title={deniedTitle} />;
  return (
    <div className="space-y-2">
      <ErrorAlert error={error} title={title} />
      {onRetry && <Button onClick={onRetry}>Retry</Button>}
    </div>
  );
}
