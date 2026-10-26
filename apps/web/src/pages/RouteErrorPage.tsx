import { isRouteErrorResponse, useRouteError } from 'react-router';

/** Top-level error boundary. Shows a safe message; details go to the browser console only. */
export function RouteErrorPage() {
  const error = useRouteError();
  console.error(error);
  const message = isRouteErrorResponse(error)
    ? `${error.status} ${error.statusText}`
    : isChunkLoadError(error)
      ? 'A new version of ExDomainVault was deployed. Reload to load the latest pages.'
      : 'An unexpected error occurred while rendering this page.';

  return (
    <div
      role="alert"
      className="mx-auto mt-24 max-w-md rounded-lg border border-red-200 bg-surface p-6 text-center"
    >
      <h1 className="text-lg font-semibold text-fg">Something went wrong</h1>
      <p className="mt-2 text-sm text-fg-muted">{message}</p>
      <a
        href={isChunkLoadError(error) ? window.location.href : '/'}
        className="mt-4 inline-block text-sm font-medium text-sky-700 hover:underline"
      >
        Reload the application
      </a>
    </div>
  );
}

/**
 * Pages are separate chunks (routes.tsx). After a deploy, a tab opened earlier may ask for a chunk
 * name that no longer exists; the fix is a reload, not an error report.
 */
function isChunkLoadError(error: unknown): boolean {
  const msg = error instanceof Error ? error.message : '';
  return /dynamically imported module|Importing a module script failed|error loading dynamically imported module/i.test(
    msg,
  );
}
