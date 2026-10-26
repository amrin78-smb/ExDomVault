import { isRouteErrorResponse, useRouteError } from 'react-router';

/** Top-level error boundary. Shows a safe message; details go to the browser console only. */
export function RouteErrorPage() {
  const error = useRouteError();
  console.error(error);
  const message = isRouteErrorResponse(error)
    ? `${error.status} ${error.statusText}`
    : 'An unexpected error occurred while rendering this page.';

  return (
    <div
      role="alert"
      className="mx-auto mt-24 max-w-md rounded-lg border border-red-200 bg-surface p-6 text-center"
    >
      <h1 className="text-lg font-semibold text-fg">Something went wrong</h1>
      <p className="mt-2 text-sm text-fg-muted">{message}</p>
      <a href="/" className="mt-4 inline-block text-sm font-medium text-sky-700 hover:underline">
        Reload the application
      </a>
    </div>
  );
}
