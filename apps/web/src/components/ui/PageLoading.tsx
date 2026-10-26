/** Shown while the first page chunk loads (routes are code-split). */
export function PageLoading() {
  return (
    <p role="status" className="p-8 text-sm text-fg-muted">
      Loading…
    </p>
  );
}
