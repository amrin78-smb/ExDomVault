/** Chart animations are skipped for viewers who ask for reduced motion (and where it is unknown). */
export function prefersReducedMotion(): boolean {
  try {
    return typeof window.matchMedia !== 'function'
      ? true
      : window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  } catch {
    return true;
  }
}
