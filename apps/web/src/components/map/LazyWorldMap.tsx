import { lazy, Suspense } from 'react';
import type { WorldMapProps } from './types.ts';

// The map module embeds the world-atlas topology (~100 KB): load it in its own chunk.
const WorldMap = lazy(() => import('./WorldMap.tsx'));

/** `WorldMap`, code-split. Shows a pulsing placeholder of the same shape while it loads. */
export function LazyWorldMap(props: WorldMapProps) {
  return (
    <Suspense
      fallback={
        <div
          role="status"
          aria-label="Loading map"
          className="aspect-[96/47] w-full animate-pulse rounded-lg border border-line-soft bg-surface-2"
        />
      }
    >
      <WorldMap {...props} />
    </Suspense>
  );
}
