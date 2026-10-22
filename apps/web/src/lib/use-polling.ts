import { useEffect, useState } from 'react';

/** A counter that increments every `ms` while `active`, for use as a reload key. */
export function usePollingKey(active: boolean, ms: number): number {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => setTick((t) => t + 1), ms);
    return () => clearInterval(id);
  }, [active, ms]);
  return tick;
}
