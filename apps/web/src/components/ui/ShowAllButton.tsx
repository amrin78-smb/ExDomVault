import { useState } from 'react';

/**
 * Cuts a long list to `limit` entries with a "Show all N …" / "Show fewer" button. `from: 'end'`
 * keeps the last entries (for oldest-first lists whose newest entries matter most).
 */
export function useShowAll<T>(
  items: readonly T[],
  { limit, noun, from = 'start' }: { limit: number; noun: string; from?: 'start' | 'end' },
) {
  const [expanded, setExpanded] = useState(false);
  const cut = !expanded && items.length > limit;
  const shown = cut ? (from === 'end' ? items.slice(-limit) : items.slice(0, limit)) : items;
  const toggle =
    items.length > limit ? (
      <button
        type="button"
        onClick={() => setExpanded((e) => !e)}
        aria-expanded={expanded}
        className="text-xs font-medium text-sky-800 hover:underline"
      >
        {expanded ? 'Show fewer' : `Show all ${items.length} ${noun}`}
      </button>
    ) : null;
  return { shown, toggle };
}
