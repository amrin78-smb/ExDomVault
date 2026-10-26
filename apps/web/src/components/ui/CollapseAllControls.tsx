import { ChevronsDownUp, ChevronsUpDown } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { CardGroup } from './Card.tsx';

/**
 * "Expand all" / "Collapse all" for the collapsible cards in `children`. Place the returned
 * `controls` where they belong (usually the page header) and wrap the cards in `group`.
 */
export function useCollapseAll(): {
  controls: ReactNode;
  group: (children: ReactNode) => ReactNode;
} {
  const [command, setCommand] = useState<{ open: boolean; seq: number } | null>(null);
  const send = (open: boolean) => setCommand((c) => ({ open, seq: (c?.seq ?? 0) + 1 }));
  const button =
    'inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium text-slate-600 hover:bg-slate-100 hover:text-slate-900';
  return {
    controls: (
      <div className="flex items-center gap-1">
        <button type="button" className={button} onClick={() => send(true)}>
          <ChevronsUpDown className="size-3.5" aria-hidden />
          Expand all
        </button>
        <button type="button" className={button} onClick={() => send(false)}>
          <ChevronsDownUp className="size-3.5" aria-hidden />
          Collapse all
        </button>
      </div>
    ),
    group: (children) => <CardGroup command={command}>{children}</CardGroup>,
  };
}
