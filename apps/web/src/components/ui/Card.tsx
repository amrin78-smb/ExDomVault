import { ChevronRight } from 'lucide-react';
import { createContext, useContext, useEffect, useId, useState, type ReactNode } from 'react';

/**
 * Expand/collapse-all broadcast for the collapsible cards below it. `seq` changes on every command
 * so repeating the same command still applies (a card may have been toggled in between).
 */
interface CardGroupCommand {
  open: boolean;
  seq: number;
}
const CardGroupContext = createContext<CardGroupCommand | null>(null);

export function CardGroup({
  command,
  children,
}: {
  command: CardGroupCommand | null;
  children: ReactNode;
}) {
  return <CardGroupContext.Provider value={command}>{children}</CardGroupContext.Provider>;
}

const STORAGE_PREFIX = 'exdv.card.';

function readStored(key: string): boolean | null {
  try {
    const v = window.localStorage.getItem(STORAGE_PREFIX + key);
    return v === '1' ? true : v === '0' ? false : null;
  } catch {
    return null;
  }
}

function writeStored(key: string, open: boolean) {
  try {
    window.localStorage.setItem(STORAGE_PREFIX + key, open ? '1' : '0');
  } catch {
    // Storage unavailable (private window, blocked site data): the choice lasts for this page only.
  }
}

export function Card({
  title,
  actions,
  children,
  className = '',
  collapsible,
  defaultOpen = true,
  summary,
}: {
  title?: string;
  /** Controls shown at the right of the title bar (needs `title`). */
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  /**
   * Makes the card collapsible (needs `title`); the value is the key under which the viewer's
   * open/closed choice is remembered in this browser, e.g. `domain.tls`.
   */
  collapsible?: string;
  /** Initial state when the viewer has made no choice yet. */
  defaultOpen?: boolean;
  /** One line shown in the title bar while collapsed (e.g. "3 certificates, 1 expiring"). */
  summary?: ReactNode;
}) {
  const bodyId = useId();
  const command = useContext(CardGroupContext);
  const [open, setOpen] = useState(() =>
    collapsible ? (readStored(collapsible) ?? defaultOpen) : true,
  );
  // Apply a new expand/collapse-all command during render (no effect round-trip).
  const [seenSeq, setSeenSeq] = useState(command?.seq ?? 0);
  if (collapsible && command && command.seq !== seenSeq) {
    setSeenSeq(command.seq);
    setOpen(command.open);
  }
  useEffect(() => {
    if (collapsible && command && command.seq === seenSeq && open === command.open) {
      writeStored(collapsible, open);
    }
  }, [collapsible, command, seenSeq, open]);

  const toggle = () => {
    if (!collapsible) return;
    setOpen((o) => {
      writeStored(collapsible, !o);
      return !o;
    });
  };

  const heading =
    title && collapsible ? (
      <h2 className="min-w-0 flex-1 text-sm font-semibold text-fg">
        <button
          type="button"
          onClick={toggle}
          aria-expanded={open}
          aria-controls={bodyId}
          className="flex w-full min-w-0 items-center gap-2 rounded text-left hover:text-fg"
        >
          <ChevronRight
            className={`size-4 shrink-0 text-fg-faint transition-transform ${open ? 'rotate-90' : ''}`}
            aria-hidden
          />
          <span className="shrink-0">{title}</span>
          {!open && summary && (
            <span className="min-w-0 truncate text-xs font-normal text-fg-subtle">{summary}</span>
          )}
        </button>
      </h2>
    ) : (
      title && <h2 className="text-sm font-semibold text-fg">{title}</h2>
    );

  return (
    <section
      className={`rounded-xl border border-line bg-surface shadow-card ${className}`}
      aria-label={title}
    >
      {title && (
        <div
          className={`flex flex-wrap items-start justify-between gap-3 px-4 py-3 ${
            open ? 'border-b border-line' : ''
          }`}
        >
          {heading}
          {actions && open && actions}
        </div>
      )}
      {/* Collapsed bodies stay mounted (their data keeps loading, and summaries can use it). */}
      <div id={bodyId} className="p-4" hidden={!open}>
        {children}
      </div>
    </section>
  );
}
