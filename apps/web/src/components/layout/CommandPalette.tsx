import { Loader2, Search, X } from 'lucide-react';
import { useEffect, useId, useRef, useState, type KeyboardEvent } from 'react';
import { useNavigate } from 'react-router';
import { ApiClientError, api } from '../../lib/api.ts';
import { SeverityBadge } from '../ui/SeverityBadge.tsx';
import { toSearchGroups, type SearchGroup } from './search-results.ts';

/** Wait this long after the last keystroke before searching. */
export const SEARCH_DEBOUNCE_MS = 250;
const MIN_QUERY = 2;

type SearchState =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'success'; q: string; groups: SearchGroup[] }
  | { status: 'error'; error: Error };

function errorMessage(error: Error): string {
  if (error instanceof ApiClientError) {
    if (error.status === 404) return 'Search is not available yet on this server.';
    if (error.status === 403) return 'Your role cannot search the inventory.';
    return error.message;
  }
  return 'Search could not reach the server. Check your connection and try again.';
}

/**
 * Global search dialog (top bar, Ctrl/Cmd+K). Debounced, abortable, grouped results with
 * combobox keyboard navigation (↑ ↓ Enter Esc). Focus stays inside while open and returns to
 * where it was on close.
 */
export function CommandPalette({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [state, setState] = useState<SearchState>({ status: 'idle' });
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const listId = useId();
  const optionId = (i: number) => `${listId}-opt-${i}`;

  // Return focus to whatever opened the palette.
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    inputRef.current?.focus();
    return () => previous?.focus?.();
  }, []);

  const trimmed = query.trim();
  useEffect(() => {
    if (trimmed.length < MIN_QUERY) return;
    const controller = new AbortController();
    const timer = setTimeout(() => {
      setState({ status: 'loading' });
      api.search(trimmed, { signal: controller.signal }).then(
        (res) => {
          if (controller.signal.aborted) return;
          setActive(0);
          setState({ status: 'success', q: trimmed, groups: toSearchGroups(res) });
        },
        (error: unknown) => {
          if (controller.signal.aborted) return;
          setState({
            status: 'error',
            error: error instanceof Error ? error : new Error(String(error)),
          });
        },
      );
    }, SEARCH_DEBOUNCE_MS);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [trimmed]);

  // Results for an earlier query are never shown (or opened with Enter) for the current one.
  const shown: SearchState =
    trimmed.length < MIN_QUERY
      ? { status: 'idle' }
      : state.status === 'success' && state.q !== trimmed
        ? { status: 'loading' }
        : state;
  const groups = shown.status === 'success' ? shown.groups : [];
  const flat = groups.flatMap((g) => g.items);
  // Index of each group's first item in `flat` (options are numbered across groups).
  const starts = groups.map((_, gi) => groups.slice(0, gi).reduce((n, g) => n + g.items.length, 0));

  const go = (i: number) => {
    const item = flat[i];
    if (!item) return;
    onClose();
    void navigate(item.to);
  };

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      onClose();
    } else if (e.key === 'ArrowDown' && flat.length > 0) {
      e.preventDefault();
      setActive((a) => (a + 1) % flat.length);
    } else if (e.key === 'ArrowUp' && flat.length > 0) {
      e.preventDefault();
      setActive((a) => (a - 1 + flat.length) % flat.length);
    } else if (e.key === 'Enter' && e.target === inputRef.current) {
      e.preventDefault();
      go(active);
    } else if (e.key === 'Tab') {
      // Focus trap: cycle between the dialog's focusable controls.
      const focusables = Array.from(
        panelRef.current?.querySelectorAll<HTMLElement>('input, button') ?? [],
      );
      const first = focusables[0];
      const last = focusables.at(-1);
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last?.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first?.focus();
      }
    }
  };

  useEffect(() => {
    document.getElementById(optionId(active))?.scrollIntoView?.({ block: 'nearest' });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- optionId is derived from listId
  }, [active, listId]);

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center px-4 pt-[12vh]">
      <div
        className="absolute inset-0 bg-[#020617]/60 backdrop-blur-sm"
        aria-hidden
        onClick={onClose}
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label="Search"
        onKeyDown={onKeyDown}
        className="relative w-full max-w-2xl overflow-hidden rounded-xl border border-line bg-surface shadow-pop"
      >
        <div className="flex items-center gap-3 border-b border-line px-4">
          <Search className="size-5 shrink-0 text-fg-subtle" aria-hidden />
          <input
            ref={inputRef}
            type="text"
            role="combobox"
            aria-label="Search domains, subdomains, IPs, ports, software, CVEs and findings"
            aria-expanded={flat.length > 0}
            aria-controls={listId}
            aria-autocomplete="list"
            aria-activedescendant={flat.length > 0 ? optionId(active) : undefined}
            placeholder="Search domains, subdomains, IPs, ports, software, CVEs…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            maxLength={100}
            autoComplete="off"
            spellCheck={false}
            className="h-14 min-w-0 flex-1 bg-transparent text-base text-fg placeholder:text-fg-faint focus:outline-none"
          />
          {shown.status === 'loading' && (
            <Loader2 className="size-4 animate-spin text-fg-subtle" aria-hidden />
          )}
          <button
            type="button"
            onClick={onClose}
            className="rounded-md p-1 text-fg-subtle hover:bg-surface-3 hover:text-fg"
            aria-label="Close search"
          >
            <X className="size-4" aria-hidden />
          </button>
        </div>

        <div className="max-h-[60vh] overflow-y-auto p-2">
          <div role="status" aria-live="polite" className="sr-only">
            {shown.status === 'success' &&
              (flat.length === 0
                ? `No results for ${shown.q}`
                : `${flat.length} ${flat.length === 1 ? 'result' : 'results'}`)}
          </div>
          {shown.status === 'idle' && (
            <p className="px-3 py-6 text-center text-sm text-fg-subtle">
              Type at least {MIN_QUERY} characters. Try a hostname, an IP address, a port such as
              443, a product name or a CVE id.
            </p>
          )}
          {shown.status === 'loading' && (
            <p className="px-3 py-6 text-center text-sm text-fg-subtle">Searching…</p>
          )}
          {shown.status === 'error' && (
            <div
              role="alert"
              className="m-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900"
            >
              <p className="font-medium">Search is unavailable</p>
              <p>{errorMessage(shown.error)}</p>
            </div>
          )}
          {shown.status === 'success' && flat.length === 0 && (
            <p className="px-3 py-6 text-center text-sm text-fg-subtle">
              No results for “{shown.q}”.
            </p>
          )}
          <div id={listId} role="listbox" aria-label="Search results">
            {groups.map((g, gi) => (
              <div key={g.id} role="group" aria-labelledby={`${listId}-${g.id}`} className="py-1">
                <div
                  id={`${listId}-${g.id}`}
                  className="px-3 pt-2 pb-1 text-[11px] font-semibold uppercase tracking-wider text-fg-subtle"
                >
                  {g.label}
                </div>
                {g.items.map((item, ii) => {
                  const i = (starts[gi] ?? 0) + ii;
                  const selected = i === active;
                  return (
                    <div
                      key={item.key}
                      id={optionId(i)}
                      role="option"
                      aria-selected={selected}
                      onMouseMove={() => setActive(i)}
                      onClick={() => go(i)}
                      className={`flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2 text-sm ${
                        selected
                          ? 'bg-accent-soft text-fg ring-1 ring-inset ring-[#3b82f6]/40'
                          : 'text-fg-2'
                      }`}
                    >
                      {item.severity && <SeverityBadge severity={item.severity} />}
                      <span className="min-w-0 truncate font-medium">{item.label}</span>
                      {item.detail && (
                        <span className="ml-auto min-w-0 shrink truncate text-xs text-fg-subtle">
                          {item.detail}
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
        </div>
        <div className="flex items-center gap-4 border-t border-line bg-surface-2 px-4 py-2 text-[11px] text-fg-subtle">
          <span>
            <Kbd>↑</Kbd> <Kbd>↓</Kbd> to move
          </span>
          <span>
            <Kbd>Enter</Kbd> to open
          </span>
          <span>
            <Kbd>Esc</Kbd> to close
          </span>
        </div>
      </div>
    </div>
  );
}

export function Kbd({ children }: { children: string }) {
  return (
    <kbd className="rounded border border-line-strong bg-surface px-1.5 py-0.5 font-sans text-[10px] font-medium text-fg-muted">
      {children}
    </kbd>
  );
}
