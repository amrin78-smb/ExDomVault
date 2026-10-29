import { CHANGE_KIND_LABELS, type ChangeEvent, type ChangeImportance } from '@exdomainvault/shared';
import { ChevronRight } from 'lucide-react';
import { useId, useState } from 'react';
import { Link } from 'react-router';
import { KIND_ICONS } from './kind-icons.ts';
import { IMPORTANCE_LABELS, dayKey, dayLabel, diffLines, timeLabel } from './format.ts';

const pill =
  'inline-flex items-center whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset';
const IMPORTANCE_STYLES: Record<ChangeImportance, string> = {
  important: 'bg-violet-50 text-violet-800 ring-violet-600/25',
  notable: 'bg-sky-50 text-sky-800 ring-sky-600/25',
  info: 'bg-surface-3 text-fg-2 ring-line-strong',
};

/** How noteworthy a change is (a display hint, not a finding severity). */
export function ImportanceChip({ importance }: { importance: ChangeImportance }) {
  return (
    <span className={`${pill} ${IMPORTANCE_STYLES[importance]}`} data-importance={importance}>
      {IMPORTANCE_LABELS[importance]}
    </span>
  );
}

/** Before/after as a line diff: removed lines red with "−", added green with "+". */
export function ChangeDiff({ before, after }: { before: unknown; after: unknown }) {
  const lines = diffLines(before, after);
  if (lines.length === 0) return <p className="text-xs text-fg-subtle">No details recorded.</p>;
  return (
    <ul
      className="overflow-x-auto rounded-lg border border-line bg-surface-2 py-1 font-mono text-xs"
      aria-label="Differences"
    >
      {lines.map((l, i) => (
        <li
          key={`${l.op}-${i}`}
          className={`whitespace-pre-wrap break-all px-3 py-0.5 ${
            l.op === 'added'
              ? 'bg-emerald-50 text-emerald-800'
              : l.op === 'removed'
                ? 'bg-red-50 text-red-800'
                : 'text-fg-muted'
          }`}
        >
          <span aria-hidden className="mr-2 select-none">
            {l.op === 'added' ? '+' : l.op === 'removed' ? '−' : ' '}
          </span>
          <span className="sr-only">
            {l.op === 'added' ? 'Added: ' : l.op === 'removed' ? 'Removed: ' : 'Unchanged: '}
          </span>
          {l.text}
        </li>
      ))}
    </ul>
  );
}

const linkClass = 'font-mono text-sky-800 hover:underline';

function ChangeRow({ event, showDomain }: { event: ChangeEvent; showDomain: boolean }) {
  const [open, setOpen] = useState(false);
  const detailId = useId();
  const Icon = KIND_ICONS[event.kind];
  const hasDiff = event.before !== null || event.after !== null;
  return (
    <li className="flex gap-3 py-2.5">
      <span
        className="mt-0.5 grid size-7 shrink-0 place-items-center rounded-full border border-line bg-surface-2"
        title={CHANGE_KIND_LABELS[event.kind]}
      >
        <Icon className="size-3.5 text-fg-subtle" aria-hidden />
        <span className="sr-only">{CHANGE_KIND_LABELS[event.kind]}</span>
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-start justify-between gap-x-3 gap-y-1">
          <p className="min-w-0 break-words text-sm text-fg">{event.summary}</p>
          <ImportanceChip importance={event.severityHint} />
        </div>
        <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-fg-subtle">
          <time dateTime={event.at}>{timeLabel(event.at)}</time>
          {event.hostname &&
            (event.assetId ? (
              <Link to={`/assets/${event.assetId}`} className={linkClass}>
                {event.hostname}
              </Link>
            ) : (
              <span className="font-mono">{event.hostname}</span>
            ))}
          {showDomain && (
            <Link to={`/domains/${event.domain.id}`} className={linkClass}>
              {event.domain.fqdn}
            </Link>
          )}
          {hasDiff && (
            <button
              type="button"
              onClick={() => setOpen((o) => !o)}
              aria-expanded={open}
              aria-controls={detailId}
              className="inline-flex items-center gap-0.5 rounded text-fg-muted hover:text-fg"
            >
              <ChevronRight
                className={`size-3.5 transition-transform ${open ? 'rotate-90' : ''}`}
                aria-hidden
              />
              {open ? 'Hide details' : 'Show details'}
            </button>
          )}
        </div>
        {hasDiff && (
          <div id={detailId} hidden={!open} className="mt-2">
            {open && <ChangeDiff before={event.before} after={event.after} />}
          </div>
        )}
      </div>
    </li>
  );
}

/** Change events grouped by UTC day, newest first (the API's order). */
export function ChangeTimeline({
  items,
  showDomain = true,
}: {
  items: readonly ChangeEvent[];
  /** Link each event's domain (off inside a single domain's page). */
  showDomain?: boolean;
}) {
  const groups: { key: string; label: string; items: ChangeEvent[] }[] = [];
  for (const e of items) {
    const key = dayKey(e.at);
    const last = groups.at(-1);
    if (last?.key === key) last.items.push(e);
    else groups.push({ key, label: dayLabel(e.at), items: [e] });
  }
  return (
    <div className="space-y-4">
      {groups.map((g) => (
        <section key={g.key} aria-label={g.label}>
          <h3 className="sticky top-0 border-b border-line bg-surface pb-1 text-xs font-semibold uppercase tracking-wide text-fg-subtle">
            {g.label}
          </h3>
          <ol className="divide-y divide-line-soft">
            {g.items.map((e) => (
              <ChangeRow key={e.id} event={e} showDomain={showDomain} />
            ))}
          </ol>
        </section>
      ))}
    </div>
  );
}
