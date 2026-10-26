import { useState } from 'react';
import { Link } from 'react-router';

const SHOWN = 3;

/** Hostnames as chips linking to their asset pages; past three, a "+N more" toggle. */
export function HostnameChips({
  hostnames,
}: {
  hostnames: readonly { assetId: string; hostname: string }[];
}) {
  const [expanded, setExpanded] = useState(false);
  if (hostnames.length === 0) return <span className="text-xs text-fg-faint">None current</span>;
  const shown = expanded ? hostnames : hostnames.slice(0, SHOWN);
  const hidden = hostnames.length - shown.length;
  return (
    <ul className="flex max-w-72 flex-wrap gap-1">
      {shown.map((h) => (
        <li key={h.assetId}>
          <Link
            to={`/assets/${h.assetId}`}
            className="inline-block max-w-64 truncate rounded-md border border-line bg-surface-2 px-1.5 py-0.5 font-mono text-xs text-fg-2 hover:border-accent hover:text-fg"
          >
            {h.hostname}
          </Link>
        </li>
      ))}
      {(hidden > 0 || expanded) && hostnames.length > SHOWN && (
        <li>
          <button
            type="button"
            onClick={() => setExpanded((e) => !e)}
            aria-expanded={expanded}
            className="rounded-md px-1.5 py-0.5 text-xs text-sky-800 hover:underline"
          >
            {expanded ? 'Show fewer' : `+${hidden} more`}
          </button>
        </li>
      )}
    </ul>
  );
}
