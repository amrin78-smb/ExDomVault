import type { SoftwareItem } from '@exdomainvault/shared';
import { CalendarX2, CheckCircle2, ExternalLink, Layers, Skull } from 'lucide-react';
import { formatDate } from '../../lib/format.ts';
import { nvdUrl } from './software-format.ts';

/**
 * End-of-life state of the version's release cycle. Text always states the condition; colour and
 * icon only reinforce it.
 */
export function EolBadge({ eol }: { eol: SoftwareItem['eol'] }) {
  if (!eol) {
    return <span className="text-xs text-fg-faint">No end-of-life data</span>;
  }
  if (eol.isEol) {
    return (
      <span className="inline-flex items-center gap-1 whitespace-nowrap rounded bg-amber-50 px-1.5 py-0.5 text-xs font-medium text-amber-900 ring-1 ring-inset ring-amber-600/30 dark:ring-amber-400/45">
        <CalendarX2 className="size-3.5" aria-hidden />
        End of life{eol.eolDate ? ` since ${formatDate(eol.eolDate)}` : ''}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 whitespace-nowrap text-xs text-fg-2">
      <CheckCircle2 className="size-3.5 text-emerald-700" aria-hidden />
      Supported{eol.eolDate ? ` until ${formatDate(eol.eolDate)}` : ''}
    </span>
  );
}

/** Cycle detail shown under the badge in the full table. */
export function EolDetail({ eol }: { eol: SoftwareItem['eol'] }) {
  if (!eol) return null;
  return (
    <div className="mt-0.5 text-xs text-fg-subtle">
      Cycle {eol.cycle}
      {eol.latestInCycle ? ` · latest ${eol.latestInCycle}` : ''}
    </div>
  );
}

/** Known-exploited CVEs whose affected range includes the version, each linking to NVD. */
export function KevChips({ items }: { items: SoftwareItem['knownExploited'] }) {
  if (items.length === 0) {
    return <span className="text-xs text-fg-faint">None matched</span>;
  }
  return (
    <ul className="flex flex-wrap gap-1" aria-label="Possibly affected by known-exploited CVEs">
      {items.map((k) => (
        <li
          key={k.cveId}
          className="inline-flex items-center gap-1 whitespace-nowrap rounded bg-orange-50 px-1.5 py-0.5 text-xs text-orange-950 ring-1 ring-inset ring-orange-600/25 dark:ring-orange-400/45"
        >
          <a
            href={nvdUrl(k.cveId)}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-0.5 font-mono font-medium underline-offset-2 hover:underline"
          >
            {k.cveId}
            <ExternalLink className="size-3" aria-hidden />
            <span className="sr-only"> (NVD, opens in a new tab)</span>
          </a>
          {k.cvss !== null && <span>CVSS {k.cvss.toFixed(1)}</span>}
          {k.ransomware && (
            <span className="inline-flex items-center gap-0.5 font-medium">
              <Skull className="size-3" aria-hidden />
              Ransomware
            </span>
          )}
        </li>
      ))}
    </ul>
  );
}

/** The disclosed version, or "hidden" (unknown, never "safe"). */
export function VersionText({ version }: { version: string | null }) {
  if (version === null) {
    return (
      <span
        className="text-xs italic text-fg-subtle"
        title="Version not disclosed: unknown, not safe"
      >
        hidden
      </span>
    );
  }
  return <span className="break-all font-mono text-xs text-fg">{version}</span>;
}

/** Distribution builds often carry backported fixes under the original version number. */
export function BackportHint({ hint }: { hint: SoftwareItem['backportHint'] }) {
  if (!hint) return null;
  return (
    <div className="mt-0.5 inline-flex items-center gap-1 text-xs text-fg-muted">
      <Layers className="size-3" aria-hidden />
      {hint.distribution} build: fixes may be backported
    </div>
  );
}
