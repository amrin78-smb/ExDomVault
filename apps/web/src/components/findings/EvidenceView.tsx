import { ExternalLink, Layers, Skull } from 'lucide-react';
import { formatDate } from '../../lib/format.ts';
import { isCveId, isVersionRange, nvdUrl, rangeText } from '../software/software-format.ts';

/**
 * Renders the evidence a rule recorded. Scalars and short lists read as key/value pairs; nested
 * structures are shown as formatted JSON so nothing is hidden or reinterpreted. A few shapes get a
 * readable form (all rendered as text, never HTML): CVE identifiers link to NVD, NVD affected
 * version ranges read as words, and CVE advisories (objects with a `cveId`) show their CVSS, KEV
 * date and ransomware use. A distribution named in the evidence adds a backport note.
 */
export function EvidenceView({ evidence }: { evidence: Record<string, unknown> }) {
  const entries = Object.entries(evidence);
  if (entries.length === 0) {
    return <p className="text-sm text-fg-subtle">The rule recorded no evidence fields.</p>;
  }
  const distribution = backportDistribution(evidence);
  return (
    <>
      {distribution && (
        <p
          role="note"
          className="mb-2 flex gap-2 rounded-md border border-line bg-surface-2 px-3 py-2 text-sm text-fg-2"
        >
          <Layers className="mt-0.5 size-4 shrink-0" aria-hidden />
          <span>
            The banner names a {distribution} build. Distributions often backport security fixes
            without changing the version number, so this host may already be patched: verify with
            the package manager.
          </span>
        </p>
      )}
      <EvidenceList entries={entries} />
    </>
  );
}

function EvidenceList({
  entries,
  nested = false,
}: {
  entries: [string, unknown][];
  nested?: boolean;
}) {
  return (
    <dl className="divide-y divide-line-soft text-sm" data-testid={nested ? undefined : 'evidence'}>
      {entries.map(([key, value]) => (
        <div key={key} className="grid gap-1 py-2 sm:grid-cols-[12rem_1fr] sm:gap-3">
          <dt className="font-medium text-fg-muted">{humanise(key)}</dt>
          <dd className="min-w-0 text-fg">
            <EvidenceValue value={value} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

function EvidenceValue({ value }: { value: unknown }) {
  if (value === null || value === undefined) return <span className="text-fg-faint">None</span>;
  if (isCveId(value)) return <CveLink cveId={value} />;
  if (isVersionRange(value)) return <span className="text-xs">{rangeText(value)}</span>;
  if (Array.isArray(value) && value.length > 0 && value.every(isVersionRange)) {
    return (
      <ul className="space-y-0.5 text-xs">
        {value.map((r, i) => (
          <li key={i}>{rangeText(r)}</li>
        ))}
      </ul>
    );
  }
  if (isAdvisory(value)) return <Advisory advisory={value} />;
  if (Array.isArray(value) && value.length > 0 && value.every(isAdvisory)) {
    return (
      <ul className="space-y-2">
        {value.map((a, i) => (
          <li key={`${a.cveId}-${i}`}>
            <Advisory advisory={a} />
          </li>
        ))}
      </ul>
    );
  }
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return <span className="break-all font-mono text-xs">{String(value)}</span>;
  }
  if (Array.isArray(value) && value.every((v) => typeof v === 'string' || typeof v === 'number')) {
    if (value.length === 0) return <span className="text-fg-faint">None</span>;
    return (
      <ul className="space-y-0.5">
        {value.map((v, i) => (
          <li key={i} className="break-all font-mono text-xs">
            {isCveId(v) ? <CveLink cveId={v} /> : String(v)}
          </li>
        ))}
      </ul>
    );
  }
  return (
    <pre className="overflow-x-auto rounded bg-surface-2 p-2 font-mono text-xs text-fg">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

/** `notAfter` / `days_remaining` → "Not after" / "Days remaining". */
function humanise(key: string): string {
  const spaced = key
    .replace(/[_-]+/g, ' ')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .trim();
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

function CveLink({ cveId }: { cveId: string }) {
  return (
    <a
      href={nvdUrl(cveId)}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-0.5 font-mono text-xs text-sky-800 hover:underline"
    >
      {cveId}
      <ExternalLink className="size-3" aria-hidden />
      <span className="sr-only"> (NVD, opens in a new tab)</span>
    </a>
  );
}

type AdvisoryEvidence = Record<string, unknown> & { cveId: string };

const isAdvisory = (value: unknown): value is AdvisoryEvidence =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  isCveId((value as Record<string, unknown>).cveId);

const ADVISORY_KEYS = new Set(['cveId', 'title', 'cvss', 'kev', 'kevDateAdded', 'ransomware']);

/** A CVE the evidence matched: link, title, CVSS, KEV date added, ransomware use, other fields. */
function Advisory({ advisory }: { advisory: AdvisoryEvidence }) {
  const { title, cvss, kevDateAdded, ransomware } = advisory;
  const rest = Object.entries(advisory).filter(([k]) => !ADVISORY_KEYS.has(k));
  return (
    <div className="rounded-md border border-line p-2">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <CveLink cveId={advisory.cveId} />
        {typeof cvss === 'number' && <span className="text-xs">CVSS {cvss.toFixed(1)}</span>}
        {typeof kevDateAdded === 'string' && (
          <span className="text-xs">
            Added to CISA KEV{' '}
            {/^\d{4}-\d{2}-\d{2}/.test(kevDateAdded) ? formatDate(kevDateAdded) : kevDateAdded}
          </span>
        )}
        {ransomware === true && (
          <span className="inline-flex items-center gap-0.5 text-xs font-medium">
            <Skull className="size-3" aria-hidden />
            Known ransomware use
          </span>
        )}
      </div>
      {typeof title === 'string' && <p className="mt-1 text-xs text-fg-2">{title}</p>}
      {rest.length > 0 && (
        <div className="mt-1">
          <EvidenceList entries={rest} nested />
        </div>
      )}
    </div>
  );
}

/** `backportDistribution: 'Ubuntu'` or `backportHint: { distribution: 'Ubuntu' }`. */
function backportDistribution(evidence: Record<string, unknown>): string | null {
  const direct = evidence.backportDistribution;
  if (typeof direct === 'string' && direct) return direct;
  const hint = evidence.backportHint;
  if (typeof hint === 'object' && hint !== null && 'distribution' in hint) {
    const d = (hint as { distribution: unknown }).distribution;
    if (typeof d === 'string' && d) return d;
  }
  return null;
}
