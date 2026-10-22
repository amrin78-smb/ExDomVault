/**
 * Renders the evidence a rule recorded. Scalars and short lists read as key/value pairs; nested
 * structures are shown as formatted JSON so nothing is hidden or reinterpreted.
 */
export function EvidenceView({ evidence }: { evidence: Record<string, unknown> }) {
  const entries = Object.entries(evidence);
  if (entries.length === 0) {
    return <p className="text-sm text-slate-500">The rule recorded no evidence fields.</p>;
  }
  return (
    <dl className="divide-y divide-slate-100 text-sm" data-testid="evidence">
      {entries.map(([key, value]) => (
        <div key={key} className="grid gap-1 py-2 sm:grid-cols-[12rem_1fr] sm:gap-3">
          <dt className="font-medium text-slate-600">{humanise(key)}</dt>
          <dd className="min-w-0 text-slate-800">
            <EvidenceValue value={value} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

function EvidenceValue({ value }: { value: unknown }) {
  if (value === null || value === undefined) return <span className="text-slate-400">None</span>;
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return <span className="break-all font-mono text-xs">{String(value)}</span>;
  }
  if (Array.isArray(value) && value.every((v) => typeof v === 'string' || typeof v === 'number')) {
    if (value.length === 0) return <span className="text-slate-400">None</span>;
    return (
      <ul className="space-y-0.5">
        {value.map((v, i) => (
          <li key={i} className="break-all font-mono text-xs">
            {String(v)}
          </li>
        ))}
      </ul>
    );
  }
  return (
    <pre className="overflow-x-auto rounded bg-slate-50 p-2 font-mono text-xs text-slate-800">
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
