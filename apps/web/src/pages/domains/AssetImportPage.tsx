import {
  ASSET_IMPORT_MAX_ENTRIES,
  ASSET_IMPORT_OUTCOMES,
  type AssetImportEntry,
  type AssetImportOutcome,
  type AssetImportResponse,
  type Domain,
  type ExtractedHosts,
} from '@exdomainvault/shared';
import { ArrowLeft, CheckCircle2, FileUp } from 'lucide-react';
import { useState, type ChangeEvent } from 'react';
import { Link, useParams } from 'react-router';
import { AssetStatusBadge, HostingHintChip } from '../../components/assets/AssetBadges.tsx';
import { Button } from '../../components/ui/Button.tsx';
import { Card } from '../../components/ui/Card.tsx';
import { ErrorAlert } from '../../components/ui/ErrorAlert.tsx';
import { PageHeader } from '../../components/ui/PageHeader.tsx';
import { PermissionDenied } from '../../components/ui/PermissionDenied.tsx';
import { api } from '../../lib/api.ts';
import { extractHostsFromFile, extractHostsFromText } from '../../lib/host-file.ts';
import { usePermission, useSession } from '../../lib/session.ts';
import { useAsync } from '../../lib/use-async.ts';

const OUTCOME_LABELS: Record<AssetImportOutcome, string> = {
  new: 'New',
  existing: 'Already an asset',
  duplicate: 'Duplicate',
  invalid: 'Invalid',
  out_of_domain: 'Outside this domain',
};

const OUTCOME_STYLES: Record<AssetImportOutcome, string> = {
  new: 'bg-sky-50 text-sky-800 ring-sky-600/20 dark:ring-sky-400/45',
  existing: 'bg-surface-3 text-fg-2 ring-slate-500/20 dark:ring-slate-500/40',
  duplicate: 'bg-surface-3 text-fg-muted ring-slate-500/20 dark:ring-slate-500/40',
  invalid: 'bg-red-50 text-red-800 ring-red-600/20 dark:ring-red-400/45',
  out_of_domain: 'bg-amber-50 text-amber-800 ring-amber-600/20 dark:ring-amber-400/45',
};

const SUMMARY_KEY: Record<AssetImportOutcome, keyof AssetImportResponse['summary']> = {
  new: 'new',
  existing: 'existing',
  duplicate: 'duplicate',
  invalid: 'invalid',
  out_of_domain: 'outOfDomain',
};

const FORMAT_LABELS: Record<ExtractedHosts['format'], string> = {
  records: 'a table of DNS records',
  zone: 'a DNS zone file',
  list: 'a list of hostnames',
};

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

function OutcomeBadge({ outcome }: { outcome: AssetImportOutcome }) {
  return (
    <span
      className={`inline-flex items-center whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${OUTCOME_STYLES[outcome]}`}
    >
      {OUTCOME_LABELS[outcome]}
    </span>
  );
}

/** Host import for one domain: route `domains/:id/import-hosts`. */
export function AssetImportPage() {
  const { id = '' } = useParams();
  const session = useSession();
  const canWrite = usePermission('domains:write');
  const domain = useAsync(
    (signal) =>
      canWrite ? api.domains.get(id, { signal }) : Promise.reject(new Error('not permitted')),
    [id, canWrite],
  );

  let body;
  if (session.status === 'loading' || (canWrite && domain.status === 'loading')) {
    body = (
      <p className="py-8 text-center text-sm text-fg-subtle" role="status">
        Loading…
      </p>
    );
  } else if (!canWrite) {
    body = (
      <PermissionDenied title="Importing hosts is not available to your role">
        Adding hostnames needs permission to manage domains. Ask an administrator if you need
        access.
      </PermissionDenied>
    );
  } else if (domain.status === 'error') {
    body = <ErrorAlert error={domain.error} title="Could not load this domain" />;
  } else if (domain.status === 'success') {
    body = <ImportFlow domain={domain.data.domain} />;
  }

  return (
    <>
      <Link
        to={`/domains/${id}`}
        className="mb-4 inline-flex items-center gap-1 text-sm text-fg-muted hover:text-fg"
      >
        <ArrowLeft className="size-4" aria-hidden />
        {domain.status === 'success' ? domain.data.domain.fqdn : 'Domain'}
      </Link>
      <PageHeader
        title="Import hosts"
        description="Add hostnames you already know about, for example from a DNS zone export. Certificate log discovery misses hosts covered by wildcard certificates; an import fills that gap. Nothing is saved until you confirm."
      />
      {body}
    </>
  );
}

interface Previewed {
  entries: AssetImportEntry[];
  fileName: string | undefined;
  response: AssetImportResponse;
}

function ImportFlow({ domain }: { domain: Domain }) {
  const [text, setText] = useState('');
  const [fileName, setFileName] = useState<string | null>(null);
  const [extracted, setExtracted] = useState<ExtractedHosts | null>(null);
  const [preview, setPreview] = useState<Previewed | null>(null);
  const [result, setResult] = useState<AssetImportResponse | null>(null);
  const [filter, setFilter] = useState<AssetImportOutcome | ''>('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const reset = () => {
    setExtracted(null);
    setPreview(null);
    setResult(null);
    setFilter('');
    setError(null);
  };

  const run = async (extract: () => Promise<ExtractedHosts>, name: string | undefined) => {
    reset();
    setBusy(true);
    try {
      const hosts = await extract();
      setExtracted(hosts);
      if (hosts.entries.length === 0) return;
      if (hosts.entries.length > ASSET_IMPORT_MAX_ENTRIES) {
        throw new Error(
          `The file contains ${hosts.entries.length} hostnames; at most ${ASSET_IMPORT_MAX_ENTRIES} can be imported at once. Split it into smaller files.`,
        );
      }
      const response = await api.domains.importAssets(domain.id, {
        entries: hosts.entries,
        dryRun: true,
        fileName: name,
      });
      setPreview({ entries: hosts.entries, fileName: name, response });
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setBusy(false);
    }
  };

  const onFile = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    setFileName(file.name);
    setText('');
    void run(() => extractHostsFromFile(file, domain.fqdn), file.name);
  };

  const onPastePreview = () => {
    setFileName(null);
    void run(() => Promise.resolve(extractHostsFromText(text, domain.fqdn)), undefined);
  };

  const confirm = async () => {
    if (!preview) return;
    setBusy(true);
    setError(null);
    try {
      setResult(
        await api.domains.importAssets(domain.id, {
          entries: preview.entries,
          dryRun: false,
          fileName: preview.fileName,
        }),
      );
      setPreview(null);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <Card title="1. Choose a file">
        <div className="space-y-3 text-sm text-fg-muted">
          <p>Accepted formats:</p>
          <ul className="list-disc space-y-1 pl-5">
            <li>
              A DNS records export as Excel (.xlsx) or CSV, with a header row naming the columns,
              for example <code className="font-mono">zoneName, name, type, ttl, data</code>. Only
              A, AAAA and CNAME records are used; names may be relative to{' '}
              <span className="font-mono">{domain.fqdn}</span>, and an empty name means the domain
              itself.
            </li>
            <li>A BIND zone file (.zone, .db or .txt).</li>
            <li>A plain list with one hostname per line.</li>
          </ul>
          <p>
            Files are read in your browser; only the hostnames (and CNAME targets) are sent. Up to{' '}
            {ASSET_IMPORT_MAX_ENTRIES} hostnames and 10 MB per file.
          </p>
          <label className="inline-flex cursor-pointer items-center gap-2 rounded-md border border-line-strong bg-surface px-3 py-1.5 font-medium text-fg-2 shadow-sm hover:bg-surface-2">
            <FileUp className="size-4" aria-hidden />
            {fileName ?? 'Choose file'}
            <input
              type="file"
              accept=".xlsx,.csv,.txt,.zone,.db,text/csv,text/plain"
              className="sr-only"
              onChange={onFile}
              disabled={busy}
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-fg-subtle">
              Or paste records, a zone file or a list of hostnames
            </span>
            <textarea
              value={text}
              onChange={(e) => {
                setFileName(null);
                setText(e.target.value);
                reset();
              }}
              rows={6}
              spellCheck={false}
              className="w-full rounded-md border border-line-strong p-2 font-mono text-xs shadow-sm"
            />
          </label>
          <Button variant="primary" onClick={onPastePreview} disabled={busy || text.trim() === ''}>
            Preview import
          </Button>
        </div>
      </Card>

      {extracted && <ExtractionSummary extracted={extracted} />}

      {busy && (
        <p className="text-sm text-fg-subtle" role="status">
          Checking hostnames…
        </p>
      )}

      {error && <ErrorAlert error={error} title="The hostnames could not be imported" />}

      {preview && (
        <PreviewCard
          preview={preview.response}
          filter={filter}
          onFilter={setFilter}
          busy={busy}
          onConfirm={() => void confirm()}
        />
      )}

      {result && <ResultCard result={result} domainId={domain.id} />}
    </div>
  );
}

function ExtractionSummary({ extracted }: { extracted: ExtractedHosts }) {
  const { skipped, entries, format } = extracted;
  const parts = [
    skipped.recordType > 0 &&
      `${plural(skipped.recordType, 'record')} that do not name a host (TXT, MX, NS, SRV and similar)`,
    skipped.serviceName > 0 &&
      `${plural(skipped.serviceName, 'service name')} (such as _dmarc or _domainkey)`,
    skipped.wildcard > 0 && plural(skipped.wildcard, 'wildcard'),
    skipped.empty > 0 && plural(skipped.empty, 'empty name'),
  ].filter((p): p is string => typeof p === 'string');
  return (
    <p className="text-sm text-fg-2" role="status">
      Read as {FORMAT_LABELS[format]}: found <strong>{plural(entries.length, 'hostname')}</strong>
      {parts.length > 0 ? `; skipped ${parts.join(', ')}.` : '.'}
      {entries.length === 0 && ' There is nothing to import from this file.'}
    </p>
  );
}

function PreviewCard({
  preview,
  filter,
  onFilter,
  busy,
  onConfirm,
}: {
  preview: AssetImportResponse;
  filter: AssetImportOutcome | '';
  onFilter: (f: AssetImportOutcome | '') => void;
  busy: boolean;
  onConfirm: () => void;
}) {
  const { summary } = preview;
  const rows = filter ? preview.rows.filter((r) => r.outcome === filter) : preview.rows;
  return (
    <Card title="2. Review and confirm">
      <p className="mb-3 text-sm text-fg-2">
        {plural(summary.total, 'hostname')}: <strong>{summary.new} new</strong>, {summary.existing}{' '}
        already assets, {summary.duplicate} duplicates, {summary.invalid} invalid,{' '}
        {summary.outOfDomain} outside this domain.
        {summary.thirdPartyHosted > 0 &&
          ` ${plural(summary.thirdPartyHosted, 'hostname appears', 'hostnames appear')} to be hosted by a third party.`}
      </p>
      <label className="mb-3 flex items-center gap-2 text-sm text-fg-2">
        Show
        <select
          value={filter}
          onChange={(e) => onFilter(e.target.value as AssetImportOutcome | '')}
          className="rounded-md border border-line-strong bg-surface px-2 py-1.5 text-sm text-fg-2 shadow-sm"
        >
          <option value="">All ({summary.total})</option>
          {ASSET_IMPORT_OUTCOMES.map((o) => (
            <option key={o} value={o}>
              {OUTCOME_LABELS[o]} ({summary[SUMMARY_KEY[o]]})
            </option>
          ))}
        </select>
      </label>
      <div className="max-h-96 overflow-auto">
        <table className="min-w-full text-sm">
          <thead className="sticky top-0 bg-surface">
            <tr className="border-b border-line text-left text-xs font-medium uppercase tracking-wide text-fg-subtle">
              <th scope="col" className="py-2 pr-3">
                Hostname
              </th>
              <th scope="col" className="py-2 pr-3">
                Result
              </th>
              <th scope="col" className="py-2">
                Hosting
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line-soft">
            {rows.map((r, i) => (
              <tr key={`${i}:${r.hostname}`}>
                <td className="break-all py-1.5 pr-3 font-mono text-xs">{r.hostname}</td>
                <td className="py-1.5 pr-3">
                  <span className="inline-flex flex-wrap items-center gap-1">
                    <OutcomeBadge outcome={r.outcome} />
                    {r.outcome === 'existing' && r.existingStatus && (
                      <AssetStatusBadge status={r.existingStatus} />
                    )}
                  </span>
                </td>
                <td className="py-1.5">
                  {r.hostingHint ? (
                    <HostingHintChip hint={r.hostingHint} />
                  ) : (
                    <span className="text-fg-faint">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && (
          <p className="py-3 text-sm text-fg-subtle">No hostnames with this result.</p>
        )}
      </div>
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <Button variant="primary" onClick={onConfirm} disabled={busy || summary.new === 0}>
          Add {plural(summary.new, 'host')} as pending
        </Button>
        <span className="text-sm text-fg-subtle">
          {summary.new === 0
            ? 'There is nothing new to add.'
            : 'They will wait for review: nothing is scanned until approved.'}
        </span>
      </div>
    </Card>
  );
}

function ResultCard({ result, domainId }: { result: AssetImportResponse; domainId: string }) {
  const { summary } = result;
  return (
    <Card title="Import complete">
      <p className="flex items-center gap-2 text-sm text-emerald-800" role="status">
        <CheckCircle2 className="size-4" aria-hidden />
        Added {plural(summary.new, 'hostname')} as pending
        {summary.existing > 0 &&
          `; ${summary.existing} were already assets and were left as they are`}
        .
      </p>
      <p className="mt-3 text-sm text-fg-muted">
        Imported hostnames are not scanned until they are approved on the Assets page. Hostnames
        hosted by a third party (a CDN, cloud or hosting provider) also need that hosting
        acknowledged when you approve them.
      </p>
      <Link
        to={`/assets?domainId=${encodeURIComponent(domainId)}&status=pending`}
        className="mt-3 inline-block text-sm text-sky-800 hover:underline"
      >
        Review pending hostnames
      </Link>
    </Card>
  );
}
