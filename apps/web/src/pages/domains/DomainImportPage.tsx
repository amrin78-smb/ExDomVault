import {
  CRITICALITY_LABELS,
  IMPORT_MAX_BYTES,
  IMPORT_MAX_ROWS,
  type ImportConfirmResponse,
  type ImportPreviewResponse,
  type ImportRowStatus,
} from '@exdomainvault/shared';
import { ArrowLeft, CheckCircle2, FileUp } from 'lucide-react';
import { useState, type ChangeEvent } from 'react';
import { Link } from 'react-router';
import { Button } from '../../components/ui/Button.tsx';
import { Card } from '../../components/ui/Card.tsx';
import { ErrorAlert } from '../../components/ui/ErrorAlert.tsx';
import { PageHeader } from '../../components/ui/PageHeader.tsx';
import { api } from '../../lib/api.ts';

const STATUS_TEXT: Record<ImportRowStatus, { label: string; cls: string }> = {
  valid: { label: 'Will be added', cls: 'text-emerald-800' },
  invalid: { label: 'Invalid', cls: 'text-red-800' },
  duplicate_in_file: { label: 'Duplicate in file', cls: 'text-slate-600' },
  already_registered: { label: 'Already registered', cls: 'text-slate-600' },
};

const EXAMPLE =
  'domain,criticality,business_owner\nexample.com,high,Platform team\nexample.org,,\n';

/** Upload → server-side validation preview → explicit confirmation → import. */
export function DomainImportPage() {
  const [csv, setCsv] = useState('');
  const [fileName, setFileName] = useState<string | null>(null);
  const [preview, setPreview] = useState<ImportPreviewResponse | null>(null);
  const [result, setResult] = useState<ImportConfirmResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const reset = (text: string) => {
    setCsv(text);
    setPreview(null);
    setResult(null);
    setError(null);
  };

  const onFile = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > IMPORT_MAX_BYTES) {
      reset('');
      setError(new Error('The file is larger than 256 KB. Split it into smaller files.'));
      return;
    }
    setFileName(file.name);
    reset(await file.text());
  };

  const act = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setBusy(false);
    }
  };

  const runPreview = () => act(async () => setPreview(await api.domains.previewImport(csv)));
  const confirm = () =>
    act(async () => {
      if (!preview) return;
      setResult(await api.domains.confirmImport(csv, preview.digest));
      setPreview(null);
    });

  return (
    <>
      <Link
        to="/domains"
        className="mb-4 inline-flex items-center gap-1 text-sm text-slate-600 hover:text-slate-900"
      >
        <ArrowLeft className="size-4" aria-hidden />
        Domains
      </Link>
      <PageHeader
        title="Import domains"
        description="Upload a CSV, review the validation results, then confirm. Nothing is saved until you confirm."
      />

      <div className="space-y-4">
        <Card title="1. Choose a file">
          <div className="space-y-3 text-sm text-slate-600">
            <p>
              A header row is required. Columns: <code className="font-mono">domain</code>{' '}
              (required), <code className="font-mono">criticality</code> (low, medium, high or
              critical; default medium) and <code className="font-mono">business_owner</code>. Up to{' '}
              {IMPORT_MAX_ROWS} rows, 256 KB.
            </p>
            <pre className="overflow-x-auto rounded bg-slate-100 p-2 font-mono text-xs text-slate-700">
              {EXAMPLE}
            </pre>
            <label className="inline-flex cursor-pointer items-center gap-2 rounded-md border border-slate-300 bg-white px-3 py-1.5 font-medium text-slate-700 shadow-sm hover:bg-slate-50">
              <FileUp className="size-4" aria-hidden />
              {fileName ?? 'Choose CSV file'}
              <input type="file" accept=".csv,text/csv" className="sr-only" onChange={onFile} />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-slate-500">
                Or paste CSV text
              </span>
              <textarea
                value={csv}
                onChange={(e) => {
                  setFileName(null);
                  reset(e.target.value);
                }}
                rows={6}
                spellCheck={false}
                className="w-full rounded-md border border-slate-300 p-2 font-mono text-xs shadow-sm"
              />
            </label>
            <Button variant="primary" onClick={runPreview} disabled={busy || csv.trim() === ''}>
              Preview import
            </Button>
          </div>
        </Card>

        {error && <ErrorAlert error={error} />}

        {preview && <PreviewCard preview={preview} busy={busy} onConfirm={confirm} />}

        {result && (
          <Card title="Import complete">
            <p className="flex items-center gap-2 text-sm text-emerald-800" role="status">
              <CheckCircle2 className="size-4" aria-hidden />
              Added {result.created.length} domain{result.created.length === 1 ? '' : 's'}
              {result.skipped > 0 &&
                `; skipped ${result.skipped} row${result.skipped === 1 ? '' : 's'}`}
              .
            </p>
            {result.created.length > 0 && (
              <ul className="mt-3 space-y-1 text-sm">
                {result.created.map((d) => (
                  <li key={d.id}>
                    <Link
                      to={`/domains/${d.id}`}
                      className="font-mono text-sky-800 hover:underline"
                    >
                      {d.fqdn}
                    </Link>
                  </li>
                ))}
              </ul>
            )}
            <p className="mt-3 text-xs text-slate-500">
              Imported domains are unverified. Verify each one before enabling monitoring.
            </p>
          </Card>
        )}
      </div>
    </>
  );
}

function PreviewCard({
  preview,
  busy,
  onConfirm,
}: {
  preview: ImportPreviewResponse;
  busy: boolean;
  onConfirm: () => void;
}) {
  const { summary } = preview;
  return (
    <Card title="2. Review and confirm">
      {preview.fileErrors.length > 0 ? (
        <div
          role="alert"
          className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800"
        >
          <p className="font-medium">This file cannot be imported</p>
          <ul className="mt-1 list-disc pl-4">
            {preview.fileErrors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        </div>
      ) : (
        <>
          <p className="mb-3 text-sm text-slate-700">
            {summary.total} row{summary.total === 1 ? '' : 's'}:{' '}
            <strong>{summary.valid} to add</strong>, {summary.invalid} invalid,{' '}
            {summary.duplicateInFile} duplicated in the file, {summary.alreadyRegistered} already
            registered.
          </p>
          <div className="max-h-96 overflow-auto">
            <table className="min-w-full text-sm">
              <thead className="sticky top-0 bg-white">
                <tr className="border-b border-slate-200 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
                  <th scope="col" className="py-2 pr-3">
                    Line
                  </th>
                  <th scope="col" className="py-2 pr-3">
                    Domain
                  </th>
                  <th scope="col" className="py-2 pr-3">
                    Criticality
                  </th>
                  <th scope="col" className="py-2 pr-3">
                    Owner
                  </th>
                  <th scope="col" className="py-2">
                    Result
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {preview.rows.map((r) => (
                  <tr key={r.line}>
                    <td className="py-1.5 pr-3 tabular-nums text-slate-500">{r.line}</td>
                    <td className="py-1.5 pr-3 font-mono text-xs">
                      {r.fqdn ?? <span className="text-slate-500">{r.input || '(empty)'}</span>}
                      {r.warnings.includes('mixed_script') && (
                        <span className="ml-2 text-amber-700">mixed scripts</span>
                      )}
                    </td>
                    <td className="py-1.5 pr-3">
                      {r.criticality ? CRITICALITY_LABELS[r.criticality] : '—'}
                    </td>
                    <td className="py-1.5 pr-3">{r.businessOwner ?? '—'}</td>
                    <td className={`py-1.5 ${STATUS_TEXT[r.status].cls}`}>
                      {STATUS_TEXT[r.status].label}
                      {r.errors.length > 0 && (
                        <ul className="text-xs">
                          {r.errors.map((e) => (
                            <li key={e}>{e}</li>
                          ))}
                        </ul>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-4 flex items-center gap-3">
            <Button variant="primary" onClick={onConfirm} disabled={busy || summary.valid === 0}>
              Import {summary.valid} domain{summary.valid === 1 ? '' : 's'}
            </Button>
            {summary.valid === 0 && (
              <span className="text-sm text-slate-500">There is nothing to import.</span>
            )}
          </div>
        </>
      )}
    </Card>
  );
}
