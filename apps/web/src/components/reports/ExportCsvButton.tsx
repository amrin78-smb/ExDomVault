import type { ExportResource, Permission } from '@exdomainvault/shared';
import { Download } from 'lucide-react';
import { useState } from 'react';
import { api, type CsvDownload } from '../../lib/api.ts';
import { usePermission } from '../../lib/session.ts';
import { Button } from '../ui/Button.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';

/** Every CSV export: the list exports plus findings (`GET /reports/findings.csv`). */
export type CsvExportTarget = ExportResource | 'findings';

/** The permission the server requires for each export (the list's read permission). */
const EXPORT_PERMISSION: Record<CsvExportTarget, Permission> = {
  findings: 'reports:generate',
  domains: 'domains:read',
  assets: 'assets:read',
  advisories: 'findings:read',
  software: 'findings:read',
  scans: 'scans:read',
  users: 'users:manage',
  'audit-logs': 'audit:read',
};

const EXPORT_NOUN: Record<CsvExportTarget, string> = {
  findings: 'findings',
  domains: 'domains',
  assets: 'assets',
  advisories: 'advisories',
  software: 'software',
  scans: 'scans',
  users: 'users',
  'audit-logs': 'audit log',
};

/** Paging never applies to an export: the server ignores it, and the client never sends it. */
const PAGING_KEYS = new Set(['page', 'pageSize']);

type Filters = Record<string, string | number | undefined>;

/** Hands a downloaded file to the browser as a save. */
function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

const plural = (n: number) => `${n.toLocaleString()} row${n === 1 ? '' : 's'}`;

/** The status line after a download. */
function exportNotice(file: CsvDownload): { text: string; warn: boolean } {
  if (file.truncated) {
    const of = file.totalRows !== null ? ` of ${file.totalRows.toLocaleString()}` : ' matching';
    return {
      text: `Exported the first ${file.rows.toLocaleString()}${of} rows (the export limit). Narrow the filters to export the rest.`,
      warn: true,
    };
  }
  return { text: `Exported ${plural(file.totalRows ?? file.rows)}.`, warn: false };
}

/**
 * "Export <list> (CSV)" for users with the export's permission; hidden otherwise (the API enforces
 * it too). `filters` are the list's current query (the same object the page sends to the list
 * endpoint, so defaults match); `page` and `pageSize` are dropped.
 */
export function ExportCsvButton({
  resource,
  filters = {},
  label = `Export ${EXPORT_NOUN[resource]} (CSV)`,
}: {
  resource: CsvExportTarget;
  filters?: Filters;
  label?: string;
}) {
  const allowed = usePermission(EXPORT_PERMISSION[resource]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [notice, setNotice] = useState<{ text: string; warn: boolean } | null>(null);
  if (!allowed) return null;

  const onExport = async () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    const params = Object.fromEntries(
      Object.entries(filters).filter(([k, v]) => !PAGING_KEYS.has(k) && v !== undefined),
    );
    try {
      const file =
        resource === 'findings'
          ? await api.reports.findingsCsv(params)
          : await api.exports.csv(resource, params);
      saveBlob(file.blob, file.filename);
      setNotice(exportNotice(file));
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col items-end gap-2">
      <Button onClick={() => void onExport()} disabled={busy} aria-busy={busy}>
        <Download className="size-4" aria-hidden />
        {busy ? 'Exporting…' : label}
      </Button>
      <div aria-live="polite" className="max-w-sm text-right">
        {notice && (
          <p
            role="status"
            className={`text-xs ${notice.warn ? 'text-amber-800' : 'text-slate-600'}`}
          >
            {notice.text}
          </p>
        )}
      </div>
      {error && <ErrorAlert error={error} title="Export failed" />}
    </div>
  );
}
