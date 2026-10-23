import { REPORT_CSV_MAX_ROWS } from '@exdomainvault/shared';
import { Download } from 'lucide-react';
import { useState } from 'react';
import { api } from '../../lib/api.ts';
import { usePermission } from '../../lib/session.ts';
import { Button } from '../ui/Button.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';

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

/**
 * "Export findings (CSV)" for users with `reports:generate`; hidden otherwise (the API enforces it).
 * `filters` are the Findings-page filters (same names as `GET /findings`); paging is ignored.
 */
export function ExportFindingsButton({
  filters = {},
  label = 'Export findings (CSV)',
}: {
  filters?: Record<string, string | undefined>;
  label?: string;
}) {
  const allowed = usePermission('reports:generate');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [notice, setNotice] = useState<{ text: string; warn: boolean } | null>(null);
  if (!allowed) return null;

  const onExport = async () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const file = await api.reports.findingsCsv(filters);
      saveBlob(file.blob, file.filename);
      setNotice(
        file.truncated
          ? {
              text: `Exported the first ${REPORT_CSV_MAX_ROWS.toLocaleString()} matching findings (the export limit). Narrow the filters to export the rest.`,
              warn: true,
            }
          : { text: 'Export downloaded.', warn: false },
      );
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col items-end gap-2">
      <Button onClick={() => void onExport()} disabled={busy}>
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
