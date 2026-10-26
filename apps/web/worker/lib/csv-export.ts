/**
 * Shared CSV writer for the downloadable exports (`GET /reports/findings.csv`,
 * `GET /exports/<resource>.csv`): RFC 4180 quoting, CRLF line endings, a UTF-8 BOM so spreadsheet
 * applications decode non-ASCII text correctly, and formula-injection protection.
 */

/** Byte order mark written at the start of every CSV body. */
export const UTF8_BOM = '﻿';

/** A cell value before encoding: lists are joined with `; `, dates become ISO 8601 UTC. */
export type CsvValue = string | number | boolean | Date | readonly string[] | null | undefined;

/** Characters that make spreadsheet applications treat a cell as a formula. */
const FORMULA_START = /^[=+\-@\t\r]/;

/** Separator for lists inside one cell (IPs, CVEs, actions). */
export const CSV_LIST_SEPARATOR = '; ';

function cellText(value: CsvValue): string {
  if (value === null || value === undefined) return '';
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) return value.join(CSV_LIST_SEPARATOR);
  return String(value);
}

/**
 * One CSV cell: formula-like values are prefixed with `'`, then RFC 4180 quoting applies. Finite
 * numbers are written as-is (a negative number such as `days_left = -2` is data, not a formula,
 * and stays numeric in a spreadsheet); strings, including numeric-looking ones, are always checked.
 */
export function csvCell(value: CsvValue): string {
  let s = cellText(value);
  const numeric = typeof value === 'number' && Number.isFinite(value);
  if (!numeric && FORMULA_START.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** One CSV record terminated by CRLF. */
export const csvLine = (cells: readonly CsvValue[]) => `${cells.map(csvCell).join(',')}\r\n`;

/** A whole CSV document: BOM, header line, then one line per row. */
export function toCsv(columns: readonly string[], rows: readonly (readonly CsvValue[])[]): string {
  const parts = [UTF8_BOM, csvLine(columns)];
  for (const r of rows) parts.push(csvLine(r));
  return parts.join('');
}

/** `YYYYMMDD` (UTC) for export file names. */
export const exportStamp = (now: Date) => now.toISOString().slice(0, 10).replace(/-/g, '');

/** The query as recorded in the audit log: parameters that were not given are dropped. */
export function auditFilters(q: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(q).filter(([, v]) => v !== undefined));
}

/** Response headers of a CSV download. */
export function csvHeaders(args: {
  filename: string;
  truncated: boolean;
  totalRows?: number;
}): Record<string, string> {
  return {
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': `attachment; filename="${args.filename}"`,
    ...(args.truncated ? { 'X-Truncated': 'true' } : {}),
    ...(args.totalRows !== undefined ? { 'X-Total-Rows': String(args.totalRows) } : {}),
  };
}
