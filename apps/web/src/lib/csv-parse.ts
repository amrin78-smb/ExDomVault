export class CsvParseError extends Error {
  override name = 'CsvParseError';
}

/** The separator of the first line: the most frequent of comma, semicolon and tab (comma on a tie). */
function detectDelimiter(text: string): string {
  const firstLine = text.split(/\r?\n/, 1)[0] ?? '';
  let best = ',';
  let bestCount = 0;
  for (const d of [',', ';', '\t']) {
    const count = firstLine.split(d).length - 1;
    if (count > bestCount) {
      best = d;
      bestCount = count;
    }
  }
  return best;
}

/**
 * Small RFC 4180 parser for files read in the browser: double-quoted fields with `""` escapes,
 * CRLF or LF line endings, optional UTF-8 BOM, separator detected from the first line (comma,
 * semicolon or tab). Blank lines are skipped. Throws CsvParseError on an unterminated quote or
 * when there are more than `maxRows` rows.
 */
export function parseCsvRows(text: string, maxRows: number): string[][] {
  const input = text.startsWith('﻿') ? text.slice(1) : text;
  const delimiter = detectDelimiter(input);
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let inQuotes = false;
  let started = false;

  const endRow = () => {
    row.push(field);
    if (started || row.length > 1 || field !== '') {
      if (rows.length >= maxRows)
        throw new CsvParseError(`The file has more than ${maxRows} rows.`);
      rows.push(row);
    }
    row = [];
    field = '';
    started = false;
  };

  for (let i = 0; i < input.length; i++) {
    const ch = input.charAt(i);
    if (inQuotes) {
      if (ch === '"') {
        if (input[i + 1] === '"') {
          field += '"';
          i++;
        } else inQuotes = false;
      } else field += ch;
      continue;
    }
    if (ch === '"' && field === '') {
      inQuotes = true;
      started = true;
    } else if (ch === delimiter) {
      row.push(field);
      field = '';
      started = true;
    } else if (ch === '\n') {
      endRow();
    } else if (ch === '\r') {
      if (input[i + 1] !== '\n') endRow();
    } else {
      field += ch;
    }
  }
  if (inQuotes) throw new CsvParseError('The file has a quoted value that is never closed.');
  if (field !== '' || row.length > 0 || started) endRow();
  return rows;
}
