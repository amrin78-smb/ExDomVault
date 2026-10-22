/** A parsed CSV record with the 1-based line it started on. */
export interface CsvRecord {
  line: number;
  fields: string[];
}

export class CsvError extends Error {
  override name = 'CsvError';
}

/**
 * Minimal RFC 4180 parser: comma separator, double-quoted fields with `""` escapes, CRLF or LF line
 * endings, optional UTF-8 BOM. Blank lines are skipped. Throws CsvError on an unterminated quote
 * or when `maxRecords` is exceeded.
 */
export function parseCsv(text: string, maxRecords: number): CsvRecord[] {
  const input = text.startsWith('﻿') ? text.slice(1) : text;
  const records: CsvRecord[] = [];
  let fields: string[] = [];
  let field = '';
  let inQuotes = false;
  let line = 1;
  let recordLine = 1;
  let fieldStarted = false;

  const endRecord = () => {
    fields.push(field);
    const blank = fields.length === 1 && fields[0] === '' && !fieldStarted;
    if (!blank) {
      if (records.length >= maxRecords) throw new CsvError(`more than ${maxRecords} rows`);
      records.push({ line: recordLine, fields });
    }
    fields = [];
    field = '';
    fieldStarted = false;
  };

  for (let i = 0; i < input.length; i++) {
    const ch = input.charAt(i);
    if (inQuotes) {
      if (ch === '"') {
        if (input[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        if (ch === '\n') line++;
        field += ch;
      }
      continue;
    }
    if (ch === '"' && field === '') {
      inQuotes = true;
      fieldStarted = true;
    } else if (ch === ',') {
      fields.push(field);
      field = '';
      fieldStarted = true;
    } else if (ch === '\r' && input[i + 1] === '\n') {
      // handled by the following \n
    } else if (ch === '\n' || ch === '\r') {
      endRecord();
      line++;
      recordLine = line;
    } else {
      field += ch;
    }
  }
  if (inQuotes) throw new CsvError(`unterminated quoted field starting on line ${recordLine}`);
  if (field !== '' || fields.length > 0 || fieldStarted) endRecord();
  return records;
}
