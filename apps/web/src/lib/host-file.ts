import {
  extractHostEntriesFromRows,
  extractHostEntriesFromZone,
  looksLikeZoneFile,
  type ExtractedHosts,
} from '@exdomainvault/shared';
import { parseCsvRows } from './csv-parse.ts';
import { XLSX_MAX_FILE_BYTES, XLSX_MAX_ROWS, looksLikeZip, readXlsxRows } from './xlsx.ts';

/** Largest file read for a host import (spreadsheet or text). */
export const HOST_FILE_MAX_BYTES = XLSX_MAX_FILE_BYTES;

export class HostFileError extends Error {
  override name = 'HostFileError';
}

/** Hostnames from pasted or text-file content: a BIND zone file, a CSV of records, or a list. */
export function extractHostsFromText(text: string, origin: string): ExtractedHosts {
  if (looksLikeZoneFile(text)) return extractHostEntriesFromZone(text, origin);
  return extractHostEntriesFromRows(parseCsvRows(text, XLSX_MAX_ROWS), origin);
}

/**
 * Reads an uploaded file in the browser and extracts hostnames. `.xlsx` is recognised by its
 * extension or ZIP signature; anything else is read as text.
 */
export async function extractHostsFromFile(file: File, origin: string): Promise<ExtractedHosts> {
  if (file.size > HOST_FILE_MAX_BYTES) {
    throw new HostFileError('The file is larger than 10 MB. Split it into smaller files.');
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (/\.xlsx$/i.test(file.name) || looksLikeZip(bytes)) {
    return extractHostEntriesFromRows(await readXlsxRows(bytes), origin);
  }
  if (/\.xls$/i.test(file.name)) {
    throw new HostFileError('Old .xls workbooks are not supported. Save the file as .xlsx or CSV.');
  }
  return extractHostsFromText(new TextDecoder().decode(bytes), origin);
}
