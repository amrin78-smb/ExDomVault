/**
 * Minimal, read-only XLSX reader for host imports: returns the cell text of the first worksheet.
 * No dependency: the ZIP container is read from its central directory and entries are inflated
 * with the browser's DecompressionStream. Only what a spreadsheet export of DNS records needs is
 * supported (shared/inline/formula strings, numbers, booleans); styles, dates and formulas are
 * not interpreted. Limits guard against oversized files and zip bombs.
 */

export const XLSX_MAX_FILE_BYTES = 10 * 1024 * 1024;
/** Total uncompressed bytes read from the archive (shared strings, workbook, worksheet). */
export const XLSX_MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024;
export const XLSX_MAX_ROWS = 20_000;

export class XlsxError extends Error {
  override name = 'XlsxError';
}

const SIG_EOCD = 0x06054b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_LOCAL = 0x04034b50;

interface ZipEntry {
  name: string;
  method: number;
  flags: number;
  compressedSize: number;
  uncompressedSize: number;
  localOffset: number;
}

/** True when the bytes start like a ZIP archive (`PK\x03\x04`), as every .xlsx does. */
export function looksLikeZip(bytes: Uint8Array): boolean {
  return bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04;
}

/** OLE compound file: an encrypted (password-protected) .xlsx or a legacy .xls. */
function looksLikeOle(bytes: Uint8Array): boolean {
  return bytes[0] === 0xd0 && bytes[1] === 0xcf && bytes[2] === 0x11 && bytes[3] === 0xe0;
}

function readCentralDirectory(bytes: Uint8Array): Map<string, ZipEntry> {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const minEocd = Math.max(0, bytes.length - 22 - 0xffff);
  let eocd = -1;
  for (let i = bytes.length - 22; i >= minEocd; i--) {
    if (view.getUint32(i, true) === SIG_EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new XlsxError('The file is not a valid .xlsx workbook (damaged archive).');
  const count = view.getUint16(eocd + 10, true);
  const cdSize = view.getUint32(eocd + 12, true);
  const cdOffset = view.getUint32(eocd + 16, true);
  const zip64 =
    (eocd >= 20 && view.getUint32(eocd - 20, true) === SIG_ZIP64_LOCATOR) ||
    count === 0xffff ||
    cdSize === 0xffffffff ||
    cdOffset === 0xffffffff;
  if (zip64) {
    throw new XlsxError('This workbook uses the ZIP64 format, which is not supported here.');
  }
  if (cdOffset + cdSize > eocd) {
    throw new XlsxError('The file is not a valid .xlsx workbook (damaged archive).');
  }

  const entries = new Map<string, ZipEntry>();
  const decoder = new TextDecoder();
  let p = cdOffset;
  for (let n = 0; n < count; n++) {
    if (p + 46 > bytes.length || view.getUint32(p, true) !== SIG_CENTRAL) {
      throw new XlsxError('The file is not a valid .xlsx workbook (damaged archive).');
    }
    const nameLen = view.getUint16(p + 28, true);
    const extraLen = view.getUint16(p + 30, true);
    const commentLen = view.getUint16(p + 32, true);
    const entry: ZipEntry = {
      flags: view.getUint16(p + 8, true),
      method: view.getUint16(p + 10, true),
      compressedSize: view.getUint32(p + 20, true),
      uncompressedSize: view.getUint32(p + 24, true),
      localOffset: view.getUint32(p + 42, true),
      name: decoder.decode(bytes.subarray(p + 46, p + 46 + nameLen)),
    };
    entries.set(entry.name, entry);
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

/** Reads a whole stream, failing as soon as more than `limit` bytes come out. */
async function readLimited(stream: ReadableStream<Uint8Array>, limit: number): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel().catch(() => undefined);
      throw new XlsxError('The workbook expands to more than 50 MB and was not read.');
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}

class ZipReader {
  private readonly entries: Map<string, ZipEntry>;
  private budget = XLSX_MAX_UNCOMPRESSED_BYTES;
  private readonly bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
    this.entries = readCentralDirectory(bytes);
  }

  has(name: string): boolean {
    return this.entries.has(name);
  }

  async text(name: string): Promise<string> {
    const entry = this.entries.get(name);
    if (!entry) throw new XlsxError(`The workbook has no ${name} part.`);
    if (entry.flags & 0x1) {
      throw new XlsxError('This workbook is encrypted. Remove the password and try again.');
    }
    if (entry.uncompressedSize > this.budget) {
      throw new XlsxError('The workbook expands to more than 50 MB and was not read.');
    }
    const view = new DataView(this.bytes.buffer, this.bytes.byteOffset, this.bytes.byteLength);
    const p = entry.localOffset;
    if (p + 30 > this.bytes.length || view.getUint32(p, true) !== SIG_LOCAL) {
      throw new XlsxError('The file is not a valid .xlsx workbook (damaged archive).');
    }
    const start = p + 30 + view.getUint16(p + 26, true) + view.getUint16(p + 28, true);
    const end = start + entry.compressedSize;
    if (end > this.bytes.length) {
      throw new XlsxError('The file is not a valid .xlsx workbook (damaged archive).');
    }
    const data = this.bytes.slice(start, end);
    let out: Uint8Array;
    if (entry.method === 0) {
      if (data.byteLength > this.budget) {
        throw new XlsxError('The workbook expands to more than 50 MB and was not read.');
      }
      out = data;
    } else if (entry.method === 8) {
      const source = new ReadableStream<BufferSource>({
        start(controller) {
          controller.enqueue(data);
          controller.close();
        },
      });
      try {
        // The declared size is not trusted: the stream is cut off at the remaining budget.
        out = await readLimited(
          source.pipeThrough(new DecompressionStream('deflate-raw')),
          this.budget,
        );
      } catch (err) {
        if (err instanceof XlsxError) throw err;
        throw new XlsxError('The file is not a valid .xlsx workbook (damaged archive).');
      }
    } else {
      throw new XlsxError('This workbook uses an unsupported compression method.');
    }
    this.budget -= out.byteLength;
    return new TextDecoder().decode(out);
  }
}

function parseXml(text: string, part: string): Document {
  const doc = new DOMParser().parseFromString(text, 'application/xml');
  if (doc.getElementsByTagName('parsererror').length > 0) {
    throw new XlsxError(`The workbook part ${part} could not be read.`);
  }
  return doc;
}

const byLocalName = (node: Document | Element, name: string): Element[] =>
  Array.from(node.getElementsByTagNameNS('*', name));

const childByLocalName = (el: Element, name: string): Element | undefined =>
  Array.from(el.children).find((c) => c.localName === name);

/** Text of a shared or inline string: plain `<t>` or rich-text runs, without phonetic hints. */
function stringItemText(si: Element): string {
  return byLocalName(si, 't')
    .filter((t) => t.parentElement?.localName !== 'rPh')
    .map((t) => t.textContent ?? '')
    .join('');
}

/** "A" → 0, "Z" → 25, "AA" → 26 (from a cell reference such as "AB12"). */
export function columnIndex(ref: string): number {
  const letters = /^[A-Z]+/i.exec(ref)?.[0].toUpperCase() ?? '';
  let n = 0;
  for (const ch of letters) n = n * 26 + (ch.charCodeAt(0) - 64);
  return n - 1;
}

/** Path of the first worksheet, from the workbook and its relationships, else the usual default. */
async function firstSheetPath(zip: ZipReader): Promise<string> {
  const fallback = 'xl/worksheets/sheet1.xml';
  if (!zip.has('xl/workbook.xml') || !zip.has('xl/_rels/workbook.xml.rels')) return fallback;
  const workbook = parseXml(await zip.text('xl/workbook.xml'), 'workbook');
  const sheet = byLocalName(workbook, 'sheet')[0];
  const relId =
    sheet?.getAttributeNS(
      'http://schemas.openxmlformats.org/officeDocument/2006/relationships',
      'id',
    ) ?? sheet?.getAttribute('r:id');
  if (!relId) return fallback;
  const rels = parseXml(await zip.text('xl/_rels/workbook.xml.rels'), 'workbook relationships');
  const target = byLocalName(rels, 'Relationship')
    .find((r) => r.getAttribute('Id') === relId)
    ?.getAttribute('Target');
  if (!target) return fallback;
  const path = target.startsWith('/') ? target.slice(1) : `xl/${target.replace(/^\.\//, '')}`;
  return zip.has(path) ? path : fallback;
}

/** Reads the first worksheet of an .xlsx file as rows of cell text (missing cells are ''). */
export async function readXlsxRows(input: ArrayBuffer | Uint8Array): Promise<string[][]> {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (bytes.byteLength > XLSX_MAX_FILE_BYTES) {
    throw new XlsxError('The workbook is larger than 10 MB. Export fewer rows or use CSV.');
  }
  if (looksLikeOle(bytes)) {
    throw new XlsxError(
      'This file is password-protected or in the old .xls format. Remove the password or save it as .xlsx or CSV.',
    );
  }
  if (!looksLikeZip(bytes)) throw new XlsxError('The file is not an .xlsx workbook.');

  const zip = new ZipReader(bytes);
  const shared = zip.has('xl/sharedStrings.xml')
    ? byLocalName(parseXml(await zip.text('xl/sharedStrings.xml'), 'shared strings'), 'si').map(
        stringItemText,
      )
    : [];
  const sheetPath = await firstSheetPath(zip);
  const sheet = parseXml(await zip.text(sheetPath), 'worksheet');

  const rows: string[][] = [];
  for (const rowEl of byLocalName(sheet, 'row')) {
    if (rows.length >= XLSX_MAX_ROWS) {
      throw new XlsxError(`The worksheet has more than ${XLSX_MAX_ROWS} rows.`);
    }
    const row: string[] = [];
    let next = 0;
    for (const c of Array.from(rowEl.children).filter((el) => el.localName === 'c')) {
      const ref = c.getAttribute('r');
      const col = ref ? columnIndex(ref) : next;
      if (col < 0 || col > 16_383) continue;
      while (row.length < col) row.push('');
      const type = c.getAttribute('t') ?? 'n';
      const v = childByLocalName(c, 'v')?.textContent ?? '';
      let value: string;
      if (type === 's') value = v === '' ? '' : (shared[Number(v)] ?? '');
      else if (type === 'inlineStr') {
        const is = childByLocalName(c, 'is');
        value = is ? stringItemText(is) : '';
      } else if (type === 'b') value = v === '1' ? 'TRUE' : v === '0' ? 'FALSE' : v;
      else value = v; // n, str, e, d
      row[col] = value;
      next = col + 1;
    }
    rows.push(row);
  }
  return rows;
}
