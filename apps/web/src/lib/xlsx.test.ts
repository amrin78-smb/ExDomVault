import { describe, expect, it } from 'vitest';
import { XLSX_MAX_ROWS, XlsxError, columnIndex, readXlsxRows } from './xlsx.ts';

// ---------------------------------------------------------------------------------------------
// Test helper: a tiny ZIP writer (stored or deflated entries) to build .xlsx files in memory.
// ---------------------------------------------------------------------------------------------

interface TestEntry {
  name: string;
  data: string | Uint8Array;
  deflate?: boolean;
  /** Overrides for corrupt/hostile archives. */
  flags?: number;
  declaredSize?: number;
}

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(bytes: Uint8Array): number {
  let c = 0xffffffff;
  for (const b of bytes) c = (CRC_TABLE[(c ^ b) & 0xff] ?? 0) ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

async function deflateRaw(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new ReadableStream<BufferSource>({
    start(controller) {
      controller.enqueue(bytes.slice());
      controller.close();
    },
  }).pipeThrough(new CompressionStream('deflate-raw'));
  const chunks: Uint8Array[] = [];
  const reader = stream.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  return concat(chunks);
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.byteLength, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.byteLength;
  }
  return out;
}

async function buildZip(
  entries: TestEntry[],
  options: { entryCount?: number } = {},
): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const locals: Uint8Array[] = [];
  const centrals: Uint8Array[] = [];
  let offset = 0;
  for (const e of entries) {
    const raw = typeof e.data === 'string' ? enc.encode(e.data) : e.data;
    const body = e.deflate ? await deflateRaw(raw) : raw;
    const name = enc.encode(e.name);
    const method = e.deflate ? 8 : 0;
    const crc = crc32(raw);
    const size = e.declaredSize ?? raw.byteLength;

    const local = new Uint8Array(30 + name.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true);
    lv.setUint16(6, e.flags ?? 0, true);
    lv.setUint16(8, method, true);
    lv.setUint32(14, crc, true);
    lv.setUint32(18, body.byteLength, true);
    lv.setUint32(22, size, true);
    lv.setUint16(26, name.length, true);
    local.set(name, 30);
    locals.push(local, body);

    const central = new Uint8Array(46 + name.length);
    const cv = new DataView(central.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 20, true);
    cv.setUint16(6, 20, true);
    cv.setUint16(8, e.flags ?? 0, true);
    cv.setUint16(10, method, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, body.byteLength, true);
    cv.setUint32(24, size, true);
    cv.setUint16(28, name.length, true);
    cv.setUint32(42, offset, true);
    central.set(name, 46);
    centrals.push(central);
    offset += local.byteLength + body.byteLength;
  }
  const cd = concat(centrals);
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, options.entryCount ?? entries.length, true);
  ev.setUint16(10, options.entryCount ?? entries.length, true);
  ev.setUint32(12, cd.byteLength, true);
  ev.setUint32(16, offset, true);
  return concat([...locals, cd, eocd]);
}

const NS = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main';
const REL_NS = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';

const sharedStrings = (items: string[]) =>
  `<?xml version="1.0" encoding="UTF-8"?><sst xmlns="${NS}" count="${items.length}">${items
    .map((s) => `<si><t>${s}</t></si>`)
    .join('')}</sst>`;

const worksheet = (rowsXml: string) =>
  `<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="${NS}"><sheetData>${rowsXml}</sheetData></worksheet>`;

const workbookParts = (sheetTarget: string): TestEntry[] => [
  {
    name: 'xl/workbook.xml',
    data: `<?xml version="1.0"?><workbook xmlns="${NS}" xmlns:r="${REL_NS}"><sheets><sheet name="Records" sheetId="1" r:id="rId7"/></sheets></workbook>`,
  },
  {
    name: 'xl/_rels/workbook.xml.rels',
    data: `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="x" Target="styles.xml"/><Relationship Id="rId7" Type="y" Target="${sheetTarget}"/></Relationships>`,
  },
];

/** The owner's export layout: zoneName, name, type, ttl, data. */
const OWNER_SHEET = worksheet(
  [
    '<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c><c r="C1" t="s"><v>2</v></c><c r="D1" t="s"><v>3</v></c><c r="E1" t="s"><v>4</v></c></row>',
    '<row r="2"><c r="A2" t="s"><v>5</v></c><c r="B2" t="s"><v>6</v></c><c r="C2" t="s"><v>7</v></c><c r="D2"><v>600</v></c><c r="E2" t="s"><v>8</v></c></row>',
    // Blank name (apex) is simply a missing cell B3.
    '<row r="3"><c r="A3" t="s"><v>5</v></c><c r="C3" t="inlineStr"><is><t>MX</t></is></c><c r="D3"><v>3600</v></c><c r="E3" t="str"><v>10 mail.example.com.</v></c></row>',
  ].join(''),
);
const OWNER_STRINGS = sharedStrings([
  'zoneName',
  'name',
  'type',
  'ttl',
  'data',
  'thaiunion.com.',
  'apiupwise',
  'A',
  '35.228.41.194',
]);

describe('readXlsxRows', () => {
  it('reads the first worksheet via the workbook relationships, filling missing cells', async () => {
    const zip = await buildZip([
      ...workbookParts('worksheets/records.xml'),
      { name: 'xl/sharedStrings.xml', data: OWNER_STRINGS },
      { name: 'xl/worksheets/records.xml', data: OWNER_SHEET },
      { name: 'xl/worksheets/sheet1.xml', data: worksheet('<row><c><v>wrong sheet</v></c></row>') },
    ]);
    expect(await readXlsxRows(zip)).toEqual([
      ['zoneName', 'name', 'type', 'ttl', 'data'],
      ['thaiunion.com.', 'apiupwise', 'A', '600', '35.228.41.194'],
      ['thaiunion.com.', '', 'MX', '3600', '10 mail.example.com.'],
    ]);
  });

  it('inflates deflated entries', async () => {
    const zip = await buildZip([
      ...workbookParts('/xl/worksheets/sheet1.xml'),
      { name: 'xl/sharedStrings.xml', data: OWNER_STRINGS, deflate: true },
      { name: 'xl/worksheets/sheet1.xml', data: OWNER_SHEET, deflate: true },
    ]);
    const rows = await readXlsxRows(zip);
    expect(rows[1]).toEqual(['thaiunion.com.', 'apiupwise', 'A', '600', '35.228.41.194']);
  });

  it('falls back to sheet1.xml and handles booleans, rich text and cells without references', async () => {
    const zip = await buildZip([
      {
        name: 'xl/sharedStrings.xml',
        data: `<sst xmlns="${NS}"><si><r><t>www</t></r><r><t>.example.com</t></r><rPh><t>phonetic</t></rPh></si></sst>`,
      },
      {
        name: 'xl/worksheets/sheet1.xml',
        data: worksheet(
          '<row><c t="s"><v>0</v></c><c t="b"><v>1</v></c><c r="D1" t="b"><v>0</v></c></row>',
        ),
      },
    ]);
    expect(await readXlsxRows(zip)).toEqual([['www.example.com', 'TRUE', '', 'FALSE']]);
  });

  it('converts column letters to indexes', () => {
    expect(columnIndex('A1')).toBe(0);
    expect(columnIndex('Z9')).toBe(25);
    expect(columnIndex('AA10')).toBe(26);
    expect(columnIndex('ab3')).toBe(27);
  });

  it('refuses files larger than 10 MB', async () => {
    const big = new Uint8Array(10 * 1024 * 1024 + 1);
    big.set([0x50, 0x4b, 0x03, 0x04]);
    await expect(readXlsxRows(big)).rejects.toThrow(/larger than 10 MB/);
  });

  it('rejects files that are not workbooks', async () => {
    await expect(readXlsxRows(new TextEncoder().encode('name,type\n'))).rejects.toThrow(
      /not an .xlsx workbook/,
    );
    const ole = new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    await expect(readXlsxRows(ole)).rejects.toThrow(/password-protected or in the old .xls/);
  });

  it('rejects encrypted entries', async () => {
    const zip = await buildZip([
      { name: 'xl/worksheets/sheet1.xml', data: OWNER_SHEET, flags: 0x1 },
    ]);
    await expect(readXlsxRows(zip)).rejects.toThrow(/encrypted/);
  });

  it('rejects ZIP64 archives', async () => {
    const zip = await buildZip([{ name: 'xl/worksheets/sheet1.xml', data: OWNER_SHEET }], {
      entryCount: 0xffff,
    });
    await expect(readXlsxRows(zip)).rejects.toThrow(/ZIP64/);
  });

  it('refuses entries that declare more than 50 MB uncompressed', async () => {
    const zip = await buildZip([
      { name: 'xl/worksheets/sheet1.xml', data: OWNER_SHEET, declaredSize: 60 * 1024 * 1024 },
    ]);
    await expect(readXlsxRows(zip)).rejects.toBeInstanceOf(XlsxError);
    await expect(readXlsxRows(zip)).rejects.toThrow(/more than 50 MB/);
  });

  it('stops inflating a zip bomb that lies about its size', async () => {
    const zip = await buildZip([
      {
        name: 'xl/worksheets/sheet1.xml',
        data: new Uint8Array(51 * 1024 * 1024),
        deflate: true,
        declaredSize: 1000,
      },
    ]);
    expect(zip.byteLength).toBeLessThan(1024 * 1024);
    await expect(readXlsxRows(zip)).rejects.toThrow(/more than 50 MB/);
  });

  it(`refuses worksheets with more than ${XLSX_MAX_ROWS} rows`, async () => {
    const zip = await buildZip([
      {
        name: 'xl/worksheets/sheet1.xml',
        data: worksheet('<row><c><v>1</v></c></row>'.repeat(XLSX_MAX_ROWS + 1)),
        deflate: true,
      },
    ]);
    await expect(readXlsxRows(zip)).rejects.toThrow(/more than 20000 rows/);
  });

  it('reports a damaged archive', async () => {
    const zip = await buildZip([{ name: 'xl/worksheets/sheet1.xml', data: OWNER_SHEET }]);
    await expect(readXlsxRows(zip.slice(0, zip.byteLength - 30))).rejects.toThrow(/damaged/);
  });
});
