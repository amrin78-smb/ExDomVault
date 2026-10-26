import { describe, expect, it } from 'vitest';
import { parseCsv } from './csv.ts';
import {
  auditFilters,
  csvCell,
  csvHeaders,
  csvLine,
  exportStamp,
  toCsv,
  UTF8_BOM,
} from './csv-export.ts';

describe('csvCell', () => {
  it('encodes non-string values', () => {
    expect(csvCell(undefined)).toBe('');
    expect(csvCell(true)).toBe('true');
    expect(csvCell(false)).toBe('false');
    expect(csvCell(0)).toBe('0');
    // Numbers cannot carry a formula: negatives stay numeric (strings are still neutralised).
    expect(csvCell(-2)).toBe('-2');
    expect(csvCell(-0.5)).toBe('-0.5');
    expect(csvCell(new Date('2026-10-23T10:00:00Z'))).toBe('2026-10-23T10:00:00.000Z');
    expect(csvCell([])).toBe('');
    expect(csvCell(['192.0.2.1', '2001:db8::1'])).toBe('192.0.2.1; 2001:db8::1');
  });

  it('neutralises formulas after joining lists, then quotes', () => {
    expect(csvCell(['=1+1', 'x'])).toBe("'=1+1; x");
    expect(csvCell(['a,b', 'c'])).toBe('"a,b; c"');
    expect(csvCell('-2')).toBe("'-2");
    expect(csvCell('\r\n=x')).toBe('"\'\r\n=x"');
  });
});

describe('toCsv', () => {
  it('writes a BOM, a header and CRLF-terminated records that round-trip', () => {
    const csv = toCsv(
      ['a', 'b'],
      [
        ['x', 'line\nbreak'],
        [null, 'say "hi"'],
      ],
    );
    expect(csv.startsWith(UTF8_BOM)).toBe(true);
    expect(csv).toBe(`${UTF8_BOM}a,b\r\nx,"line\nbreak"\r\n,"say ""hi"""\r\n`);
    expect(parseCsv(csv, 10).map((r) => r.fields)).toEqual([
      ['a', 'b'],
      ['x', 'line\nbreak'],
      ['', 'say "hi"'],
    ]);
    expect(csvLine([])).toBe('\r\n');
  });
});

describe('helpers', () => {
  it('formats the stamp, headers and audit filters', () => {
    expect(exportStamp(new Date('2026-01-02T23:59:59Z'))).toBe('20260102');
    expect(csvHeaders({ filename: 'f.csv', truncated: false, totalRows: 3 })).toEqual({
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename="f.csv"',
      'X-Total-Rows': '3',
    });
    expect(csvHeaders({ filename: 'f.csv', truncated: true })).toMatchObject({
      'X-Truncated': 'true',
    });
    expect(auditFilters({ a: 1, b: undefined, c: null, d: '' })).toEqual({ a: 1, c: null, d: '' });
  });
});
