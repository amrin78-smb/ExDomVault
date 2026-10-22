// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { CsvError, parseCsv } from './csv.ts';

const fieldsOf = (text: string) => parseCsv(text, 100).map((r) => r.fields);

describe('parseCsv', () => {
  it('parses simple rows with LF or CRLF endings', () => {
    expect(fieldsOf('a,b\n1,2\n')).toEqual([
      ['a', 'b'],
      ['1', '2'],
    ]);
    expect(fieldsOf('a,b\r\n1,2')).toEqual([
      ['a', 'b'],
      ['1', '2'],
    ]);
  });

  it('handles quoted fields with commas, escaped quotes and newlines', () => {
    expect(fieldsOf('"Smith, J","say ""hi""","line1\nline2"')).toEqual([
      ['Smith, J', 'say "hi"', 'line1\nline2'],
    ]);
  });

  it('keeps empty fields and skips blank lines', () => {
    expect(fieldsOf('a,,c\n\n\nd,e,')).toEqual([
      ['a', '', 'c'],
      ['d', 'e', ''],
    ]);
  });

  it('strips a UTF-8 BOM and reports the starting line of each record', () => {
    const records = parseCsv('﻿domain\n"multi\nline"\n\nexample.com', 100);
    expect(records.map((r) => [r.line, r.fields[0]])).toEqual([
      [1, 'domain'],
      [2, 'multi\nline'],
      [5, 'example.com'],
    ]);
  });

  it('rejects unterminated quotes and too many records', () => {
    expect(() => parseCsv('"open', 10)).toThrow(CsvError);
    expect(() => parseCsv('a\nb\nc', 2)).toThrow(/more than 2 rows/);
  });
});
