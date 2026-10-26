import { describe, expect, it } from 'vitest';
import { CsvParseError, parseCsvRows } from './csv-parse.ts';

describe('parseCsvRows', () => {
  it('parses quoted fields, escaped quotes, CRLF and a BOM, skipping blank lines', () => {
    expect(parseCsvRows('﻿name,data\r\nwww,"a, ""b"""\r\n\r\n,x\n', 10)).toEqual([
      ['name', 'data'],
      ['www', 'a, "b"'],
      ['', 'x'],
    ]);
  });

  it('detects semicolon and tab separators', () => {
    expect(parseCsvRows('name;type\nwww;A', 10)).toEqual([
      ['name', 'type'],
      ['www', 'A'],
    ]);
    expect(parseCsvRows('name\ttype\nwww\tA', 10)).toEqual([
      ['name', 'type'],
      ['www', 'A'],
    ]);
  });

  it('keeps a single-column list', () => {
    expect(parseCsvRows('a.example.com\nb.example.com\n', 10)).toEqual([
      ['a.example.com'],
      ['b.example.com'],
    ]);
  });

  it('rejects unterminated quotes and too many rows', () => {
    expect(() => parseCsvRows('"abc', 10)).toThrow(CsvParseError);
    expect(() => parseCsvRows('a\nb\nc', 2)).toThrow(/more than 2 rows/);
  });
});
