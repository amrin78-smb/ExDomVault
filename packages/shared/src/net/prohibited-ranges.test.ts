/**
 * Parity: the server's prohibited ranges and the Python worker's tables (worker/app/policy.py)
 * must list exactly the same networks, so neither side can approve or accept what the other refuses.
 * The Python source is read as text; nothing is imported from or executed in the worker.
 */
import { describe, expect, it } from 'vitest';
import policySource from '../../../../worker/app/policy.py?raw';
import { canonicalCidr } from './ip.ts';
import { PROHIBITED_RANGES } from './prohibited-ranges.ts';

const TABLES = ['_IPV4_PROHIBITED', '_IPV6_PROHIBITED'] as const;

function pythonTable(name: string): string[] {
  const start = policySource.indexOf(`${name} = _table(`);
  expect(start, `${name} not found in policy.py`).toBeGreaterThanOrEqual(0);
  // The table is a list literal closed by `]\n)` at the start of a line.
  const end = policySource.indexOf('\n)', start);
  expect(end).toBeGreaterThan(start);
  const body = policySource.slice(start, end);
  return [...body.matchAll(/\(\s*"([0-9a-fA-F:.]+\/[0-9]{1,3})"\s*,\s*"[a-z0-9_]+"\s*\)/g)].map(
    (m) => m[1] as string,
  );
}

const canonical = (cidrs: readonly string[]) =>
  new Set(
    cidrs.map((c) => {
      const out = canonicalCidr(c);
      expect(out, `unparseable CIDR ${c}`).not.toBeNull();
      return out as string;
    }),
  );

describe('prohibited ranges: TypeScript / Python parity', () => {
  it('parses a plausible number of entries from each worker table', () => {
    for (const t of TABLES) expect(pythonTable(t).length).toBeGreaterThan(10);
  });

  it('both sides list exactly the same networks', () => {
    const py = canonical(TABLES.flatMap(pythonTable));
    const ts = canonical(PROHIBITED_RANGES.map((r) => r.cidr));
    expect([...ts].filter((c) => !py.has(c)).sort(), 'only in TypeScript').toEqual([]);
    expect([...py].filter((c) => !ts.has(c)).sort(), 'only in policy.py').toEqual([]);
  });

  it('the TypeScript list has no duplicates', () => {
    const cidrs = PROHIBITED_RANGES.map((r) => canonicalCidr(r.cidr));
    expect(new Set(cidrs).size).toBe(cidrs.length);
  });
});
