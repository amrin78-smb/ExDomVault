import { describe, expect, it } from 'vitest';
import { normaliseOrgName, orgNameMatches } from './org-names.ts';

// Same cases as worker/tests/test_network_checks.py (the worker and server must agree).
describe('orgNameMatches', () => {
  it.each([
    'Thai Union Group Public Company Limited',
    'THAI UNION',
    'thai-union europe b.v.',
    'Thai  Union,  Inc.',
    'THAIUNION-TH',
    'TU-THAI-UNION-NET',
    'ｔｈａｉ ｕｎｉｏｎ',
  ])('matches %j', (candidate) => {
    expect(orgNameMatches(['Thai Union'], [candidate])).toBe(true);
  });

  it.each([
    'Thailand Unionbank',
    'Thai Unionist Party',
    'Union Thai',
    'THAIUNIONGROUP',
    '',
    null,
    'Amazon',
  ])('does not match %j', (candidate) => {
    expect(orgNameMatches(['Thai Union'], [candidate])).toBe(false);
  });

  it('matches on word boundaries only and never with an empty list', () => {
    expect(orgNameMatches(['AB Co'], ['XABCOY-NET'])).toBe(false);
    expect(orgNameMatches(['AB Co'], ['The AB Co. Ltd'])).toBe(true);
    expect(orgNameMatches([], ['Thai Union'])).toBe(false);
    expect(orgNameMatches(['  ', '--'], ['Thai Union'])).toBe(false);
    expect(normaliseOrgName(' Thai--Union!! ')).toBe('thai union');
  });
});
