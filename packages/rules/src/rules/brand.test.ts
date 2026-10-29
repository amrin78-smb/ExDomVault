import { describe, expect, it } from 'vitest';
import { evaluate, fingerprint } from '../evaluator.ts';
import { APEX, JOB_ID, NOW, input } from '../fixtures/builders.ts';
import { RULES } from '../registry.ts';
import type { LookalikeObservation } from '../types.ts';
import { look001, lookalikeSeverity } from './brand.ts';

const look = (
  candidate: string,
  records: LookalikeObservation['records'] = { NS: ['ns1.parking.example.net.'] },
  opts: Partial<LookalikeObservation> = {},
): LookalikeObservation => ({
  resultStatus: 'success',
  observedAt: NOW,
  scanJobId: JOB_ID,
  evidence: {},
  candidate,
  technique: 'omission',
  registered: true,
  records,
  ...opts,
});

const CANDIDATES = ['exampe.com', 'exmple.com', 'example.net', 'examp1e.com'];
const brandCtx = (complete: boolean, candidates = CANDIDATES) => ({
  checks: ['lookalike'],
  lookalike: { complete, candidates },
});

describe('LOOK-001 severity', () => {
  it.each([
    [{ MX: ['10 mx.example.net.'], A: ['192.0.2.1'] }, 'medium'],
    [{ MX: ['10 mx.example.net.'] }, 'medium'],
    [{ MX: ['0 .'], A: ['192.0.2.1'] }, 'low'], // null MX: accepts no mail
    [{ AAAA: ['2001:db8::1'] }, 'low'],
    [{ NS: ['ns1.example.net.'] }, 'informational'],
    [{}, 'informational'],
  ] as const)('%j → %s', (records, severity) => {
    expect(lookalikeSeverity(records)).toBe(severity);
  });
});

describe('LOOK-001 lookalike domain registered', () => {
  it('raises one finding per registered candidate on the apex, component = candidate', () => {
    const out = look001.evaluate(
      input(
        {
          lookalike: [
            look('exmple.com', { MX: ['10 mx.evil.example.'], NS: ['ns.example.net.'] }),
            look('exampe.com', { A: ['192.0.2.7'] }, { technique: 'omission' }),
            look('exampe.com', { A: ['192.0.2.7'] }), // duplicate in the same run
          ],
        },
        {},
        brandCtx(true),
      ),
    );
    expect(out.findings.map((f) => [f.hostname, f.component, f.severity])).toEqual([
      [APEX, 'exampe.com', 'low'],
      [APEX, 'exmple.com', 'medium'],
    ]);
    expect(out.findings[1]).toMatchObject({
      confidence: 'medium',
      exposure: 'public_record',
      evidence: {
        candidate: 'exmple.com',
        technique: 'omission',
        hasMail: true,
        records: { MX: ['10 mx.evil.example.'], A: [], AAAA: [], NS: ['ns.example.net.'] },
      },
    });
    expect(out.findings[1]!.description).toMatch(/not contacted/);
    // Complete run: the unregistered candidates are checked (resolvable), registered ones are not.
    expect(out.checked).toEqual([
      { hostname: APEX, component: 'examp1e.com' },
      { hostname: APEX, component: 'example.net' },
    ]);
  });

  it('an incomplete run raises but never resolves', () => {
    const out = look001.evaluate(input({ lookalike: [look('exmple.com')] }, {}, brandCtx(false)));
    expect(out.findings).toHaveLength(1);
    expect(out.checked).toEqual([]);
  });

  it('a candidate that failed to resolve neither raises nor resolves', () => {
    const out = look001.evaluate(
      input(
        {
          lookalike: [
            look('exmple.com', {}, { resultStatus: 'error', registered: false }),
            look('exampe.com', {}, { resultStatus: 'timeout', registered: false }),
          ],
        },
        {},
        brandCtx(true),
      ),
    );
    expect(out.findings).toEqual([]);
    expect(out.checked.map((c) => c.component)).toEqual(['examp1e.com', 'example.net']);
  });

  it('partial observations (some record lookups failed) still raise', () => {
    const out = look001.evaluate(
      input({ lookalike: [look('exmple.com', { NS: ['a.'] }, { resultStatus: 'partial' })] }),
    );
    expect(out.findings[0]?.severity).toBe('informational');
  });

  it('without brand context nothing is checked', () => {
    const out = look001.evaluate(input({ lookalike: [] }));
    expect(out).toEqual({ findings: [], checked: [] });
  });

  it('through the evaluator: runs only for profiles with the lookalike check', () => {
    const current = { lookalike: [look('exmple.com', { MX: ['10 mx.example.net.'] })] };
    const res = evaluate(input(current, {}, brandCtx(true)), RULES);
    const ups = res.upserts.filter((u) => u.ruleId === 'LOOK-001');
    expect(ups).toHaveLength(1);
    expect(ups[0]!.fingerprint).toBe(fingerprint('LOOK-001', 'domain-1', APEX, 'exmple.com'));
    expect(ups[0]!.advisory.recommendedActions.join(' ')).toMatch(/registrar abuse/);
    expect(res.resolutions.filter((r) => r.ruleId === 'LOOK-001')).toHaveLength(3);

    const passive = evaluate(input(current, {}, { checks: ['dns'] }), RULES);
    expect(passive.skipped).toContain('LOOK-001');
  });

  it('a complete run with nothing registered resolves every candidate', () => {
    const res = evaluate(input({}, {}, brandCtx(true)), [look001]);
    expect(res.upserts).toEqual([]);
    expect(res.resolutions.map((r) => r.component).sort()).toEqual([...CANDIDATES].sort());
  });
});
