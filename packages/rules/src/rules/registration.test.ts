import { describe, expect, it } from 'vitest';
import { evaluate, fingerprint } from '../evaluator.ts';
import { APEX, asPrevious, context, input, registration } from '../fixtures/builders.ts';
import { reg001, reg002, registrationRules } from './registration.ts';

// NOW = 2026-10-22T00:00:00Z (fixtures/builders.ts)
const expiring = (expiresAt: string | null, fields = {}) => registration({ expiresAt, ...fields });

describe('REG-001 registration expiry', () => {
  it.each([
    ['2026-10-01T00:00:00.000Z', 'critical', /has passed its expiry date/],
    ['2026-10-22T00:00:00.000Z', 'critical', /has passed/],
    ['2026-11-05T00:00:00.000Z', 'high', /within 30 days/],
    ['2026-11-21T00:00:00.000Z', 'high', /within 30 days/],
    ['2026-12-01T00:00:00.000Z', 'medium', /within 60 days/],
    ['2026-12-21T00:00:00.000Z', 'medium', /within 60 days/],
  ])('expiry %s → %s', (expiresAt, severity, title) => {
    const out = reg001.evaluate(input({ registration: [expiring(expiresAt)] }));
    expect(out.checked).toEqual([]);
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({
      hostname: APEX,
      component: 'expiry',
      severity,
      confidence: 'high',
    });
    expect(out.findings[0]!.title).toMatch(title);
  });

  it('records days remaining as evidence', () => {
    const out = reg001.evaluate(input({ registration: [expiring('2026-11-05T12:00:00.000Z')] }));
    expect(out.findings[0]?.evidence).toMatchObject({
      daysRemaining: 14,
      expiresAt: '2026-11-05T12:00:00.000Z',
    });
  });

  it('more than 60 days away: no finding, checked (resolution after renewal)', () => {
    for (const expiresAt of ['2026-12-21T00:00:01.000Z', '2027-06-01T00:00:00.000Z']) {
      expect(reg001.evaluate(input({ registration: [expiring(expiresAt)] }))).toEqual({
        findings: [],
        checked: [{ hostname: APEX, component: 'expiry' }],
      });
    }
  });

  it('works with redacted registry data', () => {
    const out = reg001.evaluate(
      input({
        registration: [
          expiring('2026-11-01T00:00:00.000Z', { dataStatus: 'redacted', registrar: null }),
        ],
      }),
    );
    expect(out.findings[0]?.severity).toBe('high');
  });

  it('insufficient evidence: unavailable data, no expiry, unparseable date, failed lookup', () => {
    const empty = { findings: [], checked: [] };
    expect(
      reg001.evaluate(
        input({
          registration: [expiring('2026-10-01T00:00:00.000Z', { dataStatus: 'unavailable' })],
        }),
      ),
    ).toEqual(empty);
    expect(reg001.evaluate(input({ registration: [expiring(null)] }))).toEqual(empty);
    expect(reg001.evaluate(input({ registration: [expiring('not-a-date')] }))).toEqual(empty);
    expect(
      reg001.evaluate(
        input({
          registration: [
            registration({ expiresAt: '2026-10-01T00:00:00.000Z' }, { status: 'timeout' }),
          ],
        }),
      ),
    ).toEqual(empty);
  });

  it('advisory recommends renewal and auto-renew', () => {
    const finding = reg001.evaluate(input({ registration: [expiring('2026-11-01T00:00:00.000Z')] }))
      .findings[0]!;
    const advisory = reg001.advisory(finding, context());
    expect(advisory.recommendedActions.join(' ')).toMatch(/Renew.*auto-renew/s);
    expect(advisory.references.length).toBeGreaterThan(0);
  });
});

describe('REG-002 registrar or nameserver change', () => {
  const previous = { registration: asPrevious([registration()]) };

  it('raises for a registrar change', () => {
    const out = reg002.evaluate(
      input({ registration: [registration({ registrar: 'Other Registrar LLC' })] }, previous),
    );
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({
      hostname: APEX,
      component: 'registrar',
      severity: 'medium',
      confidence: 'medium',
      evidence: { previous: 'Example Registrar, Inc.', current: 'Other Registrar LLC' },
    });
    expect(out.checked).toEqual([]);
  });

  it('raises for a nameserver set change with added/removed lists', () => {
    const out = reg002.evaluate(
      input(
        { registration: [registration({ nameservers: ['ns1.example.net', 'ns3.other.test'] })] },
        previous,
      ),
    );
    expect(out.findings[0]).toMatchObject({
      component: 'nameservers',
      evidence: { added: ['ns3.other.test'], removed: ['ns2.example.net'] },
    });
  });

  it('raises both components independently', () => {
    const out = reg002.evaluate(
      input(
        { registration: [registration({ registrar: 'Other', nameservers: ['ns9.other.test'] })] },
        previous,
      ),
    );
    expect(out.findings.map((f) => f.component)).toEqual(['registrar', 'nameservers']);
  });

  it('ignores case, whitespace, ordering and trailing dots; never auto-resolves', () => {
    const out = reg002.evaluate(
      input(
        {
          registration: [
            registration({
              registrar: '  example   registrar, INC. ',
              nameservers: ['NS2.example.net.', 'ns1.example.net'],
            }),
          ],
        },
        previous,
      ),
    );
    expect(out).toEqual({ findings: [], checked: [] });
  });

  it('insufficient evidence: first scan, failed or unavailable data, missing fields', () => {
    const changed = registration({ registrar: 'Other', nameservers: ['ns9.other.test'] });
    const empty = { findings: [], checked: [] };
    expect(reg002.evaluate(input({ registration: [changed] }))).toEqual(empty);
    expect(
      reg002.evaluate(input({ registration: [registration({}, { status: 'error' })] }, previous)),
    ).toEqual(empty);
    expect(
      reg002.evaluate(
        input(
          { registration: [changed] },
          { registration: asPrevious([registration({ dataStatus: 'unavailable' })]) },
        ),
      ),
    ).toEqual(empty);
    expect(
      reg002.evaluate(
        input({ registration: [registration({ registrar: null, nameservers: [] })] }, previous),
      ),
    ).toEqual(empty);
  });
});

describe('registration rules through the evaluator', () => {
  it('produces upserts with fingerprints and skips without successful evidence', () => {
    const res = evaluate(
      input(
        {
          registration: [
            registration({ expiresAt: '2026-11-01T00:00:00.000Z', registrar: 'Other' }),
          ],
        },
        { registration: asPrevious([registration()]) },
      ),
      registrationRules,
    );
    expect(res.upserts.map((u) => u.fingerprint)).toEqual([
      fingerprint('REG-001', 'domain-1', APEX, 'expiry'),
      fingerprint('REG-002', 'domain-1', APEX, 'registrar'),
    ]);
    expect(res.upserts[0]).toMatchObject({ severity: 'high', riskScore: 60 });

    const failed = evaluate(
      input({ registration: [registration({}, { status: 'timeout' })] }),
      registrationRules,
    );
    expect(failed).toMatchObject({ upserts: [], resolutions: [], skipped: ['REG-001', 'REG-002'] });

    const noRdap = evaluate(
      input({ registration: [registration()] }, {}, { checks: ['dns'] }),
      registrationRules,
    );
    expect(noRdap.skipped).toEqual(['REG-001', 'REG-002']);
  });
});
