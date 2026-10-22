import { describe, expect, it } from 'vitest';
import { evaluate, fingerprint } from './evaluator.ts';
import { riskScore } from './risk.ts';
import {
  emptyObservationSet,
  type EvaluationInput,
  type ObservationSet,
  type Rule,
} from './types.ts';

const context: EvaluationInput['context'] = {
  now: '2026-10-22T00:00:00.000Z',
  domain: { id: 'd1', fqdn: 'example.com', criticality: 'high', verified: true },
  scanJobId: 'j1',
  checks: ['dns'],
  assets: [],
  administrativeServices: [],
};

const dnsSet = (status: 'success' | 'error'): ObservationSet => ({
  ...emptyObservationSet(),
  dns: [
    {
      hostname: '_dmarc.example.com',
      recordType: 'TXT',
      ttl: null,
      values: [],
      resultStatus: status,
      observedAt: context.now,
      scanJobId: 'j1',
      evidence: {},
    },
  ],
});

function rule(overrides: Partial<Rule> = {}): Rule {
  return {
    id: 'T-001',
    version: 2,
    category: 'email',
    title: 'Test',
    requires: ['dns'],
    requiresChecks: ['dns'],
    defaultSeverity: 'medium',
    defaultConfidence: 'high',
    evidenceRequirements: '',
    detection: '',
    resolution: '',
    evaluate: () => ({
      findings: [
        {
          hostname: 'example.com',
          component: 'dmarc',
          title: 't',
          description: 'd',
          severity: 'medium',
          confidence: 'high',
          exposure: 'public_record',
          evidence: {},
        },
      ],
      checked: [
        { hostname: 'example.com', component: 'dmarc' },
        { hostname: 'example.com', component: 'spf' },
      ],
    }),
    advisory: () => ({
      title: 'a',
      summary: 's',
      businessImpact: 'b',
      recommendedActions: [],
      references: [],
    }),
    ...overrides,
  };
}

describe('evaluate', () => {
  it('produces fingerprinted upserts with risk and resolves only checked, absent components', () => {
    const res = evaluate({ context, current: dnsSet('success'), previous: emptyObservationSet() }, [
      rule(),
    ]);
    expect(res.upserts).toHaveLength(1);
    expect(res.upserts[0]).toMatchObject({
      ruleId: 'T-001',
      ruleVersion: 2,
      fingerprint: fingerprint('T-001', 'd1', 'example.com', 'dmarc'),
      riskScore: riskScore('medium', 'public_record', 'high').score,
    });
    expect(res.resolutions.map((r) => r.component)).toEqual(['spf']);
  });

  it('skips a rule without successful evidence: nothing raised, nothing resolved', () => {
    const res = evaluate({ context, current: dnsSet('error'), previous: emptyObservationSet() }, [
      rule(),
    ]);
    expect(res).toMatchObject({ upserts: [], resolutions: [], skipped: ['T-001'] });
  });

  it('skips a rule whose checks the profile did not run', () => {
    const res = evaluate(
      {
        context: { ...context, checks: ['rdap'] },
        current: dnsSet('success'),
        previous: emptyObservationSet(),
      },
      [rule()],
    );
    expect(res.skipped).toEqual(['T-001']);
  });

  it('fails safe when a rule throws', () => {
    const res = evaluate({ context, current: dnsSet('success'), previous: emptyObservationSet() }, [
      rule({
        evaluate: () => {
          throw new Error('boom');
        },
      }),
    ]);
    expect(res).toMatchObject({
      upserts: [],
      resolutions: [],
      errors: [{ ruleId: 'T-001', message: 'boom' }],
    });
  });
});

describe('riskScore', () => {
  it('multiplies the documented factors and clamps to 0–100', () => {
    expect(riskScore('medium', 'public_record', 'high')).toMatchObject({ score: 40 });
    expect(riskScore('critical', 'network_service', 'critical').score).toBe(100);
    expect(riskScore('informational', 'public_record', 'low').score).toBe(3);
    expect(riskScore('high', 'web', 'medium').inputs).toEqual({
      model: 'v1',
      severity: 'high',
      severityWeight: 75,
      exposure: 'web',
      exposureFactor: 1,
      criticality: 'medium',
      criticalityFactor: 0.85,
    });
  });
});
