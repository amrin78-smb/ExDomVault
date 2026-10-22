import { describe, expect, it } from 'vitest';
import { evaluate, fingerprint } from '../evaluator.ts';
import { input } from '../fixtures/builders.ts';
import { baseline, IP4, IP6, openPort, portState } from '../fixtures/exposure-fixtures.ts';
import { DEFAULT_ADMINISTRATIVE_SERVICES } from '../policy.ts';
import type { PortObservation, Rule } from '../types.ts';
import { exp001, exp002, exposureRules, portComponent, serviceConfidence } from './exposure.ts';

const run = (rule: Rule, current: PortObservation[], previous: PortObservation[] = []) =>
  rule.evaluate(
    input(
      { ports: current },
      { ports: previous },
      { checks: ['tcp_ports'], administrativeServices: DEFAULT_ADMINISTRATIVE_SERVICES },
    ),
  );

const FQDN = 'example.com';

describe('portComponent', () => {
  it('brackets IPv6 and lowercases', () => {
    expect(portComponent('203.0.113.10', 3389)).toBe('203.0.113.10:3389');
    expect(portComponent('2001:DB8::10', 22)).toBe('[2001:db8::10]:22');
  });
});

describe('EXP-001 newly exposed TCP port', () => {
  it('raises low when a port opens on an address with a baseline', () => {
    const out = run(
      exp001,
      [openPort(IP4, 8080, 'http-proxy')],
      baseline([portState(IP4, 8080, 'closed')]),
    );
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({
      hostname: FQDN,
      component: '203.0.113.10:8080',
      severity: 'low',
      confidence: 'high',
      exposure: 'network_service',
      evidence: { previousState: 'closed', state: 'open', service: 'http-proxy' },
    });
  });

  it('does not treat a port the previous scan never checked as new', () => {
    const out = run(exp001, [openPort(IP4, 8443)], baseline([openPort(IP4, 443)]));
    expect(out.findings).toEqual([]);
  });

  it('is informational when the port is also an administrative service (EXP-002 carries severity)', () => {
    const out = run(exp001, [openPort(IP6, 22, 'ssh')], baseline([portState(IP6, 22, 'filtered')]));
    expect(out.findings[0]).toMatchObject({
      component: '[2001:db8::10]:22',
      severity: 'informational',
      evidence: { administrativeService: 'SSH' },
    });
  });

  it('first scan of an address raises nothing', () => {
    expect(run(exp001, [openPort(IP4, 22), openPort(IP6, 443)])).toEqual({
      findings: [],
      checked: [],
    });
  });

  it('a baseline from a failed observation is not a baseline', () => {
    const out = run(exp001, [openPort(IP4, 22)], baseline([portState(IP4, 22, 'closed', 'error')]));
    expect(out.findings).toEqual([]);
  });

  it('a port that stays open is neither raised again nor resolved', () => {
    expect(run(exp001, [openPort(IP4, 443)], baseline([openPort(IP4, 443)]))).toEqual({
      findings: [],
      checked: [],
    });
  });

  it('resolves when the port is closed or filtered in a successful observation', () => {
    const out = run(exp001, [portState(IP4, 8080, 'closed'), portState(IP6, 8080, 'filtered')]);
    expect(out.checked).toEqual([
      { hostname: FQDN, component: '203.0.113.10:8080' },
      { hostname: FQDN, component: '[2001:db8::10]:8080' },
    ]);
  });

  it('insufficient evidence: failed observations neither raise nor resolve', () => {
    expect(
      run(
        exp001,
        [portState(IP4, 8080, 'closed', 'error'), portState(IP4, 22, 'open', 'timeout')],
        baseline([portState(IP4, 22, 'closed')]),
      ),
    ).toEqual({ findings: [], checked: [] });
  });
});

describe('EXP-002 public administrative service', () => {
  it("uses the policy entry's severity; medium confidence on port number only", () => {
    const out = run(exp002, [
      openPort(IP4, 3389, 'ms-wbt-server', { method: 'nmap-sT', serviceMethod: 'table' }),
    ]);
    expect(out.findings[0]).toMatchObject({
      hostname: FQDN,
      component: '203.0.113.10:3389',
      severity: 'high',
      confidence: 'medium',
      exposure: 'network_service',
      evidence: { policy: { port: 3389, service: 'Remote Desktop (RDP)', severity: 'high' } },
    });
    expect(out.findings[0]!.description).toMatch(
      /not evidence that the service has been accessed or compromised/,
    );
  });

  it('high confidence when service identification probed a matching service (IPv6)', () => {
    const out = run(exp002, [
      openPort(IP6, 22, 'ssh', {
        method: 'nmap-sT',
        product: 'OpenSSH',
        version: '9.6',
        serviceMethod: 'probed',
      }),
    ]);
    expect(out.findings[0]).toMatchObject({
      component: '[2001:db8::10]:22',
      severity: 'medium',
      confidence: 'high',
      evidence: { product: 'OpenSSH', version: '9.6' },
    });
  });

  it('critical for the plain Docker API', () => {
    expect(run(exp002, [openPort(IP4, 2375)]).findings[0]?.severity).toBe('critical');
  });

  it('ignores ports not in the policy', () => {
    expect(run(exp002, [openPort(IP4, 443, 'https'), portState(IP4, 80, 'closed')])).toEqual({
      findings: [],
      checked: [],
    });
  });

  it('one finding per address (same port on IPv4 and IPv6)', () => {
    const out = run(exp002, [openPort(IP4, 6379, 'redis'), openPort(IP6, 6379, 'redis')]);
    expect(out.findings.map((f) => f.component)).toEqual([
      '203.0.113.10:6379',
      '[2001:db8::10]:6379',
    ]);
  });

  it('resolves when the admin port is closed or filtered', () => {
    expect(run(exp002, [portState(IP4, 3389, 'filtered')])).toEqual({
      findings: [],
      checked: [{ hostname: FQDN, component: '203.0.113.10:3389' }],
    });
  });

  it('insufficient evidence: failed observation neither raises nor resolves', () => {
    expect(
      run(exp002, [portState(IP4, 3389, 'open', 'error'), portState(IP4, 22, 'closed', 'timeout')]),
    ).toEqual({
      findings: [],
      checked: [],
    });
  });

  it('respects a custom policy from context', () => {
    const out = exp002.evaluate(
      input(
        {
          ports: [
            openPort(IP4, 8443, 'https-alt', { serviceMethod: 'probed', product: 'Webmin httpd' }),
          ],
        },
        {},
        {
          checks: ['tcp_ports'],
          administrativeServices: [{ port: 8443, service: 'Webmin', severity: 'high' }],
        },
      ),
    );
    expect(out.findings[0]).toMatchObject({ severity: 'high', confidence: 'high' });
  });

  it('serviceConfidence: probed but mismatching service stays medium', () => {
    const o = openPort(IP4, 22, 'http', { serviceMethod: 'probed', product: 'nginx' });
    expect(serviceConfidence(o, { port: 22, service: 'SSH', severity: 'medium' })).toBe('medium');
  });
});

describe('exposure rules metadata and advisories', () => {
  it('declare contract fields', () => {
    for (const r of exposureRules) {
      expect(r).toMatchObject({
        version: 1,
        category: 'exposure',
        requires: ['port'],
        requiresChecks: ['tcp_ports'],
      });
    }
  });

  it('advisories have actions and references and no compromise claims', () => {
    const f = run(exp002, [openPort(IP4, 3389)]).findings[0]!;
    for (const r of exposureRules) {
      const a = r.advisory(f, input().context);
      expect(a.recommendedActions.length).toBeGreaterThan(0);
      expect(a.references.length).toBeGreaterThan(0);
      expect(`${a.summary} ${a.businessImpact}`).not.toMatch(/compromised|was exploited|breach/i);
    }
  });
});

describe('exposure rules through the evaluator', () => {
  it('raises EXP-001 and EXP-002 for a new RDP port and resolves closed ones', () => {
    const res = evaluate(
      input(
        { ports: [openPort(IP4, 3389), portState(IP4, 22, 'closed'), openPort(IP6, 443)] },
        { ports: baseline([portState(IP4, 3389, 'closed'), openPort(IP4, 22)]) },
        { checks: ['tcp_ports'], administrativeServices: DEFAULT_ADMINISTRATIVE_SERVICES },
      ),
      exposureRules,
    );
    expect(res.errors).toEqual([]);
    expect(res.upserts.map((u) => `${u.ruleId}|${u.component}|${u.severity}`)).toEqual([
      'EXP-001|203.0.113.10:3389|informational',
      'EXP-002|203.0.113.10:3389|high',
    ]);
    expect(res.upserts[1]!.fingerprint).toBe(
      fingerprint('EXP-002', 'domain-1', FQDN, '203.0.113.10:3389'),
    );
    expect(res.upserts[1]!.riskInputs).toMatchObject({
      exposure: 'network_service',
      criticality: 'high',
    });
    expect(res.resolutions.map((r) => `${r.ruleId}|${r.component}`)).toEqual([
      'EXP-001|203.0.113.10:22',
      'EXP-002|203.0.113.10:22',
    ]);
  });

  it('skips both rules without a successful port observation', () => {
    const res = evaluate(
      input({ ports: [portState(IP4, 22, 'open', 'error')] }, {}, { checks: ['tcp_ports'] }),
      exposureRules,
    );
    expect(res).toMatchObject({ upserts: [], resolutions: [], skipped: ['EXP-001', 'EXP-002'] });
  });
});
