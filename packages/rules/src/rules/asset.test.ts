import { describe, expect, it } from 'vitest';
import { evaluate, fingerprint } from '../evaluator.ts';
import { APEX, asPrevious, asset, context, discovery, input } from '../fixtures/builders.ts';
import { asset001, asset002, assetRules } from './asset.ts';

const www = `www.${APEX}`;
const dev = `dev.${APEX}`;
const api = `api.${APEX}`;

describe('ASSET-001 unapproved candidate asset', () => {
  it('raises one informational finding per unknown or pending hostname', () => {
    const out = asset001.evaluate(
      input(
        {
          discovery: [
            discovery(www),
            discovery(`DEV.${APEX}.`, { source: 'ct' }),
            discovery(dev, { source: 'passive-dns' }),
            discovery(api),
          ],
        },
        {},
        { assets: [asset(www), asset(api, { status: 'pending', assetId: 'asset-api' })] },
      ),
    );
    expect(out.findings.map((f) => [f.hostname, f.component])).toEqual([
      [api, api],
      [dev, dev],
    ]);
    expect(out.findings[1]).toMatchObject({
      severity: 'informational',
      confidence: 'medium',
      evidence: { sources: ['ct', 'passive-dns'], assetStatus: null },
    });
    expect(out.findings[0]!.evidence).toMatchObject({
      assetStatus: 'pending',
      assetId: 'asset-api',
    });
    expect(out.findings[0]!.description).toMatch(/do not prove/);
    expect(out.checked).toEqual([{ hostname: www, component: www }]);
  });

  it('decided assets (approved, rejected, suspended) are checked: resolution', () => {
    const out = asset001.evaluate(
      input(
        { discovery: [discovery(dev)] },
        {},
        {
          assets: [
            asset(dev, { status: 'rejected' }),
            asset(api, { status: 'suspended' }),
            asset(www),
          ],
        },
      ),
    );
    expect(out.findings).toEqual([]);
    expect(out.checked.map((c) => c.hostname)).toEqual([api, dev, www]);
  });

  it('ignores names outside the domain (exact label boundary)', () => {
    const out = asset001.evaluate(
      input({ discovery: [discovery(`www.not${APEX}`), discovery(`${APEX}.evil.test`)] }),
    );
    expect(out).toEqual({ findings: [], checked: [] });
  });

  it('insufficient evidence: failed discovery observations raise nothing', () => {
    const out = asset001.evaluate(input({ discovery: [discovery(dev, { status: 'error' })] }));
    expect(out.findings).toEqual([]);
  });
});

describe('ASSET-002 monitored asset missing from discovery', () => {
  const assets = [asset(www), asset(dev), asset(api, { monitoringEnabled: false })];
  const previous = { discovery: asPrevious([discovery(www), discovery(dev), discovery(api)]) };

  it('raises for an approved, monitored asset seen previously but not now', () => {
    const out = asset002.evaluate(input({ discovery: [discovery(www)] }, previous, { assets }));
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({
      hostname: dev,
      component: 'discovery',
      severity: 'medium',
      confidence: 'low',
      evidence: { assetId: `asset-${dev}`, previousScanJobId: 'job-previous' },
    });
    // api is not monitored → checked (condition does not apply); www present → checked.
    expect(out.checked.map((c) => c.hostname)).toEqual([api, www]);
  });

  it('present again → checked (resolution)', () => {
    const out = asset002.evaluate(
      input({ discovery: [discovery(www), discovery(dev)] }, previous, { assets }),
    );
    expect(out.findings).toEqual([]);
    expect(out.checked.map((c) => c.hostname)).toEqual([api, dev, www]);
  });

  it('assets the previous run never saw are not evaluated', () => {
    const out = asset002.evaluate(
      input(
        { discovery: [discovery(www)] },
        { discovery: asPrevious([discovery(www)]) },
        { assets },
      ),
    );
    expect(out.findings).toEqual([]);
    expect(out.checked.map((c) => c.hostname)).toEqual([api, www]);
  });

  it('insufficient evidence: any failed or partial source makes the run incomplete', () => {
    for (const status of ['error', 'partial', 'timeout'] as const) {
      const out = asset002.evaluate(
        input({ discovery: [discovery(www), discovery(api, { status, source: 'ct' })] }, previous, {
          assets,
        }),
      );
      expect(out).toEqual({ findings: [], checked: [] });
    }
  });
});

describe('asset rules through the evaluator', () => {
  it('runs only when the profile includes discovery and evidence succeeded', () => {
    const assets = [asset(www), asset(dev)];
    const res = evaluate(
      input(
        { discovery: [discovery(www), discovery(`new.${APEX}`)] },
        { discovery: asPrevious([discovery(www), discovery(dev)]) },
        { assets },
      ),
      assetRules,
    );
    expect(res.upserts.map((u) => [u.fingerprint, u.riskScore])).toEqual([
      [fingerprint('ASSET-001', 'domain-1', `new.${APEX}`, `new.${APEX}`), 4],
      [fingerprint('ASSET-002', 'domain-1', dev, 'discovery'), 40],
    ]);
    expect(res.resolutions.map((r) => `${r.ruleId}:${r.hostname}`)).toEqual([
      `ASSET-001:${dev}`,
      `ASSET-001:${www}`,
      `ASSET-002:${www}`,
    ]);

    const skipped = evaluate(
      input({ discovery: [discovery(www)] }, {}, { checks: ['dns', 'rdap'] }),
      assetRules,
    );
    expect(skipped.skipped).toEqual(['ASSET-001', 'ASSET-002']);
    expect(asset001.advisory(res.upserts[0]!, context()).recommendedActions.length).toBeGreaterThan(
      0,
    );
  });
});
