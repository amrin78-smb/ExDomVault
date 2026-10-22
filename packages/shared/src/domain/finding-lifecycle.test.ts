import { describe, expect, it } from 'vitest';
import { allowedTransitions, canTransition, transitionRequirements } from './finding-lifecycle.ts';
import { hasPermission } from './permissions.ts';
import type { Role } from './roles.ts';

const as = (role: Role, manualResolution = false) => ({
  can: (p: Parameters<typeof hasPermission>[1]) => hasPermission(role, p),
  manualResolution,
});

describe('finding lifecycle transitions', () => {
  it('lets analysts triage, accept risk and reopen', () => {
    expect(allowedTransitions('open', as('analyst')).sort()).toEqual(
      ['acknowledged', 'accepted_risk', 'remediation_in_progress'].sort(),
    );
    expect(canTransition('accepted_risk', 'open', as('analyst'))).toBe(true);
    expect(canTransition('remediation_in_progress', 'acknowledged', as('analyst'))).toBe(true);
  });

  it('allows manual resolution only for change-detection rules', () => {
    expect(canTransition('open', 'resolved', as('admin'))).toBe(false);
    expect(canTransition('open', 'resolved', as('admin', true))).toBe(true);
    expect(canTransition('accepted_risk', 'resolved', as('analyst', true))).toBe(true);
  });

  it('never moves a finding out of resolved by hand', () => {
    for (const role of ['admin', 'analyst', 'asset_owner', 'viewer'] as const) {
      expect(allowedTransitions('resolved', as(role, true))).toEqual([]);
    }
  });

  it('limits asset owners to starting and pausing remediation', () => {
    expect(allowedTransitions('open', as('asset_owner', true))).toEqual([
      'remediation_in_progress',
    ]);
    expect(allowedTransitions('remediation_in_progress', as('asset_owner'))).toEqual([
      'acknowledged',
    ]);
    expect(canTransition('open', 'accepted_risk', as('asset_owner'))).toBe(false);
    expect(canTransition('acknowledged', 'open', as('asset_owner'))).toBe(false);
  });

  it('gives viewers nothing', () => {
    for (const s of ['open', 'acknowledged', 'remediation_in_progress', 'accepted_risk'] as const) {
      expect(allowedTransitions(s, as('viewer', true))).toEqual([]);
    }
  });

  it('never offers a same-status transition', () => {
    for (const s of ['open', 'acknowledged', 'remediation_in_progress', 'accepted_risk'] as const) {
      expect(allowedTransitions(s, as('admin', true))).not.toContain(s);
    }
  });

  it('requires a reason and review date for accepted risk, a reason to resolve or reopen', () => {
    expect(transitionRequirements('open', 'accepted_risk')).toEqual({
      reason: 'required',
      reasonMin: 10,
      reviewDate: true,
    });
    expect(transitionRequirements('open', 'resolved').reason).toBe('required');
    expect(transitionRequirements('accepted_risk', 'open').reason).toBe('required');
    expect(transitionRequirements('open', 'acknowledged').reason).toBe('optional');
  });
});
