import type { FindingStatus } from '../api/findings.ts';
import type { Permission } from './permissions.ts';

/**
 * Finding lifecycle (design §9): open → acknowledged → remediation_in_progress → resolved, plus
 * accepted_risk. This table is the single definition of which USER transitions exist and which
 * permission each needs; the API enforces it and the UI only uses it to offer actions.
 *
 * - `resolved` is normally set by the system after a successful scan confirms the condition is
 *   absent. Users may resolve only findings of change-detection rules (`manualResolution`).
 * - Nothing leaves `resolved` by hand: a recurrence observed by a successful scan reopens it.
 * - Asset owners (`findings:remediate`) can start and pause remediation on findings they can see.
 */
interface TransitionDef {
  from: readonly FindingStatus[];
  to: FindingStatus;
  permission: Permission;
  /** Only for rules flagged `manualResolution`. */
  manualResolutionOnly?: boolean;
}

const ACTIVE: readonly FindingStatus[] = ['open', 'acknowledged', 'remediation_in_progress'];

const TRANSITIONS: readonly TransitionDef[] = [
  { from: ['open'], to: 'acknowledged', permission: 'findings:triage' },
  { from: ['remediation_in_progress'], to: 'acknowledged', permission: 'findings:remediate' },
  {
    from: ['open', 'acknowledged'],
    to: 'remediation_in_progress',
    permission: 'findings:remediate',
  },
  {
    from: ['acknowledged', 'remediation_in_progress', 'accepted_risk'],
    to: 'open',
    permission: 'findings:triage',
  },
  { from: ACTIVE, to: 'accepted_risk', permission: 'findings:accept_risk' },
  {
    from: [...ACTIVE, 'accepted_risk'],
    to: 'resolved',
    permission: 'findings:triage',
    manualResolutionOnly: true,
  },
];

export interface TransitionContext {
  can: (permission: Permission) => boolean;
  manualResolution: boolean;
}

/** Statuses a user may move a finding to from `from` (empty when none). */
export function allowedTransitions(from: FindingStatus, ctx: TransitionContext): FindingStatus[] {
  return TRANSITIONS.filter(
    (t) =>
      t.from.includes(from) &&
      ctx.can(t.permission) &&
      (!t.manualResolutionOnly || ctx.manualResolution),
  ).map((t) => t.to);
}

export function canTransition(
  from: FindingStatus,
  to: FindingStatus,
  ctx: TransitionContext,
): boolean {
  return allowedTransitions(from, ctx).includes(to);
}

export interface TransitionRequirements {
  reason: 'required' | 'optional';
  /** Minimum reason length when required. */
  reasonMin: number;
  reviewDate: boolean;
}

/** What a status change must carry (server-enforced; the UI shows the same fields). */
export function transitionRequirements(
  from: FindingStatus,
  to: FindingStatus,
): TransitionRequirements {
  if (to === 'accepted_risk') return { reason: 'required', reasonMin: 10, reviewDate: true };
  if (to === 'resolved') return { reason: 'required', reasonMin: 3, reviewDate: false };
  if (to === 'open' && from !== 'open')
    return { reason: 'required', reasonMin: 3, reviewDate: false };
  return { reason: 'optional', reasonMin: 3, reviewDate: false };
}
