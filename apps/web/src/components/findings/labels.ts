import type { FindingStatus, FindingUserRef, RiskInputsDto } from '@exdomainvault/shared';

/** Display labels for rule-engine vocabulary (category, confidence, exposure, history reasons). */
export const CATEGORY_LABELS: Record<string, string> = {
  dns: 'DNS',
  email: 'Email security',
  tls: 'TLS / certificates',
  http: 'HTTP',
  exposure: 'Network exposure',
  registration: 'Registration',
  asset: 'Assets',
  software: 'Exposed software',
};

export const CONFIDENCE_LABELS: Record<string, string> = {
  low: 'Low confidence',
  medium: 'Medium confidence',
  high: 'High confidence',
};

export const EXPOSURE_LABELS: Record<RiskInputsDto['exposure'], string> = {
  public_record: 'Public record (DNS / registration data)',
  web: 'Web endpoint reachable by any visitor',
  network_service: 'Network service reachable from the internet',
};

export const SORT_LABELS: Record<string, string> = {
  '-riskScore': 'Highest risk first',
  riskScore: 'Lowest risk first',
  '-severity': 'Most severe first',
  '-lastSeenAt': 'Most recently seen',
  '-firstSeenAt': 'Newest first',
};

const REASON_LABELS: Record<string, string> = {
  detected: 'First detected by a scan',
  recurrence: 'Observed again after being resolved',
  condition_absent: 'Resolved by scan',
  accepted_risk_expired: 'Risk acceptance expired',
  asset_decided: 'Resolved by asset review',
};

/** Friendly text for a status-history reason code; `manual` names the user who made the change. */
export function historyReasonLabel(reason: string, changedBy?: { email: string } | null): string {
  if (reason === 'manual') return `Changed by ${changedBy?.email ?? 'a user'}`;
  return REASON_LABELS[reason] ?? reason;
}

/** Display name of a user reference (assignee, approver, comment author). */
export const userLabel = (user: FindingUserRef | null | undefined, fallback = 'Unknown user') =>
  user ? (user.displayName ?? user.email) : fallback;

/** Button text for moving a finding from `from` to `to`. */
export function transitionLabel(from: FindingStatus, to: FindingStatus): string {
  switch (to) {
    case 'acknowledged':
      return from === 'open' ? 'Acknowledge' : 'Pause remediation';
    case 'remediation_in_progress':
      return 'Start remediation';
    case 'open':
      return from === 'accepted_risk' ? 'Withdraw risk acceptance' : 'Reopen';
    case 'accepted_risk':
      return 'Accept risk';
    case 'resolved':
      return 'Mark as reviewed (resolve)';
  }
}

/** Why a bulk update left a finding unchanged (server codes; unknown codes are shown as-is). */
export const SKIP_CODE_LABELS: Record<string, string> = {
  not_found: 'not found or not visible to you',
  invalid_transition: 'change not possible from their current status',
  transition_not_allowed: 'change not permitted for your role',
  no_change: 'already in that state',
};
