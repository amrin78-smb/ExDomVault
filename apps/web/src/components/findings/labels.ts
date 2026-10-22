import type { RiskInputsDto } from '@exdomainvault/shared';

/** Display labels for rule-engine vocabulary (category, confidence, exposure, history reasons). */
export const CATEGORY_LABELS: Record<string, string> = {
  dns: 'DNS',
  email: 'Email security',
  tls: 'TLS / certificates',
  http: 'HTTP',
  exposure: 'Network exposure',
  registration: 'Registration',
  asset: 'Assets',
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
  condition_absent: 'A successful scan confirmed the condition is gone',
};

export const historyReasonLabel = (reason: string) => REASON_LABELS[reason] ?? reason;
