import type { Criticality } from '@exdomainvault/shared';
import type { ExposureLevel, Severity } from './types.ts';

/**
 * Transparent risk model v1 (design §8):
 *
 *   risk_score = clamp(round(severity_weight × exposure_factor × criticality_factor), 0, 100)
 *
 * Severity stays separate from risk. The inputs are stored with every finding so the score is
 * explainable; changing any factor requires a new model version.
 */
export const RISK_MODEL_VERSION = 'v1';

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  informational: 5,
  low: 25,
  medium: 50,
  high: 75,
  critical: 95,
};

export const EXPOSURE_FACTOR: Record<ExposureLevel, number> = {
  /** Published configuration (DNS, registration): visible to anyone, not a reachable service. */
  public_record: 0.8,
  /** A web endpoint reachable by any visitor. */
  web: 1.0,
  /** A network service reachable from the internet. */
  network_service: 1.1,
};

export const CRITICALITY_FACTOR: Record<Criticality, number> = {
  low: 0.7,
  medium: 0.85,
  high: 1.0,
  critical: 1.15,
};

export interface RiskInputs {
  model: typeof RISK_MODEL_VERSION;
  severity: Severity;
  severityWeight: number;
  exposure: ExposureLevel;
  exposureFactor: number;
  criticality: Criticality;
  criticalityFactor: number;
}

export function riskScore(
  severity: Severity,
  exposure: ExposureLevel,
  criticality: Criticality,
): { score: number; inputs: RiskInputs } {
  const inputs: RiskInputs = {
    model: RISK_MODEL_VERSION,
    severity,
    severityWeight: SEVERITY_WEIGHT[severity],
    exposure,
    exposureFactor: EXPOSURE_FACTOR[exposure],
    criticality,
    criticalityFactor: CRITICALITY_FACTOR[criticality],
  };
  const raw = inputs.severityWeight * inputs.exposureFactor * inputs.criticalityFactor;
  return { score: Math.min(100, Math.max(0, Math.round(raw))), inputs };
}
