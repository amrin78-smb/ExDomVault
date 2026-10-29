import {
  DISCOVERY_PROFILE_KEY,
  type Domain,
  type ScanJob,
  type ScanProfile,
} from '@exdomainvault/shared';

/** Discovery jobs look up names in public logs; scan jobs run a profile's checks. */
export const JOB_TYPE_LABELS: Record<ScanJob['jobType'], string> = {
  scan: 'Scan',
  discovery: 'Discovery',
};

/**
 * Profiles that may be requested through the scan picker. Discovery has its own endpoint and job
 * type, and brand monitoring (lookalike checks) its own endpoint, so neither is ever offered here
 * even if the server lists it.
 */
export const isScanPickerProfile = (p: ScanProfile) =>
  p.key !== DISCOVERY_PROFILE_KEY &&
  !p.config.checks.includes('discovery') &&
  !p.config.checks.includes('lookalike');

/** Why a profile cannot be used for this domain right now, or null if it can. */
export function unavailableReason(
  profile: ScanProfile,
  domain: Pick<Domain, 'verificationStatus' | 'verificationExpiresAt'>,
  activeScanningEnabled: boolean,
): string | null {
  if (!profile.enabled) return 'disabled';
  if (!profile.config.active) return null;
  if (!activeScanningEnabled) return 'active scanning not enabled yet';
  if (domain.verificationStatus !== 'verified') return 'needs verification';
  if (domain.verificationExpiresAt && new Date(domain.verificationExpiresAt) <= new Date()) {
    return 'authorisation lapsed';
  }
  return null;
}
