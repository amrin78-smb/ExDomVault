import { DISCOVERY_PROFILE_KEY, type ScanJob, type ScanProfile } from '@exdomainvault/shared';

/** Discovery jobs look up names in public logs; scan jobs run a profile's checks. */
export const JOB_TYPE_LABELS: Record<ScanJob['jobType'], string> = {
  scan: 'Scan',
  discovery: 'Discovery',
};

/**
 * Profiles that may be requested through the scan picker. Discovery has its own endpoint and job
 * type, so it is never offered here even if the server lists it.
 */
export const isScanPickerProfile = (p: ScanProfile) =>
  p.key !== DISCOVERY_PROFILE_KEY && !p.config.checks.includes('discovery');
