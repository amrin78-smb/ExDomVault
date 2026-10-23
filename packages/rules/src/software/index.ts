import type { SoftwareApi } from './contract.ts';
import { extractSoftware } from './extract.ts';
import { eolStatus, matchAdvisories } from './intel.ts';
import { compareVersions, versionInRange } from './version.ts';

export type { EolStatus, SoftwareApi, SoftwareSighting } from './contract.ts';
export {
  detectDistribution,
  parseHeaderBanner,
  parseServiceBanner,
  sightingLocation,
} from './extract.ts';
export { compareVersions, eolStatus, extractSoftware, matchAdvisories, versionInRange };

/** The Milestone 11 software API as one object (type-checked against the contract). */
export const softwareApi: SoftwareApi = {
  extractSoftware,
  compareVersions,
  versionInRange,
  eolStatus,
  matchAdvisories,
};
