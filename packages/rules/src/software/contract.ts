import type { ObservationSet, SoftwareIntel, VersionRange } from '../types.ts';

/**
 * Milestone 11 contract between the rules package and the server (implemented in this folder).
 * All functions are pure and deterministic.
 */

/** A product/version a host reported about itself, parsed from one observation. */
export interface SoftwareSighting {
  source: 'http_header' | 'service_identification';
  /** HTTP: the URL's hostname; service identification: null. */
  hostname: string | null;
  /** Service identification: the probed address and port; HTTP: the address connected to (or null). */
  ipAddress: string | null;
  port: number | null;
  /** Catalogue key (`SOFTWARE_PRODUCTS` in @exdomainvault/shared). */
  product: string;
  /** Normalised version text as disclosed (`7.4.3`, `1.1.1f`, `8.2p1`); null if hidden. */
  version: string | null;
  /** The banner it came from, ≤ 200 chars. */
  banner: string;
  /** e.g. `Ubuntu`, `Debian`, `Red Hat`, `CentOS` when the banner names a distribution. */
  backportDistribution: string | null;
  observedAt: string;
  scanJobId: string;
}

export interface EolStatus {
  cycle: string;
  eolDate: string | null;
  isEol: boolean;
  latestInCycle: string | null;
}

export interface SoftwareApi {
  /** Sightings from SUCCESSFUL http observations (evidence.server / evidence.xPoweredBy) and port
   * observations (evidence.product / evidence.version), deduplicated per location+product. */
  extractSoftware(observations: ObservationSet): SoftwareSighting[];
  /** -1 / 0 / 1; tolerant of letter suffixes (1.1.1w, 8.2p1) and distro tails (2.4.41-ubuntu). */
  compareVersions(a: string, b: string): number;
  versionInRange(version: string, range: VersionRange): boolean;
  /** The cycle a version belongs to and whether it is end-of-life at `now`; null if unknown. */
  eolStatus(
    product: string,
    version: string,
    cycles: SoftwareIntel['eolCycles'],
    now: string,
  ): EolStatus | null;
  /** Known-exploited advisories whose ranges include the version. */
  matchAdvisories(
    product: string,
    version: string,
    advisories: SoftwareIntel['advisories'],
  ): SoftwareIntel['advisories'][number][];
}
