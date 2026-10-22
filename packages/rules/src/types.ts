import type {
  Criticality,
  DnsRecordType,
  ObservationResult,
  Severity,
} from '@exdomainvault/shared';

/**
 * Rule contract (design §8). Rules are pure functions of observations: no I/O, no clock reads
 * (use `context.now`), no randomness, no LLM. Severity and confidence come only from rule code.
 *
 * Wording discipline: an observation is not a vulnerability. Titles and descriptions state what was
 * observed and why it matters; they never claim compromise or exploitation.
 */

export type Confidence = 'low' | 'medium' | 'high';
export type { Severity };

export type RuleCategory = 'dns' | 'email' | 'tls' | 'http' | 'exposure' | 'registration' | 'asset';

export type ObservationKind = 'dns' | 'registration' | 'tls' | 'http' | 'port' | 'discovery';

// --- Observations as rules see them (normalised from storage; all times ISO UTC) -------------

interface ObservationBase {
  resultStatus: ObservationResult;
  observedAt: string;
  /** Scan job that produced the observation. */
  scanJobId: string;
  evidence: Record<string, unknown>;
}

export interface DnsRecordSetObservation extends ObservationBase {
  hostname: string;
  recordType: DnsRecordType;
  ttl: number | null;
  /** Presentation format, sorted; names keep their trailing dot; empty = no records (NODATA). */
  values: string[];
}

export interface RegistrationObservation extends ObservationBase {
  registrar: string | null;
  registeredAt: string | null;
  expiresAt: string | null;
  nameservers: string[];
  dataStatus: 'available' | 'redacted' | 'unavailable';
}

export interface TlsObservation extends ObservationBase {
  hostname: string;
  ipAddress: string;
  port: number;
  protocolVersion: string | null;
  notBefore: string | null;
  notAfter: string | null;
  issuer: string | null;
  subject: string | null;
  subjectAltNames: string[];
  fingerprintSha256: string | null;
  hostnameMatches: boolean | null;
}

export interface HttpObservation extends ObservationBase {
  url: string;
  ipAddress: string;
  statusCode: number | null;
  finalUrl: string | null;
  redirectCount: number;
  hstsEnabled: boolean | null;
}

export interface PortObservation extends ObservationBase {
  ipAddress: string;
  port: number;
  protocol: 'tcp';
  state: 'open' | 'closed' | 'filtered';
  service: string | null;
}

export interface DiscoveryObservation extends ObservationBase {
  hostname: string;
  source: string;
}

export interface ObservationSet {
  dns: DnsRecordSetObservation[];
  registration: RegistrationObservation[];
  tls: TlsObservation[];
  http: HttpObservation[];
  ports: PortObservation[];
  discovery: DiscoveryObservation[];
}

export const emptyObservationSet = (): ObservationSet => ({
  dns: [],
  registration: [],
  tls: [],
  http: [],
  ports: [],
  discovery: [],
});

// --- Context --------------------------------------------------------------------------------

export interface AssetContext {
  hostname: string;
  assetId: string | null;
  status: 'approved' | 'pending' | 'rejected' | 'suspended';
  monitoringEnabled: boolean;
}

/** A service that must not be publicly reachable unless explicitly accepted (EXP-002). */
export interface AdministrativeService {
  port: number;
  service: string;
  severity: Severity;
}

export interface EvaluationContext {
  /** Evaluation time (the job's completion time), for expiry calculations. */
  now: string;
  domain: {
    id: string;
    fqdn: string;
    criticality: Criticality;
    /** Verified by DNS TXT or admin authorisation at evaluation time. */
    verified: boolean;
  };
  scanJobId: string;
  /** Checks the job's profile listed (only these can produce or resolve findings). */
  checks: readonly string[];
  /** Known assets of the domain (approved, pending, …). */
  assets: readonly AssetContext[];
  administrativeServices: readonly AdministrativeService[];
}

export interface EvaluationInput {
  context: EvaluationContext;
  /** Observations produced by THIS successful job. */
  current: ObservationSet;
  /**
   * For change detection: the latest observation per key from earlier successful jobs of the same
   * domain (one per DNS name+type, the latest registration, per TLS host+ip+port, per HTTP url, per
   * ip+port, discovery hostnames from the previous successful discovery run). Empty on first scan.
   */
  previous: ObservationSet;
}

// --- Rule output ----------------------------------------------------------------------------

/** How exposed the affected component is; drives the risk exposure factor. */
export type ExposureLevel = 'public_record' | 'web' | 'network_service';

export interface FindingCandidate {
  /** Affected hostname (the domain itself for domain-level findings). */
  hostname: string;
  /**
   * Stable, short key for the affected component within the hostname (e.g. `dmarc`, `spf`,
   * `443`, `203.0.113.10:3389`, `ns`). Together with rule id, domain and hostname it forms the
   * fingerprint, so it must not contain volatile data (timestamps, TTLs, values that change).
   */
  component: string;
  title: string;
  /** Plain-language description of what was observed and why it matters (no compromise claims). */
  description: string;
  severity: Severity;
  confidence: Confidence;
  exposure: ExposureLevel;
  /** The observations/values the finding is based on (kept with the finding). */
  evidence: Record<string, unknown>;
}

export interface CheckedComponent {
  hostname: string;
  component: string;
}

export interface RuleOutcome {
  findings: FindingCandidate[];
  /**
   * Components for which this rule evaluated its condition with SUCCESSFUL evidence in the current
   * job. Active findings for these components that are not in `findings` are resolved. Never list a
   * component whose evidence was missing, failed or partial: that must neither raise nor resolve.
   */
  checked: CheckedComponent[];
}

export interface Advisory {
  title: string;
  summary: string;
  businessImpact: string;
  recommendedActions: string[];
  /** Reference URLs (standards, vendor docs). */
  references: string[];
}

export interface Rule {
  id: string;
  version: number;
  category: RuleCategory;
  title: string;
  /** Observation kinds the rule needs; without SUCCESSFUL current observations of these, it is skipped. */
  requires: readonly ObservationKind[];
  /** Checks one of which must be in the job's profile for this rule to run. */
  requiresChecks: readonly string[];
  defaultSeverity: Severity;
  defaultConfidence: Confidence;
  /** Human description of the evidence required (for docs/advisory-rules.md). */
  evidenceRequirements: string;
  /** Human description of the detection condition. */
  detection: string;
  /** Human description of the resolution condition. */
  resolution: string;
  evaluate(input: EvaluationInput): RuleOutcome;
  advisory(finding: FindingCandidate, context: EvaluationContext): Advisory;
}
