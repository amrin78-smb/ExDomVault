/**
 * Synthetic fixture builders for rule tests (test-only; never imported by rule code).
 * All names use reserved example domains / documentation addresses. Keep this file additive:
 * several rule test files share it.
 */
import type { DnsRecordType, ObservationResult } from '@exdomainvault/shared';
import {
  emptyObservationSet,
  type AssetContext,
  type DiscoveryObservation,
  type DnsRecordSetObservation,
  type EvaluationContext,
  type EvaluationInput,
  type HttpObservation,
  type ObservationSet,
  type PortObservation,
  type RegistrationObservation,
  type TlsObservation,
} from '../types.ts';

export const NOW = '2026-10-22T00:00:00.000Z';
export const APEX = 'example.com';
export const JOB_ID = 'job-current';
export const PREVIOUS_JOB_ID = 'job-previous';

interface BaseOptions {
  status?: ObservationResult;
  observedAt?: string;
  scanJobId?: string;
  evidence?: Record<string, unknown>;
}

function base(opts: BaseOptions) {
  return {
    resultStatus: opts.status ?? 'success',
    observedAt: opts.observedAt ?? NOW,
    scanJobId: opts.scanJobId ?? JOB_ID,
    evidence: opts.evidence ?? {},
  } as const;
}

export function context(overrides: Partial<EvaluationContext> = {}): EvaluationContext {
  return {
    now: NOW,
    domain: { id: 'domain-1', fqdn: APEX, criticality: 'high', verified: true },
    scanJobId: JOB_ID,
    checks: ['dns', 'rdap', 'discovery'],
    assets: [],
    administrativeServices: [],
    ...overrides,
  };
}

/** A DNS record set; `values` are presentation format (sorted by the builder). */
export function dns(
  hostname: string,
  recordType: DnsRecordType,
  values: string[],
  opts: BaseOptions & { ttl?: number | null } = {},
): DnsRecordSetObservation {
  const status = opts.status ?? 'success';
  return {
    ...base(opts),
    hostname,
    recordType,
    ttl: opts.ttl === undefined ? 300 : opts.ttl,
    values: status === 'success' ? [...values].sort() : [],
    evidence:
      opts.evidence ??
      (status === 'success' && values.length === 0 ? { rcode: 'NOERROR', noData: true } : {}),
  };
}

/** A failed DNS lookup (resolver error/timeout): never evidence of presence or absence. */
export function dnsFailed(
  hostname: string,
  recordType: DnsRecordType,
  status: Exclude<ObservationResult, 'success'> = 'error',
): DnsRecordSetObservation {
  return dns(hostname, recordType, [], { status, evidence: { error: 'resolver_error' } });
}

export function registration(
  fields: Partial<Omit<RegistrationObservation, keyof ReturnType<typeof base>>> = {},
  opts: BaseOptions = {},
): RegistrationObservation {
  return {
    ...base(opts),
    registrar: 'Example Registrar, Inc.',
    registeredAt: '2015-01-01T00:00:00.000Z',
    expiresAt: '2027-06-01T00:00:00.000Z',
    nameservers: ['ns1.example.net', 'ns2.example.net'],
    dataStatus: 'available',
    ...fields,
  };
}

export function discovery(
  hostname: string,
  opts: BaseOptions & { source?: string } = {},
): DiscoveryObservation {
  return { ...base(opts), hostname, source: opts.source ?? 'ct' };
}

export function tls(
  fields: Partial<Omit<TlsObservation, keyof ReturnType<typeof base>>> = {},
  opts: BaseOptions = {},
): TlsObservation {
  return {
    ...base(opts),
    hostname: `www.${APEX}`,
    ipAddress: '203.0.113.10',
    port: 443,
    protocolVersion: 'TLSv1.3',
    notBefore: '2026-09-01T00:00:00.000Z',
    notAfter: '2026-12-01T00:00:00.000Z',
    issuer: 'CN=Example Test CA',
    subject: `CN=www.${APEX}`,
    subjectAltNames: [`www.${APEX}`],
    fingerprintSha256: 'a'.repeat(64),
    hostnameMatches: true,
    ...fields,
  };
}

export function http(
  fields: Partial<Omit<HttpObservation, keyof ReturnType<typeof base>>> = {},
  opts: BaseOptions = {},
): HttpObservation {
  return {
    ...base(opts),
    url: `https://www.${APEX}/`,
    ipAddress: '203.0.113.10',
    statusCode: 200,
    finalUrl: `https://www.${APEX}/`,
    redirectCount: 0,
    hstsEnabled: true,
    ...fields,
  };
}

export function port(
  fields: Partial<Omit<PortObservation, keyof ReturnType<typeof base>>> = {},
  opts: BaseOptions = {},
): PortObservation {
  return {
    ...base(opts),
    ipAddress: '203.0.113.10',
    port: 443,
    protocol: 'tcp',
    state: 'open',
    service: 'https',
    ...fields,
  };
}

export function asset(
  hostname: string,
  overrides: Partial<Omit<AssetContext, 'hostname'>> = {},
): AssetContext {
  return {
    hostname,
    assetId: `asset-${hostname}`,
    status: 'approved',
    monitoringEnabled: true,
    ...overrides,
  };
}

/** Build an observation set from any subset of kinds. */
export function observations(parts: Partial<ObservationSet> = {}): ObservationSet {
  return { ...emptyObservationSet(), ...parts };
}

/** Mark observations as coming from an earlier successful job. */
export function asPrevious<T extends { scanJobId: string; observedAt: string }>(items: T[]): T[] {
  return items.map((o) => ({
    ...o,
    scanJobId: PREVIOUS_JOB_ID,
    observedAt: '2026-10-15T00:00:00.000Z',
  }));
}

export function input(
  current: Partial<ObservationSet> = {},
  previous: Partial<ObservationSet> = {},
  ctx: Partial<EvaluationContext> = {},
): EvaluationInput {
  return {
    context: context(ctx),
    current: observations(current),
    previous: observations(previous),
  };
}
