import { z } from 'zod';
import { isValidHostname } from '../hostname/labels.ts';

/**
 * Observations submitted by the worker with job results (design §5.8), and the read model the UI
 * shows. Observations are evidence only; findings are derived later by the deterministic rules
 * engine (Milestone 7). Milestone 5 carries DNS and registration (RDAP) observations; TLS, HTTP and
 * port observations follow with active scanning in Milestone 6.
 */

const isoDateTime = z.iso.datetime();

/** Outcome of one check. Only `success` observations may ever resolve findings. */
export const OBSERVATION_RESULTS = ['success', 'partial', 'error', 'timeout', 'skipped'] as const;
export const observationResultSchema = z.enum(OBSERVATION_RESULTS);
export type ObservationResult = z.infer<typeof observationResultSchema>;

export const DNS_RECORD_TYPES = [
  'A',
  'AAAA',
  'CNAME',
  'MX',
  'NS',
  'TXT',
  'CAA',
  'SOA',
  'DS',
  'DNSKEY',
] as const;
export const dnsRecordTypeSchema = z.enum(DNS_RECORD_TYPES);
export type DnsRecordType = z.infer<typeof dnsRecordTypeSchema>;

/** Small, structured, non-secret supporting data (resolver used, error class, raw RDAP status...). */
export const MAX_EVIDENCE_BYTES = 16_384;
// Present in every target runtime (Workers, browsers, Node); declared because this package compiles
// without DOM or Node typings.
declare const TextEncoder: new () => { encode(input: string): Uint8Array };
const utf8 = new TextEncoder();
const evidenceSchema = z
  .record(z.string().max(64), z.unknown())
  // Measured in UTF-8 bytes (what is stored), not UTF-16 code units.
  .refine(
    (v) => utf8.encode(JSON.stringify(v)).length <= MAX_EVIDENCE_BYTES,
    'Evidence must be at most 16 KB.',
  )
  .default({});

const observationBase = {
  /** Target of the job this observation belongs to. */
  targetId: z.uuid(),
  observedAt: isoDateTime,
  checkerVersion: z.string().regex(/^[0-9A-Za-z.+-]{1,40}$/),
  resultStatus: observationResultSchema,
  evidence: evidenceSchema,
};

const HOSTNAME_MESSAGE =
  'Hostnames must be lowercase A-labels (1–63 letters, digits or inner hyphens each) without a trailing dot.';

/** A host that may be connected to: LDH labels only. */
const hostnameSchema = z
  .string()
  .min(1)
  .max(253)
  .refine((v) => isValidHostname(v), HOSTNAME_MESSAGE);

/** A DNS query name: as `hostnameSchema`, plus leading service labels such as `_dmarc`. */
const dnsQueryNameSchema = z
  .string()
  .min(1)
  .max(253)
  .refine((v) => isValidHostname(v, { allowServiceLabels: true }), HOSTNAME_MESSAGE);

export const dnsObservationSchema = z.strictObject({
  kind: z.literal('dns'),
  ...observationBase,
  /** Name queried: the target or a name beneath the job's domain (e.g. `_dmarc.example.com`). */
  hostname: dnsQueryNameSchema,
  recordType: dnsRecordTypeSchema,
  ttl: z.int().min(0).max(2_147_483_647).nullable(),
  /** Presentation-format record data, sorted. Empty when the name/type has no records. */
  values: z.array(z.string().max(4096)).max(100),
});
export type DnsObservation = z.infer<typeof dnsObservationSchema>;

export const REGISTRATION_DATA_STATUSES = ['available', 'redacted', 'unavailable'] as const;

export const registrationObservationSchema = z.strictObject({
  kind: z.literal('registration'),
  ...observationBase,
  registrar: z.string().max(300).nullable(),
  registeredAt: isoDateTime.nullable(),
  expiresAt: isoDateTime.nullable(),
  nameservers: z.array(hostnameSchema).max(20),
  /** `redacted`: the registry withheld data for privacy; `unavailable`: no RDAP data obtained. */
  dataStatus: z.enum(REGISTRATION_DATA_STATUSES),
});
export type RegistrationObservation = z.infer<typeof registrationObservationSchema>;

/** IPv4/IPv6 address in canonical text form (validated as public on the server). */
const ipAddressSchema = z.union([z.ipv4(), z.ipv6()]);

const sha256HexSchema = z.string().regex(/^[0-9a-f]{64}$/);

/** The TLS check that produced an observation (a profile must list it). */
export const TLS_OBSERVATION_CHECKS = ['tls_certificate', 'tls_configuration'] as const;

export const tlsObservationSchema = z.strictObject({
  kind: z.literal('tls'),
  ...observationBase,
  /**
   * `tls_certificate` (web tier) inspects the certificate a hostname serves; `tls_configuration`
   * (network tier) probes protocol support, so its address must lie in an approved network.
   */
  check: z.enum(TLS_OBSERVATION_CHECKS).default('tls_certificate'),
  /** SNI hostname; must be the target's own hostname. */
  hostname: hostnameSchema,
  /** The validated address the connection was pinned to. */
  ipAddress: ipAddressSchema,
  port: z.int().min(1).max(65535),
  protocolVersion: z.string().max(20).nullable(),
  notBefore: isoDateTime.nullable(),
  notAfter: isoDateTime.nullable(),
  issuer: z.string().max(1000).nullable(),
  subject: z.string().max(1000).nullable(),
  subjectAltNames: z.array(z.string().max(253)).max(200),
  fingerprintSha256: sha256HexSchema.nullable(),
  /** Certificate matches the hostname (SNI) per RFC 6125. */
  hostnameMatches: z.boolean().nullable(),
});
export type TlsObservation = z.infer<typeof tlsObservationSchema>;

export const httpObservationSchema = z.strictObject({
  kind: z.literal('http'),
  ...observationBase,
  /** First URL requested (`http(s)://<hostname>[:port]/`); the host must be the target's hostname. */
  url: z.string().max(2048),
  ipAddress: ipAddressSchema,
  statusCode: z.int().min(100).max(599).nullable(),
  /** Last URL reached after validated redirects (or the stopping point if a hop was refused). */
  finalUrl: z.string().max(2048).nullable(),
  redirectCount: z.int().min(0).max(10),
  hstsEnabled: z.boolean().nullable(),
});
export type HttpObservation = z.infer<typeof httpObservationSchema>;

export const portObservationSchema = z.strictObject({
  kind: z.literal('port'),
  ...observationBase,
  ipAddress: ipAddressSchema,
  port: z.int().min(1).max(65535),
  protocol: z.literal('tcp'),
  state: z.enum(['open', 'closed', 'filtered']),
  /** Service name from limited identification (e.g. `https`, `ssh`), product/version in evidence. */
  service: z.string().max(100).nullable(),
});
export type PortObservation = z.infer<typeof portObservationSchema>;

export const observationSchema = z.discriminatedUnion('kind', [
  dnsObservationSchema,
  registrationObservationSchema,
  tlsObservationSchema,
  httpObservationSchema,
  portObservationSchema,
]);
export type Observation = z.infer<typeof observationSchema>;

export const MAX_OBSERVATIONS_PER_SUBMISSION = 500;

// --- Read model (UI) ----------------------------------------------------------------------------

export const dnsRecordSetSchema = z.object({
  hostname: z.string(),
  recordType: dnsRecordTypeSchema,
  ttl: z.int().nullable(),
  values: z.array(z.string()),
  resultStatus: observationResultSchema,
  observedAt: isoDateTime,
  scanJobId: z.uuid(),
});
export type DnsRecordSet = z.infer<typeof dnsRecordSetSchema>;

export const registrationSnapshotSchema = z.object({
  registrar: z.string().nullable(),
  registeredAt: isoDateTime.nullable(),
  expiresAt: isoDateTime.nullable(),
  nameservers: z.array(z.string()),
  dataStatus: z.enum(REGISTRATION_DATA_STATUSES),
  resultStatus: observationResultSchema,
  observedAt: isoDateTime,
  scanJobId: z.uuid(),
});
export type RegistrationSnapshot = z.infer<typeof registrationSnapshotSchema>;

const readBase = {
  resultStatus: observationResultSchema,
  observedAt: isoDateTime,
  scanJobId: z.uuid(),
  evidence: z.record(z.string(), z.unknown()),
};

export const tlsSnapshotSchema = z.object({
  hostname: z.string(),
  ipAddress: z.string(),
  port: z.int(),
  protocolVersion: z.string().nullable(),
  notBefore: isoDateTime.nullable(),
  notAfter: isoDateTime.nullable(),
  issuer: z.string().nullable(),
  subject: z.string().nullable(),
  subjectAltNames: z.array(z.string()),
  fingerprintSha256: z.string().nullable(),
  hostnameMatches: z.boolean().nullable(),
  ...readBase,
});
export type TlsSnapshot = z.infer<typeof tlsSnapshotSchema>;

export const httpSnapshotSchema = z.object({
  url: z.string(),
  ipAddress: z.string(),
  statusCode: z.int().nullable(),
  finalUrl: z.string().nullable(),
  redirectCount: z.int(),
  hstsEnabled: z.boolean().nullable(),
  ...readBase,
});
export type HttpSnapshot = z.infer<typeof httpSnapshotSchema>;

export const portSnapshotSchema = z.object({
  ipAddress: z.string(),
  port: z.int(),
  protocol: z.string(),
  state: z.enum(['open', 'closed', 'filtered']),
  service: z.string().nullable(),
  ...readBase,
});
export type PortSnapshot = z.infer<typeof portSnapshotSchema>;

/**
 * Latest observation per (hostname, record type); latest registration; latest TLS per
 * (hostname, ip, port); latest HTTP per url; latest port state per (ip, port).
 */
export const domainObservationsResponseSchema = z.object({
  dns: z.array(dnsRecordSetSchema),
  registration: registrationSnapshotSchema.nullable(),
  tls: z.array(tlsSnapshotSchema).default([]),
  http: z.array(httpSnapshotSchema).default([]),
  ports: z.array(portSnapshotSchema).default([]),
});
export type DomainObservationsResponse = z.infer<typeof domainObservationsResponseSchema>;
