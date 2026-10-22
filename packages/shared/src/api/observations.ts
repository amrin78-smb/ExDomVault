import { z } from 'zod';

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
const evidenceSchema = z
  .record(z.string().max(64), z.unknown())
  .refine((v) => JSON.stringify(v).length <= 16_384, 'Evidence must be at most 16 KB.')
  .default({});

const observationBase = {
  /** Target of the job this observation belongs to. */
  targetId: z.uuid(),
  observedAt: isoDateTime,
  checkerVersion: z.string().regex(/^[0-9A-Za-z.+-]{1,40}$/),
  resultStatus: observationResultSchema,
  evidence: evidenceSchema,
};

const hostnameSchema = z
  .string()
  .min(1)
  .max(253)
  .regex(/^[a-z0-9_.-]+$/, 'Hostnames must be lowercase A-labels without a trailing dot.');

export const dnsObservationSchema = z.strictObject({
  kind: z.literal('dns'),
  ...observationBase,
  /** Name queried: the target or a name beneath the job's domain (e.g. `_dmarc.example.com`). */
  hostname: hostnameSchema,
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

export const observationSchema = z.discriminatedUnion('kind', [
  dnsObservationSchema,
  registrationObservationSchema,
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

/** Latest observation per (hostname, record type), and the latest registration observation. */
export const domainObservationsResponseSchema = z.object({
  dns: z.array(dnsRecordSetSchema),
  registration: registrationSnapshotSchema.nullable(),
});
export type DomainObservationsResponse = z.infer<typeof domainObservationsResponseSchema>;
