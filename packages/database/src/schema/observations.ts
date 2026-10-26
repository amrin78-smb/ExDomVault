import {
  boolean,
  index,
  inet,
  integer,
  jsonb,
  pgTable,
  text,
  uniqueIndex,
  uuid,
  type PgColumnBuilderBase,
  type PgTableExtraConfigValue,
} from 'drizzle-orm/pg-core';
import type { BuildExtraConfigColumns } from 'drizzle-orm';
import { assets } from './assets.ts';
import { id, ts } from './common.ts';
import { domains } from './domains.ts';
import { observationResult, registrationDataStatus } from './enums.ts';
import { scanJobs, scanJobTargets } from './scans.ts';

/**
 * Columns shared by every observation table (design §5.8). `result_id` is the idempotency key
 * supplied with a worker result, so duplicate submissions insert nothing.
 */
const observationColumns = () => ({
  id: id(),
  resultId: text('result_id').notNull(),
  assetId: uuid('asset_id').references(() => assets.id, { onDelete: 'cascade' }),
  scanJobId: uuid('scan_job_id')
    .notNull()
    .references(() => scanJobs.id, { onDelete: 'cascade' }),
  scanJobTargetId: uuid('scan_job_target_id').references(() => scanJobTargets.id, {
    onDelete: 'set null',
  }),
  observedAt: ts('observed_at').notNull(),
  checker: text('checker').notNull(),
  checkerVersion: text('checker_version').notNull(),
  resultStatus: observationResult('result_status').notNull(),
  evidence: jsonb('evidence').$type<Record<string, unknown>>().notNull().default({}),
});

type ObservationTableExtras = Record<string, PgColumnBuilderBase>;
type ObservationColumns<T extends ObservationTableExtras> = BuildExtraConfigColumns<
  string,
  ReturnType<typeof observationColumns> & T,
  'pg'
>;

function observationTable<T extends ObservationTableExtras>(
  name: string,
  extras: T,
  /** Extra per-table indexes (e.g. latest-per-key lookups). */
  more: (t: ObservationColumns<T>) => PgTableExtraConfigValue[] = () => [],
) {
  return pgTable(name, { ...observationColumns(), ...extras }, (t) => [
    uniqueIndex(`${name}_result_id_key`).on(t.resultId),
    index(`${name}_asset_time_idx`).on(t.assetId, t.observedAt),
    index(`${name}_job_idx`).on(t.scanJobId),
    ...more(t as unknown as ObservationColumns<T>),
  ]);
}

export const dnsObservations = observationTable('dns_observations', {
  hostname: text('hostname').notNull(),
  recordType: text('record_type').notNull(),
  ttl: integer('ttl'),
  recordValues: text('record_values').array().notNull().default([]),
});

export const registrationObservations = observationTable('registration_observations', {
  domainId: uuid('domain_id')
    .notNull()
    .references(() => domains.id, { onDelete: 'cascade' }),
  registrar: text('registrar'),
  registeredAt: ts('registered_at'),
  expiresAt: ts('expires_at'),
  nameservers: text('nameservers').array().notNull().default([]),
  dataStatus: registrationDataStatus('data_status').notNull(),
});

export const tlsObservations = observationTable(
  'tls_observations',
  {
    hostname: text('hostname').notNull(),
    ipAddress: inet('ip_address'),
    port: integer('port').notNull(),
    protocolVersion: text('protocol_version'),
    notBefore: ts('not_before'),
    notAfter: ts('not_after'),
    issuer: text('issuer'),
    subject: text('subject'),
    subjectAltNames: text('subject_alt_names').array().notNull().default([]),
    fingerprintSha256: text('fingerprint_sha256'),
    hostnameMatches: boolean('hostname_matches'),
  },
  // Latest certificate per (hostname, port) — GET /certificates (Milestone 13).
  (t) => [index('tls_observations_host_port_time_idx').on(t.hostname, t.port, t.observedAt.desc())],
);

export const httpObservations = observationTable('http_observations', {
  url: text('url').notNull(),
  ipAddress: inet('ip_address'),
  statusCode: integer('status_code'),
  finalUrl: text('final_url'),
  redirectCount: integer('redirect_count').notNull().default(0),
  hstsEnabled: boolean('hsts_enabled'),
});

export const portObservations = observationTable(
  'port_observations',
  {
    ipAddress: inet('ip_address').notNull(),
    port: integer('port').notNull(),
    protocol: text('protocol').notNull().default('tcp'),
    state: text('state').notNull(),
    service: text('service'),
  },
  // Latest state per (address, port, protocol) — GET /ports, asset roles (Milestone 13).
  (t) => [
    index('port_observations_ip_port_time_idx').on(
      t.ipAddress,
      t.port,
      t.protocol,
      t.observedAt.desc(),
    ),
  ],
);

export const discoveryObservations = observationTable('discovery_observations', {
  domainId: uuid('domain_id')
    .notNull()
    .references(() => domains.id, { onDelete: 'cascade' }),
  hostname: text('hostname').notNull(),
  source: text('source').notNull(),
  /** The name was seen only as a wildcard (`*.name`), stripped to `name`. */
  wildcard: boolean('wildcard').notNull().default(false),
});
