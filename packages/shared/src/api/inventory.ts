import { z } from 'zod';
import { assetRoleSchema } from '../domain/asset-roles.ts';
import { paginatedSchema } from './pagination.ts';

/**
 * Cross-domain inventory views (Milestone 13). Read-only projections of data already collected:
 * latest port, certificate and software observations, asset roles, hosting and IP geolocation.
 * All scoped like other lists (asset owners: only their assets). Pages capped at 100 items.
 *
 *   GET /api/v1/ports             (`assets:read`)
 *   GET /api/v1/certificates      (`assets:read`)
 *   GET /api/v1/vulnerabilities   (`findings:read`)
 *   GET /api/v1/attack-surface    (`assets:read`)
 */

const isoDateTime = z.iso.datetime();
const ref = z.object({ id: z.uuid(), fqdn: z.string() });
const pageParams = {
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
};
const search = z.string().trim().min(1).max(100).optional();
const countryCode = z.string().regex(/^[A-Z]{2}$/);

// --- Open ports ---------------------------------------------------------------------------------

export const portsQuerySchema = z.object({
  state: z.enum(['open', 'closed', 'filtered', 'all']).default('open'),
  port: z.coerce.number().int().min(1).max(65535).optional(),
  domainId: z.uuid().optional(),
  /** Matches IP, hostname or service name. */
  q: search,
  sort: z.enum(['port', 'ip', 'last_observed']).default('port'),
  ...pageParams,
});
export type PortsQuery = z.input<typeof portsQuerySchema>;

/** Latest observation per (ip, port, protocol) on approved networks. */
export const portItemSchema = z.object({
  ipAddress: z.string(),
  port: z.int(),
  protocol: z.string(),
  state: z.enum(['open', 'closed', 'filtered']),
  service: z.string().nullable(),
  /** Assets currently resolving to this address (visible ones only). */
  hostnames: z.array(z.object({ assetId: z.uuid(), hostname: z.string() })),
  domain: ref.nullable(),
  country: countryCode.nullable(),
  /** The port is not on the allowed exposure policy (an active EXP-002 finding exists). */
  policyViolation: z.boolean(),
  firstObservedAt: isoDateTime,
  lastObservedAt: isoDateTime,
});
export type PortItem = z.infer<typeof portItemSchema>;
export const portsResponseSchema = paginatedSchema(portItemSchema).extend({
  /** Counts over the whole filtered set (ignores paging), by state. */
  counts: z.object({ open: z.int(), closed: z.int(), filtered: z.int() }),
});
export type PortsResponse = z.infer<typeof portsResponseSchema>;

// --- Certificates -------------------------------------------------------------------------------

export const CERTIFICATE_STATUSES = [
  'expired',
  'expiring',
  'valid',
  'mismatch',
  'untrusted',
] as const;
export type CertificateStatus = (typeof CERTIFICATE_STATUSES)[number];
/** "Expiring" = notAfter within this many days. */
export const CERTIFICATE_EXPIRING_DAYS = 30;

export const certificatesQuerySchema = z.object({
  status: z.enum(CERTIFICATE_STATUSES).optional(),
  domainId: z.uuid().optional(),
  /** Matches hostname, issuer or subject. */
  q: search,
  sort: z.enum(['expiry', 'hostname']).default('expiry'),
  ...pageParams,
});
export type CertificatesQuery = z.input<typeof certificatesQuerySchema>;

/** Latest successful TLS observation per (hostname, port), any address. */
export const certificateItemSchema = z.object({
  hostname: z.string(),
  domain: ref,
  assetId: z.uuid().nullable(),
  ipAddress: z.string(),
  port: z.int(),
  issuer: z.string().nullable(),
  subject: z.string().nullable(),
  subjectAltNames: z.array(z.string()),
  notBefore: isoDateTime.nullable(),
  notAfter: isoDateTime.nullable(),
  daysLeft: z.int().nullable(),
  hostnameMatches: z.boolean().nullable(),
  /** Chain validated against the worker's trust store; null when not recorded. */
  trusted: z.boolean().nullable(),
  protocolVersion: z.string().nullable(),
  /** Primary status: expired > mismatch > untrusted > expiring > valid. */
  status: z.enum(CERTIFICATE_STATUSES),
  observedAt: isoDateTime,
});
export type CertificateItem = z.infer<typeof certificateItemSchema>;
export const certificatesResponseSchema = paginatedSchema(certificateItemSchema).extend({
  counts: z.record(z.enum(CERTIFICATE_STATUSES), z.int()),
});
export type CertificatesResponse = z.infer<typeof certificatesResponseSchema>;

// --- Vulnerabilities ----------------------------------------------------------------------------

export const vulnerabilitiesQuerySchema = z.object({
  kev: z
    .enum(['true', 'false'])
    .transform((v) => v === 'true')
    .optional(),
  /** Matches CVE id, product or vendor/title. */
  q: search,
  sort: z.enum(['cvss', 'hosts', 'cve']).default('hosts'),
  ...pageParams,
});
export type VulnerabilitiesQuery = z.input<typeof vulnerabilitiesQuerySchema>;

/**
 * One row per CVE that POSSIBLY affects at least one reported software version (same matching as
 * rule SOFT-002: KEV CVE + NVD version range). "Possibly" — banners can hide backported fixes.
 */
export const vulnerabilityItemSchema = z.object({
  cve: z.string(),
  title: z.string().nullable(),
  cvss: z.number().nullable(),
  kev: z.boolean(),
  knownRansomwareUse: z.boolean().nullable(),
  products: z.array(z.object({ product: z.string(), productLabel: z.string() })),
  affectedHosts: z.int(),
  affectedDomains: z.int(),
  /** Active SOFT-002 findings naming this CVE. */
  openFindings: z.int(),
  kevDateAdded: z.iso.date().nullable(),
  kevDueDate: z.iso.date().nullable(),
});
export type VulnerabilityItem = z.infer<typeof vulnerabilityItemSchema>;
export const vulnerabilitiesResponseSchema = paginatedSchema(vulnerabilityItemSchema);
export type VulnerabilitiesResponse = z.infer<typeof vulnerabilitiesResponseSchema>;

// --- Attack surface -----------------------------------------------------------------------------

export const CONTINENTS = [
  'Africa',
  'Antarctica',
  'Asia',
  'Europe',
  'North America',
  'Oceania',
  'South America',
] as const;
export type Continent = (typeof CONTINENTS)[number];

export const attackSurfaceResponseSchema = z.object({
  totals: z.object({
    approvedAssets: z.int(),
    currentIps: z.int(),
    openPorts: z.int(),
    thirdPartyHosted: z.int(),
  }),
  /** Approved assets by primary role (`classifyAssetRole`), all roles present (0 allowed). */
  assetRoles: z.array(z.object({ role: assetRoleSchema, assets: z.int() })),
  /** Approved assets by hosting provider; provider null = no known third party matched. */
  hostingProviders: z.array(
    z.object({
      provider: z.string().nullable(),
      kind: z.enum(['cdn', 'cloud', 'paas', 'saas', 'hosting']).nullable(),
      assets: z.int(),
    }),
  ),
  /** Current IPs of approved assets by country (from the worker's IP geolocation). */
  countries: z.array(z.object({ country: countryCode, assets: z.int(), ips: z.int() })),
  continents: z.array(z.object({ continent: z.enum(CONTINENTS), assets: z.int(), ips: z.int() })),
  /** Current IPs without a known country (not yet geolocated, private or unknown range). */
  unknownCountryIps: z.int(),
  /** Attribution required by the geolocation data licence; null when no data. */
  geoAttribution: z.string().nullable(),
  /** Most common open ports across current IPs (max 10). */
  exposedServices: z.array(
    z.object({ port: z.int(), service: z.string().nullable(), ips: z.int() }),
  ),
});
export type AttackSurfaceResponse = z.infer<typeof attackSurfaceResponseSchema>;

/** CC BY 4.0 attribution for DB-IP Lite data. */
export const DBIP_ATTRIBUTION = 'IP geolocation by DB-IP (db-ip.com), CC BY 4.0';
