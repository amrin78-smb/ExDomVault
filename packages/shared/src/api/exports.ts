/**
 * CSV exports (owner request 2026-10-24). One endpoint per list, accepting the SAME query filters
 * and sort as the list endpoint (paging parameters are ignored), returning the rows the caller can
 * already see:
 *
 *   GET /api/v1/exports/<resource>.csv?<list filters>
 *
 * - Permission = the list's read permission (users: `users:manage`, audit log: `audit:read`;
 *   ports and certificates: `assets:read`; vulnerabilities: `findings:read`).
 *   Findings keep their existing endpoint `GET /reports/findings.csv` (`reports:generate`).
 * - `Content-Type: text/csv; charset=utf-8`, body starts with a UTF-8 BOM (Excel shows non-ASCII
 *   text correctly), CRLF line endings, RFC 4180 quoting, formula-injection protection (cells
 *   starting with = + - @ TAB CR are prefixed with `'`; numeric values such as a negative
 *   `days_left` are written as numbers), fixed columns (EXPORT_COLUMNS).
 * - `Content-Disposition: attachment; filename="exdomainvault-<resource>-YYYYMMDD.csv"` (UTC date).
 * - At most EXPORT_MAX_ROWS rows; `X-Truncated: true` and `X-Total-Rows: <n>` when more matched.
 * - Lists inside a cell (IPs, CVEs, actions) are joined with `; `; dates are ISO 8601 UTC.
 * - Audited `report.exported` with { resource, filters, rows, truncated } in the same transaction.
 */

export const EXPORT_MAX_ROWS = 10_000;

export const EXPORT_RESOURCES = [
  'domains',
  'assets',
  'advisories',
  'software',
  'scans',
  'users',
  'audit-logs',
  'ports',
  'certificates',
  'vulnerabilities',
] as const;
export type ExportResource = (typeof EXPORT_RESOURCES)[number];

export const EXPORT_COLUMNS: Record<ExportResource, readonly string[]> = {
  domains: [
    'domain',
    'unicode_name',
    'verification_status',
    'verification_method',
    'verification_expires_at',
    'criticality',
    'business_owner',
    'monitoring',
    'registrar',
    'registration_expires_at',
    'open_findings',
    'created_at',
  ],
  assets: [
    'hostname',
    'domain',
    'asset_type',
    'status',
    'source',
    'current_ips',
    'hosting_provider',
    'wildcard_only',
    'owner',
    'decided_by',
    'decided_at',
    'decision_reason',
    'first_seen_at',
    'last_seen_at',
    'active_findings',
  ],
  advisories: [
    'finding_id',
    'rule_id',
    'severity',
    'risk_score',
    'finding_status',
    'domain',
    'hostname',
    'advisory_title',
    'summary',
    'business_impact',
    'recommended_actions',
    'references',
  ],
  software: [
    'domain',
    'hostname',
    'ip_address',
    'port',
    'source',
    'product',
    'version',
    'eol_cycle',
    'eol_date',
    'is_eol',
    'known_exploited_cves',
    'backport_distribution',
    'banner',
    'first_seen_at',
    'last_seen_at',
  ],
  scans: [
    'scan_id',
    'job_type',
    'domain',
    'profile',
    'trigger',
    'status',
    'requested_by',
    'created_at',
    'started_at',
    'completed_at',
    'duration_seconds',
    'targets',
    'targets_failed',
    'attempt',
    'error_code',
  ],
  users: ['email', 'display_name', 'role', 'active', 'signed_in', 'last_login_at', 'created_at'],
  'audit-logs': [
    'created_at',
    'actor_type',
    'actor',
    'action',
    'resource_type',
    'resource_id',
    'request_id',
    'metadata',
  ],
  // Milestone 13 inventory views (GET /ports, /certificates, /vulnerabilities).
  ports: [
    'ip_address',
    'port',
    'protocol',
    'state',
    'service',
    'hostnames',
    'domain',
    'country',
    'policy_violation',
    'first_observed_at',
    'last_observed_at',
  ],
  certificates: [
    'hostname',
    'domain',
    'ip_address',
    'port',
    'status',
    'issuer',
    'subject',
    'subject_alt_names',
    'not_before',
    'not_after',
    'days_left',
    'hostname_matches',
    'trusted',
    'protocol_version',
    'observed_at',
  ],
  vulnerabilities: [
    'cve',
    'title',
    'cvss',
    'kev',
    'known_ransomware_use',
    'products',
    'affected_hosts',
    'affected_domains',
    'open_findings',
    'kev_date_added',
  ],
};
