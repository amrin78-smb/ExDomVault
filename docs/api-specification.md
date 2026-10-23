# API specification

Base path: `/api/v1`. JSON only. Contracts are zod schemas in `packages/shared/src/api/`. This document
lists **implemented** endpoints; the full planned surface is in `docs/design.md` §10.

## Conventions

- **Request ID:** every response carries `X-Request-Id` (server-generated; client values are ignored).
- **Errors:** always this shape, with a stable `code` and a safe message:

  ```json
  {
    "error": {
      "code": "forbidden",
      "message": "…",
      "requestId": "…",
      "details": [{ "path": "…", "message": "…" }]
    }
  }
  ```

  Codes: `bad_request`, `validation_failed`, `unauthenticated`, `forbidden`, `not_found`,
  `method_not_allowed`, `conflict`, `rate_limited`, `internal_error`, `service_unavailable`. Internal
  errors never include stack traces, hostnames or connection details.

- **Headers:** `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, HSTS.

## Authentication and authorisation

Every route except `/health` and the signed internal worker API (`/api/v1/internal/worker/*`, see
[below](#internal-worker-api--signed-requests)) requires an authenticated, provisioned user. Unknown paths
also require authentication, so route existence isn't revealed.

| Situation                                                                              | Response                                |
| -------------------------------------------------------------------------------------- | --------------------------------------- |
| Authentication not configured (`AUTH_PROVIDER` unset, or Access team/AUD missing)      | `503 service_unavailable` (fail closed) |
| No or invalid Cloudflare Access token                                                  | `401 unauthenticated`                   |
| Valid identity but no matching active user                                             | `403 forbidden`                         |
| User lacks the permission for the route                                                | `403 forbidden`                         |
| State-changing request (`POST/PUT/PATCH/DELETE`) without a same-origin `Origin` header | `403 forbidden` (CSRF)                  |
| Database unreachable                                                                   | `503 service_unavailable`               |

Routes check their permission after authentication: scan reads need `scans:read`, requesting or
cancelling a scan needs `scans:request`, worker administration needs `settings:manage` and approved
networks need `scan_policies:manage` (both admin only); otherwise `403 forbidden`.

**Providers** (`AUTH_PROVIDER`):

- `cloudflare_access` (production): verifies the Access JWT from `Cf-Access-Jwt-Assertion` (or the
  `CF_Authorization` cookie) — RS256 signature against the team JWKS, issuer
  `https://<team>.cloudflareaccess.com`, audience = the application's AUD tag, expiry. Plain identity
  headers such as `Cf-Access-Authenticated-User-Email` are ignored. Tokens without an email (service
  tokens) are rejected.
- `dev` (local only): a fixed identity from `DEV_AUTH_EMAIL`. Refused at startup when
  `APP_ENV=production`.

**User mapping:** existing user by provider subject → pre-provisioned user by email that has never
signed in (subject is bound) → email in `BOOTSTRAP_ADMIN_EMAILS` (created as admin, audited
`user.bootstrap_admin`) → otherwise denied. An email already bound to a different subject is denied.

**Permissions** (`packages/shared/src/domain/permissions.ts`):

| Role        | Permissions                                                                                                                                                         |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| admin       | all                                                                                                                                                                 |
| analyst     | read domains/assets/scans/findings/reports; `scans:request`, `findings:triage`, `findings:assign`, `findings:accept_risk`, `findings:remediate`, `reports:generate` |
| asset_owner | `assets:read`, `findings:read`, `findings:remediate`, `reports:read` (scoped to assigned assets by the endpoints)                                                   |
| viewer      | `domains:read`, `assets:read`, `scans:read`, `findings:read`, `reports:read`                                                                                        |

## Endpoints

### `GET /api/v1/health` — public

```json
{
  "status": "ok",
  "service": "exdomainvault-api",
  "version": "0.1.0",
  "environment": "development",
  "time": "2026-10-22T04:46:25.571Z",
  "components": { "database": "ok", "auth": "ok" }
}
```

`status` is `ok` only when every component is `ok`, else `degraded`. Components: `ok`, `down`,
`not_configured`. `database` runs `select 1` through Hyperdrive.

### `GET /api/v1/me` — any authenticated user

```json
{
  "user": {
    "id": "uuid",
    "email": "dev@example.com",
    "displayName": "Local Developer",
    "role": "admin"
  },
  "permissions": ["users:manage", "…"],
  "authProvider": "dev"
}
```

## Domains

All domain endpoints use the `Domain` object:

```json
{
  "id": "uuid",
  "fqdn": "xn--mnchen-3ya.de",
  "unicodeFqdn": "münchen.de",
  "warnings": ["idn"],
  "registrar": null,
  "registeredAt": null,
  "expiresAt": null,
  "registrationDataStatus": "unknown",
  "criticality": "high",
  "businessOwner": "Platform team",
  "verificationStatus": "pending",
  "verifiedAt": null,
  "monitoringEnabled": false,
  "createdAt": "2026-10-22T10:00:00.000Z",
  "updatedAt": "2026-10-22T10:00:00.000Z"
}
```

- `fqdn` is the canonical form (lowercase A-label, no trailing dot) and is what the UI shows first.
  `warnings`: `idn` (contains non-ASCII characters), `mixed_script` (a label mixes scripts such as Latin
  and Cyrillic — possible homograph).
- `registrationDataStatus`: `unknown` (not collected yet), `available`, `redacted`, `unavailable`.
  Registration fields are filled from the newest successful RDAP (`registration`) observation.
- `verificationStatus`: `unverified` → `pending` (DNS challenge issued) → `verified`; `revoked` after an
  administrator revokes it. `verificationMethod` says how a verified domain was authorised: `dns_txt`
  (DNS proof) or `admin_attestation` (administrator authorisation, with `verificationExpiresAt` = its
  review date). The UI labels these "Verified (DNS)" and "Authorised (admin)".
- **What verification gates:** only active scanning. Passive monitoring (public DNS, certificates, CT
  logs, registration data) is allowed for every domain, verified or not.

### Domain name rules

Input is trimmed; case and one trailing dot are ignored; Unicode names are converted to A-labels with
IDNA/UTS #46 (WHATWG URL parser). Rejected, with a field error on `fqdn`:

- anything except letters, digits, `-` and `.` in ASCII (no scheme, path, port, `@`, `%`, `_`, spaces);
- wildcards, IP addresses (including shorthands such as `0x7f.1`), labels that are empty, longer than
  63 characters, start/end with `-` or have `--` in positions 3–4 (except valid `xn--` A-labels), names
  over 253 characters, malformed punycode;
- single labels, public suffixes (`co.uk`), unknown/special-use TLDs (`.local`, `.internal`, `.test`),
  `.arpa`, and names under the PSL's _private_ section (`*.github.io`, `*.workers.dev`);
- subdomains: only the registrable domain (eTLD+1, Public Suffix List via `tldts`) can be registered.
  The error suggests it (`www.example.co.uk` → `example.co.uk`).

### `GET /api/v1/domains` — `domains:read`

Query: `page` (default 1), `pageSize` (1–100, default 25), `q` (substring of the A-label; a Unicode
term is converted first; `%`/`_` are literal), `verificationStatus`, `criticality`, `monitoring`
(`true`/`false`), `sort` (`fqdn`, `-fqdn`, `createdAt`, `-createdAt`, `criticality`, `-criticality`;
default `fqdn`). Response: `{ "items": Domain[], "page", "pageSize", "total" }`.

### `POST /api/v1/domains` — `domains:write`

Body: `{ "fqdn": string, "criticality"?: "low"|"medium"|"high"|"critical" (default medium),
"businessOwner"?: string|null (≤200; empty → null) }`. Unknown fields are rejected.
`201 { "domain": Domain, "verification": null }`. `409 conflict` if the normalised name already
exists (enforced by the `domains_fqdn_key` unique index as well). Audited `domain.created`.

### `GET /api/v1/domains/:id` — `domains:read`

`{ "domain": Domain, "verification": Challenge | null }` — the pending challenge, otherwise the most
recent one. The challenge value is never returned here. Malformed or unknown ids → `404`.

### `GET /api/v1/domains/:id/observations` — `domains:read`

The latest scan observations for the domain (contract `domainObservationsResponseSchema` in
`packages/shared/src/api/observations.ts`; unknown domain → `404`):

```text
{
  "dns": [{ "hostname", "recordType", "ttl", "values": [], "resultStatus", "observedAt", "scanJobId" }],
  "registration": { "registrar", "registeredAt", "expiresAt", "nameservers": [], "dataStatus", "resultStatus", "observedAt", "scanJobId" },
  "tls": [{ "hostname", "ipAddress", "port", "protocolVersion", "notBefore", "notAfter", "issuer", "subject", "subjectAltNames": [], "fingerprintSha256", "hostnameMatches", "resultStatus", "observedAt", "scanJobId", "evidence": {} }],
  "http": [{ "url", "ipAddress", "statusCode", "finalUrl", "redirectCount", "hstsEnabled", "resultStatus", "observedAt", "scanJobId", "evidence": {} }],
  "ports": [{ "ipAddress", "port", "protocol", "state", "service", "resultStatus", "observedAt", "scanJobId", "evidence": {} }]
}
```

- `dns`: latest observation per (hostname, record type), ≤ 500. `registration`: latest, or `null`.
- `tls`: latest per (hostname, address, port); `evidence` holds `trusted`, `verifyError?` and `check`
  (`tls_certificate` or `tls_configuration`, set by the server at ingestion).
- `http`: latest per first URL; `evidence.hops` lists every hop with its decision, plus
  `securityHeaders`, `server`, `xPoweredBy` when headers were checked.
- `ports`: latest state per (address, port); `evidence` holds `method`, `reason?`, `product?`,
  `version?`.
- `tls`, `http` and `ports` are each capped at 500 rows and default to `[]`. Field meanings:
  [`worker-protocol.md`](worker-protocol.md#active-checks-milestone-6).

### `PATCH /api/v1/domains/:id` — `domains:write`

Body: any of `criticality`, `businessOwner` (string or null; empty clears), `monitoringEnabled`; at
least one. Monitoring can be turned on for any domain (it is passive). Audited `domain.updated` (with
`{ changes: { field: { from, to } } }`) and `domain.monitoring_enabled` / `domain.monitoring_disabled`.

### Verification (DNS TXT) — `domains:verify`

`Challenge`:

```json
{
  "id": "uuid",
  "method": "dns_txt",
  "status": "pending",
  "recordName": "_exdomainvault-challenge.example.com",
  "createdAt": "…",
  "expiresAt": "…",
  "lastCheckedAt": null,
  "verifiedAt": null,
  "failureReason": null
}
```

`POST /api/v1/domains/:id/verification` issues a challenge and returns it **once** with the record to
publish:

```json
{
  "challenge": { "…": "…" },
  "record": {
    "type": "TXT",
    "name": "_exdomainvault-challenge.example.com",
    "value": "exdomainvault-verification=<43-char token>"
  }
}
```

- The token is 256 random bits; only its SHA-256 is stored. Lost values cannot be shown again — issuing
  a new challenge marks the previous pending one `superseded`.
- Challenges expire after **72 hours**. Expiry is applied whenever domain data is read or changed: the
  challenge becomes `expired` and the domain returns to `unverified` (audited
  `domain.verification_expired`, actor `system`).
- `409` if the domain is already verified. Audited `domain.verification_started`.

`POST /api/v1/domains/:id/verify` checks the record:
`{ "outcome", "message", "domain": Domain, "verification": Challenge | null }` with `outcome`:

| Outcome            | Meaning                                                                           |
| ------------------ | --------------------------------------------------------------------------------- |
| `verified`         | A TXT value at the record name hashes to the stored hash; domain is `verified`    |
| `record_not_found` | NXDOMAIN or no TXT records at the name                                            |
| `value_mismatch`   | TXT records exist but none is the current value (e.g. a superseded one)           |
| `dns_error`        | The resolver failed or timed out (5 s); try again                                 |
| `expired`          | The challenge expired before verification                                         |
| `too_soon`         | Checked less than 10 s ago (atomic per-challenge throttle); no DNS query was made |

The lookup is one DNS-over-HTTPS query (`https://cloudflare-dns.com/dns-query`, JSON, redirects not
followed) made by the Worker — no connection to the domain's own servers. Hashes are compared in
constant time. Verification also requires the challenge to still be pending and unexpired at commit
time. Audited `domain.verified` (with `dnssecAuthenticated`) or `domain.verification_failed`. `409` if
already verified or no challenge has been issued.

**Verification grants nothing else.** It does not create or approve IP addresses or network scope:
network-tier checks (port probes, service identification) only reach
[approved networks](#approved-networks--scan_policiesmanage). (The apex is approved as an asset when the
first active scan is requested, see below.)

### Administrator authorisation — `domains:verify`

For domains the organisation owns but whose DNS it cannot edit (e.g. registrar-managed zones). Body
(`Authorisation`): `{ "reason": string (10–500), "reference"?: string|null (≤200), "reviewBy":
"YYYY-MM-DD" }`. The review date must be in the future and within 24 months; the authorisation lapses at
the end of that day (UTC).

- `POST /api/v1/domains/:id/authorise` — body `Authorisation`. Supersedes a pending DNS challenge.
  Returns the domain detail; the `verification` is the attestation (`method: admin_attestation`,
  `reason`, `reference`, `recordName: null`). `409` if already verified.
- `POST /api/v1/domains/authorise` — body `Authorisation` + `domainIds` (1–500 unique UUIDs).
  `{ "authorised": [{ id, fqdn }], "skipped": [{ id, fqdn, reason: already_verified|not_found }] }`.
  Set-based (a fixed number of statements), one transaction.
- `POST /api/v1/domains/:id/revoke` — body `{ "reason": string (10–500) }`. Only for verified
  domains (`409` otherwise), either method. Domain becomes `revoked`; its verification record
  `revoked`. A new DNS challenge or authorisation can follow. In the same transaction the domain's
  active-profile jobs are stopped: queued ones are cancelled (`errorCode: domain_not_authorised`,
  audited `scan.cancelled`), claimed/running ones get `cancelRequestedAt` (audited
  `scan.cancel_requested`) and the worker is told to stop at its next heartbeat. Passive jobs are not
  affected. An authorisation lapsing at its review date stops active jobs the same way (system actor).

Audited per domain: `domain.authorised` (reason, reference, reviewBy, `source`: manual/bulk/import),
`domain.verification_revoked` (reason, previous method), and `domain.authorisation_lapsed` (system,
when the review date passes; applied lazily like challenge expiry).

### CSV import — `domains:write`

Header row required (case-insensitive): `domain` (or `fqdn`, required), `criticality`,
`business_owner` (or `owner`). Unknown or repeated columns block the file. ≤ 1000 rows, ≤ 256 KB.

`POST /api/v1/domains/import/preview` — body `{ "csv": string }`. Writes nothing. Returns
`{ digest, rows[], fileErrors[], summary }`; each row has `line`, `input`, `fqdn`, `criticality`,
`businessOwner`, `status` (`valid`, `invalid`, `duplicate_in_file`, `already_registered`), `errors[]`,
`warnings[]`. `digest` is the SHA-256 of the CSV text.

`POST /api/v1/domains/import` — body `{ "csv": string, "digest": string, "authorisation"?:
Authorisation }`. The digest must match the
CSV (`400` otherwise, so only a previewed file is imported); rows are re-validated and only `valid` rows
are inserted, in one transaction (`ON CONFLICT DO NOTHING` for names registered meanwhile). `201
{ "created": [{ id, fqdn }], "skipped": n, "authorised": n }`. With `authorisation` (requires
`domains:verify` as well), every created domain is authorised in the same transaction; an invalid
authorisation rejects the whole import. Audited `domain.created` per domain (`source: import`), plus
`domain.authorised` per domain when authorising, plus `domain.import_completed`. 339 rows with
authorisation take about 1.4 s against Neon.

## Scans

Scans are asynchronous **jobs** run by the home scanning worker. The API only records and tracks them;
nothing in the Cloudflare Worker contacts a scan target. Contracts: `packages/shared/src/api/scans.ts`.
Lifecycle, leases and retries: [`architecture.md`](architecture.md#scan-jobs-and-the-worker-protocol).
Safety rules: [`scan-safety.md`](scan-safety.md).

| Permission             | Roles                  | Grants                                          |
| ---------------------- | ---------------------- | ----------------------------------------------- |
| `scans:read`           | admin, analyst, viewer | list profiles, list scans, scan detail          |
| `scans:request`        | admin, analyst         | request a scan for a domain, cancel a scan      |
| `settings:manage`      | admin                  | worker administration (`/api/v1/workers`)       |
| `scan_policies:manage` | admin                  | approved networks (`/api/v1/approved-networks`) |

### `GET /api/v1/scan-profiles` — `scans:read`

```json
{
  "items": [
    {
      "key": "passive",
      "name": "Passive",
      "description": "…",
      "version": 1,
      "defaultSchedule": "daily",
      "enabled": true,
      "config": {
        "active": false,
        "checks": ["dns", "rdap"],
        "tcpPorts": [],
        "timeouts": { "connectMs": 3000, "readMs": 5000, "targetSeconds": 60 },
        "concurrency": 4,
        "ratePerSecond": 5,
        "maxTargets": 50
      }
    }
  ],
  "activeScanningEnabled": false
}
```

Profiles are server-defined rows in `scan_profiles` (seeded keys in
[`database-schema.md`](database-schema.md#seeded-scan-profiles)). A stored `config` that fails
`scanProfileConfigSchema` is omitted (fail closed). `activeScanningEnabled` mirrors the
`ACTIVE_SCANNING_ENABLED` Worker var. The `discovery` profile is **not** listed: discovery is a job type
of its own ([`POST /domains/:id/discovery`](#post-apiv1domainsiddiscovery--scansrequest)).

### `POST /api/v1/domains/:id/scans` — `scans:request`

Body: `{ "profile": string (1–40), "reason"?: string|null (≤500; empty → null) }`. Unknown fields are
rejected. Returns **`202 Accepted`** with the scan detail (same shape as `GET /scans/:id`); the job is
`queued` and runs when a worker claims it.

Before creating the job, pending-challenge expiry and admin-authorisation lapse are applied to the domain.
Then, in one transaction with the domain row locked:

| Condition                                                                       | Response                              |
| ------------------------------------------------------------------------------- | ------------------------------------- |
| Unknown or disabled profile, or `discovery`                                     | `400 validation_failed` (`profile`)   |
| Active profile and `ACTIVE_SCANNING_ENABLED` is not `true`                      | `409 conflict`                        |
| Unknown domain                                                                  | `404 not_found`                       |
| Active profile and the domain is not `verified` (or its review date has passed) | `409 conflict`                        |
| No approved targets                                                             | `409 conflict`                        |
| A job for the same domain and profile is already `queued`/`claimed`/`running`   | `409 conflict` (partial unique index) |

Targets: approved assets of the domain (exact label-boundary check against the domain), ordered by
hostname, capped at the profile's `maxTargets`. Passive profiles always include the apex hostname. For
active profiles, domain verification approves the apex as an asset (audited `asset.approved` with
`basis: domain_verification`) unless that asset was explicitly rejected or suspended. The scope is frozen
into the job's immutable `scopeSnapshot`, together with — for active profiles only — every currently
active [approved network](#approved-networks--scan_policiesmanage) (networks are organisation-wide;
passive snapshots carry none). Audited `scan.requested` (domain, profile, active, target count,
approved-network count, reason).

### `POST /api/v1/domains/:id/discovery` — `scans:request`

No body. Queues passive subdomain discovery for the domain: a job with `jobType: "discovery"`, profile
`discovery` (checks `["discovery"]`, `active: false`) and exactly one target, the apex hostname with
`assetId: null`. Passive (the worker queries Certificate Transparency logs and public resolvers, never
the domain's hosts), so domain verification is not required. Returns `discoveryRequestResponseSchema`:

- **`201`** `{ "scanJobId": "uuid", "created": true }` — a job was queued (audited `scan.requested` with
  `jobType: "discovery"`);
- **`200`** `{ "scanJobId": "uuid", "created": false }` — a discovery job for the domain is already
  `queued`/`claimed`/`running` (also when a concurrent request wins the race).

`404 not_found` for an unknown domain; `403` without `scans:request`. Progress and results: `GET
/scans/:id`. Discovery is also scheduled weekly by the cron (see [Discovery scheduling](#discovery-scheduling-cron)).

### Discovery scheduling (cron)

Each 5-minute maintenance run creates discovery jobs (`trigger: "schedule"`, priority 250 — behind
user-requested scans at 100 and scheduled passive monitoring at 200) for domains with
`monitoring_enabled` that have had no discovery job queued, running or created in the last 7 days. A
domain that has never had discovery waits for its slot in the week (a stable hash of its id over a
7-day cycle), so a large inventory spreads over the week; afterwards each domain recurs about 7 days
after its previous job. At most 50 jobs per run; the one-active-job-per-domain+profile index absorbs
races. Scheduled jobs are refused at claim time if monitoring was switched off meanwhile.

### `GET /api/v1/scans` — `scans:read`

Query: `page` (default 1), `pageSize` (1–100, default 25), `status` (`queued`, `claimed`, `running`,
`succeeded`, `failed`, `cancelled`), `domainId` (UUID), `profile` (≤40). Newest first. Response:
`{ "items": ScanJob[], "page", "pageSize", "total" }`.

`ScanJob`:

```json
{
  "id": "uuid",
  "jobType": "scan",
  "profile": "passive",
  "domain": { "id": "uuid", "fqdn": "example.com" },
  "status": "running",
  "priority": 100,
  "reason": null,
  "trigger": "manual",
  "requestedBy": { "id": "uuid", "email": "analyst@example.com" },
  "createdAt": "…",
  "scheduledAt": "…",
  "startedAt": "…",
  "completedAt": null,
  "leaseExpiresAt": "…",
  "attempts": 1,
  "maxAttempts": 3,
  "worker": { "id": "uuid", "name": "home-1" },
  "progress": { "completedTargets": 1, "totalTargets": 3, "message": "…" },
  "cancelRequestedAt": null,
  "errorCode": null,
  "errorSummary": null,
  "targetCounts": { "pending": 2, "running": 0, "succeeded": 1, "failed": 0, "skipped": 0 }
}
```

`trigger` is `schedule` for daily passive monitoring jobs (`requestedBy` is then `null`). `domain` is
`null` if the domain was deleted. `errorCode`/`errorSummary` hold the last error, also while a retry is
queued.

### `GET /api/v1/scans/:id` — `scans:read`

`{ "job": ScanJob, "targets": ScanJobTarget[], "scopeSnapshot": ScopeSnapshot }`.
`ScanJobTarget`: `id`, `assetId` (null for an apex without an asset row), `hostname`, `ip`, `status`
(`pending`, `running`, `succeeded`, `failed`, `skipped`), `startedAt`, `completedAt`, `errorCode`.
`ScopeSnapshot` (version 1): `createdAt`, `requestedBy`, `trigger`, `domain` (`id`, `fqdn` and its
verification status, method and expiry at request time), `profile` (`key`, `version`, full `config`),
`targets` (`assetId`, `hostname`), `approvedNetworks` (canonical CIDRs captured at creation; the
networks a running job may actually probe are this list intersected with the approvals still active).
Malformed or unknown ids → `404`.

### `POST /api/v1/scans/:id/cancel` — `scans:request`

No body. Returns the scan detail.

- `queued` → `cancelled` immediately (`errorCode: cancelled`, unfinished targets `skipped`); audited
  `scan.cancelled`.
- `claimed`/`running` → `cancelRequestedAt` is set and the worker is told at its next heartbeat (the
  worker then stops in-progress HTTP checks between hops and kills a running Nmap); the job
  becomes `cancelled` when the worker reports a failure or when the lease reaper finds the lease expired.
  Audited `scan.cancel_requested`. Repeating the request is a no-op.
- Already `succeeded`/`failed`/`cancelled` → `409 conflict`.

## Approved networks — `scan_policies:manage`

Admin-approved networks are the **only** destinations of network-tier checks (`tcp_ports`,
`service_identification`, `tls_configuration`). Domain verification never authorises them; web-tier
checks (TLS certificate, HTTP) do not need them. Contracts: `packages/shared/src/api/networks.ts`;
service `apps/web/worker/services/networks.ts`. Every endpoint requires `scan_policies:manage` (admin
only); state-changing calls need a same-origin `Origin` (CSRF).

`ApprovedNetwork`:

```json
{
  "id": "uuid",
  "cidr": "203.0.113.0/24",
  "label": "Primary web servers",
  "reason": "Owned range, contract ABC-123",
  "reference": "ABC-123",
  "createdBy": { "id": "uuid", "email": "admin@example.com" },
  "createdAt": "…",
  "expiresAt": "…",
  "revokedAt": null,
  "revokeReason": null
}
```

An approval is **active** while `revokedAt` is null and `expiresAt` (end of the review day, UTC) is in
the future. Expiry is evaluated wherever the set is used (job creation, claim, heartbeat, ingestion);
there is no status column.

| Endpoint                                    | Body                                            | Response                                      | Audit              |
| ------------------------------------------- | ----------------------------------------------- | --------------------------------------------- | ------------------ |
| `GET /api/v1/approved-networks`             | —                                               | `{ items: ApprovedNetwork[] }` (newest first) | —                  |
| `POST /api/v1/approved-networks`            | `{ cidr, label, reason, reference?, reviewBy }` | `201 ApprovedNetwork`                         | `network.approved` |
| `POST /api/v1/approved-networks/:id/revoke` | `{ reason }`                                    | `ApprovedNetwork`                             | `network.revoked`  |

Validation for `POST` (`400 validation_failed` with a field error unless noted):

- `cidr` (2–64 chars, trimmed): an IPv4 or IPv6 network in CIDR notation, or a single address (stored
  as `/32` / `/128`), parsed strictly (no alternative IPv4 encodings, no zone ids) and stored in
  canonical form; host bits are cleared (`203.0.113.7/24` is stored as `203.0.113.0/24`).
- Entirely public: it must not overlap any range in the shared prohibited table
  (`packages/shared/src/net/prohibited-ranges.ts`) in either direction, and IPv6 must lie inside
  `2000::/3`. The error names the category (e.g. `private`, `documentation`).
- No broader than **/16 (IPv4)** or **/32 (IPv6)**, so one approval cannot cover a whole provider.
- `label` 1–100 chars; `reason` 10–500 chars; `reference` ≤ 200 chars (empty → null).
- `reviewBy` `YYYY-MM-DD`, in the future and within 24 months; the approval lapses at the end of that
  day (UTC).
- **`409 conflict`** if the same network is already actively approved, or if it overlaps an active
  approval ("Revoke it first"). Approvals are serialised with a transaction-scoped advisory lock, so two
  concurrent overlapping requests cannot both succeed. A lapsed (never revoked) approval of the same
  CIDR is closed automatically (`revokeReason: "Expired (review date passed)."`) so it can be approved
  again.

Revocation: `reason` 10–500 chars; unknown id → `404`; already revoked → `409`. The audit metadata
records the CIDR, the reason and whether the approval was still active.

Effect on jobs: active jobs snapshot the active networks at creation; at claim and at every heartbeat
the snapshot is intersected with the approvals active at that moment, and the heartbeat sends the
result to the worker, which shrinks (never widens) its scope. `port` and `tls_configuration`
observations are rejected unless their address lies in that intersection at ingestion time. Revoking or
letting an approval lapse therefore stops further probes of it within one heartbeat interval.

## Scanning workers (administration) — `settings:manage`

Contracts: `packages/shared/src/api/workers.ts`. Only Ed25519 **public** keys are ever sent or stored.

`Worker`: `{ id, name, status: active|disabled, version, lastSeenAt, createdAt, credentials[] }`;
each credential: `{ id, fingerprint, createdAt, expiresAt, revokedAt, lastUsedAt }`. `fingerprint` is
the first 8 bytes of the SHA-256 of the raw key, colon-separated hex. The credential `id` is the **key
id** the worker sends in `X-EDV-Key-Id`.

Public key format: base64 (standard or URL-safe, padding optional) of the raw 32-byte key. Keys that do
not decode to 32 bytes, are not importable as Ed25519, or are one of the known small-order (degenerate)
points are rejected with `400 validation_failed` (`publicKey`). Keys are stored in canonical standard
base64; the same key cannot be registered twice.

| Endpoint                                                    | Body                                  | Response                        | Audit                                |
| ----------------------------------------------------------- | ------------------------------------- | ------------------------------- | ------------------------------------ |
| `GET /api/v1/workers`                                       | —                                     | `{ items: Worker[] }` (by name) | —                                    |
| `POST /api/v1/workers`                                      | `{ name, publicKey, expiresInDays? }` | `201 { worker, credentialId }`  | `worker.registered`                  |
| `PATCH /api/v1/workers/:id`                                 | `{ status: "active" \| "disabled" }`  | `{ worker }`                    | `worker.enabled` / `worker.disabled` |
| `POST /api/v1/workers/:id/credentials`                      | `{ publicKey, expiresInDays? }`       | `201 { worker, credentialId }`  | `worker.credential_added`            |
| `POST /api/v1/workers/:id/credentials/:credentialId/revoke` | —                                     | `{ worker }`                    | `worker.credential_revoked`          |

- `name`: 1–63 characters, lowercase letters, digits and hyphens, starting with a letter or digit;
  unique (`409` otherwise). `expiresInDays`: 1–730, default 365.
- Adding a credential is key rotation: the old key keeps working until it is revoked or expires.
- Revoking an already revoked key, or setting the current status, is a no-op (no audit entry). A
  credential that belongs to another worker → `404`.
- A disabled worker's requests are refused; its credentials are kept.

## Findings and advisories

Findings come only from the deterministic rules engine ([`advisory-rules.md`](advisory-rules.md)).
Asset owners see only findings on assets they own (domain-level findings have no asset and are not
visible to them); an invisible finding answers `404` exactly like a missing one.

### `GET /api/v1/findings` — `findings:read`

Query: `page`, `pageSize` (≤ 100), `status` (`active` = everything except resolved, default; `all`; or
one status), `severity`, `category`, `domainId`, `ruleId`, `assignee` (`me`, `unassigned` or a user
id), `q` (title/hostname), `sort` (`-riskScore` default, `riskScore`, `-lastSeenAt`, `-firstSeenAt`,
`-severity`). Each finding carries `assignee`, `acceptedRisk` (`{ reason, approvedBy, reviewAt }`, only
while `accepted_risk`) and `manualResolution` (its rule is a change-detection rule).

### `GET /api/v1/findings/summary` — `findings:read`

Active findings by severity and category; optional `domainId`.

### `GET /api/v1/findings/:id` — `findings:read`

`{ finding, advisory, history, comments, rule }`. History `reason` is a code: `detected`,
`recurrence`, `condition_absent` (resolved by a successful scan), `accepted_risk_expired`, or `manual`
(a user's change; their text is in `note`).

### `PATCH /api/v1/findings/:id` — a finding permission

Body: `{ expectedStatus, status?, reason?, acceptedRiskReviewAt?, assigneeId? }` (status and/or
assignee). Allowed transitions (`packages/shared/src/domain/finding-lifecycle.ts`):

| From                                                 | To                      | Permission             | Requires                                  |
| ---------------------------------------------------- | ----------------------- | ---------------------- | ----------------------------------------- |
| open                                                 | acknowledged            | `findings:triage`      | —                                         |
| remediation_in_progress                              | acknowledged            | `findings:remediate`   | —                                         |
| open, acknowledged                                   | remediation_in_progress | `findings:remediate`   | —                                         |
| acknowledged, remediation_in_progress, accepted_risk | open                    | `findings:triage`      | reason                                    |
| open, acknowledged, remediation_in_progress          | accepted_risk           | `findings:accept_risk` | reason ≥ 10 chars, review date ≤ 366 days |
| any non-resolved                                     | resolved                | `findings:triage`      | reason; **change-detection rules only**   |

Nothing leaves `resolved` by hand; a successful scan that observes the condition again reopens it.
Accepting a risk records the acting user as approver; leaving `accepted_risk` clears the acceptance.
Assignment needs `findings:assign`; the assignee must be an active user (`null` unassigns).

Errors (shared codes, cause in `details[0].path`): `403 forbidden` (permission), `404 not_found`,
`409 conflict` path `expectedStatus` (the finding changed since the client read it — nothing changed),
`409 conflict` path `status` (no user may make this transition), `400 validation_failed` (reason,
review date or assignee). Audit: `finding.status_changed`, `finding.risk_accepted`,
`finding.assigned` / `finding.unassigned`.

### `POST /api/v1/findings/bulk` — a finding permission

Body: `{ ids (1–500), status?, reason?, acceptedRiskReviewAt?, assigneeId? }`. Each finding is checked
like a PATCH; response `{ updated, skipped: [{ id, code }] }` with codes `not_found`,
`invalid_transition`, `transition_not_allowed`, `no_change`. Set-based, one transaction.

### `POST /api/v1/findings/:id/comments` — `findings:triage` or `findings:remediate`

Body `{ body }` (1–4000 chars). `201 { comment }`. Append-only. Audit `finding.commented` (length only).

### `POST /api/v1/findings/:id/reassess` — `scans:request`

Queues a scan of the finding's domain with the cheapest enabled profile (passive → quick → standard →
deep, then `discovery` for asset-inventory rules such as ASSET-001/ASSET-002) that runs the rule's
checks, through the normal scan rules (active scanning switch, domain authorisation; discovery jobs are
passive and created as by `POST /domains/:id/discovery`). `201 { scanJobId, profile, created: true }`, or `200` with `created: false` when the same
job is already queued or running. `409 conflict` path `ruleId` when no profile runs the rule.

### `GET /api/v1/users/assignable` — `findings:assign`

Active users `{ id, email, displayName, role }`, by email.

### `GET /api/v1/advisories` — `findings:read`

Advisories with a summary of their finding; `status` `active` (default) or `all`; paginated.

### `GET /api/v1/rules` — `findings:read`

The rule catalogue (id, version, category, severity, detection, resolution, evidence required).

### Accepted-risk expiry (cron)

Every 5 minutes, accepted risks whose review date has passed return to `open` (history
`accepted_risk_expired` with the previous reason as note; system audit
`finding.risk_acceptance_expired`).

## Assets

The asset inventory: hostnames beneath a registered domain (design §5.4–5.5, §7, §10). Contracts:
`packages/shared/src/api/assets.ts`. Passive discovery creates `pending` candidates; only an explicit,
audited approval puts a hostname into scan scope, and approval never authorises network-tier checks
against third-party hosting (those still need an [approved network](#approved-networks--scan_policiesmanage)).

| Permission       | Roles                                 | Grants                                                    |
| ---------------- | ------------------------------------- | --------------------------------------------------------- |
| `assets:read`    | admin, analyst, viewer, asset_owner\* | list and read assets                                      |
| `assets:approve` | admin                                 | approve, reject, suspend (single and bulk); set the owner |

\* Asset owners see only assets with `owner_user_id` = themselves; any other asset is `404 not_found`.

**Asset** (`assetSchema`): `id`, `domain {id, fqdn}`, `hostname`, `assetType` (`apex`/`subdomain`),
`status` (`pending`/`approved`/`rejected`/`suspended`), `source` (`manual`/`import`/
`certificate_transparency`/`dns`), `firstSeenAt`, `lastSeenAt`, `currentIps` (addresses with
`asset_ips.is_current`), `hostingHint` (`{provider, kind, matchedName}` or `null` — `null` means no
known provider matched, not that the host is self-hosted), `wildcardOnly`, `decidedBy {id, email}|null`,
`decidedAt`, `decisionReason`, `owner {id, email}|null` (the asset owner: users with the `asset_owner`
role see only assets they own and those assets' findings), `activeFindings` (non-resolved findings with
the asset's domain and hostname).

### `GET /api/v1/assets` — `assets:read`

Query (`assetListQuerySchema`): `page` (≥1), `pageSize` (1–100, default 25), `status`, `domainId`,
`source`, `thirdParty` (`true` = has a hosting hint, `false` = none), `q` (substring of the hostname,
case-insensitive, LIKE wildcards literal), `sort` (`hostname` default, `-lastSeenAt`, `-firstSeenAt`).
Returns the standard page envelope `{ items, page, pageSize, total }`.

### `GET /api/v1/domains/:id/assets` — `assets:read`

As `GET /assets`, scoped to the domain (a `domainId` query parameter cannot widen it). `404` for an
unknown domain, and for an asset owner who owns no asset in it.

### `GET /api/v1/assets/:id` — `assets:read`

`{ asset, ips, discovery }`: `ips` is the address history (`ipAddress`, `firstSeenAt`, `lastSeenAt`,
`isCurrent`, `source`; current first, then most recently seen); `discovery` is the latest 50 discovery
sightings, newest first (`source`, `observedAt`, `wildcard`, `scanJobId`, `evidence`).

### `PATCH /api/v1/assets/:id` — `assets:approve`

Sets or clears the asset owner. Body (`assetOwnerUpdateRequestSchema`, strict): `{ ownerUserId: uuid | null }`.
The owner must be an existing, **active** user of any role (`asset_owner` is the role it scopes);
otherwise `400 validation_failed` path `ownerUserId`. The user row is share-locked in the same
transaction, so a concurrent deactivation cannot interleave. Unknown asset → `404`. Response
`200 { asset }`. A change is audited `asset.owner_changed` with `domainId`, `hostname`, `from` and `to`
(`{id, email}` or `null`); setting the current owner again is a no-op without an audit row.

### Decisions — `assets:approve`

| Endpoint                          | Body                                                         | Allowed from                                      |
| --------------------------------- | ------------------------------------------------------------ | ------------------------------------------------- |
| `POST /api/v1/assets/:id/approve` | `{ reason (3–1000), acknowledgeThirdPartyHosting? = false }` | `pending`, `suspended`, `rejected`                |
| `POST /api/v1/assets/:id/reject`  | `{ reason }`                                                 | `pending` subdomains (the apex is never rejected) |
| `POST /api/v1/assets/:id/suspend` | `{ reason }`                                                 | `approved`                                        |

The rules are `allowedAssetActions(status, assetType)` from the shared package. Responses: `200 { asset }`.
Errors:

| Condition                                                        | Response                                                     |
| ---------------------------------------------------------------- | ------------------------------------------------------------ |
| Unknown asset (or not visible)                                   | `404 not_found`                                              |
| Decision not allowed from the current status (incl. same status) | `409 conflict`, details path `status`                        |
| Approving an asset with a `hostingHint` without acknowledgement  | `400 validation_failed`, path `acknowledgeThirdPartyHosting` |
| Invalid body (short reason, unknown fields)                      | `400 validation_failed`                                      |
| Missing `assets:approve`                                         | `403 forbidden`                                              |

Effects, all in one transaction:

- `approve` sets `approved_by`/`approved_at`, `monitoring_enabled = true`; `reject`/`suspend` set
  `monitoring_enabled = false`. Every decision records `decided_by`, `decided_at`, `decision_reason`.
- Audit `asset.approved` / `asset.rejected` / `asset.suspended` with `domainId`, `hostname`, `from`,
  `to`, `reason`, `hostingHint`, `acknowledgeThirdPartyHosting` (and `bulk: true` for bulk).
- The hostname's active **ASSET-001** finding (fingerprint `ASSET-001|domainId|hostname|hostname`) is
  resolved at once: `status = resolved`, `resolved_at` = now, a status-history entry with
  `reason = asset_decided`, `changed_by` = the actor and `note = "Asset <status>: <reason>"`, and an
  audit `finding.status_changed`. The per-domain findings lock is taken so a concurrent rules
  evaluation cannot reopen it from stale asset data.
- `suspend` also stops in-flight **active** jobs that target the asset (`scan_job_targets.asset_id`):
  its unfinished targets are skipped (`asset_suspended`), claimed/running jobs are flagged for
  cancellation (the worker stops at its next heartbeat; audited `scan.cancel_requested`), and active
  evidence for it is refused from then on. Passive jobs are unaffected.

Approved subdomains become scan targets of later jobs (re-checked on an exact label boundary at job
creation); suspended and rejected assets are skipped at claim time.

### `POST /api/v1/assets/bulk` — `assets:approve`

Body `{ ids: uuid[1..500], action: "approve"|"reject"|"suspend", reason, acknowledgeThirdPartyHosting? }`.
Set-based (a few statements regardless of size). Response `{ updated, skipped: [{ id, code }] }` with
codes `not_found`, `invalid_transition`, `third_party_not_acknowledged`, `no_change` (already in the
target status). Effects per updated asset as above.

## Users — `users:manage`

User administration (design §4; contracts `packages/shared/src/api/users.ts`). Administrators only.
Identity comes from the identity provider: adding a user pre-provisions their email and role, and
they must **also** be allowed by the Cloudflare Access policy. Their provider subject is bound at first
sign-in (see _User mapping_ above). Deactivated users are refused at authentication with
`403 forbidden` ("Your account has been deactivated.") on every route.

**User** (`userSchema`): `id`, `email`, `displayName`, `role`, `isActive`, `signedIn` (subject bound),
`lastLoginAt`, `createdAt`, `updatedAt`.

### `GET /api/v1/users`

Query (`userListQuerySchema`): `page`, `pageSize` (1–100, default 50), `q` (substring of email or display
name, case-insensitive, LIKE wildcards literal), `role`, `active` (`true`/`false`). Ordered by email;
standard page envelope.

### `GET /api/v1/users/:id`

`{ user }`; `404` for unknown or malformed ids.

### `POST /api/v1/users`

Body (`userCreateRequestSchema`, strict): `{ email, displayName?, role }`. The email is lowercased;
`auth_provider` is the configured provider and the subject stays empty until first sign-in.
`201 { user }`, audited `user.created` (`email`, `role`, `displayName`). Duplicate email
(case-insensitive) → `409 conflict` path `email`.

### `PATCH /api/v1/users/:id`

Body (`userUpdateRequestSchema`, strict, at least one field): `{ role?, isActive?, displayName? (null
clears) }`. Fields equal to the stored value are ignored; a request that changes nothing returns the
user without an audit row. `200 { user }`. Each change is audited separately: `user.role_changed`
(`from`, `to`), `user.activated` / `user.deactivated`, `user.updated` (`displayName {from, to}`); all
carry `email`.

| Condition                                  | Response                        |
| ------------------------------------------ | ------------------------------- |
| Changing your own role                     | `409 conflict`, path `role`     |
| Deactivating yourself                      | `409 conflict`, path `isActive` |
| Demoting the last **active** administrator | `409 conflict`, path `role`     |
| Deactivating the last active administrator | `409 conflict`, path `isActive` |
| Unknown user                               | `404 not_found`                 |
| Empty body, unknown field, invalid role    | `400 validation_failed`         |

The last-admin check runs in the update's transaction after locking every active admin row
(`FOR UPDATE`, ordered by id, then the target row), so two concurrent cross-demotions serialise and the
second sees the first one's result (one `200`, one `409`).

## Audit log — `audit:read`

### `GET /api/v1/audit-logs`

Administrators only; read-only (entries are append-only). Query (`auditListQuerySchema`): `page`,
`pageSize` (1–100, default 50), `action` (exact, or a prefix when it ends with `.`, e.g. `finding.`;
characters `[a-z_.]`), `resourceType`, `resourceId`, `actorUserId`, `actorType`
(`user`/`worker`/`system`), `from` / `to` (ISO date-times, inclusive, on `created_at`). Newest first.
Items: `id`, `actorType`, `actor {id, email}|null` (null for system/worker entries or deleted users),
`action`, `resourceType`, `resourceId`, `requestId`, `metadata`, `createdAt`.

## Reports

Contracts: `packages/shared/src/api/reports.ts`.

### `GET /api/v1/reports/summary` — `reports:read`

`reportSummaryResponseSchema`, computed from stored data with a fixed number of aggregate statements
(GROUP BY, `generate_series`, `DISTINCT ON`) regardless of portfolio size. All windows are UTC.

| Section                 | Definition                                                                                                                                                                                                                               |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `coverage`              | Domain counts (all / `monitoring_enabled` / verified), asset counts (approved / pending), `lastScanAt` = newest `completed_at` of a succeeded scan or discovery job                                                                      |
| `findings`              | `open` = non-resolved; `bySeverity`, `byCategory` over non-resolved; `byStatus` over all; `meanDaysToResolve` = mean (`resolved_at` − `first_seen_at`) of findings resolved in the last 90 days, 2 decimals, `null` if none              |
| `trend`                 | 30 days ending today: `created` = findings whose `first_seen_at` falls on the day, `resolved` = findings whose `resolved_at` falls on the day (currently resolved findings only; a reopened finding's earlier resolution is not counted) |
| `topDomains`            | Up to 10 domains by total `risk_score` of open findings (then open count, fqdn), with `highestSeverity`                                                                                                                                  |
| `byBusinessOwner`       | Per `domains.business_owner` (null grouped): domain count, open findings, open high/critical; most open first; ≤ 100 rows                                                                                                                |
| `expiringRegistrations` | Domains with `expires_at` ≤ now + 60 days (incl. expired), soonest first, ≤ 50; `daysLeft` = floor of days remaining (negative if expired)                                                                                               |
| `expiringCertificates`  | The latest **successful** TLS observation per hostname within the last 90 days, if its `not_after` ≤ now + 30 days, soonest first, ≤ 50. The domain comes from the observation's asset, else its scan job                                |
| `acceptedRisksDue`      | Accepted risks with a review date ≤ now + 30 days (incl. passed), soonest first, ≤ 50                                                                                                                                                    |

**Asset owners** receive a summary of what they can see: the `findings`, `trend` and
`acceptedRisksDue` sections cover only findings on assets they own; `coverage.approvedAssets` /
`pendingAssets` count their own assets and `expiringCertificates` covers their own assets. Domain-level
sections are zero or empty for them: `coverage.domains` / `monitoredDomains` / `verifiedDomains` = 0,
`lastScanAt` = null, and `topDomains`, `byBusinessOwner`, `expiringRegistrations` = `[]`.

### `GET /api/v1/reports/findings.csv` — `reports:generate`

Admins and analysts. Query: the `GET /findings` filters (`status` default `active`, `severity`,
`category`, `domainId`, `ruleId`, `assignee`, `q`, `sort`) without paging; the same filter builder and
visibility rules are used. Response `200`, `Content-Type: text/csv; charset=utf-8`,
`Content-Disposition: attachment; filename="findings-YYYYMMDD.csv"` (UTC date), CRLF line endings, no
BOM. Columns (`REPORT_CSV_COLUMNS`): `finding_id, rule_id, severity, risk_score, status, domain,
hostname, component, title, first_seen_at, last_seen_at, resolved_at, assignee` (email)`,
business_owner`. At most `REPORT_CSV_MAX_ROWS` (5000) rows in the requested sort order; when more
matched, the header `X-Truncated: true` is set.

Cell encoding: any cell starting with `=`, `+`, `-`, `@`, tab or CR is prefixed with `'` (CSV/formula
injection), then RFC 4180 quoting applies (cells containing `"`, `,`, CR or LF are quoted, `"` doubled).
Each export is audited `report.exported` (`resourceType: report`, `resourceId: findings.csv`, metadata
`report`, `format`, `filters`, `rows`, `truncated`) in the same transaction as the read.

## Internal worker API — signed requests

`/api/v1/internal/worker/*` is used only by the home scanning worker. It does **not** use Cloudflare
Access user identity, user sessions or the CSRF check; every request is authenticated by an Ed25519
signature (`middleware/worker-auth.ts`). All endpoints are `POST` with a JSON body.

### Request signing

Headers:

| Header                 | Value                                                          |
| ---------------------- | -------------------------------------------------------------- |
| `X-EDV-Key-Id`         | The credential id (UUID) returned at registration              |
| `X-EDV-Timestamp`      | Unix time in seconds (1–12 digits)                             |
| `X-EDV-Nonce`          | 16–64 characters of `A–Z a–z 0–9 _ -`, unique per request      |
| `X-EDV-Signature`      | Base64 of the 64-byte Ed25519 signature                        |
| `X-EDV-Worker-Version` | Optional; first 40 characters stored as the worker's `version` |

Signing string (UTF-8, fields joined by `\n`, no trailing newline):

```text
EDV1
<METHOD, upper-case>
<path including query string, e.g. /api/v1/internal/worker/claim>
<X-EDV-Timestamp value>
<X-EDV-Nonce value>
<lower-case hex SHA-256 of the exact request body bytes>
```

Checks, in order (any failure → `401 unauthenticated`, message "Worker authentication failed.", the
specific reason only in the server log as `worker_auth_failed`):

1. Header shapes as above.
2. Timestamp within **±300 s** of server time.
3. Body ≤ 1 MB, measured in bytes (`400 bad_request` otherwise).
4. Credential exists, is not revoked, has not expired, and its worker is `active`.
5. Signature verifies against the stored public key (small-order keys never verify).
6. Rate limit: at most **120 accepted requests per credential per rolling minute** → `429 rate_limited`.
7. Nonce not seen before for this credential (stored in `worker_request_nonces`; a replay → `401`).
   Nonces are kept for at least 600 s (twice the window), so a replay inside the window is always caught.

A nonce is consumed once authentication succeeds, even if the request then fails (e.g. `409`), so
retries must use a new nonce and a new signature. On success the credential's `lastUsedAt` and the
worker's `lastSeenAt` are updated.

### Fencing and errors

`claim` returns an `attempt` number. Every later call for that job sends `jobId` + `attempt`; the server
accepts it only if the job is still `claimed`/`running`, held by the same worker and `attempts` equals
the given attempt. Otherwise → **`409 conflict`** ("The job lease is no longer held by this worker
attempt.") — the worker must stop work on that job. An unknown `jobId` → `404`. Bodies are validated
strictly (`400 validation_failed`).

### `POST /api/v1/internal/worker/claim`

Body: `{ "profiles"?: string[] (≤10) }` — profiles this worker can run; omitted or empty = all. Response
`{ "job": ClaimedJob | null }`:

```json
{
  "job": {
    "id": "uuid",
    "attempt": 1,
    "profile": "passive",
    "leaseExpiresAt": "…",
    "leaseSeconds": 300,
    "heartbeatSeconds": 60,
    "snapshot": { "…": "ScopeSnapshot" },
    "targets": [{ "id": "uuid", "hostname": "example.com", "ip": null }]
  }
}
```

The oldest due `queued` job (lowest `priority` first, then `scheduledAt`) with attempts left is claimed
atomically. `targets` are the job's targets that are not yet `succeeded`/`failed`/`skipped`. Jobs with
an active profile are re-authorised first; a refused job is cancelled (see architecture) and the next
candidate is tried (up to 5 per call). For active jobs, targets whose asset is no longer `approved` are
marked `skipped` (`errorCode: asset_not_approved`) and left out; if none remain the job is cancelled
with `no_approved_targets`. `snapshot.approvedNetworks` in the response is the creation-time list
intersected with the approvals active now.

### `POST /api/v1/internal/worker/heartbeat`

Body: `{ jobId, attempt, progress?: { completedTargets, totalTargets (0–100000), message? (≤200) } }`.
Extends the lease by 300 s and moves the job to `running`. Response:

```json
{ "leaseExpiresAt": "…", "cancelRequested": false, "approvedNetworks": ["203.0.113.0/24"] }
```

- The job's authorisation is re-checked on every heartbeat (same rules as claim: server
  `ACTIVE_SCANNING_ENABLED` for active profiles, domain present and authorised, monitoring on for
  scheduled jobs). If it fails, `cancelRequestedAt` is set (audited `scan.cancel_requested`, system
  actor, with the reason) and the response is still `200`.
- `cancelRequested` is true after a user cancel or when authorisation was withdrawn; the worker should
  stop and report a failure with `errorCode: "cancelled"`.
- `approvedNetworks` is the job's current network scope: snapshot ∩ approvals active now; `[]` for
  passive jobs and for jobs that are no longer authorised. The worker intersects its scope with it and
  never widens it.

### `POST /api/v1/internal/worker/results`

Body:

```json
{
  "jobId": "uuid",
  "attempt": 1,
  "resultId": "8–128 chars of A–Z a–z 0–9 _ -",
  "targets": [{ "targetId": "uuid", "status": "succeeded", "errorCode": "optional_snake_case" }],
  "observations": [],
  "complete": false
}
```

- `resultId` is an idempotency key: a submission whose `(jobId, resultId)` was already processed changes
  nothing and returns `{ "accepted": false, "status": <current job status> }`. This is checked before
  the lease (so a retry after completion still succeeds), but only against the same worker's own
  submissions; another worker gets the usual `409`.
- Each `targetId` may appear once per submission (≤1000) and must belong to this job's snapshot,
  otherwise `400 validation_failed`. `status` is `running`, `succeeded`, `failed` or `skipped`. A target
  that already reached `succeeded`, `failed` or `skipped` keeps that status.
- `complete: false` records target progress, renews the lease and moves the job to `running`.
- `complete: true` marks every target not reported as finished `failed` (`errorCode: not_reported`) and
  the job `succeeded` — also after a cancel request, since the work was done.
- Response `{ "accepted": true, "status": "running" | "succeeded" }`.
- `observations` (≤ 500, default `[]`): `discovery`, `dns`, `registration`, `tls`, `http`, `port` observations
  (shapes and rules in [`worker-protocol.md`](worker-protocol.md#observations-milestone-5)), stored in
  the same transaction. Any invalid observation rejects the whole submission (`400 validation_failed`
  with the observation's index and field). Highlights: `tls.hostname` and the `http` URL host must equal
  the target's hostname; addresses must be public unicast; `port` (and `tls` with
  `check: "tls_configuration"`) addresses must lie in the job's currently approved networks; evidence
  ≤ 16 KB (UTF-8 bytes).
- **`discovery` observations** are accepted only for a job with `jobType: "discovery"` whose snapshot
  profile lists the `discovery` check (else `400`, field `kind`), and the hostname is re-checked on an
  exact label boundary against the job's domain (else `400`, field `hostname`: `evil-example.com`,
  `example.com.evil.net` are rejected). Every observation is stored in `discovery_observations`. Each
  **successful** hostname is upserted as an asset in one statement per submission: a new hostname becomes
  a `pending` candidate (`apex` if it equals the domain, else `subdomain`; source
  `certificate_transparency`; first/last seen = `observedAt`; `wildcard_only` = the sighting's
  `wildcard`); an existing asset only gets `last_seen_at` advanced (never moved back) and
  `wildcard_only` narrowed (`existing AND incoming`). **Ingestion never changes an asset's approval
  status**, so discovery cannot put a hostname into scan scope. `error`/`timeout`/`partial`
  observations are stored as evidence only.
- **DNS → inventory (any job type):** successful `A`/`AAAA` observations whose hostname is an asset of
  the job's domain upsert `asset_ips` (source `dns`, `last_seen_at` advanced); addresses of the same
  family last seen before the newest answer stop being current (an empty answer leaves none current; an
  older, out-of-order answer revives nothing). A successful `CNAME` observation recomputes the asset's
  `hosting_hint` with `classifyHosting(values)` (empty answer or no known provider → `null`); no CNAME
  observation leaves it unchanged. Set-based (a few statements per submission).
- **Authorisation withdrawn:** the job's authorisation is re-checked first. If it no longer holds, the
  job is flagged for cancellation (committed), and a submission containing any `tls`, `http` or `port`
  observation is refused with **`409 conflict`** ("This job is no longer authorised for active checks;
  its active evidence was not accepted."). Status-only and passive (`dns`/`registration`) submissions
  are still accepted. The same `409` applies to active evidence for a target whose asset is no longer
  `approved` (suspended or rejected mid-job); the job is flagged for cancellation too. The worker treats
  any `409` as "stop work on this job".

After a successful submission that completes the job, the rules engine evaluates its observations
(immediately, best effort, and otherwise by the 5-minute cron).

### `POST /api/v1/internal/worker/failures`

Body: `{ jobId, attempt, errorCode (^[a-z0-9_]{1,64}$), errorSummary (≤500), retryable: boolean }`.
Response `{ "status": "queued" | "failed" | "cancelled", "retryAt": "…" | null }`.

- Cancellation requested → `cancelled` (remaining targets `skipped`).
- Retryable and attempts remain → `queued` again after the backoff, with running targets reset to
  `pending`.
- Otherwise → `failed` (remaining targets `failed` with the error code).

A failed or cancelled job never resolves anything.
