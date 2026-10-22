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
`ACTIVE_SCANNING_ENABLED` Worker var.

### `POST /api/v1/domains/:id/scans` — `scans:request`

Body: `{ "profile": string (1–40), "reason"?: string|null (≤500; empty → null) }`. Unknown fields are
rejected. Returns **`202 Accepted`** with the scan detail (same shape as `GET /scans/:id`); the job is
`queued` and runs when a worker claims it.

Before creating the job, pending-challenge expiry and admin-authorisation lapse are applied to the domain.
Then, in one transaction with the domain row locked:

| Condition                                                                       | Response                              |
| ------------------------------------------------------------------------------- | ------------------------------------- |
| Unknown or disabled profile                                                     | `400 validation_failed` (`profile`)   |
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
- `observations` (≤ 500, default `[]`): `dns`, `registration`, `tls`, `http`, `port` observations
  (shapes and rules in [`worker-protocol.md`](worker-protocol.md#observations-milestone-5)), stored in
  the same transaction. Any invalid observation rejects the whole submission (`400 validation_failed`
  with the observation's index and field). Highlights: `tls.hostname` and the `http` URL host must equal
  the target's hostname; addresses must be public unicast; `port` (and `tls` with
  `check: "tls_configuration"`) addresses must lie in the job's currently approved networks; evidence
  ≤ 16 KB (UTF-8 bytes).
- **Authorisation withdrawn:** the job's authorisation is re-checked first. If it no longer holds, the
  job is flagged for cancellation (committed), and a submission containing any `tls`, `http` or `port`
  observation is refused with **`409 conflict`** ("This job is no longer authorised for active checks;
  its active evidence was not accepted."). Status-only and passive (`dns`/`registration`) submissions
  are still accepted. The worker treats any `409` as "stop work on this job".

Findings are not produced yet (Milestone 7).

### `POST /api/v1/internal/worker/failures`

Body: `{ jobId, attempt, errorCode (^[a-z0-9_]{1,64}$), errorSummary (≤500), retryable: boolean }`.
Response `{ "status": "queued" | "failed" | "cancelled", "retryAt": "…" | null }`.

- Cancellation requested → `cancelled` (remaining targets `skipped`).
- Retryable and attempts remain → `queued` again after the backoff, with running targets reset to
  `pending`.
- Otherwise → `failed` (remaining targets `failed` with the error code).

A failed or cancelled job never resolves anything.
