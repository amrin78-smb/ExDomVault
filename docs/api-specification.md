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

- **Headers:** `Cache-Control: no-store`, `Content-Security-Policy: default-src 'none';
frame-ancestors 'none'; base-uri 'none'; form-action 'none'`, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`,
  `Cross-Origin-Resource-Policy: same-origin`, `Permissions-Policy` (all sensor/device features off),
  HSTS (`middleware/security-headers.ts`). The SPA's HTML and assets get their own CSP from
  `apps/web/public/_headers` (see [threat-model.md](threat-model.md)).
- **Rate limits (`429 rate_limited`):** every authenticated request counts against 300 requests per
  minute per user, and `POST`/`PUT`/`PATCH`/`DELETE` also against 60 mutations per minute per user
  (`RATE_LIMITS`; Workers Rate Limiting bindings `API_RATE_LIMITER` / `MUTATION_RATE_LIMITER`, keyed
  by user ID, applied after authentication by `middleware/rate-limit.ts`). These limits are approximate
  (counted per Cloudflare location) and **degrade open**: a missing or failing binding lets the request
  through and logs `rate_limiter_unavailable`. A limited request answers `429` with the standard envelope
  and `Retry-After: 60`. Scan creation also enforces exact quotas — see
  [Scan quotas](#scan-quotas). The internal worker API has its own limit (120 signed requests per
  minute per key).
- **Database failures:** a connection failure, or a query failing with a connection/availability class
  (SQLSTATE classes 08, 40, 53, 57, 58, `55P03`, or a network error), answers
  `503 service_unavailable` with `Retry-After: 30`; any other database error is a bug and answers
  `500 internal_error`. Both log one `db_error` line with only the error class and SQLSTATE (never the
  SQL text or parameters).

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
  "authProvider": "dev",
  "organisation": "Example Org"
}
```

`organisation` (Milestone 13) comes from the optional Worker binding `ORG_NAME` (a Worker secret in
production, so the name is not committed): control characters removed, trimmed, cut to 100
characters; `null` when unset or blank. It is a display label only and never fails configuration.

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

### Scan quotas

Checked inside the job-creating transaction (`services/quotas.ts`, called by `createScan`) as exact
counts over `scan_jobs`, for **user-requested** jobs only (snapshot `trigger = "manual"`: manual
scans, `POST /findings/:id/reassess`, `POST /domains/:id/discovery`). Scheduled jobs never count and
are never refused by a quota. Rolling windows; every created job counts, whatever its outcome.

| Quota                               | Limit     | Counted over                                    |
| ----------------------------------- | --------- | ----------------------------------------------- |
| Scan requests per user              | 60 / hour | the requesting user's jobs (scan and discovery) |
| Requested active scans per domain   | 24 / day  | jobs with an active profile, all users          |
| Requested discovery runs per domain | 6 / day   | discovery jobs, all users                       |

Over a quota → `429 rate_limited`, message naming the limit, `Retry-After` = seconds until the oldest
counted job leaves the window (exact). No job is created and nothing is audited. The domain row lock
taken by `createScan` serialises the per-domain quotas; a transaction-scoped advisory lock on the user
serialises the per-user quota, so concurrent requests cannot both pass. A discovery or reassessment
request that returns an already queued job (`created: false`) creates nothing and is not refused.

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

### Scan schedule (scheduled active scans)

Off by default. When an administrator enables it, each 5-minute maintenance run queues the chosen
**active** profile for domains that are monitored and currently authorised for active scanning — but
only while the server's `ACTIVE_SCANNING_ENABLED` switch is on. Stored in `application_settings`
under key `scan_schedule` (`packages/shared/src/api/schedule.ts`).

`ScanSchedule`: `{ "enabled": false, "profile": "quick", "intervalDays": 1 }` — `profile` is `quick`
or `standard`; `intervalDays` an integer 1–30; unknown keys rejected.

#### `GET /api/v1/settings/scan-schedule` — `scans:read`

```json
{
  "schedule": { "enabled": true, "profile": "quick", "intervalDays": 1 },
  "updatedAt": "…",
  "updatedBy": { "id": "uuid", "email": "admin@example.com" },
  "eligibleDomains": 12,
  "activeScanningEnabled": false,
  "scheduledLast24h": 0
}
```

Without a stored setting: the default schedule (disabled) with `updatedAt`/`updatedBy` `null`. A
stored value that no longer validates is reported (and treated) as disabled. `eligibleDomains`:
domains with monitoring on, `verified` (DNS TXT or administrator authorisation) and review date not
passed. `activeScanningEnabled`: the server switch — when `false`, nothing active is scheduled
regardless of `enabled`. `scheduledLast24h`: jobs of the schedule's profile with `trigger: "schedule"`
created in the last 24 hours.

#### `PUT /api/v1/settings/scan-schedule` — `scan_policies:manage`

Body: `ScanSchedule` (all three fields). Upserts the setting (`updated_by` = caller) and returns the
same shape as `GET`. Enabling while the server switch is off is allowed (saved; reported with
`activeScanningEnabled: false`). Audited `settings.scan_schedule_updated` with `before` (null when
unset) and `after`. `400 validation_failed` for an invalid body; `403` without the permission (admin
only).

#### Scheduling (cron)

`services/scan-schedule.ts` `scheduleActiveScans`, a failure-isolated maintenance step. A domain is
**due** when monitoring is on, it is authorised for active scanning, and no job of the profile
(scheduled or manual) is queued/claimed/running or was created within `intervalDays`. A domain that
has never had a job of the profile waits for its slot within the interval (stable hash of its id, as
for discovery); afterwards it recurs about one interval after its previous job. At most 30 jobs per
run, least recently scanned first. Jobs: `jobType: "scan"`, priority 220 (behind user-requested 100
and passive monitoring 200, ahead of discovery 250), `trigger: "schedule"`, `requestedBy: null`,
reason `Scheduled <profile> scan`.

Each job is created in its own transaction with the same scope rules as `POST /domains/:id/scans`:
the domain row is locked and authorisation and monitoring re-checked; targets are the approved assets
(the apex is approved implicitly through domain verification — audited `asset.approved` as a system
action with `onBehalfOf` = the administrator who last saved the schedule, who is recorded as
`approved_by`; without one, no implicit approval happens); the snapshot carries the currently
approved networks; claim-time and heartbeat re-checks apply unchanged. A domain with no approved
target, or with a job already queued (one-active-job index), is skipped. Each run that found due
domains writes one `scan.scheduled` audit row (system actor) with `profile`, `intervalDays`, `due`,
`jobs`, `jobIds`, `skipped` (by reason) and `failed`.

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

`trigger` is `schedule` for cron-created jobs — passive monitoring, discovery and scheduled active
scans (`requestedBy` is then `null`). `domain` is
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

Milestone 13: every asset carries `role` — its primary role from collected evidence
(`classifyAssetRole`, computed per page by `assetRolesFor` in one statement): MX/NS target of a
monitored apex (latest successful answer), open TCP role ports on its current addresses (latest
port observation per address/port), a successful HTTP response within 30 days, or third-party
hosting; else `unclassified`. Optional `role` filter (`ASSET_ROLES`; invalid → `400`): roles are
evaluated for up to `ASSET_ROLE_FILTER_LIMIT` (5000) assets matching the other filters, in sort
order, then paged in memory (beyond that the list and `total` are truncated). The asset CSV export
ignores `role`. `GET /assets/:id` includes `role` too.

### `GET /api/v1/domains/:id/assets` — `assets:read`

As `GET /assets`, scoped to the domain (a `domainId` query parameter cannot widen it). `404` for an
unknown domain, and for an asset owner who owns no asset in it.

### `POST /api/v1/domains/:id/assets/import` — `domains:write`

Host import. This adds hostnames the browser took from a DNS zone export, a CSV/XLSX record list or a
plain list as **pending** assets, so hosts that discovery misses (behind wildcard certificates, or
with no public certificate) can still be reviewed. Only admins hold `domains:write`. Contract:
`packages/shared/src/api/asset-import.ts`.

Body `assetImportRequestSchema` (strict):
`{ "entries": [{ "hostname": string ≤ 253, "cnameTarget"?: string ≤ 253 }] (1–5000), "dryRun"?:
boolean (default false), "fileName"?: string ≤ 255 }`. This route accepts bodies up to 4 MB; the
default cap is 300 KB. `404 not_found` for an unknown domain or a malformed id. `400
validation_failed` for schema errors.

The server classifies every entry again and does not trust the client's extraction. Rows come back in
input order:

| Outcome         | When                                                                                                                                                                                                                                                                                                                                                                                                      |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `invalid`       | The hostname is not valid after normalisation. This covers bad syntax, a single label, an IP address, a wildcard or `*` label, a label starting with `_`, or malformed IDN. `hostname` is the input, trimmed and cut to 253 characters. Normalisation runs `normaliseDomain`; rejections that are only about registrability (`not_registrable`, public or private suffix) still count as valid hostnames. |
| `out_of_domain` | The hostname is valid, but it is neither the domain's FQDN nor beneath it at an exact label boundary. `evil-example.com` and `example.com.evil.net` are not within `example.com`, and a parent domain is never within its subdomain.                                                                                                                                                                      |
| `duplicate`     | The same normalised hostname appeared earlier in the request.                                                                                                                                                                                                                                                                                                                                             |
| `existing`      | The hostname is already an asset of this domain, in any status. `existingStatus` gives that status. The asset is left untouched.                                                                                                                                                                                                                                                                          |
| `new`           | The hostname will be added (dry run) or was added.                                                                                                                                                                                                                                                                                                                                                        |

`hostingHint` comes from `classifyHosting` run over every `cnameTarget` given for the hostname
anywhere in the request, duplicate rows included. For `existing` rows it is the asset's stored hint.
It is `null` for `invalid` rows. `summary` = `{ total, new, existing, duplicate, invalid, outOfDomain,
thirdPartyHosted }`, where `thirdPartyHosted` counts `new` rows that have a hint.

- **`dryRun: true`** → `200`. Nothing is written and no audit record is made (this is the preview).
- **Otherwise** → `201`, in one transaction:
  - New rows are inserted with source `import`, status `pending`, monitoring off, type `apex` for the
    FQDN and `subdomain` otherwise, and first/last seen set to now.
  - The insert uses `ON CONFLICT (domain_id, hostname) DO NOTHING`, so a host inserted concurrently
    is reported as `existing` and the import does not fail.
  - The transaction writes one audit record: `asset.imported` (resource `domain`), with metadata
    `{ fileName, total, new, existing, duplicate, invalid, outOfDomain, thirdPartyHosted }`. The
    hostnames themselves are not stored in the audit record.

An import never approves an asset, never changes an existing asset, never enables monitoring and
never queues a job. Approval is still the only way into scope. The work is set-based: one select of
existing hostnames and one insert, each chunked at 1000 rows. A re-import of the same file returns
every in-domain row as `existing`.

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
`Content-Disposition: attachment; filename="findings-YYYYMMDD.csv"` (UTC date), CRLF line endings; the
body starts with a UTF-8 BOM (as every CSV export does, so spreadsheet applications decode non-ASCII
text correctly). Columns (`REPORT_CSV_COLUMNS`): `finding_id, rule_id, severity, risk_score, status, domain,
hostname, component, title, first_seen_at, last_seen_at, resolved_at, assignee` (email)`,
business_owner`. At most `REPORT_CSV_MAX_ROWS` (5000) rows in the requested sort order; when more
matched, the header `X-Truncated: true` is set.

Cell encoding: any text cell starting with `=`, `+`, `-`, `@`, tab or CR is prefixed with `'`
(CSV/formula injection; numeric values such as a negative number are written as numbers), then RFC 4180
quoting applies (cells containing `"`, `,`, CR or LF are quoted, `"` doubled).
Each export is audited `report.exported` (`resourceType: report`, `resourceId: findings.csv`, metadata
`report`, `format`, `filters`, `rows`, `truncated`) in the same transaction as the read.

## Exports

`GET /api/v1/exports/<resource>.csv` downloads the rows of a list as CSV (contract:
`packages/shared/src/api/exports.ts`; implementation `routes/exports.ts`, `services/exports.ts`,
`lib/csv-export.ts`). Each export accepts the **same query parameters as its list** (the same zod
schema; `page` and `pageSize` are accepted and ignored), uses the list's own WHERE / ORDER BY builders
(so filters, sort order and object-level visibility are identical to the list), and requires the
list's permission:

| Resource          | Same filters and sort as | Permission      | Visibility                                             |
| ----------------- | ------------------------ | --------------- | ------------------------------------------------------ |
| `domains`         | `GET /domains`           | `domains:read`  | all domains                                            |
| `assets`          | `GET /assets`            | `assets:read`   | asset owners: only assets they own                     |
| `advisories`      | `GET /advisories`        | `findings:read` | asset owners: only findings on their assets            |
| `software`        | `GET /software`          | `findings:read` | asset owners: only software on their assets            |
| `scans`           | `GET /scans`             | `scans:read`    | all jobs                                               |
| `users`           | `GET /users`             | `users:manage`  | all users                                              |
| `audit-logs`      | `GET /audit-logs`        | `audit:read`    | all entries                                            |
| `ports`           | `GET /ports`             | `assets:read`   | asset owners: only addresses their assets resolve to   |
| `certificates`    | `GET /certificates`      | `assets:read`   | asset owners: only certificates of their assets        |
| `vulnerabilities` | `GET /vulnerabilities`   | `findings:read` | asset owners: only software / findings on their assets |

Findings keep their existing endpoint, `GET /reports/findings.csv` (above). An invalid filter value is
`400 validation_failed`, as on the list.

**Response** `200`:

- `Content-Type: text/csv; charset=utf-8`;
  `Content-Disposition: attachment; filename="exdomainvault-<resource>-YYYYMMDD.csv"` (UTC date).
- Body: UTF-8 BOM, a header row with the fixed columns (`EXPORT_COLUMNS[resource]`), one record per
  row; CRLF line endings; RFC 4180 quoting (cells containing `"`, `,`, CR or LF are quoted, `"`
  doubled).
- Formula-injection protection: a text cell starting with `=`, `+`, `-`, `@`, tab or CR is prefixed
  with `'`. Numeric values (e.g. a negative `days_left`) are written as plain numbers.
- Lists inside a cell (IP addresses, CVE IDs, recommended actions, references) are joined with `; `;
  timestamps are ISO 8601 UTC (`2026-10-23T10:00:00.000Z`); booleans are `true` / `false`; missing
  values are empty cells.
- At most `EXPORT_MAX_ROWS` (10,000) rows. `X-Total-Rows: <n>` is always sent (the number of rows that
  matched); `X-Truncated: true` is added when more rows matched than were written.

**Columns:**

| Resource          | Columns                                                                                                                                                                                                                                                                                                  |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `domains`         | `domain` (A-label), `unicode_name`, `verification_status`, `verification_method`, `verification_expires_at` (attestation review date), `criticality`, `business_owner`, `monitoring`, `registrar`, `registration_expires_at`, `open_findings` (non-resolved), `created_at`                               |
| `assets`          | `hostname`, `domain`, `asset_type`, `status`, `source`, `current_ips`, `hosting_provider` (hosting hint), `wildcard_only`, `owner` (email), `decided_by` (email), `decided_at`, `decision_reason`, `first_seen_at`, `last_seen_at`, `active_findings`                                                    |
| `advisories`      | `finding_id`, `rule_id`, `severity`, `risk_score`, `finding_status`, `domain`, `hostname`, `advisory_title`, `summary`, `business_impact`, `recommended_actions`, `references`                                                                                                                           |
| `software`        | `domain`, `hostname`, `ip_address`, `port`, `source`, `product`, `version`, `eol_cycle`, `eol_date`, `is_eol` (empty when the version has no end-of-life data), `known_exploited_cves`, `backport_distribution`, `banner`, `first_seen_at`, `last_seen_at`                                               |
| `scans`           | `scan_id`, `job_type`, `domain`, `profile`, `trigger` (`manual` / `schedule`), `status`, `requested_by` (email), `created_at`, `started_at`, `completed_at`, `duration_seconds` (completed − started, rounded), `targets`, `targets_failed`, `attempt` (attempts used), `error_code`                     |
| `users`           | `email`, `display_name`, `role`, `active`, `signed_in` (identity bound by a first sign-in), `last_login_at`, `created_at`                                                                                                                                                                                |
| `audit-logs`      | `created_at`, `actor_type`, `actor` (email; empty for worker/system), `action`, `resource_type`, `resource_id`, `request_id`, `metadata` (JSON)                                                                                                                                                          |
| `ports`           | `ip_address`, `port`, `protocol`, `state`, `service`, `hostnames` (visible assets currently resolving to the address), `domain`, `country`, `policy_violation` (active EXP-002), `first_observed_at`, `last_observed_at`                                                                                 |
| `certificates`    | `hostname`, `domain`, `ip_address`, `port`, `status` (primary status), `issuer`, `subject`, `subject_alt_names`, `not_before`, `not_after`, `days_left` (relative to the export time; negative when expired), `hostname_matches`, `trusted` (empty when not recorded), `protocol_version`, `observed_at` |
| `vulnerabilities` | `cve`, `title`, `cvss` (highest, one decimal), `kev`, `known_ransomware_use`, `products` (catalogue product ids), `affected_hosts`, `affected_domains`, `open_findings` (active SOFT-002), `kev_date_added`                                                                                              |

**Software:** end-of-life and known-exploited status are computed at export time exactly as
`GET /software` computes them: the stored intelligence is loaded once for every product the export can
contain, then each row is matched in memory. With `status=eol` or `status=kev` the candidate rows
(version disclosed, product with intelligence) are scanned in batches of 2,500 and only matching rows
are kept; at most 50,000 candidates are scanned (`SOFTWARE_EXPORT_SCAN_LIMIT`) — beyond that the
export is flagged `X-Truncated: true` and `X-Total-Rows` counts the matches found in the scanned rows.

**Inventory views (Milestone 13):** the export reads the list's rows through the same service
functions (`portItems` / `certificateItems` / `vulnerabilityItems` in `services/inventory.ts`) with a
row limit instead of a page, so rows, order and visibility match the list; `X-Total-Rows` is the
list's `total` for the same filters (the state/status filter included). Vulnerabilities are computed
in memory over the bounded CVE set exactly as `GET /vulnerabilities` does (`kev=false` exports an
empty file). Possible matches only: banners can hide backported fixes.

**Audit:** every export writes `report.exported` (`resourceType: report`, `resourceId:
<resource>.csv`, metadata `{ resource, filters, rows, truncated }`, where `filters` is the parsed query
without unset parameters) in the same transaction as the read.

## Exposed software (Milestone 11)

Contracts: `packages/shared/src/api/software.ts`, catalogue `packages/shared/src/domain/software.ts`.
Server: `apps/web/worker/routes/software.ts`, `services/software.ts`.

Software is what hosts **report about themselves** (HTTP `Server` / `X-Powered-By`, Nmap service
identification). It is evidence to verify, never proof: distributions backport fixes without changing
the version string (`backportHint`), and a hidden version is unknown, not "not affected".

**Permission:** `findings:read` for all three endpoints (the inventory is evidence in the same sense as
findings). Admins, analysts and viewers see everything; **asset owners** see only rows whose
`software_inventory.asset_id` is an asset they own (rows without an asset are invisible to them).

**Inventory maintenance:** rules evaluation of every succeeded job upserts `software_inventory` from
`extractSoftware(current observations)` (successful observations only, open ports only), keyed by
`(domain_id, location_key)` with `location_key = source|hostname|ip|port|product` (HTTP sightings have
no ip/port: CDN addresses rotate). Existing rows advance `last_seen_at` and take the newest version,
banner and backport hint, only from evidence at least as new as theirs; rows are never deleted. The
asset is the asset with the sighting's hostname; for service identification, the asset whose name
resolved to that address in the same job, when exactly one did.

**Status at read time:** `eol` (`eolStatus`) and `knownExploited` (`matchAdvisories`, KEV advisories
only) are computed from the stored intelligence on every read, so they follow feed updates
immediately. Findings (SOFT-001 / SOFT-002) are **not** re-evaluated when feeds change; they update on
the domain's next successful scan.

### `GET /api/v1/software` — `findings:read`

Query `softwareListQuerySchema`: `page` (default 1), `pageSize` (1–100, default 50), `domainId`,
`product` (catalogue key), `status` = `all` (default) | `eol` (end-of-life versions) | `kev` (possibly
affected by a known-exploited CVE), `q` (substring of hostname, IP, domain, product, version or banner).
Response `softwareListResponseSchema`, ordered by domain, hostname, IP, port, product.

- `status=all` pages in SQL; status is computed for the page's rows only.
- `status=eol|kev` needs the computed status to filter: rows with a disclosed version of products that
  have the relevant intelligence are pre-scanned (at most `STATUS_PRESCAN_LIMIT` = 5000, in list order),
  filtered in memory and paged. Beyond 5000 candidates results and `total` are truncated.

### `GET /api/v1/software/summary` — `findings:read`

`softwareSummaryResponseSchema`: per product, `hosts` (inventory locations), `eol` and `knownExploited`
(locations whose version is end-of-life / possibly KEV-affected) and the version distribution. One
`GROUP BY (product, version)` (≤ 5000 groups) with status computed once per pair; products sorted by
`hosts` descending. Same visibility as the list.

### `GET /api/v1/domains/:id/software` — `findings:read`

The list endpoint with `domainId` fixed (same query parameters and visibility). Unknown domain → `404`.

## Intelligence feeds (Milestone 11)

Server: `apps/web/worker/services/intel-feeds.ts`, `lib/feed-fetch.ts`. Feed state lives in
`intel_feeds` (one row per feed).

| Feed        | Source (verified 2026-10-23)                                                                                        | Schedule                                                                              |
| ----------- | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `endoflife` | endoflife.date **API v1** (current): `https://endoflife.date/api/v1/products/<eolSlug>` → `result.releases[]`       | Daily (cron); retried at most hourly after a failure; manual sync                     |
| `cisa_kev`  | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (linked from CISA's KEV page) | Daily (cron), conditional request (ETag / Last-Modified); manual sync                 |
| `nvd`       | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<id>`                                                       | Every cron run: ≤ 5 CVEs (≤ 20 with `NVD_API_KEY`), runs ≥ 30 s apart; no manual sync |

- **endoflife.date:** each release maps to a `software_eol_cycles` row: `cycle = name`, `release_date`,
  `eol_date = eolFrom`, `eol_boolean = isEol` only when `eolFrom` is null, `latest = latest.name`. One
  product failing does not stop the others (`last_error = partial_<class>`); the feed fails only if all
  fail. No conditional requests (validators are per URL; the feed has one state row).
- **CISA KEV:** `catalogVersion` → `source_version`. An entry pre-matches a catalogue product when any
  of its `kevAliases` occurs as a whole word sequence in lowercase `vendorProject + ' ' + product`
  (`php` matches "PHP FPM" but not "phpMyAdmin"; `iis` matches "Internet Information Services (IIS)").
  Upsert per (CVE, product): `kev = true`, `kev_date_added`, `ransomware = (knownRansomwareCampaignUse
=== 'Known')`, `title = vulnerabilityName`, `description = shortDescription`; new rows have empty
  ranges and `nvd_fetched_at` null. CVEs that leave the catalogue keep their row with `kev = false`.
  Malformed entries are skipped (logged); a malformed envelope fails the sync. Remaining alias false
  positives are dropped by the NVD step (`no_product_match`).
- **NVD:** pending = `nvd_fetched_at` null and not in back-off. From `configurations`, `cpeMatch`
  entries with `vulnerable: true` whose criteria is `cpe:2.3:a:<vendor>:<product>:…` for the
  advisory's catalogue CPE (negated nodes ignored). A concrete version (`…:openssh:8.2:p1:…` → `8.2p1`)
  becomes `{startIncluding = endIncluding = version}`; `*` uses `versionStart*` / `versionEnd*` (none =
  every version); `-` is skipped. CVSS: v3.1 base score (`Primary` first), else v4.0, else v3.0.
  `published_at` from `published` (UTC). Outcome `nvd_status`: `ok` (ranges found), `no_product_match`
  (empty ranges, never matches), `not_found` (no record / 404) — all three set `nvd_fetched_at`.
  `error` leaves the row pending and records the attempt (`updated_at`); it is retried after 6 hours.
  Rate limits: a sliding window of 5 (50 with a key) requests per 30 s within a run, plus a feed claim
  that keeps runs at least 30 s apart; HTTP 403/429 (`rate_limited`) stops the batch without
  penalising the CVE. The optional key is sent as the `apiKey` header.

Every fetch: HTTPS to the fixed host only (same-host `https` redirects, ≤ 2, are followed; any other
redirect is refused), timeout (endoflife 10 s, KEV 30 s, NVD 15 s), body cap (2 MB / 16 MB / 4 MB),
`User-Agent: ExDomainVault/<APP_VERSION> (+https://exdomainvault.amrin78.workers.dev)`, zod validation
before any write, set-based writes. Failures are stored as a short class in `last_error` (`timeout`,
`network`, `http_<status>`, `rate_limited`, `redirect_refused`, `too_large`, `invalid_json`,
`invalid_schema`, `not_found`, `internal`), never a response body.

**Evaluation:** `context.softwareIntel` contains the cycles and the `nvd_status = 'ok'` advisories of
the products sighted in the job; `asOf` = newest `last_success_at` of any feed. If no feed has ever
synced it is omitted, and the software rules neither raise nor resolve.

### `GET /api/v1/intel/feeds` — `findings:read`

`intelFeedsResponseSchema`: per feed (`endoflife`, `cisa_kev`, `nvd`, always all three)
`lastSuccessAt`, `lastAttemptAt`, `lastError`, `items` (cycles held / KEV advisories with `kev = true` /
advisories with `nvd_status = 'ok'`), `sourceVersion` (KEV `catalogVersion`), `pending` (NVD only:
advisories with `nvd_fetched_at` null). Readable by everyone who can read software, because feed
freshness qualifies every software verdict.

### `POST /api/v1/intel/feeds/sync` — `settings:manage`

Admins. No body (same-origin rule applies). Audited `intel.sync_requested` (`resourceType:
intel_feed`, metadata `feeds: ['endoflife', 'cisa_kev']`) before the sync runs, then synchronises
endoflife.date and CISA KEV immediately (bounded by the timeouts above; at most once a minute per feed —
within a minute of the last attempt the call is a no-op). NVD is never triggered manually (rate limits).
Response `200` with **`intelFeedsResponseSchema`** — the feed list after the sync, so feed errors show
up as `lastError` rather than as an HTTP error.

## Overview dashboard and search (Milestone 13)

Contracts: `packages/shared/src/api/dashboard.ts`, `packages/shared/src/api/search.ts`.
Implementation: `routes/dashboard.ts`, `services/dashboard.ts`, `routes/search.ts`,
`services/search.ts`.

Both routes accept any role holding at least one of `domains:read`, `assets:read` or
`findings:read` (today: every role) and gate each **section / group** by the permission of the list
it summarises: domain counts — `domains:read`; scans — `scans:read`; assets, IPs, ports and
certificates — `assets:read`; findings, software and vulnerabilities — `findings:read`. A section the
caller may not read is zero / empty. Asset owners additionally see only data on assets they own
(findings, assets, current IPs, certificates, software rows with that `asset_id`); domain counts and
scans are always empty for them.

### `GET /api/v1/dashboard?range=7|30|90`

`dashboardResponseSchema`; `range` defaults to 30, anything else is `400 validation_failed`. Every card
is one aggregate statement (`generate_series` for daily series, `DISTINCT ON` for latest
observations), so the response costs a fixed number of queries. Days are UTC; a series has
`range + 1` points (range start … today); `delta` = last point − first point.

| Field                        | Definition                                                                                                                                                                                                                                                                                            |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `lastScanAt`                 | Newest `completed_at` of a succeeded scan or discovery job                                                                                                                                                                                                                                            |
| `stats.domains`              | `value` = all domains, `active` = `monitoring_enabled`; series = domains with `created_at` before each day's end                                                                                                                                                                                      |
| `stats.assets`               | `value` = approved, `pending` = pending; series = currently approved assets with `approved_at` before each day's end                                                                                                                                                                                  |
| `stats.openFindings`         | `value` = non-resolved findings (accepted risks included, as in reports); series = `first_seen_at` < day end and (`resolved_at` null or ≥ day end) — a reopened finding counts from its current `resolved_at` only                                                                                    |
| `stats.criticalHigh`         | The same for `critical` and `high`                                                                                                                                                                                                                                                                    |
| `stats.expiringCertificates` | Distinct hostnames whose latest **successful** TLS observation in the last 90 days has `not_after` ≤ now + 30 days (expired included); no history (`series` `[]`, `delta` null)                                                                                                                       |
| `stats.eolSoftware`          | Software inventory rows whose (product, version) is on an end-of-life cycle; `kev` = rows with a possible known-exploited CVE — the same read-time computation as `GET /software` (`statusComputer`); no history                                                                                      |
| `severity`                   | Non-resolved findings per severity (every severity key present)                                                                                                                                                                                                                                       |
| `trend`                      | Per day: findings first seen that day by severity, and findings whose `resolved_at` falls on the day                                                                                                                                                                                                  |
| `topRemediation`             | ≤ 5 actionable findings (`open`, `acknowledged`, `remediation_in_progress`; accepted risks excluded) by `risk_score` desc, severity desc, `first_seen_at`, id. `cves` = `evidence.cveId` when it is a CVE id (SOFT-002), else `[]`; `assetRole` from `assetRolesFor` (null for domain-level findings) |
| `latestScans`                | ≤ 5 scan/discovery jobs newest first (`created_at`), `profile` = the scan profile's name                                                                                                                                                                                                              |
| `certificateExpiry`          | ≤ 5 of the expiring certificates above, soonest first; `daysLeft` = floor of days remaining (negative if expired)                                                                                                                                                                                     |
| `recentAssets`               | ≤ 5 assets by `first_seen_at` desc (any status), with their role                                                                                                                                                                                                                                      |
| `topSoftware`                | ≤ 5 products by distinct hosts (`coalesce(hostname, ip)`), then product key; `versions` = ≤ 3 disclosed versions by distinct hosts (ties alphabetical); `eolHosts` = hosts on an end-of-life version; `kevCves` = distinct possible KEV CVEs across the reported versions                             |

### `GET /api/v1/search?q=`

`searchResponseSchema`. `q` is trimmed and must be 2–100 characters (`400 validation_failed`
otherwise). Matching is case-insensitive substring `ILIKE` with `%`, `_` and `\` escaped (no
wildcards); each group returns at most `SEARCH_GROUP_LIMIT` (5) rows ordered exact match first, then
shortest, then alphabetically. Rate limiting is the global API limiter.

| Group             | Matches                                                                                                                                                                                                                                                    |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `domains`         | `domains.fqdn` (a Unicode term is also tried as its A-label)                                                                                                                                                                                               |
| `assets`          | `assets.hostname` (same A-label handling)                                                                                                                                                                                                                  |
| `ips`             | Only for IP-looking text (digits and dots, or hex with a colon): **prefix** match on `host(ip_address)` of current `asset_ips`; each with ≤ 10 visible assets currently resolving to it                                                                    |
| `ports`           | Only for `443`, `port:443`, `port 443` (1–65535): addresses whose latest successful observation of that port is `open` (TCP preferred when both protocols exist), ordered by address; `hostname` = first visible asset currently on the address, else null |
| `software`        | Inventory rows by product key, catalogue label or version (distinct product, version, host, domain); exact product/version first, then product, version                                                                                                    |
| `vulnerabilities` | Only for CVE-looking text (`CVE-2024-38475`, `cve-2024`, `2024-384`): CVE ids that possibly affect at least one visible reported version (SOFT-002 matching), `affectedHosts` = distinct hosts on an affected version; `kev` from the advisory             |
| `findings`        | Finding titles (all statuses)                                                                                                                                                                                                                              |

## Inventory views (Milestone 13)

Contract: `packages/shared/src/api/inventory.ts`. Implementation: `routes/inventory.ts`,
`services/inventory.ts`, `services/attack-surface.ts`, `services/asset-roles.ts`. Read-only
projections of collected observations, each a fixed handful of set-based statements. Paged lists
take `page` (1–10 000) and `pageSize` (1–100, default 25); `q` is a trimmed 1–100 character
case-insensitive substring. Asset owners see only data tied to assets they own; every other role
sees everything (all four roles hold the permissions below, so no role gets `403` today).

### `GET /api/v1/ports` — `assets:read`

Query `portsQuerySchema`: `state` (`open` default, `closed`, `filtered`, `all`), `port` (1–65535),
`domainId`, `q` (address, service or hostname), `sort` (`port` default → port, address, protocol;
`ip` → address, port, protocol; `last_observed` → newest first, then address, port, protocol).

One row per (address, port, protocol): the **latest successful** port observation. `hostnames` =
assets whose current address it is (visible ones only, by hostname); `domain` = the first
hostname's domain, else the observing job's domain; `country` = the address's `asset_ips`
`country_code` (current rows first); `policyViolation` = an active (non-resolved) `EXP-002`
finding whose component is `<ip>:<port>` (`[v6]:port`); `firstObservedAt` = earliest successful
observation of that key. Asset owners see only addresses one of their assets currently resolves to.
`counts` = rows by state over every filter **except** `state`; `total` = rows for the requested
state.

### `GET /api/v1/certificates` — `assets:read`

Query `certificatesQuerySchema`: `status` (`expired`, `expiring`, `valid`, `mismatch`,
`untrusted`), `domainId`, `q` (hostname, issuer or subject), `sort` (`expiry` default → `notAfter`
ascending, nulls last, then hostname, port; `hostname` → hostname, port).

One row per (hostname, port): the latest successful `tls_certificate` observation within the last
90 days (older ones are ignored, as in the reports). `trusted` = `evidence.trusted` recorded by the
worker's chain validation (null when absent). Status precedence: `expired` (`notAfter` passed) >
`mismatch` (`hostnameMatches = false`) > `untrusted` (`trusted = false`) > `expiring` (`notAfter`
within `CERTIFICATE_EXPIRING_DAYS` = 30) > `valid`. `daysLeft` = whole days to `notAfter` (floor).
Asset owners see only observations of assets they own. `counts` cover every filter except `status`.

### `GET /api/v1/vulnerabilities` — `findings:read`

Query `vulnerabilitiesQuerySchema`: `kev` (`true`/`false`), `q` (CVE id, title, product key or
label), `sort` (`hosts` default → affected hosts desc, CVSS desc, CVE; `cvss` → CVSS desc nulls
last, CVE; `cve` → CVE ascending by year then number).

One row per CVE that **possibly** affects at least one disclosed version in the software inventory,
matched exactly like `SOFT-002`: a version precise enough to range-match (`preciseEnough`) inside
any NVD range of a CISA KEV advisory (`matchAdvisories`, `nvd_status = 'ok'`). `affectedHosts` =
distinct inventory locations (hostname, else address); `affectedDomains` = distinct domains;
`openFindings` = active `SOFT-002` findings whose `evidence.cveId` is the CVE; `cvss` = highest over
the CVE's product rows; `kevDueDate` is always null (the KEV sync stores `dateAdded` only). Every
advisory the matcher considers is a KEV entry, so `kev=false` returns an empty list. Without any
synced feed the list is empty. Up to 5000 (product, version) groups are evaluated. Asset owners see
only inventory rows and findings on assets they own.

### `GET /api/v1/attack-surface` — `assets:read`

`attackSurfaceResponseSchema`, no query. Scope: **approved** assets visible to the caller and their
**current** addresses.

- `totals`: approved assets, distinct current addresses, open TCP ports (latest successful
  observation per address/port that is `open`), approved assets with a hosting hint.
- `assetRoles`: every role in `ASSET_ROLES` order with its count (0 allowed), from `assetRolesFor`.
- `hostingProviders`: by `hosting_hint` provider/kind, null bucket = no known third party; sorted by
  count desc, null last, then name.
- `countries`: by `asset_ips.country_code` (an address whose rows disagree takes the lowest code);
  `assets` / `ips` are distinct counts; sorted by addresses desc, assets desc, code.
- `continents`: the same, via `continentOf` (`packages/shared/src/domain/continents.ts`: all 249
  ISO 3166-1 codes plus `XK`; Russia → Europe, Turkey → Asia, Egypt → Africa, Panama → North America,
  AQ/BV/GS/HM/TF → Antarctica). Only continents with data are listed.
- `unknownCountryIps`: current addresses without a country; `geoAttribution` = `DBIP_ATTRIBUTION`
  when any country is known, else null.
- `exposedServices`: top 10 open TCP ports by distinct current addresses (ties by port), `service` =
  the most common reported service name.

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

## Operations (Milestone 12)

Contracts: `packages/shared/src/api/ops.ts`. Implementation: `routes/ops.ts`, `services/ops.ts`.

### `GET /api/v1/ops/health` — `settings:manage`

`opsHealthResponseSchema`, computed from stored state with SQL aggregation (nothing estimated):

- `workers`: every registered worker with `lastSeenAt` and `status` — `online` (seen ≤ 5 min ago),
  `stale` (≤ 30 min), `offline`, `never_seen`.
- `outage`: `active` when jobs are queued and no **active** (not disabled) worker has been seen for
  30 minutes (a never-seen worker counts as unseen). `since` is the cron-recorded start
  (`ops_state.outageSince`), or before the cron has run, the later of last-seen + 30 min and the
  oldest queued job's creation. `queuedJobs` is the current number of queued jobs.
- `queue`: queued, running (`claimed` + `running`), oldest queued job's age (from creation), per
  profile.
- `scans.last24h` / `last7d`: jobs **completed** in the window — succeeded, failed, cancelled,
  `successRate` = succeeded / (succeeded + failed) (null when both are 0), p50/p95 run time
  (`percentile_cont` over `completed_at − started_at` of succeeded jobs, seconds, one decimal).
- `failuresByCode`: the 10 most frequent error codes of failed jobs and of targets completed in the
  last 24 hours.
- `database`: `ok: true` and the latency of a `select 1` (a database outage answers `503` instead).
- `feeds`: the same entries as `GET /intel/feeds`.
- `retention`: last run time and rows deleted (from `ops_state`), and `RETENTION_POLICY`.

### `GET /api/v1/ops/alerts` — any authenticated user

`opsAlertsResponseSchema`. Active alerts, for the banner:

| Kind                       | Severity | Raised when                                                                                                        |
| -------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------ |
| `worker_outage`            | critical | the outage condition above holds                                                                                   |
| `feeds_stale`              | warning  | a feed's last success is over 3 days old, or it was attempted and never succeeded; NVD only while CVEs are pending |
| `active_scanning_disabled` | warning  | the scan schedule is enabled while `ACTIVE_SCANNING_ENABLED` is off                                                |

Users with `settings:manage` get specific messages (queued job count, feed names and error classes,
the switch name); everyone else gets generic text ("Scans are delayed. Administrators have been
alerted.", "Vulnerability intelligence may be out of date.", "Scheduled active scans are paused.").

### Cron steps (`services/maintenance.ts`)

- `worker_outage_check` (`checkWorkerOutage`): compares the outage condition with
  `application_settings` key `ops_state` (row locked) and logs `worker_outage_started` (error) or
  `worker_outage_ended` (info) **once per transition**, with `alert: "worker_outage"`, `since`,
  `queuedJobs` / `durationSeconds` and `lastSeenAt`. Alert routing: [operations.md](operations.md).
- `retention` (`services/retention.ts`, `RETENTION_POLICY`): at most hourly (sooner while a previous run
  hit the batch limit); per table at most 5000 rows per run, each table failure-isolated
  (`retention_step_failed`). Observations older than 180 days are deleted except, per key, the latest
  successful observation and the latest observation of any status (keys scoped to the job's domain:
  DNS name+type, registration per domain, TLS host+IP+port, HTTP URL, port IP+port, discovery
  hostname+source). Finished jobs (succeeded/failed/cancelled) completed over 365 days ago are deleted
  with their targets and result receipts (`software_inventory.last_scan_job_id` → null), **except**
  jobs referenced by a finding's status history, jobs that still own any observation (observations
  cascade with their job, so this protects the latest-per-key ones), and succeeded jobs not yet
  evaluated. Queued/claimed/running jobs are never touched. Audit logs, findings, status history and
  comments are never deleted. The run's totals go to `ops_state.retention`
  (`lastRunAt`, `deletedLastRun`, `byTable`, `more`, `failed`).
