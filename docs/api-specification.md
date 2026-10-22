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

Every route except `/health` requires an authenticated, provisioned user. Unknown paths also require
authentication, so route existence isn't revealed.

| Situation                                                                              | Response                                |
| -------------------------------------------------------------------------------------- | --------------------------------------- |
| Authentication not configured (`AUTH_PROVIDER` unset, or Access team/AUD missing)      | `503 service_unavailable` (fail closed) |
| No or invalid Cloudflare Access token                                                  | `401 unauthenticated`                   |
| Valid identity but no matching active user                                             | `403 forbidden`                         |
| User lacks the permission for the route                                                | `403 forbidden`                         |
| State-changing request (`POST/PUT/PATCH/DELETE`) without a same-origin `Origin` header | `403 forbidden` (CSRF)                  |
| Database unreachable                                                                   | `503 service_unavailable`               |

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
  Registration fields stay `null` until RDAP collection exists.
- `verificationStatus`: `unverified` → `pending` (challenge issued) → `verified`; `revoked` is reserved.

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

### `PATCH /api/v1/domains/:id` — `domains:write`

Body: any of `criticality`, `businessOwner` (string or null; empty clears), `monitoringEnabled`; at
least one. Enabling monitoring on a domain that is not verified → `409`. Audited `domain.updated` (with
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

**Verification grants nothing else.** It does not create or approve assets, IP addresses or scan
scope; hosting, CDN and cloud infrastructure need separate approval (later milestones).

### CSV import — `domains:write`

Header row required (case-insensitive): `domain` (or `fqdn`, required), `criticality`,
`business_owner` (or `owner`). Unknown or repeated columns block the file. ≤ 1000 rows, ≤ 256 KB.

`POST /api/v1/domains/import/preview` — body `{ "csv": string }`. Writes nothing. Returns
`{ digest, rows[], fileErrors[], summary }`; each row has `line`, `input`, `fqdn`, `criticality`,
`businessOwner`, `status` (`valid`, `invalid`, `duplicate_in_file`, `already_registered`), `errors[]`,
`warnings[]`. `digest` is the SHA-256 of the CSV text.

`POST /api/v1/domains/import` — body `{ "csv": string, "digest": string }`. The digest must match the
CSV (`400` otherwise, so only a previewed file is imported); rows are re-validated and only `valid` rows
are inserted, in one transaction (`ON CONFLICT DO NOTHING` for names registered meanwhile). `201
{ "created": [{ id, fqdn }], "skipped": n }`. Audited `domain.created` per domain (`source: import`)
plus `domain.import_completed`.
