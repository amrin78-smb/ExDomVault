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
