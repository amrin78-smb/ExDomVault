# ExDomainVault — Build Progress

Updated by Claude at the end of every milestone. Newest entries at the top of each section.

## Milestone status

| #   | Milestone                                  | Status      | Notes                                   |
| --- | ------------------------------------------ | ----------- | --------------------------------------- |
| 1   | Repository foundation                      | done        |                                         |
| 2   | Database and authentication                | done        | Deployed; production migrated           |
| 3   | Domain inventory                           | done        | Deployed 2026-10-22 (`cf062f76`)        |
| 4   | Scan job lifecycle                         | not started |                                         |
| 5   | Python worker                              | not started |                                         |
| 6   | Scanning and target safety (security gate) | not started | Active scanning disabled until complete |
| 7   | Deterministic rules engine                 | not started |                                         |
| 8   | Finding lifecycle                          | not started |                                         |
| 9   | Passive subdomain discovery                | not started |                                         |
| 10  | Frontend integration                       | not started |                                         |
| 11  | Production hardening                       | not started |                                         |

## Decisions log

- 2026-10-22 — **Verification gates only active scanning (owner decision).** Passive monitoring (public DNS, certificates, CT logs, registration data) is allowed for every domain; monitoring no longer requires verification. Milestones 4–6 must require `verification_status = 'verified'` (either method, review date not passed) before any active scan.
- 2026-10-22 — **Second verification method: administrator authorisation (owner decision)** for owned domains whose DNS cannot carry a TXT record (317 of the 339 portfolio domains use the registrar's CSC DNS). Requires `domains:verify`, a reason (≥10 chars), optional reference, review-by date (default 12 months, max 24); audited per domain; labelled "Authorised (admin)" everywhere, distinct from "Verified (DNS)"; lapses on the review date. Available per domain, in bulk from the list, and as an option on CSV import.
- 2026-10-22 — **Revocation** of either method with a mandatory reason (`revoked` status); re-verification is allowed afterwards.
- 2026-10-22 — **Bulk writes are set-based** (one statement per step + one multi-row audit insert): 339-domain import with authorisation went from 66 s to 1.4 s against Neon.
- 2026-10-22 — **Portfolio import file** built from the CSC export with only `domain`, `criticality` (`Vital Domain` = Yes → high, else medium) and `business_owner` (`Business Unit`). Registrant/admin/tech contact data is deliberately not imported. Registration and expiry dates in the export are not imported either; RDAP collection will supply verified values.
- 2026-10-22 — `punycode` is imported from its ES-module file (`punycode/punycode.es6.js`): the CommonJS entry broke the local workerd dev runner, and `punycode/` broke plain Node ESM.

- 2026-10-22 — **Only registrable domains (eTLD+1) can be registered**; subdomains are rejected with a suggestion (they become assets later). PSL via `tldts` 7.4.17, ICANN section only: private-section suffixes (`github.io`, `workers.dev`), unknown/special-use TLDs and `.arpa` are rejected.
- 2026-10-22 — **IDN handling:** WHATWG URL (UTS #46) produces A-labels; ASCII input is pre-filtered to `[a-z0-9.-]` first so percent-encoding and numeric IP shorthands never reach the parser; `xn--` labels must round-trip. Canonical A-label is shown first; Unicode form is secondary; mixed-script labels are flagged (`mixed_script`) but allowed, because DNS verification proves control anyway.
- 2026-10-22 — **Verification by DoH from the Worker** (Cloudflare `dns-query` JSON), not a worker job: one passive query to a public resolver, no scanning infrastructure needed. Record `_exdomainvault-challenge.<domain>` TXT `exdomainvault-verification=<token>`.
- 2026-10-22 — **Challenge secrecy:** 256-bit token shown once, SHA-256 stored (no pepper: the token is high-entropy). Lost value → issue a new challenge (old one `superseded`). **72 h expiry**, applied lazily on reads/writes and audited as a system action. Checks throttled to one per 10 s per challenge (atomic UPDATE). Failed checks are audited (`domain.verification_failed`).
- 2026-10-22 — **Monitoring can only be enabled on verified domains** (409 otherwise). Turning it on/off requires a UI confirmation. Monitoring has no scanning effect until later milestones.
- 2026-10-22 — **Permissions unchanged:** domain create/edit/import need `domains:write`, verification `domains:verify` (admin only today); analysts and viewers read. Asset owners have no domain access.
- 2026-10-22 — **CSV import is stateless:** preview returns the file's SHA-256; confirm must send the same file + digest, is re-validated, inserts only valid rows in one transaction (`ON CONFLICT DO NOTHING`). Unknown/repeated columns block the whole file. Limits 1000 rows / 256 KB.
- 2026-10-22 — `revoked` verification status exists in the schema but nothing sets it yet.

- 2026-10-22 — **Production deployed** to `exdomainvault.amrin78.workers.dev`, protected by the Worker's Access tab (All traffic, owner-only Allow policy). Preview URLs disabled so no unprotected alternate hostname exists.
- 2026-10-22 — **`exdomainvault_app` created with SQL, not the Neon CLI/console** — those add `neon_superuser` membership (read/write all data, CREATEROLE, BYPASSRLS).
- 2026-10-22 — **`BOOTSTRAP_ADMIN_EMAILS` is a Worker secret**, not a `wrangler.jsonc` var, so the owner's email is not committed. Access team domain and AUD are committed (public identifiers).
- 2026-10-22 — **Migrations: drizzle-kit `generate` only; applied by `scripts/migrate.ts`** (drizzle-orm migrator). Guarded: refuses `NEON_BRANCH=production` without `ALLOW_PRODUCTION_MIGRATION=yes`, and pooled URLs. TLS mode forced to `verify-full`.
- 2026-10-22 — **Schema work happens on Neon branch `dev`** (from `neon.ts`, 7-day TTL); `production` stays empty until the owner approves migrating it.
- 2026-10-22 — **DB tests use PGlite** (PostgreSQL in WASM) with the real migrations — no Docker or local Postgres needed, runs in CI.
- 2026-10-22 — **Auth: Cloudflare Access JWT verified in the Worker** (jose, RS256, issuer + AUD + expiry, JWKS cached per isolate); header or `CF_Authorization` cookie. Service tokens rejected for user sessions. Dev provider is a fixed server-side identity, refused when `APP_ENV=production`.
- 2026-10-22 — **Unconfigured auth → 503 on all protected routes** (health still reports `auth: not_configured`). Unknown API paths also require auth.
- 2026-10-22 — **User provisioning:** authentication never auto-creates users except emails in `BOOTSTRAP_ADMIN_EMAILS` (become admin, audited). Pre-provisioned emails bind their subject on first sign-in; an email already bound to another subject is denied.
- 2026-10-22 — **Permissions** defined in `packages/shared` (18 permissions, 4 roles). Asset-owner object-level scoping is enforced per endpoint as those endpoints are built.
- 2026-10-22 — **CSRF:** unsafe methods require `Origin` equal to the request origin (Access session is cookie-based).
- 2026-10-22 — **Findings recurrence** modelled per CLAUDE.md: partial unique index on `fingerprint WHERE status <> 'resolved'` plus `recurrence_count` and status history.
- 2026-10-22 — **Worker credentials not modelled yet** (no secrets in `worker_registry`); HMAC key storage is designed in Milestone 4.
- 2026-10-22 — `typecheck` uses per-project `tsc -p` (not `tsc -b`), after build-mode reported a stale pass once.
- 2026-10-22 — **Neon linked**: project `ExDomVault` (`flat-sound-26073660`), branch `production`, via `neon init` + `neon deploy` (no policy changes). Credentials in git-ignored `.env.local`.
- 2026-10-22 — **DB driver: `pg` (node-postgres) + Drizzle through Cloudflare Hyperdrive**, per Neon's agent-skill guidance and Cloudflare's Neon guide. Hyperdrive's origin is Neon's direct endpoint; the Worker opens one client per request. `@neondatabase/serverless` not used.
- 2026-10-22 — Local dev reaches Neon through the Hyperdrive binding's local connection string (`DATABASE_URL_UNPOOLED` → `CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE`, set in `vite.config.ts`).
- 2026-10-22 — Neon tooling (`neon` CLI global; `@neon/config`, `@neon/env` as root devDependencies). `neon.ts` holds the branch policy (non-default branches expire after 7 days).
- 2026-10-22 — **npm workspaces** chosen as the single package manager (pnpm not installed; npm 11 available).
- 2026-10-22 — **Hono** for Worker API routing: small, Workers-native, typed context, easy to test via `app.request()`.
- 2026-10-22 — SPA and API live in one Worker (`apps/web`): `src/` = UI, `worker/` = API. Matches Cloudflare's React + Vite template; responsibilities stay in separate directories.
- 2026-10-22 — TypeScript pinned to `~6.0` (typescript-eslint 8.72 supports `<6.1`; TS 7 not yet supported).
- 2026-10-22 — API tests run the Hono app in Node (Vitest) rather than in workerd; revisit `@cloudflare/vitest-pool-workers` in M2 when bindings (Hyperdrive) exist.
- 2026-10-22 — Client-supplied `X-Request-Id` is ignored; the server always generates the request ID.
- 2026-10-22 — npm 11 blocks install scripts by default; `esbuild` and `workerd` are explicitly allowed in root `package.json` `allowScripts`.
- 2026-10-22 — Deploy target is Cloudflare Workers; `netlify.toml` from the design layout is not used.
- 2026-10-22 — Resolved findings that recur are reopened (same fingerprint) with a status-history entry `reason = recurrence`.

## Operator actions required

_Things only the owner can do (Cloudflare account, Neon project, Access app, secrets). Add exact steps as they arise._

- [x] ~~Install Python venv support on the scan host~~ — done 2026-10-22; `npm run worker:install` / `worker:lint` / `worker:test` verified locally (18 pass).
- [x] ~~First production deploy~~ — done 2026-10-22: production migrated, `exdomainvault_app` + grants, Hyperdrive, Access, bootstrap admin signed in (details in `docs/deployment.md`).
- [ ] Optional: replace the shared `demo-allowlist` Access policy with a dedicated ExDomainVault policy.
- [ ] Optional: delete the `BOOTSTRAP_ADMIN_EMAILS` secret now that the first admin exists.
- [ ] Before Milestone 5/6 on the scan host: `sudo apt install -y nmap` (Claude will ask before doing anything that changes the machine).

## Known limitations

- Neon `dev` branch expires 2026-10-29; recreate with `neon checkout dev --create && npm run db:migrate`.
- No user-management UI/API yet: non-bootstrap users must be inserted into `users` manually.
- A positive DNS TXT verification has only been tested with a mocked resolver (needs a domain whose DNS you control); administrator authorisation was exercised end to end on the Neon `dev` branch with all 339 portfolio domains.
- Challenge expiry is lazy (applied when domain data is read or changed); no scheduled sweep until Cron Triggers arrive (Milestone 4).
- No domain deletion, no rate limit on domain creation beyond permissions. No bulk monitoring toggle yet (monitoring has no effect until collection exists).
- Registration (RDAP) data is not collected; the UI says "Not collected yet".
- Local dev connects as the Neon owner role (`neondb_owner`); production uses `exdomainvault_app`.
- Overview panels show empty states; other sections are placeholders naming their milestone.
- No deploy workflow; deploys are manual `wrangler deploy` with owner approval.

## Session log

_Per milestone: files changed, checks run (with real results), limitations, next step._

### Milestone 1 — 2026-10-22

**Built:** npm-workspace monorepo; React/Vite/Tailwind SPA with persistent navigation, Overview dashboard (honest empty states, optional labelled dev fixtures stripped from prod), placeholder sections, API status indicator; Cloudflare Worker API (Hono) with request IDs, JSON logging, security headers, fail-closed config, standard error envelope and typed `GET /api/v1/health`; `packages/shared` zod contracts; Python worker skeleton with validated config; ESLint/Prettier/tsc/Vitest/ruff/pytest; GitHub Actions CI; README, `docs/architecture.md`, CLAUDE.md commands.

**Checks (all run locally):**

- `npm run lint` — pass
- `npm run typecheck` — pass
- `npm test` — 7 files, 22 tests pass
- `npm run build` — pass (fixture data confirmed absent from production JS)
- `npm run dev` — verified in workerd: `/api/v1/health` 200 with headers, unknown API path → 404 envelope, `/domains` serves SPA; UI checked in a browser
- Worker: `ruff check`, `ruff format --check`, `pytest` (18 pass) — run in a scratch venv bootstrapped without `python3-venv`; `npm run worker:install` itself not runnable here yet
- CI — first run happens on this push

### Neon wiring — 2026-10-22

**Changed:** `neon init`/`neon deploy` linked the repo (`.neon`, `neon.ts`, `.env.local`); new `packages/database` (`connect()`, `pingDatabase()` with `pg` + Drizzle); `HYPERDRIVE` binding (placeholder id) in `wrangler.jsonc`; `vite.config.ts` feeds the local Hyperdrive connection string from `.env.local`; health route pings the DB; `docs/deployment.md`.

**Checks:** lint pass · typecheck pass · 27 tests pass · build pass (no DB code in browser bundle) · dev server: `/api/v1/health` → `"database":"ok"` (~300 ms per ping to Neon) · with a deliberately wrong password → `"database":"down"`, Neon's auth error only in server logs.

**Next:** Milestone 2 — database and authentication (`docs/prompts/02-database-and-auth.md`).

### Milestone 2 — 2026-10-22

**Built:** Drizzle schema for all design §5 entities (22 tables, 17 enums, checks, partial unique indexes) + initial migration; guarded migration runner; PGlite test harness; replaceable `AuthProvider` with Cloudflare Access JWT verification and dev provider; identity → user resolution with admin bootstrap; role/permission matrix; `requireAuth` / `requirePermission`; CSRF same-origin check; per-request DB connection; audit writer; `GET /api/v1/me`; health reports real auth status; top bar shows the signed-in user; docs (`database-schema.md`, `api-specification.md`, `deployment.md` Access/roles/Hyperdrive steps, `architecture.md`).

**Checks (all run locally):**

- `npm run lint` pass · `npm run typecheck` pass (verified it catches a deliberate error) · `npm run build` pass (PGlite not in Worker bundle)
- `npm test` — 12 files, 86 tests pass (migrations + constraints on PGlite; Access JWT: valid/cookie/missing/spoofed header/wrong aud/wrong iss/expired/unknown key/no email/alg=none/tampered; user resolution; config; API auth flows; CSRF; permissions; UI user states)
- `npm run db:check` pass; `drizzle-kit generate` reports no drift
- `npm run db:migrate` on Neon `dev`: 22 tables created (PostgreSQL 18.6); re-run is a no-op; production-branch and pooled-URL guards refuse
- `npm run dev` (workerd + Neon `dev`): health `database: ok, auth: ok`; `/me` bootstrapped `dev@example.com` as admin with one `user.bootstrap_admin` audit row; CSRF 403 without/foreign Origin; Access mode unconfigured → 503, configured without token → 401, spoofed identity header → 401; dev provider with `APP_ENV=production` → 500

**Next:** Milestone 3 — domain inventory (`docs/prompts/03-domain-inventory.md`).

### Production setup — 2026-10-22

**Done (owner-approved):** Neon `production` migrated (22 tables); `exdomainvault_app` created via SQL after the CLI-created role turned out to inherit `neon_superuser` (deleted); grants verified (append-only tables enforced, no DDL/role creation); Hyperdrive `exdomainvault-db`; Worker deployed (first with auth unconfigured → `/me` 503, health `database: ok`); owner enabled Access on the Worker; `ACCESS_TEAM_DOMAIN`/`ACCESS_AUD` set, `BOOTSTRAP_ADMIN_EMAILS` secret, redeployed (version `fc72fb76`).

**Verified live:** unauthenticated `/`, `/api/v1/health`, `/api/v1/me` and a forged `Cf-Access-Jwt-Assertion` → 302 to Access login; owner signed in → UI shows Administrator, API healthy, `production`; Neon `production` has one admin user bound to the Access subject and one `user.bootstrap_admin` audit row.

### Milestone 3 — 2026-10-22

**Built:** domain normalisation + label-boundary helper (`packages/shared/src/hostname`, `tldts` + `punycode`); shared domain/pagination/import contracts; Worker routes `GET/POST /domains`, `GET/PATCH /domains/:id`, `POST /domains/:id/verification`, `POST /domains/:id/verify`, `POST /domains/import/preview`, `POST /domains/import`; services for domains, DNS TXT verification (DoH resolver, hashing, expiry, throttle) and CSV import (RFC 4180 parser); request validation helpers; audit events `domain.created|updated|monitoring_enabled|monitoring_disabled|verification_started|verification_failed|verification_expired|verified|import_completed`. UI: session/permission context, Domains list (search, filters, sort, pagination), add form, detail page (verification panel with one-time value, owner/criticality edit, confirmed monitoring toggle, registration status, empty states), CSV import with preview/confirm. Docs: `api-specification.md` (domains), `architecture.md`. No schema change, so no migration.

**Checks (all run locally):**

- `npm run lint` pass · `npm run typecheck` pass · `npm run build` pass (PSL only in the Worker bundle, 1.0 MB / 278 KB gzip; none in the browser bundle)
- `npm test` — 18 files, 215 tests pass (+58 normalisation incl. `evil-example.com`, `example.com.evil.net`, Cyrillic homograph, IDN, PSL boundaries, IP shorthands; +40 domain API incl. RBAC denials per role, duplicates, CSRF, hash-only storage, superseded value rejected, expiry at exactly 72 h vs 1 ms before, throttle, import preview/confirm/digest mismatch; DoH/CSV/hash unit tests; 11 UI tests)
- Mutation checks: disabling the throttle and the expiry sweep each made the corresponding test fail
- `npm run dev` (workerd + Neon `dev`): create (normalised), duplicate → 409, subdomain → 400 with suggestion, start verification, real DoH check → `record_not_found`, second check → `too_soon`, monitoring before verification → 409, list/search, import preview/confirm; detail page checked in a browser
- Bug found by that run and fixed: Workers `fetch` rejects `redirect: 'error'` (Node accepts it) → DoH returned `dns_error`; now `redirect: 'manual'` with redirects treated as failures (unit-tested)
- `worker:test` not run — Python worker unchanged

**Deployed** 2026-10-22 on request, version `cf062f76-4896-4c7a-be8a-50d813fbd696` (no migration needed). Unauthenticated `/`, `/domains`, `/api/v1/domains` and a forged-token POST → 302 to the Access login.

**Next:** Milestone 4 — scan job lifecycle (`docs/prompts/04-scan-job-lifecycle.md`).

### Milestone 3 follow-up: administrator authorisation — 2026-10-22

**Why:** 339 owned domains, most with registrar-managed DNS where a TXT record per domain is impractical (owner request).

**Built:** migration `0001_domain_authorisation` (new enum values, attestation fields, domain verification method/review date, backfill, checks); `services/domain-authorisation.ts` (authorise single/bulk, revoke, lapse); routes `POST /domains/:id/authorise`, `POST /domains/authorise`, `POST /domains/:id/revoke`; optional `authorisation` on import confirm; monitoring no longer gated; set-based bulk audit (`writeAuditMany`). UI: badges distinguish DNS vs admin, "Authorise without DNS" form, revoke with reason, list row selection + bulk authorise, rows per page, import "also authorise" option.

**Checks:** lint pass · typecheck pass · build pass · `db:check` pass, no drift · `npm test` 18 files / 235 tests pass (+ constraint and backfill migration tests, authorisation API incl. review-date validation, RBAC, bulk skip rules, lapse at end of review day, revoke, import+authorise and rollback, UI flows) · Neon `dev` migrated (`0001`) · rehearsal on `dev`: full 339-row portfolio import with authorisation → 339 created/authorised, 1.4 s, audit rows per domain.

**Production:** not migrated or deployed yet — needs the owner's go-ahead (`0001` must run before deploying this code).
