# ExDomainVault — Build Progress

Updated by Claude at the end of every milestone. Newest entries at the top of each section.

## Milestone status

| #   | Milestone                                  | Status      | Notes                                   |
| --- | ------------------------------------------ | ----------- | --------------------------------------- |
| 1   | Repository foundation                      | done        |                                         |
| 2   | Database and authentication                | done        | Deployed; production migrated           |
| 3   | Domain inventory                           | done        | Deployed 2026-10-22 (`cf062f76`)        |
| 4   | Scan job lifecycle                         | done        | Deployed 2026-10-22 (`663d3165`)        |
| 5   | Python worker                              | done        | Deployed; worker live on this host      |
| 6   | Scanning and target safety (security gate) | not started | Active scanning disabled until complete |
| 7   | Deterministic rules engine                 | not started |                                         |
| 8   | Finding lifecycle                          | not started |                                         |
| 9   | Passive subdomain discovery                | not started |                                         |
| 10  | Frontend integration                       | not started |                                         |
| 11  | Production hardening                       | not started |                                         |

## Decisions log

- 2026-10-22 — **Milestone 5 built by four parallel agents** (server ingestion, Python worker, deployment/docs, UI) after I fixed the shared contract first: `packages/shared/src/api/observations.ts` + `docs/worker-protocol.md`, with an RFC 8032-based signing test vector asserted by both the TypeScript and Python test suites.
- 2026-10-22 — **Observations ride on `results` submissions**, ingested in the same transaction after the idempotency row (duplicates store nothing); row ids `jobId:resultId:index`. DNS hostnames must be within the job's domain on a label boundary; registration only for the apex target; `observedAt` within −7 days/+5 min of server time. The newest successful RDAP observation updates the domain's registrar/dates/status (never regressing; `unavailable` doesn't erase known data).
- 2026-10-22 — **Worker DNS defaults to public resolvers** (1.1.1.1, 9.9.9.9 + IPv6), not the host stub: systemd-resolved answered DS/DNSKEY with SERVFAIL in the end-to-end run, and records should be seen as the internet sees them. `EXDV_DNS_RESOLVERS=system` opts back in.
- 2026-10-22 — **Worker runtime deps** pinned (≥14 days old): httpx 0.28.1, dnspython 2.8.0, cryptography 50.0.2 (+ transitive). No Nmap; network-connecting checks (`tls_checks`, `http_checks`, `port_checks`) only raise the scope error until Milestone 6.
- 2026-10-22 — **Deployment:** systemd unit with a dedicated system user, `LoadCredential=` for the root-owned private key, no capabilities, `IPAddressDeny` for private/LAN ranges (allowing the local DNS stub), strict sandboxing (offline `systemd-analyze security` 1.2); optional hardened Docker image (non-root, read-only). The worker reaches the app through a Cloudflare Access **service token** with a Service Auth policy (configured by the owner 2026-10-22).

- 2026-10-22 — **Worker authentication uses Ed25519 request signatures, not HMAC.** The spec asked for credentials "stored hashed" and "HMAC-signed requests", which conflict (HMAC verification needs the secret). With Ed25519 the server stores only public keys, so nothing in the database can impersonate a worker. Signing string `EDV1\nMETHOD\npath\ntimestamp\nnonce\nsha256(body)`, ±300 s window, single-use nonces (DB primary key), 120 requests/min per key, keys expire (≤730 days), rotate (several active keys) and revoke. Small-order public keys are rejected.
- 2026-10-22 — **Fencing token = attempt number.** Heartbeat/results/failures must quote the attempt returned by claim; a worker that lost its lease is refused (409). No extra column needed.
- 2026-10-22 — **Profiles seeded by migration** (`passive`, `quick`, `standard`, `deep`) and validated with `scanProfileConfigSchema` on every read (an invalid stored profile is ignored = fail closed). `passive` (DNS + RDAP only) never contacts target hosts, so it runs for any domain (owner decision on verification).
- 2026-10-22 — **Active scanning is refused server-side** (`ACTIVE_SCANNING_ENABLED=false` in `wrangler.jsonc`) until Milestone 6, both at job creation and again at claim time; active jobs are also re-checked against the domain's current authorisation at claim time.
- 2026-10-22 — **One queued/active job per domain and profile** (partial unique index) instead of idempotency keys on create: duplicate clicks and overlapping schedules collapse.
- 2026-10-22 — **Domain verification approves the apex as an asset** (audited `asset.approved`, basis `domain_verification`) when the first active scan is requested; a rejected/suspended apex is never re-approved implicitly.
- 2026-10-22 — **No Cloudflare Queues:** the worker polls `claim` (state stays in Postgres; avoids another resource). **Cron Trigger every 5 min** runs lease reaping, verification expiry, nonce pruning and the daily passive scheduler (23 h interval, 200 domains per run, priority 200 behind manual scans).
- 2026-10-22 — Retries: max 3 attempts, backoff 60 s × 2^(attempt−1) capped at 30 min; non-retryable errors fail immediately; `complete: true` marks unreported targets `failed/not_reported` (never "checked").

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
- [x] ~~Cloudflare Access service token + Service Auth policy for the worker~~ — done by the owner 2026-10-22.
- [x] ~~Install the worker on this host~~ — done by the owner 2026-10-22 (`install.sh`, key registered as `home-worker-01`, service token in `worker.env`, systemd unit enabled).
- [ ] Before Milestone 5/6 on the scan host: `sudo apt install -y nmap` (Claude will ask before doing anything that changes the machine).

## Future enhancements (owner requests)

- **Exposed software / vulnerability monitoring** (asked 2026-10-22, re CSA alert AL-2026-151 "PHP2Shell", CVE-2026-109618/-109619). Approach agreed in principle, not scheduled: the worker records product/version fingerprints it already sees (HTTP `Server`/`X-Powered-By`, cookies, TLS, limited service identification) with confidence levels (M5–6); deterministic rules for EOL versions, version disclosure and advisory matches reported as "possibly affected — verify" (M7); feed data (CISA KEV + a web-stack CVE/EOL feed, ideally published by nocvault-eol, which already serves Ed25519-signed EOL and firewall-CVE feeds) after M11. Caveats: distro backports keep old version strings, hidden banners mean "unknown" never "not affected", no exploit or vulnerability probing.

## Known limitations

- Neon `dev` branch expires 2026-10-29; recreate with `neon checkout dev --create && npm run db:migrate`.
- No user-management UI/API yet: non-bootstrap users must be inserted into `users` manually.
- A positive DNS TXT verification has only been tested with a mocked resolver (needs a domain whose DNS you control); administrator authorisation was exercised end to end on the Neon `dev` branch with all 339 portfolio domains.
- Challenge expiry is lazy (applied when domain data is read or changed); no scheduled sweep until Cron Triggers arrive (Milestone 4).
- No domain deletion, no rate limit on domain creation beyond permissions. No bulk monitoring toggle yet (monitoring has no effect until collection exists).
- Registration (RDAP) data is not collected; the UI says "Not collected yet".
- Local dev connects as the Neon owner role (`neondb_owner`); production uses `exdomainvault_app`.
- Overview panels show empty states; other sections are placeholders naming their milestone.
- The worker is not installed on the scan host yet (owner steps in `docs/home-worker-setup.md`): queued scans stay queued until it runs. Scheduled passive jobs only start once monitoring is on for a domain; with no worker they wait (one per domain, no pile-up).
- Result submissions carry target statuses only; observation payloads (DNS/RDAP/TLS/HTTP) are added with the worker in Milestones 5–6.
- The home worker will need a Cloudflare Access service token + Service Auth policy to reach `/api/v1/internal/worker/*` (the hostname is behind Access for all traffic).
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

**Production (owner-approved):** Neon `production` migrated with `0001` (existing `thaiunion.com` unchanged; `exdomainvault_app` has privileges on the new columns), then deployed as version `5d9dae9a-0ec1-45d8-8b3e-226db24a33e5`. Unauthenticated requests, including a forged-token POST to `/domains/authorise`, → 302 to Access.

### Milestone 4 — 2026-10-22

**Built:** migration `0002_scan_job_lifecycle` (worker credentials, request nonces, processed results, one-active-job index, seeded profiles); shared contracts for profiles, jobs, snapshots, worker admin and the signed worker protocol; services for scan creation (immutable snapshot + targets, apex approval, active gating), listing/detail/cancel, claim (`FOR UPDATE SKIP LOCKED`, lease, attempt fencing, claim-time re-authorisation), heartbeat, idempotent results, failures with bounded backoff, lease reaper, passive scheduler, nonce pruning; Ed25519 worker-auth middleware (timestamp window, nonce replay, rate limit, revocation/expiry/disabled checks); worker admin API; Cron Trigger (`scheduled` handler, every 5 min); `ACTIVE_SCANNING_ENABLED` flag. UI: Scans list and detail (auto-refresh while active, cancel), Scans card on domain detail, Settings → Workers (register key, revoke, disable). Docs: API spec, architecture, database schema, deployment, scan safety.

**Checks:**

- `npm run lint` pass · `npm run typecheck` pass · `npm run build` pass · `npm run db:check` pass, no drift
- `npm test` — 21 files, 279 tests pass (incl. 29 scan/worker API tests: one job to one worker, lease expiry → requeue with backoff → old attempt fenced, retry ceiling, non-retryable failure, duplicate result no-op, foreign target rejected, cancellation queued/running, claim-time refusal, active flag; signature tests: unsigned, tampered body, wrong key, stale timestamp, unknown key, replayed nonce, revoked/expired key, disabled worker, rate limit, user session refused; small-order key rejection; scheduler idempotency; UI tests)
- Neon `dev` migrated (`0002`); local workerd + Neon `dev`: Cron handler ran all four steps and scheduled 30 passive jobs; **40 concurrent signed claims from two workers → 30 jobs claimed, 30 unique, 10 empty (real PostgreSQL `SKIP LOCKED`)**, heartbeat, results, replayed result → `accepted: false`, other worker → 409. Test data removed afterwards.
- A unit test caught that an all-zero (small-order) Ed25519 key was accepted → now rejected.
- A parallel docs agent reviewed the code while documenting it; fixed from its findings: body limits now in bytes and 1 MB on the worker API, refused jobs' targets marked `skipped`, scheduled jobs refused if monitoring was turned off, scheduler applies the label-boundary check, duplicate-result lookup limited to the submitting worker (no status probing), final target statuses can no longer regress, UI shows lapsed authorisations, stale schema comment. Left as documented behaviour: a job completed after a cancel request ends `succeeded`; profile `default_schedule` is not used yet (only passive is scheduled); key rotation is API-only.
- `worker:test` not run — Python worker unchanged (Milestone 5).

**Production (owner-approved):** Neon `production` migrated with `0002` (profiles seeded; `exdomainvault_app` has privileges on the new tables; the owner's 339-domain import is present, monitoring off), deployed as `663d3165-211d-4998-8172-71b3eaff4e92` with the `*/5 * * * *` trigger. `wrangler tail` showed the Cron runs at 08:35 and 08:40 UTC completing all four maintenance steps through Hyperdrive. `/scans`, `/api/v1/scans` and the internal worker API without Access → 302.

**Next:** Milestone 5 — Python worker (`docs/prompts/05-python-worker.md`), split across parallel agents.

### Milestone 5 — 2026-10-22

**Built (in parallel by four agents, integrated by me):**

- _Contract:_ observation schemas (`dns`, `registration`) in worker results; `GET /domains/:id/observations` read model; `docs/worker-protocol.md`; signing test vector.
- _Server:_ `services/observations.ts` (validated, idempotent batch ingestion; domain registration update; latest-per-record read), route, 14 tests.
- _Python worker:_ `worker/app/` — config, identity, signed httpx client (retries re-sign, 409 stops work), scope guard (passive checks only, label-boundary target check), DNS checks (dnspython, rate/concurrency limits), RDAP (IANA bootstrap, redaction detection), batching, queue loop with heartbeats/cancellation/graceful SIGTERM, health file + `--health`, JSON logs with redaction; 145 pytest tests (mocked API, DNS and RDAP; no live targets).
- _Deployment:_ `worker/Dockerfile` (+ `.dockerignore`), `worker/deploy/exdomainvault-worker.service` (+ health timer), `.env.example`, `worker/README.md`, `docs/home-worker-setup.md`.
- _UI:_ Registration and DNS records cards on the domain page (expiry highlighting, redacted/unavailable wording, grouped record sets), 9 tests.

**Checks:**

- `npm run lint` pass (now also covers `apps/web/worker/` — `.prettierignore` had been excluding it; found by the server agent) · `npm run typecheck` pass · `npm run build` pass · `npm test` 23 files / 303 tests pass
- `npm run worker:install` · `worker:lint` pass · `worker:test` 145 passed
- **End to end (real Python worker → local workerd → Neon `dev`):** registered a key, requested a passive scan of `armoric.com`, `exdomainvault-worker --once` claimed, ran real DNS + RDAP lookups (public resolvers/registry only), uploaded 11 DNS + 1 registration observations, job `succeeded`; domain page showed registrar CSC, registered 1997-10-14, expiry 2027-10-13, CSC nameservers, A/MX/NS/SOA, no DMARC, no DNSSEC. Test data removed afterwards.
- Found and fixed by the end-to-end run: systemd-resolved SERVFAIL on DS/DNSKEY (→ public resolver default); `pip install .` failed because `deploy/` made setuptools see two packages (→ explicit `packages = ["app"]`, `worker:install` now installs the CLI).
- Not verifiable here: Docker image build (Docker not installed), the systemd unit under real root (`systemd-analyze verify` only).
- Deployed to production 2026-10-22 on request (no migration): version `98621b00-60c9-4d98-baee-0a6a3ea001d6`.
- Pre-install review found that `worker.env` setting `EXDV_PRIVATE_KEY_FILE` would override the unit's `LoadCredential=` path (systemd `EnvironmentFile=` beats `Environment=`) and break start-up; removed from the template and guide. Added `worker/deploy/install.sh` (idempotent; steps 2–4 + unit install; shellcheck clean).

**Production worker (2026-10-22):** first start failed `--check-config`: systemd `LoadCredential=` copies are `0440` inside the per-service credentials directory, which the strict `0600` key check rejected → fixed (`f2c57c5`: inside `$CREDENTIALS_DIRECTORY` the directory and file must be closed to others; elsewhere `0600` still required). After `install.sh` + restart the worker started, passed Access with the service token and the signature check, and completed the queued passive scan of `alstertor.info` (11 DNS + 1 registration observation; registrar CSC, expiry 2027-03-04, data status `redacted`).

**Next:** Milestone 6 — scanning and target safety (the security gate for active scanning).
