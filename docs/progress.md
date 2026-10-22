# ExDomainVault — Build Progress

Updated by Claude at the end of every milestone. Newest entries at the top of each section.

## Milestone status

| #   | Milestone                                  | Status      | Notes                                   |
| --- | ------------------------------------------ | ----------- | --------------------------------------- |
| 1   | Repository foundation                      | not started |                                         |
| 2   | Database and authentication                | not started |                                         |
| 3   | Domain inventory                           | not started |                                         |
| 4   | Scan job lifecycle                         | not started |                                         |
| 5   | Python worker                              | not started |                                         |
| 6   | Scanning and target safety (security gate) | not started | Active scanning disabled until complete |
| 7   | Deterministic rules engine                 | not started |                                         |
| 8   | Finding lifecycle                          | not started |                                         |
| 9   | Passive subdomain discovery                | not started |                                         |
| 10  | Frontend integration                       | not started |                                         |
| 11  | Production hardening                       | not started |                                         |

## Decisions log

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
- [ ] Before first production deploy (all steps in `docs/deployment.md`):
  - [ ] Create a **Cloudflare Access** self-hosted application for the app hostname; set `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD`, `BOOTSTRAP_ADMIN_EMAILS` in `wrangler.jsonc`.
  - [ ] Approve migrating the Neon `production` branch (`ALLOW_PRODUCTION_MIGRATION=yes npm run db:migrate`).
  - [ ] Create least-privilege role `exdomainvault_app` and apply the grants.
  - [ ] Create the Hyperdrive config with that role's direct URL; replace the placeholder Hyperdrive id.
- [ ] Before Milestone 5/6 on the scan host: `sudo apt install -y nmap` (Claude will ask before doing anything that changes the machine).

## Known limitations

- Neon `dev` branch expires 2026-10-29; recreate with `neon checkout dev --create && npm run db:migrate`.
- No user-management UI/API yet: non-bootstrap users must be inserted into `users` manually.
- Cloudflare Access verification is tested with locally generated keys; it has not yet run against your real Access team (needs the owner setup above).
- Local dev connects as the Neon owner role (`neondb_owner`); a least-privilege app role is required before production.
- Overview panels show empty states; other sections are placeholders naming their milestone.
- No deploy workflow; nothing has been deployed.

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
