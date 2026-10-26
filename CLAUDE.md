# CLAUDE.md — ExDomainVault

External Domain Security & Exposure Monitoring. Primary principle: **evidence-backed, authorised and explainable security monitoring.**

## Source of truth

- `docs/design.md` — product specification (primary requirement). Read the relevant sections before changing a feature.
- `docs/prompts/00-master-build-prompt.md` — full build instructions, milestone definitions, testing and documentation standards.
- `docs/prompts/NN-*.md` — one kickoff prompt per milestone session.
- `docs/progress.md` — milestone status, decisions, known limitations. **Read it at the start of every session; update it at the end of every milestone.**

Where a detail is unspecified, choose a secure default, record the decision in `docs/progress.md` (Decisions log), and continue. Ask only for credentials, paid services, irreversible actions, or information that cannot reasonably be inferred.

## Stack (do not change without a documented, verified incompatibility)

- **Frontend:** React + Vite + TypeScript (strict) + Tailwind, in `apps/web/`.
- **App/API:** Cloudflare Workers via the current `@cloudflare/vite-plugin` React integration, static assets served by the Worker. Not Pages Functions. TS API handlers under `/api/v1`. Queues for dispatch, Cron Triggers for scheduling, Wrangler for dev/deploy.
- **DB:** Neon PostgreSQL + Drizzle ORM + versioned SQL migrations in `packages/database/`. Hyperdrive or Neon serverless driver — choose per runtime and document why.
- **Shared contracts:** `packages/shared/` (zod schemas + types used by API and UI).
- **Rules engine:** `packages/rules/` (pure, deterministic, versioned).
- **Worker:** Python 3.12+ in `worker/` (dnspython, stdlib ssl, httpx-style client with strict timeouts, Nmap as OS package, pytest), systemd deployment.
- **Package manager:** npm workspaces (`apps/web`, `packages/shared`; add packages to root `workspaces` as they gain code). Do not introduce pnpm/yarn. No Redis, Kubernetes, microservices, or extra databases.
- **Versions in use (Oct 2026):** Vite 8, `@cloudflare/vite-plugin` 1.x, Wrangler 4, React 19, react-router 8, Tailwind 4, Hono 4 (API routing), zod 4, Vitest 5, ESLint 10. TypeScript is pinned to `~6.0` because typescript-eslint does not support TS 7 yet.

## Spec clarifications (decided)

- `netlify.toml` in the design's repo layout is an error — the app deploys to Cloudflare Workers. Use `wrangler.jsonc` instead; do not add Netlify config.
- Documentation set is the union of both documents: `architecture.md`, `threat-model.md`, `database-schema.md`, `api-specification.md`, `scan-safety.md`, `advisory-rules.md`, `deployment.md`, `home-worker-setup.md`, `troubleshooting.md`.
- Domain verification (DNS TXT **or** audited administrator authorisation with a review date) gates **active scanning only**; passive monitoring is allowed for every domain (owner decision, 2026-10-22).
- Recurrence of a resolved finding: reopen the same finding (same fingerprint) and append a status-history entry with `reason = recurrence`, unless the design later specifies linked findings.

## Hard rules (never violate)

**Scanning safety**

- No exploit execution, credential brute forcing, destructive tests, or scanning outside verified, approved scope.
- Active network scanning stays **disabled** until the scope validator (Milestone 6) is implemented and fully tested.
- Scope validator must: enforce exact DNS label boundaries; reject loopback/private/link-local/multicast/reserved/CGNAT/documentation ranges (incl. IPv4-mapped IPv6 and alternative encodings); validate every resolved address immediately before connecting and pin it; revalidate every redirect and CNAME hop; log every decision.
- Scanner arguments come only from server-defined profiles. Never pass user input to a shell or as Nmap flags. Use argument lists, never `shell=True`.
- Domain verification does not authorise scanning third-party hosting/CDN/cloud IPs. CT-log discoveries are `pending` until approved.
- Tests never touch live third-party systems — use synthetic targets and mocks.

**Data integrity**

- PostgreSQL is the durable source of job state. Queue messages may be delivered more than once — all handlers idempotent.
- Job claim is atomic (`FOR UPDATE SKIP LOCKED` or equivalent) with expiring leases, heartbeats, bounded retries.
- Failed or incomplete scans **never** resolve findings. Only a successful relevant check confirming absence resolves.
- Active findings are deduplicated by a stable fingerprint (asset + rule + affected component) enforced by a partial unique index.
- Never invent scan results. Dev fixtures must be visibly labelled and impossible to enable in production.
- Severity comes only from deterministic rules — no LLM. Keep severity separate from `risk_score`; store risk inputs.

**Security**

- Production auth fails closed. Never trust identity headers unless cryptographically verified (e.g. Cloudflare Access JWT checked against team JWKS + AUD). Dev auth is a separate, explicitly-enabled code path.
- All authorisation enforced server-side per role (admin, analyst, asset_owner, viewer).
- Validate all external input with schemas. Errors: `{ error: { code, message, requestId, details? } }` — no stack traces, internal addresses or secrets.
- Separate credentials for app, worker, and migrations. Never commit `.env`, `.dev.vars`, keys, tunnel creds or DB URLs. `.env.example` holds placeholders only.
- Audit-log privileged actions (verification, scope approval, scan launch, policy changes, user admin, finding status changes).

## Things that need explicit user permission

Deploying, changing Cloudflare/Neon account settings, creating paid resources, running migrations against a non-local database, and any destructive git operation (force-push, history rewrite, reset).

**Standing authorisation:** commit at the end of each milestone (and at other sensible checkpoints) and push directly to `main` without asking. Never force-push.

## Working method

1. Start of session: read this file, `docs/progress.md`, and the relevant `docs/design.md` sections; check `git status`.
2. Work in small, reviewable changes; preserve working code — no repeated rewrites.
3. Every feature ships with tests (Vitest for TS, pytest for worker).
4. Before declaring a milestone done, run and pass: `lint`, `typecheck`, `test`, `build`, and `worker:test` where relevant. Report failures honestly; never claim an unrun test passed.
5. Docs must describe what is actually implemented, not aspirations.
6. End of milestone: update `docs/progress.md` (files changed, checks run with results, limitations, next milestone).
7. When framework APIs matter (Cloudflare Workers/Vite plugin, Queues, Hyperdrive, Neon, Drizzle), check current official docs instead of relying on memory.

## Commands

All from the repo root unless noted.

| Command                                                                        | What it does                                                                                                                           |
| ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| `npm run dev`                                                                  | Vite dev server with the Worker running in workerd (needs `apps/web/.dev.vars`, copy from `.dev.vars.example`)                         |
| `npm run build`                                                                | Production build of SPA + Worker into `apps/web/dist/`                                                                                 |
| `npm run preview`                                                              | Build, then serve the production build locally                                                                                         |
| `npm run lint`                                                                 | ESLint + Prettier check (`npm run format` to fix)                                                                                      |
| `npm run typecheck`                                                            | `tsc` across all workspaces                                                                                                            |
| `npm test`                                                                     | Vitest (projects: `web` = UI in jsdom + Worker API/services in Node against PGlite; `shared`; `database` = migration/constraint tests) |
| `npm run cf-typegen`                                                           | Regenerate `apps/web/worker-configuration.d.ts` after editing `wrangler.jsonc`                                                         |
| `npm run worker:install`                                                       | Create `worker/.venv` and install pinned Python deps (needs `python3.12-venv`)                                                         |
| `npm run worker:lint` / `worker:test`                                          | ruff / pytest for the Python worker                                                                                                    |
| `worker/.venv/bin/exdomainvault-worker --check-config` / `--once` / `--health` | Run the worker locally (env from `worker/.env.example`; protocol in `docs/worker-protocol.md`)                                         |

| `neon env pull` | Refresh `.env.local` (git-ignored) with `DATABASE_URL` / `DATABASE_URL_UNPOOLED` for the linked Neon branch |
| `neon deploy` | Apply `neon.ts` branch policy to the linked branch (outward-facing: only when asked) |

| `npm run db:generate` | Generate a SQL migration from `packages/database/src/schema` (no DB needed); commit it |
| `npm run db:check` | drizzle-kit consistency check (CI also fails on schema/migration drift) |
| `npm run db:migrate` | Apply migrations to the Neon branch in `.env.local` (direct URL). Refuses `NEON_BRANCH=production` unless `ALLOW_PRODUCTION_MIGRATION=yes`, and refuses pooled URLs |

**Database wiring (since 2026-10-26):** production runs on PostgreSQL 16 on the scan host via Hyperdrive `exdomainvault-local` → Workers VPC → Cloudflare Tunnel (docs/local-database.md); always `npm run build` before `wrangler deploy`. Former setup, kept as fallback: Neon project `flat-sound-26073660`. Worker → `HYPERDRIVE` binding → Neon direct endpoint, `pg` + Drizzle, one client per request (`packages/database`); locally `vite.config.ts` points the binding at the branch in `.env.local`. Branches: `production` (live, migrated; app connects as least-privilege `exdomainvault_app` via Hyperdrive `exdomainvault-db`) and `dev` (local default; expires 7 days after creation — recreate with `neon checkout dev --create` then `npm run db:migrate`). Never migrate `production` without the user asking.

**Live:** https://exdomainvault.amrin78.workers.dev behind Cloudflare Access (see `docs/deployment.md`). Deploy = `cd apps/web && npx wrangler deploy`, only with the user's approval.

**Scan wiring:** jobs live in Postgres (`services/scans.ts`, `services/job-lifecycle.ts`); the worker calls `/api/v1/internal/worker/*` signed with Ed25519 (`middleware/worker-auth.ts`, shared `workerSigningString`), never with user sessions. Cron (`worker/index.ts` `scheduled` → `services/maintenance.ts`) reaps leases, expires verifications, prunes nonces, schedules passive jobs. `ACTIVE_SCANNING_ENABLED` stays `false` until Milestone 6. Worker-API tests use `worker/testing/harness.ts` (`workerCall` signs requests).

**Auth wiring:** `AUTH_PROVIDER` = `cloudflare_access` (prod; vars `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD`) or `dev` (local `.dev.vars`; refused in production). Unconfigured → protected routes 503. New routes go on the `authed` sub-app in `app.ts` and must add `requirePermission(...)`; audit privileged changes with `writeAudit()` in the same transaction. DB-backed tests use `createTestDatabase()` from `@exdomainvault/database/testing` (PGlite) via `createApp({ connect })`.

## Code map

- `apps/web/src/` — React SPA. `routes.tsx`, `components/layout/` (shell, nav), `components/ui/` (shared UI, `SeverityBadge` is the only severity styling), `pages/`, `lib/api.ts` (typed client validated against shared schemas), `lib/fixtures/` (dev-only, stripped from prod builds), `lib/session.ts` (`useSession`, `usePermission`), `pages/domains/`, `components/domains/`.
- `apps/web/worker/` — Worker API. `index.ts` entry, `app.ts` builds the Hono app (public vs `authed` routes), `middleware/` (request context, security headers, config, database, csrf, auth/permissions), `auth/` (`AuthProvider` + Cloudflare Access + dev), `services/` (users, audit), `routes/` (one module per resource; `domains.ts`), `services/domains.ts` / `domain-verification.ts` / `domain-import.ts`, `lib/validation.ts` (`parseJsonBody`, `parseQuery`, `uuidParam`), `lib/doh.ts` (TXT over DoH), `lib/csv.ts`, `lib/db.ts` (`firstRow`), `lib/errors.ts` (`ApiError` + envelope), `lib/logger.ts`, `config.ts` (validated bindings, fails closed).
- `packages/database/` — `src/schema/` (Drizzle tables/enums), `migrations/` (generated SQL, committed), `src/client.ts` (`connect`, `Database` type), `src/health.ts`, `src/testing.ts` (PGlite, tests only), `scripts/migrate.ts`.
- `packages/shared/src/` — zod schemas + types shared by API and UI (`api/`, `domain/`). `hostname/normalise.ts` (`normaliseDomain`, `isWithinDomain`) is server-only via `@exdomainvault/shared/hostname` (bundles the PSL).
- `worker/app/` — Python worker (`config.py`, `main.py`); tests in `worker/tests/`.
