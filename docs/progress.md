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

- [ ] **Install Python venv support on the scan host** (this machine): `sudo apt install -y python3.12-venv`. Needed for `npm run worker:install`. Until then the worker can only be tested in CI.
- [ ] Before Milestone 5/6 on the scan host: `sudo apt install -y nmap` (Claude will ask before doing anything that changes the machine).

## Known limitations

- No database, authentication, or real data — health reports `degraded` by design.
- Overview panels show empty states; other sections are placeholders naming their milestone.
- `worker:install` fails on this host until `python3.12-venv` is installed (see Operator actions).
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

**Next:** Milestone 2 — database and authentication (`docs/prompts/02-database-and-auth.md`).
