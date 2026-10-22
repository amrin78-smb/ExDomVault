# ExDomainVault

**External Domain Security & Exposure Monitoring** — evidence-backed, authorised and explainable
monitoring of an organisation's internet-facing domains.

> **Status: Milestone 1 (repository foundation).** The app shell, navigation, typed health API,
> test suite and CI are in place. There is no database, authentication or scanning yet — every
> dashboard panel shows an empty state rather than invented data. See [`docs/progress.md`](docs/progress.md).

## Architecture at a glance

| Part             | Location            | Technology                                                               |
| ---------------- | ------------------- | ------------------------------------------------------------------------ |
| Web UI           | `apps/web/src`      | React 19, Vite 8, TypeScript (strict), Tailwind 4                        |
| API              | `apps/web/worker`   | Cloudflare Worker (Hono) serving `/api/v1` and the SPA's static assets   |
| Shared contracts | `packages/shared`   | zod schemas and types used by both API and UI                            |
| Database         | `packages/database` | Neon PostgreSQL + Drizzle _(Milestone 2)_                                |
| Rules engine     | `packages/rules`    | Deterministic, versioned rules _(Milestone 7)_                           |
| Scanning worker  | `worker/`           | Python 3.12 on a home Linux host, pull-based, systemd _(Milestones 5–6)_ |

Details: [`docs/architecture.md`](docs/architecture.md). Product specification: [`docs/design.md`](docs/design.md).

## Prerequisites

- Node.js 22.12+ (24 recommended, see `.nvmrc`) and npm 11
- Python 3.12+ with `venv` (Ubuntu: `sudo apt install python3.12-venv`) for the worker

## Local development

```bash
git clone https://github.com/amrin78-smb/ExDomVault.git
cd ExDomVault
npm ci

# Worker runtime variables for local dev (git-ignored)
cp apps/web/.dev.vars.example apps/web/.dev.vars

npm run dev        # http://localhost:5173 — UI and /api/v1 in the local Workers runtime
```

Check the API: `curl http://localhost:5173/api/v1/health`. It reports `"status": "degraded"`
because the database and authentication are not configured yet; that is expected.

### Development fixtures (optional)

To lay out the dashboard with synthetic data, create `apps/web/.env.development.local`:

```bash
VITE_DEV_FIXTURES=true
```

Pages then show a yellow **"Development data — synthetic fixtures, not real scan results"** banner.
Fixtures are removed from production builds and cannot be enabled there.

## Quality checks

```bash
npm run lint        # ESLint + Prettier (npm run format to fix)
npm run typecheck   # TypeScript across all workspaces
npm test            # Vitest: UI components, Worker API, shared schemas
npm run build       # Production build into apps/web/dist

npm run worker:install   # once: create worker/.venv with pinned deps
npm run worker:lint      # ruff
npm run worker:test      # pytest
```

CI (`.github/workflows/ci.yml`) runs all of these on every push and pull request. It never deploys.

## Configuration

| File                                            | Purpose                                                      | Committed |
| ----------------------------------------------- | ------------------------------------------------------------ | --------- |
| `apps/web/wrangler.jsonc`                       | Worker config and non-secret vars (`APP_ENV`, `APP_VERSION`) | yes       |
| `apps/web/.dev.vars`                            | Local Worker variables/secrets (from `.dev.vars.example`)    | **no**    |
| `apps/web/.env.development.local`               | Vite build-time flags (from `apps/web/.env.example`)         | **no**    |
| `worker/.env` / `/etc/exdomainvault/worker.env` | Worker settings (from `worker/.env.example`)                 | **no**    |

Secrets are never placed in `wrangler.jsonc` or `VITE_*` variables. Production secrets are set with
`wrangler secret put`.

## Deployment

Not yet available. Deployment, Cloudflare Access and Neon setup are documented as they are built
(Milestones 2 and 11). Nothing in this repository deploys automatically.

## Safety principles

ExDomainVault performs only non-destructive checks against verified, explicitly approved scope. No
exploit execution, credential testing or destructive testing. Active scanning remains disabled until
the scope validator (Milestone 6) is complete and tested. See `CLAUDE.md` for the full rules.
