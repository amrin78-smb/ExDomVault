# ExDomainVault

**External Domain Security & Exposure Monitoring** — evidence-backed, authorised and explainable
monitoring of an organisation's internet-facing domains.

> **Status: Milestone 2 (database and authentication).** Full PostgreSQL schema with migrations on Neon,
> Cloudflare Access sign-in (with a separate development sign-in), role-based permissions, CSRF protection
> and audit logging are in place. There is no domain management or scanning yet. See
> [`docs/progress.md`](docs/progress.md).

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

# Worker runtime variables for local dev (git-ignored): dev sign-in as dev@example.com (admin)
cp apps/web/.dev.vars.example apps/web/.dev.vars

# Database: link Neon and pull credentials into .env.local (git-ignored), then migrate the dev branch
npm i -g neon
neon checkout dev --create
npm run db:migrate

npm run dev        # http://localhost:5173 — UI and /api/v1 in the local Workers runtime
```

Check the API: `curl http://localhost:5173/api/v1/health` should report `database: ok` and `auth: ok`, and
`curl http://localhost:5173/api/v1/me` returns the development administrator.

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
npm run db:check    # Migration history consistency

npm run worker:install   # once: create worker/.venv with pinned deps
npm run worker:lint      # ruff
npm run worker:test      # pytest
```

CI (`.github/workflows/ci.yml`) runs all of these on every push and pull request. It never deploys.

## Configuration

| File                                            | Purpose                                                                                  | Committed |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------- | --------- |
| `apps/web/wrangler.jsonc`                       | Worker config and non-secret vars (`APP_ENV`, `APP_VERSION`)                             | yes       |
| `apps/web/.dev.vars`                            | Local Worker variables: dev sign-in identity, bootstrap admin (from `.dev.vars.example`) | **no**    |
| `.env.local`                                    | Neon connection strings for the checked-out branch (written by the `neon` CLI)           | **no**    |
| `.neon`                                         | Linked Neon project and checked-out branch                                               | **no**    |
| `apps/web/.env.development.local`               | Vite build-time flags (from `apps/web/.env.example`)                                     | **no**    |
| `worker/.env` / `/etc/exdomainvault/worker.env` | Worker settings (from `worker/.env.example`)                                             | **no**    |

Secrets are never placed in `wrangler.jsonc` or `VITE_*` variables. Production secrets are set with
`wrangler secret put`.

## Deployment

Not deployed yet. Three owner actions are required first — a least-privilege Neon role, a Hyperdrive
configuration, and a Cloudflare Access application — documented step by step in
[`docs/deployment.md`](docs/deployment.md). Without Access configured, the API refuses all protected
requests (503). Nothing in this repository deploys automatically.

## Safety principles

ExDomainVault performs only non-destructive checks against verified, explicitly approved scope. No
exploit execution, credential testing or destructive testing. Active scanning remains disabled until
the scope validator (Milestone 6) is complete and tested. See `CLAUDE.md` for the full rules.
