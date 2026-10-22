# Milestone 1 — Repository foundation (first session)

You are the lead architect and senior full-stack/security engineer building ExDomainVault. Read `CLAUDE.md`, then `docs/design.md` in full, then `docs/prompts/00-master-build-prompt.md` in full. Check `git status`. Briefly report the repository state, a concise implementation checklist for this milestone, and any genuine blockers — then **start coding immediately**. The output of this session must be real, working code.

Before scaffolding, check current official docs for the Cloudflare React + Vite Workers integration (`@cloudflare/vite-plugin`, `wrangler.jsonc`, static assets) and use the currently supported layout.

## Scope
1. Monorepo scaffold per design §15 (`apps/web`, `packages/{database,shared,rules}`, `worker/`, `tests/`, `docs/`), adapted to the Cloudflare framework. Pick one package manager (npm workspaces or pnpm) and record it in `CLAUDE.md`.
2. React + Vite + strict TypeScript + Tailwind frontend served as Worker static assets.
3. Worker API with a small router (modules, not one file), `/api/v1` base, request-ID middleware, the standard JSON error envelope, and a typed `GET /api/v1/health` whose response schema lives in `packages/shared` (zod).
4. App shell: persistent sidebar navigation — Overview, Domains, Assets, Scans, Findings, Advisories, Reports, Settings — with an Overview dashboard layout and placeholder pages. Accessible, desktop-first, professional security-operations look; no decorative animation.
5. Dev fixtures only behind an explicit dev flag, with a visible "Development data — not real scan results" banner; impossible to enable in production builds.
6. `.env.example` / `.dev.vars.example` with placeholders, `.gitignore` (env files, `.dev.vars`, keys, venvs, build output).
7. ESLint, Prettier, `tsc --noEmit` typecheck, Vitest (API health test + one component test). Root scripts: `dev`, `build`, `lint`, `typecheck`, `test` — only scripts that actually work.
8. Minimal `worker/` Python skeleton (pyproject/requirements pinned, pytest with one passing test) and `worker:install` / `worker:test` scripts.
9. GitHub Actions CI: install, lint, typecheck, test, build, worker tests. No deploy job, no self-hosted runners.
10. README with exact local setup and dev instructions; `docs/architecture.md` initial version; fill in the Commands section of `CLAUDE.md`.

Do not implement later milestones. Prioritise a clean, tested foundation.

## Finish
1. Run lint, typecheck, test, build (and `worker:test` if the worker changed). Fix failures; report anything that genuinely cannot run and why.
2. Update the relevant docs in `docs/` to match what was actually built.
3. Update `docs/progress.md`: status table, decisions, operator actions, limitations, session log.
4. Summarise files changed, check results, remaining limitations, and the next milestone. Commit and push to `main`.
