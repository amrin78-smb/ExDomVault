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
- **Package manager:** one only (decide in Milestone 1, record it here). No Redis, Kubernetes, microservices, or extra databases.

## Spec clarifications (decided)

- `netlify.toml` in the design's repo layout is an error — the app deploys to Cloudflare Workers. Use `wrangler.jsonc` instead; do not add Netlify config.
- Documentation set is the union of both documents: `architecture.md`, `threat-model.md`, `database-schema.md`, `api-specification.md`, `scan-safety.md`, `advisory-rules.md`, `deployment.md`, `home-worker-setup.md`, `troubleshooting.md`.
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

Fill this in with the real scripts once Milestone 1 creates them. Do not list commands that do not work.

<!-- e.g. npm run dev | build | lint | typecheck | test | db:generate | db:migrate | worker:install | worker:test -->
