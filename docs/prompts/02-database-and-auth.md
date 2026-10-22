# Milestone 2 — Database and authentication

Read `CLAUDE.md`, `docs/progress.md`, and `docs/prompts/00-master-build-prompt.md` (especially §6–§11). Check `git status` and confirm the previous milestone is marked done in `docs/progress.md`; if it is not, report what is missing and finish it first.

Spec: `docs/design.md` §4 (roles), §5 (data model), §12 (credentials, application security). Milestone definition: master prompt §5, "Milestone 2".

## Scope
- Drizzle schema for every entity in design §5 (users, domains, domain_verifications, assets, asset_ips, scan_jobs, scan_job_targets, all six observation tables, findings + status history, advisories, audit_logs, worker_registry, scan_profiles, security_rules, notification_preferences, application_settings). UUID PKs, FKs, UTC `timestamptz`, `inet` for IPs, enums as PG enums or check constraints, JSONB evidence plus typed queryable columns.
- Constraints/indexes: unique normalised `domains.fqdn`, unique `(domain_id, hostname)` on assets, partial unique index on active finding fingerprint, job-claim index on `(status, scheduled_at, priority)`.
- Versioned SQL migrations (`db:generate`, `db:migrate`) and a migration test against a local/ephemeral Postgres (document how to run it; skip with an explicit message if unavailable).
- DB connection layer for the Worker runtime — evaluate Hyperdrive vs Neon serverless driver against current docs; record the choice and reasoning.
- Auth behind a replaceable `AuthProvider` interface: production = Cloudflare Access JWT verification (JWKS + AUD + issuer); dev = explicit local provider enabled only by a dev-only var. Production fails closed when auth config is missing. Map identities to `users` and roles.
- Server-side RBAC helper (`requireRole`/permission matrix for admin, analyst, asset_owner, viewer) with tests, and an audit-log writer.
- Document the exact Cloudflare Access + Neon setup steps the owner must perform in `docs/deployment.md` and the "Operator actions" section of `docs/progress.md`. Do not create cloud resources yourself.
- Write `docs/database-schema.md`.

## Finish
1. Run lint, typecheck, test, build (and `worker:test` if the worker changed). Fix failures; report anything that genuinely cannot run and why.
2. Update the relevant docs in `docs/` to match what was actually built.
3. Update `docs/progress.md`: status table, decisions, operator actions, limitations, session log.
4. Summarise files changed, check results, remaining limitations, and the next milestone. Commit and push to `main`.
