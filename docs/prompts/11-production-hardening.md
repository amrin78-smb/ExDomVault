# Milestone 11 — Production hardening

Read `CLAUDE.md`, `docs/progress.md`, and `docs/prompts/00-master-build-prompt.md` (especially §6–§11). Check `git status` and confirm the previous milestone is marked done in `docs/progress.md`; if it is not, report what is missing and finish it first.

Spec: `docs/design.md` §12, §13, §16 Phase 5, §17 (Definition of done). Milestone definition: master prompt §5, "Milestone 11".

## Scope

- Fill test gaps: authN/authZ, input validation, worker auth/replay, scope validation, migration verification, lease/retry, finding idempotency.
- Rate limiting and scan quotas; CSRF protection for session-authenticated requests; security headers (CSP etc.) on the app.
- Structured logging with request IDs end to end; worker last-seen, queue depth/oldest job, scan duration/success metrics; persistent worker-outage notification.
- Retention/cleanup jobs for observations.
- Dependency vulnerability scanning in CI (npm audit / pip-audit), secret scanning, lockfile checks.
- Docs: `deployment.md` (deploy + rollback, secrets, Access setup), backup/restore with Neon branching/PITR, `troubleshooting.md`, final README.
- Walk through design §17 Definition of done item by item and report each as met / not met with evidence. Do not deploy — produce the exact deployment checklist for the owner.

## Finish

1. Run lint, typecheck, test, build (and `worker:test` if the worker changed). Fix failures; report anything that genuinely cannot run and why.
2. Update the relevant docs in `docs/` to match what was actually built.
3. Update `docs/progress.md`: status table, decisions, operator actions, limitations, session log.
4. Summarise files changed, check results, remaining limitations, and the next milestone. Commit and push to `main`.
