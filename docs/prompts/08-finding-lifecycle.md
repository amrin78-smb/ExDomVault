# Milestone 8 — Finding lifecycle

Read `CLAUDE.md`, `docs/progress.md`, and `docs/prompts/00-master-build-prompt.md` (especially §6–§11). Check `git status` and confirm the previous milestone is marked done in `docs/progress.md`; if it is not, report what is missing and finish it first.

Spec: `docs/design.md` §5.9–5.10, §9. Milestone definition: master prompt §5, "Milestone 8".

## Scope

- States: open → acknowledged → remediation_in_progress → resolved, plus accepted_risk (reason, approver, review date). Enforce allowed transitions and role permissions server-side.
- Status history table, assignee, first/last seen, resolved_at, recurrence count.
- Ingestion semantics: update last_seen on recurrence; reopen resolved findings on confirmed recurrence; resolve only after a **successful** relevant check confirms absence; failed/incomplete scans never resolve.
- Fingerprint-based dedupe under concurrent ingestion (partial unique index + upsert).
- Advisories generated from findings + evidence only.
- `PATCH /findings/:id`, `GET /findings`, `GET /findings/:id`, `GET /advisories` with audit events.
- Tests: every transition (allowed and denied), recurrence, failed-scan non-resolution, duplicate/concurrent ingestion.

## Finish

1. Run lint, typecheck, test, build (and `worker:test` if the worker changed). Fix failures; report anything that genuinely cannot run and why.
2. Update the relevant docs in `docs/` to match what was actually built.
3. Update `docs/progress.md`: status table, decisions, operator actions, limitations, session log.
4. Summarise files changed, check results, remaining limitations, and the next milestone. Commit and push to `main`.
