# Milestone 3 — Domain inventory

Read `CLAUDE.md`, `docs/progress.md`, and `docs/prompts/00-master-build-prompt.md` (especially §6–§11). Check `git status` and confirm the previous milestone is marked done in `docs/progress.md`; if it is not, report what is missing and finish it first.

Spec: `docs/design.md` §5.2–5.3, §10 (Domains), §14 (Domain detail). Milestone definition: master prompt §5, "Milestone 3".

## Scope
- APIs + UI: list (paginated, filterable), add, detail, edit business owner/criticality, enable/disable monitoring. All validated with shared zod schemas; RBAC enforced server-side; audit events written.
- Domain normalisation (case, trailing dot, IDN → A-label via a vetted library, reject IPs/wildcards/invalid labels, registrable-domain boundary using the Public Suffix List). Duplicate prevention at API and DB level.
- DNS TXT verification: generate a random challenge, store only its hash and expiry, show the user the record to publish, verify via DNS-over-HTTPS from the Worker (or by worker job — document the choice), expire stale challenges. Verification never auto-authorises third-party infrastructure.
- CSV import: upload → server-side validation → preview with per-row errors → explicit confirm → import with audit.
- Unit tests: normalisation, label-boundary cases (`evil-example.com`, `example.com.evil.net`, IDN homographs), verification expiry and hash comparison, RBAC denials.
- Update `docs/api-specification.md`.

## Finish
1. Run lint, typecheck, test, build (and `worker:test` if the worker changed). Fix failures; report anything that genuinely cannot run and why.
2. Update the relevant docs in `docs/` to match what was actually built.
3. Update `docs/progress.md`: status table, decisions, operator actions, limitations, session log.
4. Summarise files changed, check results, remaining limitations, and the next milestone. Commit and push to `main`.
