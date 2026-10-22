# Milestone 9 — Passive subdomain discovery

Read `CLAUDE.md`, `docs/progress.md`, and `docs/prompts/00-master-build-prompt.md` (especially §6–§11). Check `git status` and confirm the previous milestone is marked done in `docs/progress.md`; if it is not, report what is missing and finish it first.

Spec: `docs/design.md` §7, §10 (`POST /domains/:id/discovery`, asset approve/suspend). Milestone definition: master prompt §5, "Milestone 9".

## Scope
- Provider abstraction; first provider: Certificate Transparency (e.g. crt.sh) with timeouts, rate limits and response-size limits; runs in the worker or Worker per a documented choice.
- Candidate pipeline: normalise (case, trailing dot, IDN), strip/flag wildcards, exact root boundary check, record source + timestamp, dedupe, optional DNS resolution, store as `pending`.
- Approval workflow: `POST /assets/:id/approve` / `suspend` with confirmation, RBAC and audit; policy for shared hosting/CDN/cloud requiring explicit approval.
- Never auto-expand scan scope from CT data. Feeds ASSET-001/ASSET-002.
- Tests: malformed hostnames, wildcards, duplicates, IDNs, boundary bypasses, provider errors/timeouts (all mocked).

## Finish
1. Run lint, typecheck, test, build (and `worker:test` if the worker changed). Fix failures; report anything that genuinely cannot run and why.
2. Update the relevant docs in `docs/` to match what was actually built.
3. Update `docs/progress.md`: status table, decisions, operator actions, limitations, session log.
4. Summarise files changed, check results, remaining limitations, and the next milestone. Commit and push to `main`.
