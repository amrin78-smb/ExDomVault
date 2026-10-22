# Milestone 7 — Deterministic rules engine

Read `CLAUDE.md`, `docs/progress.md`, and `docs/prompts/00-master-build-prompt.md` (especially §6–§11). Check `git status` and confirm the previous milestone is marked done in `docs/progress.md`; if it is not, report what is missing and finish it first.

Spec: `docs/design.md` §8 (rules, severity and risk). Milestone definition: master prompt §5, "Milestone 7".

## Scope
- `packages/rules`: rule interface (id, version, category, title, required observation types, detect, default severity/confidence, evidence builder, remediation, resolve condition), registry, and a pure evaluator: (observations, previous state, asset context) → finding upserts + resolutions.
- Implement all 14 initial rules (DNS-001…004, TLS-001…004, EXP-001/002, REG-001/002, ASSET-001/002) with fixtures and unit tests per rule (positive, negative, insufficient-evidence).
- Risk score = severity_weight × exposure_factor × criticality_factor, enum-defined, clamped, inputs stored with the finding.
- Wording discipline: observations are not vulnerabilities; no claims of compromise without evidence.
- Wire evaluation into result ingestion (idempotent).
- Write `docs/advisory-rules.md` generated from or kept in sync with the rule registry.

## Finish
1. Run lint, typecheck, test, build (and `worker:test` if the worker changed). Fix failures; report anything that genuinely cannot run and why.
2. Update the relevant docs in `docs/` to match what was actually built.
3. Update `docs/progress.md`: status table, decisions, operator actions, limitations, session log.
4. Summarise files changed, check results, remaining limitations, and the next milestone. Commit and push to `main`.
