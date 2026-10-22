# @exdomainvault/rules

Deterministic, versioned security rules and the pure evaluator that turns a successful scan job's
observations into evidence-backed findings (design §8). No I/O, no clock reads, no LLM.

- `src/types.ts` — the rule contract (`Rule`, `RuleOutcome`, observation shapes, context).
- `src/evaluator.ts` — `evaluate(input, rules)`: upserts (present conditions), resolutions (checked
  and absent), skipped rules (insufficient evidence), errors (fail safe). Fingerprint =
  `ruleId|domainId|hostname|component`.
- `src/risk.ts` — risk model v1 (`severity_weight × exposure_factor × criticality_factor`, clamped).
- `src/policy.ts` — default administrative-service exposure policy (EXP-002).
- `src/rules/*.ts` — rule implementations; `src/registry.ts` — the registry.
- `docs/advisory-rules.md` is generated from the registry (`npm run rules:docs`).
