import { riskScore, type RiskInputs } from './risk.ts';
import type {
  Advisory,
  EvaluationInput,
  FindingCandidate,
  ObservationKind,
  ObservationSet,
  Rule,
} from './types.ts';

/** Stable identity of a logical issue: rule + domain + hostname + component. */
export function fingerprint(ruleId: string, domainId: string, hostname: string, component: string) {
  return `${ruleId}|${domainId}|${hostname}|${component}`;
}

export interface FindingUpsert extends FindingCandidate {
  ruleId: string;
  ruleVersion: number;
  fingerprint: string;
  riskScore: number;
  riskInputs: RiskInputs;
  advisory: Advisory;
}

export interface Resolution {
  ruleId: string;
  ruleVersion: number;
  fingerprint: string;
  hostname: string;
  component: string;
}

export interface RuleError {
  ruleId: string;
  message: string;
}

export interface EvaluationResult {
  /** Conditions present now: create, update (last seen) or reopen. */
  upserts: FindingUpsert[];
  /** Components checked successfully where the condition is absent: resolve if an active finding exists. */
  resolutions: Resolution[];
  /** Rules skipped for lack of successful evidence (neither raise nor resolve). */
  skipped: string[];
  /** Rules that threw; they produce nothing (fail safe). */
  errors: RuleError[];
}

const KIND_FIELD: Record<ObservationKind, keyof ObservationSet> = {
  dns: 'dns',
  registration: 'registration',
  tls: 'tls',
  http: 'http',
  port: 'ports',
  discovery: 'discovery',
};

function hasSuccessfulEvidence(set: ObservationSet, kind: ObservationKind): boolean {
  return set[KIND_FIELD[kind]].some((o) => o.resultStatus === 'success');
}

/**
 * Pure evaluation of one successful job's observations. The caller persists the result: upserts
 * create/refresh/reopen findings (same fingerprint), resolutions resolve active findings. Failed or
 * incomplete jobs must never be evaluated (the caller only passes successful jobs), and a rule
 * without successful evidence of every required kind is skipped entirely.
 */
export function evaluate(input: EvaluationInput, rules: readonly Rule[]): EvaluationResult {
  const result: EvaluationResult = { upserts: [], resolutions: [], skipped: [], errors: [] };
  const { context } = input;

  for (const rule of rules) {
    const profileRuns = rule.requiresChecks.some((c) => context.checks.includes(c));
    const evidence = rule.requires.every((k) => hasSuccessfulEvidence(input.current, k));
    if (!profileRuns || !evidence) {
      result.skipped.push(rule.id);
      continue;
    }

    let outcome;
    try {
      outcome = rule.evaluate(input);
    } catch (err) {
      result.errors.push({
        ruleId: rule.id,
        message: err instanceof Error ? err.message : String(err),
      });
      continue;
    }

    const found = new Set<string>();
    for (const candidate of outcome.findings) {
      const fp = fingerprint(rule.id, context.domain.id, candidate.hostname, candidate.component);
      if (found.has(fp)) continue;
      found.add(fp);
      const risk = riskScore(candidate.severity, candidate.exposure, context.domain.criticality);
      result.upserts.push({
        ...candidate,
        ruleId: rule.id,
        ruleVersion: rule.version,
        fingerprint: fp,
        riskScore: risk.score,
        riskInputs: risk.inputs,
        advisory: rule.advisory(candidate, context),
      });
    }

    const resolved = new Set<string>();
    for (const checked of outcome.checked) {
      const fp = fingerprint(rule.id, context.domain.id, checked.hostname, checked.component);
      if (found.has(fp) || resolved.has(fp)) continue;
      resolved.add(fp);
      result.resolutions.push({
        ruleId: rule.id,
        ruleVersion: rule.version,
        fingerprint: fp,
        hostname: checked.hostname,
        component: checked.component,
      });
    }
  }
  return result;
}
