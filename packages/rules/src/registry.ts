import { assetRules } from './rules/asset.ts';
import { dnsRules } from './rules/dns.ts';
import { exposureRules } from './rules/exposure.ts';
import { httpRules } from './rules/http.ts';
import { registrationRules } from './rules/registration.ts';
import { softwareRules } from './rules/software.ts';
import { tlsRules } from './rules/tls.ts';
import type { Rule } from './types.ts';

/** All rules, in evaluation order. Rule ids are unique; versions bump on any logic change. */
export const RULES: readonly Rule[] = [
  ...dnsRules,
  ...registrationRules,
  ...tlsRules,
  ...httpRules,
  ...exposureRules,
  ...assetRules,
  ...softwareRules,
];

export function ruleById(id: string): Rule | undefined {
  return RULES.find((r) => r.id === id);
}
