import { RULES, type Rule } from '@exdomainvault/rules';
import type { RuleCatalogueEntry } from '@exdomainvault/shared';
import { Hono } from 'hono';
import { requirePermission } from '../middleware/auth.ts';
import { ruleCatalogue } from '../services/findings.ts';
import type { AppBindings } from '../types.ts';

/** The deterministic rule catalogue (what each rule detects, needs and how it resolves). */
export function ruleRoutes(deps: { rules?: readonly Rule[] } = {}) {
  const rules = deps.rules ?? RULES;
  return new Hono<AppBindings>().get('/', requirePermission('findings:read'), (c) => {
    const res: { items: RuleCatalogueEntry[] } = { items: ruleCatalogue(rules) };
    return c.json(res);
  });
}
