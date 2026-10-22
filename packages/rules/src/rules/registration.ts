import type {
  Advisory,
  CheckedComponent,
  FindingCandidate,
  RegistrationObservation,
  Rule,
  RuleOutcome,
  Severity,
} from '../types.ts';
import { normaliseName } from './dns.ts';

/*
 * Registration rules from the worker's RDAP `registration` observation (apex only): `registrar`,
 * `expiresAt`, `nameservers` (lowercase, no trailing dot), `dataStatus`. Only `success`
 * observations with `dataStatus` `available` or `redacted` are evidence; `unavailable` means the
 * registry returned nothing usable and neither raises nor resolves.
 */

const DAY_MS = 86_400_000;

/** REG-001 thresholds (days until the registry expiry date). */
export const REGISTRATION_EXPIRY_THRESHOLDS: readonly { maxDays: number; severity: Severity }[] = [
  { maxDays: 0, severity: 'critical' },
  { maxDays: 30, severity: 'high' },
  { maxDays: 60, severity: 'medium' },
];

/** The latest successful registration observation with usable data. */
function usable(records: readonly RegistrationObservation[]): RegistrationObservation | undefined {
  let best: RegistrationObservation | undefined;
  for (const r of records) {
    if (r.resultStatus !== 'success' || r.dataStatus === 'unavailable') continue;
    if (!best || r.observedAt > best.observedAt) best = r;
  }
  return best;
}

const none = (): RuleOutcome => ({ findings: [], checked: [] });

const REGISTRATION_REFERENCES = [
  'https://www.icann.org/resources/pages/errp-2013-02-28-en',
  'https://www.icann.org/resources/pages/epp-status-codes-2014-06-16-en',
  'https://www.rfc-editor.org/rfc/rfc9083',
];

// --- REG-001 Domain registration expiry -----------------------------------------------------

export const reg001: Rule = {
  id: 'REG-001',
  version: 1,
  category: 'registration',
  title: 'Domain registration expiry within 30 days',
  requires: ['registration'],
  requiresChecks: ['rdap'],
  defaultSeverity: 'high',
  defaultConfidence: 'high',
  evidenceRequirements:
    'Successful RDAP registration observation with dataStatus available or redacted and an expiry date.',
  detection:
    'The registry expiry date is within 60 days of the evaluation time: passed → critical (expired, ' +
    'possibly in a grace period), ≤ 30 days → high, ≤ 60 days → medium.',
  resolution: 'The registry expiry date is more than 60 days away (the registration was renewed).',
  evaluate(input) {
    const reg = usable(input.current.registration);
    if (!reg?.expiresAt) return none();
    const expires = Date.parse(reg.expiresAt);
    const now = Date.parse(input.context.now);
    if (Number.isNaN(expires) || Number.isNaN(now)) return none();
    const apex = normaliseName(input.context.domain.fqdn);
    const component: CheckedComponent = { hostname: apex, component: 'expiry' };
    const daysRemaining = Math.floor((expires - now) / DAY_MS);
    const msRemaining = expires - now;
    const band = REGISTRATION_EXPIRY_THRESHOLDS.find((t) =>
      t.maxDays === 0 ? msRemaining <= 0 : msRemaining <= t.maxDays * DAY_MS,
    );
    if (!band) return { findings: [], checked: [component] };
    const expired = msRemaining <= 0;
    const date = reg.expiresAt.slice(0, 10);
    const finding: FindingCandidate = {
      hostname: apex,
      component: 'expiry',
      title: expired
        ? `Domain registration for ${apex} has passed its expiry date`
        : `Domain registration for ${apex} expires within ${band.maxDays} days`,
      description: expired
        ? `The registry reports an expiry date of ${date}, which has passed. The domain may be in a ` +
          'registrar grace or redemption period; if it is not renewed it can be deleted and registered ' +
          'by anyone, taking web, e-mail and DNS with it.'
        : `The registry reports an expiry date of ${date} (${daysRemaining} days from the scan). If ` +
          'the registration lapses, web, e-mail and DNS for the domain stop working and the name can ' +
          'eventually be registered by someone else. Auto-renewal may already be configured; the ' +
          'registry date is what was observed.',
      severity: band.severity,
      confidence: 'high',
      exposure: 'public_record',
      evidence: {
        expiresAt: reg.expiresAt,
        daysRemaining,
        registrar: reg.registrar,
        dataStatus: reg.dataStatus,
        evaluatedAt: input.context.now,
        observedAt: reg.observedAt,
      },
    };
    return { findings: [finding], checked: [] };
  },
  advisory(finding): Advisory {
    return {
      title: `Renew the registration of ${finding.hostname}`,
      summary: 'The domain registration is close to, or past, its registry expiry date.',
      businessImpact:
        'An expired domain stops resolving, interrupting web and e-mail, and a dropped domain can be ' +
        're-registered by a third party who would then receive its traffic and mail.',
      recommendedActions: [
        'Renew the domain with the registrar now, for several years if possible.',
        'Enable auto-renew and keep the payment method and registrar contact addresses current.',
        'Confirm the new expiry date is visible in RDAP after renewal (the finding resolves on the next scan).',
        'Track registrar ownership and renewal responsibility in the asset inventory.',
      ],
      references: REGISTRATION_REFERENCES,
    };
  },
};

// --- REG-002 Unexpected registrar or nameserver change --------------------------------------

const normaliseRegistrar = (name: string) => name.trim().replace(/\s+/g, ' ').toLowerCase();

export const reg002: Rule = {
  id: 'REG-002',
  version: 1,
  category: 'registration',
  title: 'Unexpected registrar or nameserver change',
  requires: ['registration'],
  requiresChecks: ['rdap'],
  defaultSeverity: 'medium',
  defaultConfidence: 'medium',
  evidenceRequirements:
    'Successful RDAP registration observations (dataStatus available or redacted) in the current job ' +
    'and the previous successful job, with the compared field present in both.',
  detection:
    'The registrar name (compared case- and whitespace-insensitively) or the registration nameserver ' +
    'set differs from the previous observation. Components: registrar, nameservers. There is no ' +
    'change-approval workflow yet, so every change is reported for review.',
  resolution:
    'Not auto-resolved: a change is an event that needs review, so the finding stays open until an ' +
    'analyst resolves or accepts it.',
  manualResolution: true,
  evaluate(input) {
    const cur = usable(input.current.registration);
    const prev = usable(input.previous.registration);
    if (!cur || !prev) return none();
    const apex = normaliseName(input.context.domain.fqdn);
    const findings: FindingCandidate[] = [];
    const base = {
      previousObservedAt: prev.observedAt,
      previousScanJobId: prev.scanJobId,
      currentObservedAt: cur.observedAt,
    };

    if (cur.registrar && prev.registrar) {
      if (normaliseRegistrar(cur.registrar) !== normaliseRegistrar(prev.registrar)) {
        findings.push({
          hostname: apex,
          component: 'registrar',
          title: `Registrar for ${apex} changed`,
          description:
            `RDAP reports the registrar as "${cur.registrar}"; the previous successful scan reported ` +
            `"${prev.registrar}". A registrar transfer may be planned; unplanned transfers move control ` +
            'of the domain to another account. This is a change for review, not evidence of compromise.',
          severity: 'medium',
          confidence: 'medium',
          exposure: 'public_record',
          evidence: { previous: prev.registrar, current: cur.registrar, ...base },
        });
      }
    }

    const curNs = [...new Set(cur.nameservers.map(normaliseName))].sort();
    const prevNs = [...new Set(prev.nameservers.map(normaliseName))].sort();
    if (curNs.length > 0 && prevNs.length > 0) {
      const changed = curNs.length !== prevNs.length || curNs.some((n, i) => n !== prevNs[i]);
      if (changed) {
        findings.push({
          hostname: apex,
          component: 'nameservers',
          title: `Registered nameservers for ${apex} changed`,
          description:
            `The registry lists the nameservers ${curNs.join(', ')}; the previous successful scan ` +
            `listed ${prevNs.join(', ')}. The delegation decides who answers DNS for the domain. This ` +
            'may be a planned provider change and is reported for review.',
          severity: 'medium',
          confidence: 'medium',
          exposure: 'public_record',
          evidence: {
            previous: prevNs,
            current: curNs,
            added: curNs.filter((n) => !prevNs.includes(n)),
            removed: prevNs.filter((n) => !curNs.includes(n)),
            ...base,
          },
        });
      }
    }
    return { findings, checked: [] };
  },
  advisory(finding): Advisory {
    const registrar = finding.component === 'registrar';
    return {
      title: registrar
        ? `Review the registrar change for ${finding.hostname}`
        : `Review the nameserver delegation change for ${finding.hostname}`,
      summary: registrar
        ? 'The sponsoring registrar of the domain changed since the previous scan.'
        : 'The nameservers registered for the domain at the registry changed since the previous scan.',
      businessImpact:
        'Control of the registration or delegation means control of the domain: its web traffic, ' +
        'e-mail and the ability to obtain certificates for it.',
      recommendedActions: [
        'Confirm with the domain owner that the change was planned (transfer or DNS migration ticket).',
        'If unplanned: contact the registrar immediately, secure the registrar account (credentials, ' +
          'MFA, contact e-mail) and request the change be reversed.',
        'Enable clientTransferProhibited / registrar lock and, for critical domains, registry lock.',
        'Once reviewed, resolve the finding (or accept it) in ExDomainVault.',
      ],
      references: [
        'https://www.icann.org/resources/pages/transfer-policy-2016-06-01-en',
        'https://www.cisa.gov/news-events/directives/ed-19-01-mitigate-dns-infrastructure-tampering',
        ...REGISTRATION_REFERENCES.slice(1),
      ],
    };
  },
};

export const registrationRules: readonly Rule[] = [reg001, reg002];
