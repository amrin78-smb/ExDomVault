import type {
  Advisory,
  CheckedComponent,
  FindingCandidate,
  LookalikeObservation,
  Rule,
  Severity,
} from '../types.ts';
import { normaliseName } from './dns.ts';

/*
 * Brand (lookalike-domain) rules, Milestone 15. The `lookalike` check of the weekly `brand` profile
 * resolves server-generated lookalike names of the domain (typos, homoglyphs, other TLDs) through
 * public resolvers only and reports the ones that exist in DNS. The lookalike hosts are never
 * contacted. Registration says nothing about intent: many lookalikes are parked, defensive
 * registrations by the organisation itself, or unrelated businesses. Findings ask for a review.
 */

const LOOKALIKE_REFERENCES = [
  'https://attack.mitre.org/techniques/T1583/001/',
  'https://www.icann.org/resources/pages/abuse-2014-01-29-en',
  'https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-attacks',
];

const GOOD = new Set(['success', 'partial']);

/** MX values other than a null MX (`0 .`, RFC 7505: "accepts no mail"). */
const mailExchangers = (records: LookalikeObservation['records']) =>
  (records.MX ?? []).filter((v) => !/^\d+\s+\.$/.test(v.trim()));

/**
 * LOOK-001 severity, deterministic:
 *  - medium: the lookalike has mail exchangers (MX other than a null MX) — it can receive mail and
 *    is likely set up to send it, the usual phishing / business-e-mail-compromise setup;
 *  - low: no MX but web addresses (A/AAAA) — it can host a look-alike site (often only a parking page);
 *  - informational: delegated only (NS/SOA), no A/AAAA/MX — registered but not in use.
 */
export function lookalikeSeverity(records: LookalikeObservation['records']): Severity {
  if (mailExchangers(records).length > 0) return 'medium';
  if ((records.A ?? []).length > 0 || (records.AAAA ?? []).length > 0) return 'low';
  return 'informational';
}

// --- LOOK-001 Lookalike domain registered ----------------------------------------------------

export const look001: Rule = {
  id: 'LOOK-001',
  version: 1,
  category: 'asset',
  title: 'Lookalike domain registered',
  requires: [],
  requiresChecks: ['lookalike'],
  defaultSeverity: 'medium',
  defaultConfidence: 'medium',
  evidenceRequirements:
    'Lookalike observations of a brand-monitoring job (public-resolver NS/SOA, A, AAAA and MX ' +
    "lookups of server-generated candidates) and the job's candidate list with its completeness.",
  detection:
    'A lookalike candidate of the domain exists in DNS (NS or SOA at the candidate; A/AAAA/MX for ' +
    'subdomain-split candidates). One finding per candidate (component = the candidate). Severity: ' +
    'medium with mail exchangers (MX, not a null MX), low with only web addresses (A/AAAA), ' +
    'informational when only delegated (NS/SOA).',
  resolution:
    'A complete brand run (every candidate checked; the time budget was not exhausted) no longer ' +
    'finds the candidate registered. Candidates that failed to resolve in that run (SERVFAIL, ' +
    'timeout) and incomplete runs never resolve.',
  evaluate(input) {
    const apex = normaliseName(input.context.domain.fqdn);
    const observations = input.current.lookalike;
    const findings: FindingCandidate[] = [];
    const registered = new Set<string>();
    const failed = new Set<string>();

    const sorted = [...observations].sort(
      (a, b) => a.candidate.localeCompare(b.candidate) || a.observedAt.localeCompare(b.observedAt),
    );
    for (const o of sorted) {
      const candidate = normaliseName(o.candidate);
      if (!GOOD.has(o.resultStatus)) {
        failed.add(candidate);
        continue;
      }
      if (!o.registered || registered.has(candidate)) continue;
      registered.add(candidate);
      const severity = lookalikeSeverity(o.records);
      const mx = mailExchangers(o.records);
      const web = [...(o.records.A ?? []), ...(o.records.AAAA ?? [])];
      const usage =
        severity === 'medium'
          ? `It has mail exchangers (${mx.slice(0, 3).join(', ')}), so it can receive and is likely set up to send e-mail`
          : severity === 'low'
            ? `It resolves to web addresses (${web.slice(0, 3).join(', ')}), so it can host a website`
            : 'It is delegated (name servers exist) but has no web or mail records';
      findings.push({
        hostname: apex,
        component: candidate,
        title: `Lookalike domain ${candidate} is registered`,
        description:
          `${candidate} looks like ${apex} (${o.technique.replace('_', ' ')}) and exists in DNS. ` +
          `${usage}. Registration alone does not show intent: it may be parked, a defensive ` +
          'registration by your organisation, or an unrelated business. It was only looked up ' +
          'through public resolvers; it was not contacted.',
        severity,
        confidence: 'medium',
        exposure: 'public_record',
        evidence: {
          candidate,
          technique: o.technique,
          records: {
            A: o.records.A ?? [],
            AAAA: o.records.AAAA ?? [],
            MX: o.records.MX ?? [],
            NS: o.records.NS ?? [],
          },
          hasMail: mx.length > 0,
          resultStatus: o.resultStatus,
          observedAt: o.observedAt,
        },
      });
    }

    const checked: CheckedComponent[] = [];
    const run = input.context.lookalike;
    if (run?.complete) {
      for (const c of [...new Set(run.candidates.map(normaliseName))].sort()) {
        if (!registered.has(c) && !failed.has(c)) checked.push({ hostname: apex, component: c });
      }
    }
    return { findings, checked };
  },
  advisory(finding): Advisory {
    const candidate = String(finding.evidence.candidate ?? finding.component);
    return {
      title: `Review the lookalike domain ${candidate}`,
      summary:
        `${candidate} resembles ${finding.hostname} and is registered. Lookalike domains are used ` +
        'for phishing, invoice fraud and brand impersonation, but many are parked or harmless.',
      businessImpact:
        'Customers, suppliers and staff can mistake a lookalike for the real domain: e-mail from it ' +
        'can request payments or credentials, and a website on it can imitate yours. Mail-capable ' +
        'lookalikes are the most common setup for business e-mail compromise.',
      recommendedActions: [
        'Check who holds it: look up the registrar and registrant in RDAP/WHOIS and confirm it is not ' +
          'a registration made by your own organisation or a partner.',
        'If it is yours, record it as a defensive registration (accept the risk, or add it to the ' +
          'domain inventory) so it is not reported again as a threat.',
        'If it is unknown, watch it: changes to its MX or web records are worth an alert to your ' +
          'mail-security and SOC teams; consider blocking it on your mail gateway and web proxy.',
        'If it is used for phishing or impersonation, report it to the registrar abuse contact (from ' +
          'RDAP) and the hosting provider, and consider a UDRP complaint for trademark abuse.',
        'Consider registering the most convincing variants of your main domains defensively.',
      ],
      references: LOOKALIKE_REFERENCES,
    };
  },
};

export const brandRules: readonly Rule[] = [look001];
