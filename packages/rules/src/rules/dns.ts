import type { DnsRecordType } from '@exdomainvault/shared';
import type {
  Advisory,
  CheckedComponent,
  DnsRecordSetObservation,
  FindingCandidate,
  Rule,
  RuleOutcome,
  Severity,
} from '../types.ts';

/*
 * DNS and e-mail authentication rules (design §8). Inputs are the worker's `dns` observations
 * (docs/worker-protocol.md): hostnames lowercase without trailing dot; values in presentation
 * format (names keep the trailing dot; CNAME/NS/MX/SOA lowercased; TXT as quoted character
 * strings); NXDOMAIN/NODATA are `success` with `values: []`. Only `success` observations are
 * evidence: failed, timed-out, partial (truncated) or missing lookups neither raise nor resolve.
 */

// --- Shared helpers (also used by the asset rules) -------------------------------------------

/** Lowercase and drop one trailing dot. */
export function normaliseName(name: string): string {
  const lower = name.trim().toLowerCase();
  return lower.endsWith('.') ? lower.slice(0, -1) : lower;
}

/** True when `name` is `apex` or beneath it on an exact label boundary. */
export function isWithinDomain(name: string, apex: string): boolean {
  const n = normaliseName(name);
  const a = normaliseName(apex);
  return n === a || n.endsWith(`.${a}`);
}

/** The latest successful observation for a name and record type, or undefined. */
export function successfulRecord(
  records: readonly DnsRecordSetObservation[],
  hostname: string,
  recordType: DnsRecordType,
): DnsRecordSetObservation | undefined {
  const host = normaliseName(hostname);
  let best: DnsRecordSetObservation | undefined;
  for (const r of records) {
    if (r.resultStatus !== 'success' || r.recordType !== recordType) continue;
    if (normaliseName(r.hostname) !== host) continue;
    if (!best || r.observedAt > best.observedAt) best = r;
  }
  return best;
}

/**
 * Decode a TXT record in presentation format into its text: concatenates the quoted character
 * strings (`"v=spf1 include:a" " -all"` → `v=spf1 include:a -all`) and decodes `\"`, `\\` and
 * `\DDD` escapes. Unquoted input is returned unchanged (already joined).
 */
export function decodeTxt(value: string): string {
  const v = value.trim();
  if (!v.startsWith('"')) return v;
  // Collect the text as percent-encoded UTF-8 so `\DDD` byte escapes decode correctly.
  let encoded = '';
  let i = 0;
  let inString = false;
  while (i < v.length) {
    const ch = v.charAt(i);
    if (!inString) {
      if (ch === '"') inString = true;
      i += 1;
      continue;
    }
    if (ch === '"') {
      inString = false;
      i += 1;
    } else if (ch === '\\') {
      const digits = v.slice(i + 1, i + 4);
      if (/^\d{3}$/.test(digits)) {
        encoded += `%${(Number(digits) & 0xff).toString(16).padStart(2, '0')}`;
        i += 4;
      } else {
        encoded += encodeURIComponent(v.charAt(i + 1));
        i += 2;
      }
    } else {
      const s = String.fromCodePoint(v.codePointAt(i) ?? 0);
      encoded += encodeURIComponent(s);
      i += s.length;
    }
  }
  try {
    return decodeURIComponent(encoded);
  } catch {
    // Not valid UTF-8: fall back to one character per byte (SPF/DMARC parsing only needs ASCII).
    return encoded.replace(/%([0-9a-f]{2})/gi, (_, h: string) =>
      String.fromCharCode(parseInt(h, 16)),
    );
  }
}

const SEVERITY_ORDER: readonly Severity[] = ['informational', 'low', 'medium', 'high', 'critical'];

export function maxSeverity(severities: readonly Severity[]): Severity {
  let max: Severity = 'informational';
  for (const s of severities) {
    if (SEVERITY_ORDER.indexOf(s) > SEVERITY_ORDER.indexOf(max)) max = s;
  }
  return max;
}

const sameSet = (a: readonly string[], b: readonly string[]) => {
  const sa = new Set(a);
  const sb = new Set(b);
  return sa.size === sb.size && [...sa].every((x) => sb.has(x));
};

const apexOf = (input: { context: { domain: { fqdn: string } } }) =>
  normaliseName(input.context.domain.fqdn);

const none = (): RuleOutcome => ({ findings: [], checked: [] });

/** True when the apex MX lookup succeeded and shows no mail exchanger (none or null MX `0 .`). */
function mailState(records: readonly DnsRecordSetObservation[], apex: string) {
  const mx = successfulRecord(records, apex, 'MX');
  if (!mx) return 'unknown' as const;
  const real = mx.values.filter((v) => {
    const parts = v.trim().split(/\s+/);
    return parts.length >= 2 && parts[1] !== '.';
  });
  return real.length > 0 ? ('mail' as const) : ('no_mail' as const);
}

// --- DNS-001 Unexpected authoritative DNS change --------------------------------------------

/** SOA presentation: `mname rname serial refresh retry expire minimum`. */
const soaPrimary = (values: readonly string[]) => {
  const first = values[0];
  return first ? normaliseName(first.trim().split(/\s+/)[0] ?? '') : null;
};

export const dns001: Rule = {
  id: 'DNS-001',
  version: 1,
  category: 'dns',
  title: 'Unexpected authoritative DNS change',
  requires: ['dns'],
  requiresChecks: ['dns'],
  defaultSeverity: 'medium',
  defaultConfidence: 'high',
  evidenceRequirements:
    'Successful apex NS lookups in the current job and in the previous successful job (both non-empty); ' +
    'apex SOA lookups in both jobs are compared when available.',
  detection:
    'The apex NS set, or the SOA primary name server (MNAME), differs from the previous successful observation. ' +
    'There is no change-approval workflow yet, so every change is treated as unexpected until reviewed.',
  resolution:
    'Not auto-resolved: a change is an event that needs review, so the finding stays open until an analyst ' +
    'resolves or accepts it (a repeated identical observation does not undo the change).',
  manualResolution: true,
  evaluate(input) {
    const apex = apexOf(input);
    const curNs = successfulRecord(input.current.dns, apex, 'NS');
    const prevNs = successfulRecord(input.previous.dns, apex, 'NS');
    if (!curNs || !prevNs || curNs.values.length === 0 || prevNs.values.length === 0) return none();

    const nsCurrent = [...new Set(curNs.values.map(normaliseName))].sort();
    const nsPrevious = [...new Set(prevNs.values.map(normaliseName))].sort();
    const nsChanged = !sameSet(nsCurrent, nsPrevious);

    const curSoa = successfulRecord(input.current.dns, apex, 'SOA');
    const prevSoa = successfulRecord(input.previous.dns, apex, 'SOA');
    const soaCurrent = curSoa ? soaPrimary(curSoa.values) : null;
    const soaPrevious = prevSoa ? soaPrimary(prevSoa.values) : null;
    const soaChanged = soaCurrent !== null && soaPrevious !== null && soaCurrent !== soaPrevious;

    if (!nsChanged && !soaChanged) return none();

    const parts: string[] = [];
    if (nsChanged) {
      parts.push(
        `the apex NS set changed from ${nsPrevious.join(', ')} to ${nsCurrent.join(', ')}`,
      );
    }
    if (soaChanged) {
      parts.push(`the SOA primary name server changed from ${soaPrevious} to ${soaCurrent}`);
    }
    return {
      findings: [
        {
          hostname: apex,
          component: 'ns',
          title: `Authoritative DNS for ${apex} changed`,
          description:
            `Between two successful scans ${parts.join(' and ')}. The authoritative name servers ` +
            'control every record of the domain. This may be a planned migration; there is no ' +
            'change-approval workflow yet, so the change is reported for review. It is not evidence ' +
            'of compromise on its own.',
          severity: 'medium',
          confidence: 'high',
          exposure: 'public_record',
          evidence: {
            ns: { previous: nsPrevious, current: nsCurrent, changed: nsChanged },
            soaPrimary: { previous: soaPrevious, current: soaCurrent, changed: soaChanged },
            previousObservedAt: prevNs.observedAt,
            previousScanJobId: prevNs.scanJobId,
            currentObservedAt: curNs.observedAt,
          },
        },
      ],
      checked: [],
    };
  },
  advisory(finding): Advisory {
    return {
      title: `Review the authoritative DNS change for ${finding.hostname}`,
      summary:
        'The name servers (or SOA primary) answering for this domain changed since the previous ' +
        'successful scan. Planned DNS provider migrations look exactly like this; unplanned changes ' +
        'can indicate an unauthorised registrar or DNS-provider account change.',
      businessImpact:
        'Whoever controls the authoritative name servers controls web, e-mail and certificate ' +
        'validation for the domain. An unplanned change could redirect traffic or allow certificates ' +
        'to be issued to a third party.',
      recommendedActions: [
        'Confirm with the domain owner that the change was planned (change ticket, provider migration).',
        'If unplanned: verify the delegation at the registrar, rotate registrar and DNS-provider ' +
          'credentials, enable MFA, and review account audit logs.',
        'Enable registrar lock / registry lock where available to prevent unauthorised delegation changes.',
        'Compare the zone content served by the new name servers with the expected records.',
        'Once reviewed, resolve the finding (or accept it) in ExDomainVault.',
      ],
      references: [
        'https://www.cisa.gov/news-events/directives/ed-19-01-mitigate-dns-infrastructure-tampering',
        'https://www.rfc-editor.org/rfc/rfc1034',
        'https://www.icann.org/resources/pages/epp-status-codes-2014-06-16-en',
      ],
    };
  },
};

// --- DNS-002 Potential dangling CNAME requiring validation ----------------------------------

/**
 * Service domains where an unclaimed resource referenced by a CNAME can commonly be registered by
 * someone else (sources: can-i-take-over-xyz, Microsoft and AWS guidance). Suffix match on labels.
 */
export const TAKEOVER_PRONE_SUFFIXES: readonly string[] = [
  's3.amazonaws.com',
  'elasticbeanstalk.com',
  'azurewebsites.net',
  'cloudapp.net',
  'cloudapp.azure.com',
  'trafficmanager.net',
  'blob.core.windows.net',
  'azureedge.net',
  'azure-api.net',
  'azurefd.net',
  'herokuapp.com',
  'herokudns.com',
  'github.io',
  'bitbucket.io',
  'pantheonsite.io',
  'ghost.io',
  'surge.sh',
  'myshopify.com',
  'readthedocs.io',
  'helpscoutdocs.com',
  'netlify.app',
  'fly.dev',
  'webflow.io',
];

/** Regional S3 website endpoints, e.g. `bucket.s3-website-eu-west-1.amazonaws.com`. */
const S3_REGIONAL = /(^|\.)s3[.-][a-z0-9.-]*\.amazonaws\.com$/;

export function takeoverProneService(target: string): string | null {
  const t = normaliseName(target);
  for (const suffix of TAKEOVER_PRONE_SUFFIXES) {
    if (t === suffix || t.endsWith(`.${suffix}`)) return suffix;
  }
  return S3_REGIONAL.test(t) ? 'amazonaws.com (S3)' : null;
}

const MAX_CHAIN = 8;

export const dns002: Rule = {
  id: 'DNS-002',
  version: 1,
  category: 'dns',
  title: 'Potential dangling CNAME requiring validation',
  requires: ['dns'],
  requiresChecks: ['dns'],
  defaultSeverity: 'medium',
  defaultConfidence: 'medium',
  evidenceRequirements:
    'Successful CNAME lookup for the hostname and successful A and AAAA lookups for the same hostname ' +
    '(the resolver follows the CNAME chain, so they describe the final target). CNAME lookups of ' +
    'in-domain chain members are followed when present in the same job.',
  detection:
    'The hostname is a CNAME whose chain leaves the monitored domain and neither A nor AAAA returns an ' +
    'address (NXDOMAIN or NODATA). Confidence is medium when the target is a known takeover-prone ' +
    'service or the answer was NXDOMAIN, low otherwise. Nothing is probed: this needs manual validation.',
  resolution:
    'The CNAME lookup succeeds with no CNAME, the chain stays inside the domain, or A/AAAA now return an address.',
  evaluate(input) {
    const apex = apexOf(input);
    const records = input.current.dns;
    const findings: FindingCandidate[] = [];
    const checked: CheckedComponent[] = [];
    const hosts = [
      ...new Set(
        records
          .filter((r) => r.recordType === 'CNAME' && r.resultStatus === 'success')
          .map((r) => normaliseName(r.hostname)),
      ),
    ].sort();

    for (const host of hosts) {
      const cname = successfulRecord(records, host, 'CNAME');
      if (!cname) continue;
      const component = { hostname: host, component: 'cname' };
      const firstTarget = cname.values[0];
      if (firstTarget === undefined) {
        checked.push(component);
        continue;
      }
      const a = successfulRecord(records, host, 'A');
      const aaaa = successfulRecord(records, host, 'AAAA');
      if (!a || !aaaa) continue; // insufficient evidence: neither raise nor resolve

      // Follow the chain through CNAME observations of the same job (bounded, loop-safe).
      const chain: string[] = [normaliseName(firstTarget)];
      for (let i = 0; i < MAX_CHAIN; i += 1) {
        const last = chain[chain.length - 1] ?? '';
        const next = successfulRecord(records, last, 'CNAME')?.values[0];
        if (next === undefined || chain.includes(normaliseName(next))) break;
        chain.push(normaliseName(next));
      }
      const canonical = [a.evidence.canonicalName, aaaa.evidence.canonicalName].find(
        (c): c is string => typeof c === 'string' && c.length > 0,
      );
      if (canonical && !chain.includes(normaliseName(canonical)))
        chain.push(normaliseName(canonical));

      const outside = chain.filter((t) => !isWithinDomain(t, apex));
      const hasAddress = a.values.length > 0 || aaaa.values.length > 0;
      if (outside.length === 0 || hasAddress) {
        checked.push(component);
        continue;
      }
      const service = chain.map(takeoverProneService).find((s) => s !== null) ?? null;
      const nxdomain = a.evidence.rcode === 'NXDOMAIN' || aaaa.evidence.rcode === 'NXDOMAIN';
      const confidence = service !== null || nxdomain ? 'medium' : 'low';
      const finalTarget = chain[chain.length - 1] ?? '';
      findings.push({
        hostname: host,
        component: 'cname',
        title: `Potential dangling CNAME on ${host}`,
        description:
          `${host} is an alias (CNAME) for ${chain.join(' → ')}, outside ${apex}, and the alias ` +
          `currently resolves to no address (${nxdomain ? 'NXDOMAIN' : 'no A/AAAA records'}).` +
          (service
            ? ` The target belongs to a service (${service}) where unclaimed resources can often be ` +
              'registered by another customer.'
            : '') +
          ' If the referenced resource was deleted, someone else might be able to claim it and serve ' +
          'content under this hostname. This requires validation; no takeover has been attempted or observed.',
        severity: 'medium',
        confidence,
        exposure: 'web',
        evidence: {
          cnameChain: chain,
          finalTarget,
          outOfDomainTargets: outside,
          takeoverProneService: service,
          a: { values: a.values, rcode: a.evidence.rcode ?? null },
          aaaa: { values: aaaa.values, rcode: aaaa.evidence.rcode ?? null },
          observedAt: cname.observedAt,
        },
      });
    }
    return { findings, checked };
  },
  advisory(finding): Advisory {
    const service = finding.evidence.takeoverProneService;
    return {
      title: `Validate the CNAME on ${finding.hostname}`,
      summary:
        'The hostname points at an external name that currently has no address. This is a common ' +
        'sign of a deprovisioned cloud or SaaS resource whose DNS alias was left behind.',
      businessImpact:
        'If another party can claim the referenced resource, they could serve content, collect ' +
        'cookies scoped to the parent domain, or obtain certificates for this hostname.',
      recommendedActions: [
        'Confirm whether the referenced resource still exists and is owned by your organisation.',
        'If it is no longer used, delete the CNAME record (and any related records) now.',
        typeof service === 'string'
          ? `If it is still needed, re-claim the resource on ${service} under your account before re-enabling traffic.`
          : 'If it is still needed, restore the target so it resolves, under an account you control.',
        'Make DNS cleanup part of the decommissioning checklist for cloud resources.',
      ],
      references: [
        'https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover',
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover',
        'https://github.com/EdOverflow/can-i-take-over-xyz',
      ],
    };
  },
};

// --- DMARC parsing --------------------------------------------------------------------------

export interface DmarcRecord {
  raw: string;
  tags: Record<string, string>;
}

/** DMARC records among decoded TXT strings (first tag `v=DMARC1`, case-insensitive). */
export function dmarcRecords(values: readonly string[]): DmarcRecord[] {
  return values
    .map(decodeTxt)
    .filter((t) => /^\s*v\s*=\s*dmarc1\s*(;|$)/i.test(t))
    .map((raw) => {
      const tags: Record<string, string> = {};
      for (const part of raw.split(';')) {
        const eq = part.indexOf('=');
        if (eq < 0) continue;
        const key = part.slice(0, eq).trim().toLowerCase();
        if (key && !(key in tags)) tags[key] = part.slice(eq + 1).trim();
      }
      return { raw, tags };
    });
}

const DMARC_POLICIES = ['none', 'quarantine', 'reject'];

/** The effective policy of a single valid record, or null (missing/invalid `p`). */
const dmarcPolicy = (r: DmarcRecord) => {
  const p = r.tags.p?.toLowerCase();
  return p && DMARC_POLICIES.includes(p) ? p : null;
};

const EMAIL_REFERENCES = [
  'https://www.rfc-editor.org/rfc/rfc7489',
  'https://www.cisa.gov/news-events/directives/bod-18-01-enhance-email-and-web-security',
  'https://www.m3aawg.org/sites/default/files/m3aawg_parked_domains_bp-2015-12.pdf',
  'https://www.rfc-editor.org/rfc/rfc7505',
];

const parkedDomainActions = (apex: string) => [
  `This domain does not appear to receive e-mail: publish "v=DMARC1; p=reject;" at _dmarc.${apex}.`,
  `Publish a null MX ("${apex}. MX 0 .", RFC 7505) and an SPF record "v=spf1 -all" so no server is authorised to send.`,
];

// --- DNS-003 Missing DMARC policy -----------------------------------------------------------

export const dns003: Rule = {
  id: 'DNS-003',
  version: 1,
  category: 'email',
  title: 'Missing DMARC policy',
  requires: ['dns'],
  requiresChecks: ['dns'],
  defaultSeverity: 'medium',
  defaultConfidence: 'high',
  evidenceRequirements:
    'Successful TXT lookup at _dmarc.<apex> (NXDOMAIN/NODATA count as "no record"). The apex MX ' +
    'lookup, when successful, tailors the advice for domains that do not send or receive mail.',
  detection:
    'No TXT record at _dmarc.<apex> starts with v=DMARC1, more than one does (receivers then ignore ' +
    'DMARC, RFC 7489 §6.6.3), or the single record has no valid p= policy. A monitoring-only policy ' +
    '(p=none) is reported separately by DNS-007.',
  resolution: 'Exactly one DMARC record with a valid p= policy is published at _dmarc.<apex>.',
  evaluate(input) {
    const apex = apexOf(input);
    const name = `_dmarc.${apex}`;
    const txt = successfulRecord(input.current.dns, name, 'TXT');
    if (!txt) return none();
    const component = { hostname: apex, component: 'dmarc' };
    const records = dmarcRecords(txt.values);
    const mail = mailState(input.current.dns, apex);
    let problem: string | null = null;
    let detail = '';
    if (records.length === 0) {
      problem = 'missing';
      detail = `No DMARC record is published at ${name}.`;
    } else if (records.length > 1) {
      problem = 'multiple';
      detail = `${records.length} DMARC records are published at ${name}; receivers treat this as no DMARC policy.`;
    } else if (records[0] && dmarcPolicy(records[0]) === null) {
      problem = 'invalid_policy';
      detail = `The DMARC record at ${name} has no valid policy tag (p=none|quarantine|reject).`;
    }
    if (!problem) return { findings: [], checked: [component] };
    return {
      findings: [
        {
          hostname: apex,
          component: 'dmarc',
          title: `No effective DMARC policy for ${apex}`,
          description:
            `${detail} Without DMARC, receiving mail systems have no domain-owner policy for ` +
            `messages that falsely use ${apex} in the From address, which makes spoofing easier. ` +
            'This is a configuration issue, not evidence that the domain has been abused.',
          severity: 'medium',
          confidence: 'high',
          exposure: 'public_record',
          evidence: {
            queriedName: name,
            problem,
            records: records.map((r) => r.raw),
            txtValues: txt.values,
            rcode: txt.evidence.rcode ?? null,
            mail,
            observedAt: txt.observedAt,
          },
        },
      ],
      checked: [],
    };
  },
  advisory(finding): Advisory {
    const apex = finding.hostname;
    const noMail = finding.evidence.mail === 'no_mail';
    return {
      title: `Publish a DMARC policy for ${apex}`,
      summary:
        'DMARC lets the domain owner tell receivers what to do with mail that fails SPF/DKIM ' +
        'alignment and where to send reports.',
      businessImpact:
        'Without an effective DMARC policy, phishing that impersonates the domain is more likely to ' +
        'reach recipients, and the owner gets no visibility into who sends mail using the domain.',
      recommendedActions: noMail
        ? parkedDomainActions(apex)
        : [
            `Publish one TXT record at _dmarc.${apex}, starting with "v=DMARC1; p=none; rua=mailto:<reporting address>" to collect reports.`,
            'Inventory legitimate senders from the aggregate reports and align them with SPF and DKIM.',
            'Move to p=quarantine and then p=reject (BOD 18-01 requires p=reject for US federal domains).',
            'Make sure only one DMARC record exists at that name.',
          ],
      references: EMAIL_REFERENCES,
    };
  },
};

// --- DNS-007 Monitoring-only DMARC policy ---------------------------------------------------

export const dns007: Rule = {
  id: 'DNS-007',
  version: 1,
  category: 'email',
  title: 'Monitoring-only DMARC policy',
  requires: ['dns'],
  requiresChecks: ['dns'],
  defaultSeverity: 'low',
  defaultConfidence: 'high',
  evidenceRequirements: 'Successful TXT lookup at _dmarc.<apex>.',
  detection:
    'Exactly one DMARC record is published and its policy is p=none (monitoring only). Missing, ' +
    'duplicate or invalid records are DNS-003.',
  resolution:
    'The DMARC policy is quarantine or reject (or the record is missing/invalid, which DNS-003 reports instead).',
  evaluate(input) {
    const apex = apexOf(input);
    const name = `_dmarc.${apex}`;
    const txt = successfulRecord(input.current.dns, name, 'TXT');
    if (!txt) return none();
    const component = { hostname: apex, component: 'dmarc' };
    const records = dmarcRecords(txt.values);
    const only = records.length === 1 ? records[0] : undefined;
    if (!only || dmarcPolicy(only) !== 'none') return { findings: [], checked: [component] };
    return {
      findings: [
        {
          hostname: apex,
          component: 'dmarc',
          title: `DMARC policy for ${apex} is monitoring-only (p=none)`,
          description:
            `The DMARC record at ${name} uses p=none, so receivers are asked to deliver messages that ` +
            'fail DMARC as normal. This is a useful first step for collecting reports, but it does not ' +
            'protect recipients from spoofed mail.',
          severity: 'low',
          confidence: 'high',
          exposure: 'public_record',
          evidence: {
            queriedName: name,
            record: only.raw,
            policy: 'none',
            subdomainPolicy: only.tags.sp ?? null,
            reportingConfigured: Boolean(only.tags.rua),
            mail: mailState(input.current.dns, apex),
            observedAt: txt.observedAt,
          },
        },
      ],
      checked: [],
    };
  },
  advisory(finding): Advisory {
    const apex = finding.hostname;
    return {
      title: `Enforce the DMARC policy for ${apex}`,
      summary:
        'A p=none policy only monitors; it does not ask receivers to reject or quarantine spoofed mail.',
      businessImpact:
        'Phishing that impersonates the domain is still delivered while the policy stays at p=none.',
      recommendedActions:
        finding.evidence.mail === 'no_mail'
          ? parkedDomainActions(apex)
          : [
              finding.evidence.reportingConfigured
                ? 'Review the aggregate (rua) reports and fix SPF/DKIM alignment for every legitimate sender.'
                : 'Add a rua= reporting address and review the aggregate reports for every legitimate sender.',
              'Move to p=quarantine (optionally with pct= for a staged rollout), then to p=reject.',
              'Set sp= for subdomains that do not send mail.',
            ],
      references: EMAIL_REFERENCES,
    };
  },
};

// --- DNS-004 Significant SPF configuration issue --------------------------------------------

export interface SpfIssue {
  code: string;
  severity: Severity;
  message: string;
}

const SPF_MECHANISMS = new Set(['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists']);
const LOOKUP_TERMS = new Set(['include', 'a', 'mx', 'ptr', 'exists', 'redirect']);
const IP4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\d{1,2}))?$/;
const IP6 = /^[0-9a-f:.]+(\/\d{1,3})?$/i;

/** Analyse one SPF record (top level only: included records are not fetched). */
export function analyseSpf(record: string): {
  issues: SpfIssue[];
  lookupTerms: number;
  all: string | null;
  redirect: string | null;
} {
  const issues: SpfIssue[] = [];
  const terms = record.trim().split(/\s+/).slice(1);
  let lookupTerms = 0;
  let all: string | null = null;
  let redirect: string | null = null;
  const syntax: string[] = [];

  for (const term of terms) {
    const modifier = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(term);
    if (modifier) {
      const name = (modifier[1] ?? '').toLowerCase();
      if (name === 'redirect') {
        if (redirect !== null) syntax.push(term);
        redirect = modifier[2] ?? '';
        if (!redirect) syntax.push(term);
        lookupTerms += 1;
      }
      continue; // exp= and unknown modifiers are allowed (RFC 7208 §6)
    }
    const m = /^([+\-~?]?)([a-z0-9]+)([:/].*)?$/i.exec(term);
    const name = m?.[2]?.toLowerCase();
    if (!m || !name || !SPF_MECHANISMS.has(name)) {
      syntax.push(term);
      continue;
    }
    const qualifier = m[1] || '+';
    const arg = m[3] ?? '';
    if (LOOKUP_TERMS.has(name)) lookupTerms += 1;
    if (name === 'all') {
      if (arg) syntax.push(term);
      if (all === null) all = `${qualifier}all`;
    } else if (name === 'include' || name === 'exists') {
      if (!arg.startsWith(':') || arg.length < 2) syntax.push(term);
    } else if (name === 'ip4') {
      const ip = IP4.exec(arg.slice(1));
      const octetsOk = ip ? [1, 2, 3, 4].every((i) => Number(ip[i]) <= 255) : false;
      const prefixOk = !ip?.[6] || Number(ip[6]) <= 32;
      if (!arg.startsWith(':') || !ip || !octetsOk || !prefixOk) syntax.push(term);
    } else if (name === 'ip6') {
      if (!arg.startsWith(':') || !IP6.test(arg.slice(1)) || !arg.slice(1).includes(':')) {
        syntax.push(term);
      }
    } else if (name === 'ptr') {
      issues.push({
        code: 'ptr_mechanism',
        severity: 'low',
        message:
          'Uses the ptr mechanism, which RFC 7208 says should not be used (slow, unreliable).',
      });
    }
  }

  if (syntax.length > 0) {
    issues.push({
      code: 'syntax_error',
      severity: 'medium',
      message: `Unrecognised or malformed terms (${syntax.join(' ')}): receivers return permerror, so SPF fails for all mail.`,
    });
  }
  if (all === '+all') {
    issues.push({
      code: 'pass_all',
      severity: 'high',
      message: '"+all" authorises every server on the internet to send mail for the domain.',
    });
  } else if (all === '?all') {
    issues.push({
      code: 'neutral_all',
      severity: 'low',
      message:
        '"?all" gives a neutral result for unauthorised senders, which offers no protection.',
    });
  } else if (all === null && redirect === null) {
    issues.push({
      code: 'no_all',
      severity: 'low',
      message:
        'No "all" mechanism or redirect=: mail from unlisted servers gets a neutral result by default.',
    });
  }
  if (lookupTerms > 10) {
    issues.push({
      code: 'too_many_lookups',
      severity: 'medium',
      message: `At least ${lookupTerms} DNS-querying terms at the top level (limit 10, RFC 7208 §4.6.4): receivers return permerror. Nested includes are not counted, so the real total may be higher.`,
    });
  }
  return { issues, lookupTerms, all, redirect };
}

export const dns004: Rule = {
  id: 'DNS-004',
  version: 1,
  category: 'email',
  title: 'Significant SPF configuration issue',
  requires: ['dns'],
  requiresChecks: ['dns'],
  defaultSeverity: 'medium',
  defaultConfidence: 'high',
  evidenceRequirements:
    'Successful apex TXT lookup. A missing SPF record is only reported when the apex MX lookup also ' +
    'succeeded and lists a mail exchanger.',
  detection:
    'Apex SPF (v=spf1) has: more than one record (medium, permerror); "+all" (high); malformed or ' +
    'unknown terms (medium); more than 10 DNS-querying terms counted at the top level only — ' +
    'include, a, mx, ptr, exists, redirect (medium); "?all" or no all/redirect (low); ptr (low). A ' +
    'domain with MX but no SPF is low. Severity is the highest of the issues found.',
  resolution:
    'A single, well-formed SPF record with a restrictive all (or redirect=) and at most 10 top-level ' +
    'lookups — or no SPF where the domain has no MX.',
  evaluate(input) {
    const apex = apexOf(input);
    const txt = successfulRecord(input.current.dns, apex, 'TXT');
    if (!txt) return none();
    const component = { hostname: apex, component: 'spf' };
    const records = txt.values.map(decodeTxt).filter((t) => /^v=spf1(\s|$)/i.test(t.trim()));
    let issues: SpfIssue[] = [];
    let analysis: ReturnType<typeof analyseSpf> | null = null;
    let mail: ReturnType<typeof mailState> | null = null;

    if (records.length === 0) {
      mail = mailState(input.current.dns, apex);
      if (mail === 'unknown') return none();
      if (mail === 'mail') {
        issues = [
          {
            code: 'missing_with_mx',
            severity: 'low',
            message: 'The domain publishes MX records but no SPF record.',
          },
        ];
      }
    } else if (records.length > 1) {
      issues = [
        {
          code: 'multiple_records',
          severity: 'medium',
          message: `${records.length} SPF records are published; receivers return permerror (RFC 7208 §4.5).`,
        },
      ];
    } else {
      analysis = analyseSpf(records[0] ?? '');
      issues = analysis.issues;
    }
    if (issues.length === 0) return { findings: [], checked: [component] };
    const severity = maxSeverity(issues.map((i) => i.severity));
    return {
      findings: [
        {
          hostname: apex,
          component: 'spf',
          title: `SPF configuration issue on ${apex}`,
          description:
            `The SPF configuration of ${apex} has ${issues.length === 1 ? 'an issue' : `${issues.length} issues`}: ` +
            `${issues.map((i) => i.message).join(' ')} SPF tells receivers which servers may send mail ` +
            'for the domain; this is a configuration weakness, not evidence of abuse.',
          severity,
          confidence: 'high',
          exposure: 'public_record',
          evidence: {
            records,
            issues,
            topLevelLookupTerms: analysis?.lookupTerms ?? null,
            all: analysis?.all ?? null,
            redirect: analysis?.redirect ?? null,
            mail,
            observedAt: txt.observedAt,
          },
        },
      ],
      checked: [],
    };
  },
  advisory(finding): Advisory {
    const codes = new Set(
      (Array.isArray(finding.evidence.issues) ? finding.evidence.issues : []).map(
        (i: { code?: string }) => i.code,
      ),
    );
    const actions: string[] = [];
    if (codes.has('multiple_records')) {
      actions.push('Merge all SPF policies into a single TXT record starting with v=spf1.');
    }
    if (codes.has('pass_all') || codes.has('neutral_all') || codes.has('no_all')) {
      actions.push(
        'End the record with "-all" (or "~all" while validating senders); never use "+all".',
      );
    }
    if (codes.has('syntax_error')) {
      actions.push(
        'Fix the malformed terms; validate the record with an SPF checker before publishing.',
      );
    }
    if (codes.has('too_many_lookups')) {
      actions.push(
        'Reduce DNS-querying terms to 10 or fewer (remove unused includes, replace a/mx with ip4/ip6, or use subdomains for separate senders).',
      );
    }
    if (codes.has('ptr_mechanism'))
      actions.push('Replace ptr with explicit ip4/ip6 or include terms.');
    if (codes.has('missing_with_mx')) {
      actions.push(
        `Publish an SPF record listing the servers allowed to send for ${finding.hostname}, ending in -all or ~all.`,
      );
    }
    actions.push('Pair SPF with DKIM and an enforced DMARC policy.');
    return {
      title: `Fix the SPF record for ${finding.hostname}`,
      summary:
        'SPF lists the servers allowed to send mail for the domain. Errors make receivers ignore it ' +
        '(permerror) and permissive endings authorise anyone.',
      businessImpact:
        'Spoofed messages using the domain are easier to deliver, and legitimate mail may fail DMARC alignment.',
      recommendedActions: actions,
      references: [
        'https://www.rfc-editor.org/rfc/rfc7208',
        'https://www.cisa.gov/news-events/directives/bod-18-01-enhance-email-and-web-security',
        'https://www.m3aawg.org/sites/default/files/m3aawg_parked_domains_bp-2015-12.pdf',
      ],
    };
  },
};

// --- DNS-005 DNSSEC not enabled -------------------------------------------------------------

export const dns005: Rule = {
  id: 'DNS-005',
  version: 1,
  category: 'dns',
  title: 'DNSSEC not enabled',
  requires: ['dns'],
  requiresChecks: ['dns'],
  defaultSeverity: 'low',
  defaultConfidence: 'high',
  evidenceRequirements:
    'Successful DS lookup for the apex (the DNSKEY lookup, when successful, distinguishes "unsigned" ' +
    'from "signed but no DS at the parent").',
  detection:
    'The parent zone publishes no DS record for the apex, so DNS answers cannot be validated.',
  resolution: 'A DS record for the apex is published.',
  evaluate(input) {
    const apex = apexOf(input);
    const ds = successfulRecord(input.current.dns, apex, 'DS');
    if (!ds) return none();
    const component = { hostname: apex, component: 'dnssec' };
    if (ds.values.length > 0) return { findings: [], checked: [component] };
    const dnskey = successfulRecord(input.current.dns, apex, 'DNSKEY');
    const signed = dnskey ? dnskey.values.length > 0 : null;
    return {
      findings: [
        {
          hostname: apex,
          component: 'dnssec',
          title: `DNSSEC is not enabled for ${apex}`,
          description:
            `No DS record for ${apex} is published in the parent zone, so validating resolvers cannot ` +
            'detect forged or modified DNS answers for the domain.' +
            (signed
              ? ' The zone publishes DNSKEY records, so it appears to be signed but the DS record was not added at the registrar.'
              : ''),
          severity: 'low',
          confidence: 'high',
          exposure: 'public_record',
          evidence: {
            ds: ds.values,
            dsRcode: ds.evidence.rcode ?? null,
            dnskeyPresent: signed,
            observedAt: ds.observedAt,
          },
        },
      ],
      checked: [],
    };
  },
  advisory(finding): Advisory {
    const signed = finding.evidence.dnskeyPresent === true;
    return {
      title: `Enable DNSSEC for ${finding.hostname}`,
      summary: 'DNSSEC signs DNS data so resolvers can detect spoofed or tampered answers.',
      businessImpact:
        'Without DNSSEC, users of validating resolvers get no protection against cache poisoning or on-path DNS tampering for this domain.',
      recommendedActions: signed
        ? [
            "The zone is already signed: publish the DS record at the registrar (from the DNS provider's DNSSEC settings).",
            'Verify the chain of trust with a DNSSEC analyser after the DS appears.',
          ]
        : [
            'Enable DNSSEC signing at the DNS provider (most managed providers support automatic signing and key rollover).',
            'Publish the provided DS record at the registrar.',
            'Verify the chain of trust and monitor for signature expiry.',
          ],
      references: [
        'https://www.rfc-editor.org/rfc/rfc4033',
        'https://www.rfc-editor.org/rfc/rfc9364',
        'https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en',
      ],
    };
  },
};

// --- DNS-006 No CAA record ------------------------------------------------------------------

export const dns006: Rule = {
  id: 'DNS-006',
  version: 1,
  category: 'dns',
  title: 'No CAA record',
  requires: ['dns'],
  requiresChecks: ['dns'],
  defaultSeverity: 'informational',
  defaultConfidence: 'high',
  evidenceRequirements: 'Successful CAA lookup at the apex.',
  detection:
    'The apex publishes no CAA record, so any public CA may issue certificates for the domain.',
  resolution: 'At least one CAA record is published at the apex.',
  evaluate(input) {
    const apex = apexOf(input);
    const caa = successfulRecord(input.current.dns, apex, 'CAA');
    if (!caa) return none();
    const component = { hostname: apex, component: 'caa' };
    if (caa.values.length > 0) return { findings: [], checked: [component] };
    return {
      findings: [
        {
          hostname: apex,
          component: 'caa',
          title: `No CAA record for ${apex}`,
          description:
            `${apex} publishes no CAA record, so every publicly trusted certificate authority is ` +
            'permitted to issue certificates for it. CAA is a defence-in-depth control; its absence is not a vulnerability by itself.',
          severity: 'informational',
          confidence: 'high',
          exposure: 'public_record',
          evidence: {
            caa: caa.values,
            rcode: caa.evidence.rcode ?? null,
            observedAt: caa.observedAt,
          },
        },
      ],
      checked: [],
    };
  },
  advisory(finding): Advisory {
    return {
      title: `Publish CAA records for ${finding.hostname}`,
      summary: 'CAA records name the certificate authorities allowed to issue for the domain.',
      businessImpact:
        'Restricting issuance to the CAs you use reduces the chance of a mis-issued certificate for the domain.',
      recommendedActions: [
        'List the CAs currently issuing your certificates (check Certificate Transparency logs).',
        `Publish CAA records such as ${finding.hostname}. CAA 0 issue "<ca-domain>" for each, and 0 issuewild if wildcards are used.`,
        'Optionally add an iodef contact to receive violation reports.',
      ],
      references: [
        'https://www.rfc-editor.org/rfc/rfc8659',
        'https://cabforum.org/working-groups/server/baseline-requirements/',
      ],
    };
  },
};

export const dnsRules: readonly Rule[] = [dns001, dns002, dns003, dns004, dns005, dns006, dns007];
