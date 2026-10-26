import { softwareProduct } from '@exdomainvault/shared';
import type { SoftwareSighting } from '../software/contract.ts';
import { extractSoftware, sightingLocation } from '../software/extract.ts';
import { eolStatus, matchAdvisories, rangedKevAdvisories } from '../software/intel.ts';
import { parseVersion } from '../software/version.ts';
import type {
  Advisory,
  Confidence,
  EvaluationInput,
  ExposureLevel,
  FindingCandidate,
  Rule,
  RuleOutcome,
  Severity,
  SoftwareIntel,
} from '../types.ts';

/**
 * Software rules (SOFT-001 end-of-life, SOFT-002 possibly affected by a known-exploited CVE).
 *
 * Evidence is what a host REPORTS about itself (HTTP `Server` / `X-Powered-By`, Nmap service
 * identification), parsed by `extractSoftware` from SUCCESSFUL observations of the current job and
 * matched against `context.softwareIntel` (endoflife.date, CISA KEV, NVD ranges). It is never proof:
 * distributions backport fixes without changing the version string, so findings say "verify".
 *
 * - Hostname: the URL's hostname for HTTP headers; the domain FQDN for service identification
 *   (port observations carry no hostname), as in the exposure rules.
 * - Component (fingerprint) WITHOUT the version, so an upgrade to another affected version refreshes
 *   the same finding: SOFT-001 `<source>:<location>:<product>`, SOFT-002
 *   `<source>:<location>:<product>:<CVE>`; location = hostname or `ip:port` (`[v6]:port`).
 * - Resolution only from a successful observation of the same source+location that discloses the
 *   product WITH a version that is not end-of-life / not in any affected range. Product absent,
 *   version hidden, cycle unknown to the feed, or a failed observation: unknown → neither raised
 *   nor resolved. Both rules also allow manual resolution (e.g. after verifying a backport).
 * - Without `context.softwareIntel` both rules return nothing at all.
 * - Requires no observation kind (`requires: []`): the evidence may be HTTP or port observations,
 *   and `extractSoftware` keeps only successful ones.
 */

const SOFTWARE_CHECKS = ['http_headers', 'http_availability', 'service_identification'] as const;

/** Products whose end of life matters most when they serve the web (SOFT-001 high band). */
const CORE_WEB_STACK = new Set(['php', 'apache_httpd', 'nginx', 'openssl', 'microsoft_iis']);
const DAY_MS = 86_400_000;
const LONG_EOL_DAYS = 365;

const REFS = {
  cisaKev: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
  nvd: (cve: string) => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`,
  endOfLife: (slug: string) => `https://endoflife.date/${slug}`,
  owaspComponents: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
} as const;

/** Vendor security / support pages where an obvious official one exists. */
const VENDOR_PAGES: Record<string, string> = {
  php: 'https://www.php.net/supported-versions.php',
  nginx: 'https://nginx.org/en/security_advisories.html',
  apache_httpd: 'https://httpd.apache.org/security/vulnerabilities_24.html',
  apache_tomcat: 'https://tomcat.apache.org/security.html',
  openssl: 'https://openssl-library.org/news/vulnerabilities/',
  openssh: 'https://www.openssh.com/security.html',
  microsoft_iis: 'https://msrc.microsoft.com/update-guide',
  nodejs: 'https://nodejs.org/en/about/previous-releases',
  postgresql: 'https://www.postgresql.org/support/security/',
  exim: 'https://www.exim.org/static/doc/security/',
};

/** Distribution security trackers (per CVE when the tracker has a CVE page). */
function distributionReference(distribution: string | null, cveId?: string): string | null {
  switch (distribution) {
    case 'Ubuntu':
      return cveId
        ? `https://ubuntu.com/security/${encodeURIComponent(cveId)}`
        : 'https://ubuntu.com/about/release-cycle';
    case 'Debian':
      return cveId
        ? `https://security-tracker.debian.org/tracker/${encodeURIComponent(cveId)}`
        : 'https://www.debian.org/releases/';
    case 'Red Hat':
    case 'CentOS':
      return cveId
        ? `https://access.redhat.com/security/cve/${encodeURIComponent(cveId)}`
        : 'https://access.redhat.com/support/policy/updates/errata';
    default:
      return null;
  }
}

function label(product: string): string {
  return softwareProduct(product)?.label ?? product;
}

function exposureOf(s: SoftwareSighting): ExposureLevel {
  return s.source === 'http_header' ? 'web' : 'network_service';
}

function sourceText(source: SoftwareSighting['source']): string {
  return source === 'http_header' ? 'in its HTTP response headers' : 'to service identification';
}

function hostnameOf(s: SoftwareSighting, input: EvaluationInput): string {
  return s.source === 'http_header' && s.hostname ? s.hostname : input.context.domain.fqdn;
}

function baseComponent(s: SoftwareSighting): string {
  return `${s.source}:${sightingLocation(s)}:${s.product}`;
}

function sightingEvidence(s: SoftwareSighting, intel: SoftwareIntel) {
  return {
    product: s.product,
    productLabel: label(s.product),
    version: s.version,
    banner: s.banner,
    source: s.source,
    location: sightingLocation(s),
    hostname: s.hostname,
    ipAddress: s.ipAddress,
    port: s.port,
    backportDistribution: s.backportDistribution,
    observedAt: s.observedAt,
    scanJobId: s.scanJobId,
    intelAsOf: intel.asOf,
  };
}

const confidenceFor = (s: SoftwareSighting): Confidence =>
  s.backportDistribution ? 'low' : 'medium';

function backportNote(distribution: string | null): string {
  return distribution
    ? ` The banner names ${distribution}: distributions may still patch older versions without changing the version string (backports), so check ${distribution}'s support status for this package before concluding.`
    : '';
}

const ev = (f: FindingCandidate, key: string): string | null => {
  const v = f.evidence[key];
  return typeof v === 'string' ? v : null;
};

function backportAction(distribution: string | null): string[] {
  return distribution
    ? [
        `The banner names ${distribution}. Check the ${distribution} security tracker / support status for this package: a supported distribution release may carry the fixes despite the old upstream version. If it does, record that and resolve the finding manually.`,
      ]
    : [];
}

// --- SOFT-001 End-of-life software exposed ----------------------------------------------------

export const soft001: Rule = {
  id: 'SOFT-001',
  version: 1,
  category: 'software',
  title: 'End-of-life software exposed',
  requires: [],
  requiresChecks: SOFTWARE_CHECKS,
  defaultSeverity: 'medium',
  defaultConfidence: 'medium',
  manualResolution: true,
  evidenceRequirements:
    'A successful http observation with evidence.server / evidence.xPoweredBy (profile runs `http_headers`) or a successful open port observation with evidence.product / evidence.version (`service_identification`), plus end-of-life cycles from endoflife.date in `context.softwareIntel`. Without feed data the rule produces nothing.',
  detection:
    'A catalogue product reports a version whose release cycle (the longest numeric cycle that is a dotted prefix of the version) is end of life upstream: the feed says `eol: true` or the EOL date is on or before the evaluation time. Severity medium; high when the cycle has been end of life for more than 365 days AND (the evidence is service identification OR the product is PHP, Apache HTTP Server, nginx, OpenSSL or IIS). Confidence medium; low when the banner names a distribution (fixes may be backported).',
  resolution:
    'A successful observation of the same source and location reports the product with a version whose cycle is not end of life. A hidden version, a missing product, a cycle the feed does not know, or failed/partial evidence is unknown and does not resolve.',
  evaluate(input) {
    const out: RuleOutcome = { findings: [], checked: [] };
    const intel = input.context.softwareIntel;
    if (!intel) return out;
    const nowMs = Date.parse(input.context.now);
    for (const s of extractSoftware(input.current)) {
      if (!s.version) continue;
      const status = eolStatus(s.product, s.version, intel.eolCycles, input.context.now);
      if (!status) continue;
      const hostname = hostnameOf(s, input);
      const component = baseComponent(s);
      if (!status.isEol) {
        out.checked.push({ hostname, component });
        continue;
      }
      const eolMs = status.eolDate ? Date.parse(status.eolDate) : Number.NaN;
      const eolDays = Number.isNaN(eolMs) ? null : Math.floor((nowMs - eolMs) / DAY_MS);
      const longEol = eolDays !== null && eolDays > LONG_EOL_DAYS;
      const severity: Severity =
        longEol && (s.source === 'service_identification' || CORE_WEB_STACK.has(s.product))
          ? 'high'
          : 'medium';
      const where = sightingLocation(s);
      out.findings.push({
        hostname,
        component,
        title: `End-of-life ${label(s.product)} ${s.version} reported by ${where}`,
        description: `${where} reports ${label(s.product)} ${s.version} ${sourceText(s.source)}. Release cycle ${status.cycle} reached its upstream end of life${status.eolDate ? ` on ${status.eolDate}` : ''} and no longer receives upstream security fixes. This is based on the version the server reports about itself; it is not proof that the host is vulnerable.${backportNote(s.backportDistribution)}`,
        severity,
        confidence: confidenceFor(s),
        exposure: exposureOf(s),
        evidence: {
          ...sightingEvidence(s, intel),
          cycle: status.cycle,
          eolDate: status.eolDate,
          latestInCycle: status.latestInCycle,
          daysSinceEol: eolDays,
        },
      });
    }
    return out;
  },
  advisory(f): Advisory {
    const product = ev(f, 'product') ?? 'unknown';
    const name = ev(f, 'productLabel') ?? label(product);
    const version = ev(f, 'version') ?? 'an end-of-life version';
    const cycle = ev(f, 'cycle');
    const distribution = ev(f, 'backportDistribution');
    const slug = softwareProduct(product)?.eolSlug ?? null;
    const references = [
      ...(slug ? [REFS.endOfLife(slug)] : []),
      ...(VENDOR_PAGES[product] ? [VENDOR_PAGES[product]] : []),
      ...[distributionReference(distribution)].filter((r): r is string => r !== null),
      REFS.owaspComponents,
    ];
    return {
      title: `Upgrade ${name} to a supported release`,
      summary: `${f.hostname} reports ${name} ${version}${cycle ? ` (release cycle ${cycle})` : ''}, which is end of life upstream.${distribution ? ` Because the banner names ${distribution}, the distribution may still ship security fixes for it.` : ''}`,
      businessImpact:
        'End-of-life software stops receiving upstream security fixes, so newly found vulnerabilities stay open. The finding is based on the version the server reports; it does not confirm a vulnerability or an attack.',
      recommendedActions: [
        `Confirm which ${name} version actually runs on this host.`,
        ...backportAction(distribution),
        `Plan an upgrade to a supported ${name} release cycle and track it to completion.`,
        'Hide version details in banners once patched (this reduces disclosure, not risk).',
      ],
      references,
    };
  },
};

// --- SOFT-002 Possibly affected by a known-exploited vulnerability ----------------------------

/**
 * Versions that are too coarse to range-match (`2` from `Apache/2`) are treated as hidden. Exported
 * so read models (GET /vulnerabilities) match exactly like SOFT-002.
 */
export function preciseEnough(version: string): boolean {
  const p = parseVersion(version);
  return p !== null && (p.numbers.length >= 2 || p.suffix !== '');
}

export const soft002: Rule = {
  id: 'SOFT-002',
  version: 1,
  category: 'software',
  title: 'Version possibly affected by a known-exploited vulnerability',
  requires: [],
  requiresChecks: SOFTWARE_CHECKS,
  defaultSeverity: 'high',
  defaultConfidence: 'medium',
  manualResolution: true,
  evidenceRequirements:
    'A successful http observation with evidence.server / evidence.xPoweredBy (`http_headers`) or a successful open port observation with evidence.product / evidence.version (`service_identification`), plus CISA KEV advisories with NVD affected version ranges in `context.softwareIntel`. Advisories without ranges are ignored. Without feed data the rule produces nothing.',
  detection:
    'A catalogue product reports a version (at least two numeric segments, e.g. not `Apache/2`) inside ANY affected range of a CISA KEV CVE for that product. One finding per location, product and CVE. Severity high; critical when the CVSS base score is 9.0 or more or KEV marks the CVE as used in ransomware campaigns. Confidence medium; low when the banner names a distribution (fixes may be backported). Wording: possibly affected — verify; never a claim of compromise.',
  resolution:
    'A successful observation of the same source and location reports the product with a version outside every affected range of that CVE. A hidden or too-coarse version, a missing product, failed/partial evidence, or a CVE no longer in the feed does not resolve.',
  evaluate(input) {
    const out: RuleOutcome = { findings: [], checked: [] };
    const intel = input.context.softwareIntel;
    if (!intel) return out;
    for (const s of extractSoftware(input.current)) {
      if (!s.version || !preciseEnough(s.version)) continue;
      const candidates = rangedKevAdvisories(s.product, intel.advisories);
      if (candidates.length === 0) continue;
      const matched = new Set(
        matchAdvisories(s.product, s.version, intel.advisories).map((a) => a.cveId),
      );
      const hostname = hostnameOf(s, input);
      const where = sightingLocation(s);
      for (const a of candidates) {
        const component = `${baseComponent(s)}:${a.cveId}`;
        if (!matched.has(a.cveId)) {
          out.checked.push({ hostname, component });
          continue;
        }
        const severity: Severity =
          (a.cvss !== null && a.cvss >= 9) || a.ransomware ? 'critical' : 'high';
        out.findings.push({
          hostname,
          component,
          title: `${label(s.product)} ${s.version} on ${where} possibly affected by ${a.cveId}`,
          description: `${where} reports ${label(s.product)} ${s.version} ${sourceText(s.source)}, which falls in the affected range of ${a.cveId} (${a.title}), a vulnerability listed in the CISA Known Exploited Vulnerabilities catalogue. This is not proof — verify (distribution backports, configuration, whether the affected feature is in use). It does not mean this host has been compromised or attacked.${backportNote(s.backportDistribution)}`,
          severity,
          confidence: confidenceFor(s),
          exposure: exposureOf(s),
          evidence: {
            ...sightingEvidence(s, intel),
            cveId: a.cveId,
            advisoryTitle: a.title,
            ranges: a.ranges.map((r) => ({ ...r })),
            cvss: a.cvss,
            kevDateAdded: a.kevDateAdded,
            ransomware: a.ransomware,
          },
        });
      }
    }
    return out;
  },
  advisory(f): Advisory {
    const product = ev(f, 'product') ?? 'unknown';
    const name = ev(f, 'productLabel') ?? label(product);
    const version = ev(f, 'version') ?? 'the reported version';
    const cve = ev(f, 'cveId') ?? 'the CVE';
    const distribution = ev(f, 'backportDistribution');
    const references = [
      REFS.cisaKev,
      ...(ev(f, 'cveId') ? [REFS.nvd(cve)] : []),
      ...(VENDOR_PAGES[product] ? [VENDOR_PAGES[product]] : []),
      ...[distributionReference(distribution, ev(f, 'cveId') ?? undefined)].filter(
        (r): r is string => r !== null,
      ),
    ];
    return {
      title: `Verify and patch ${name} for ${cve}`,
      summary: `${f.hostname} reports ${name} ${version}, which falls in the affected range of ${cve}, a vulnerability CISA lists as exploited in the wild. This is possibly affected, not confirmed.`,
      businessImpact:
        'Vulnerabilities in the KEV catalogue are actively used by attackers, so an affected internet-facing service is a priority to verify. The match is based on the version the server reports; backported fixes or configuration may mean the host is not affected, and nothing here indicates that the host was attacked.',
      recommendedActions: [
        `Confirm the exact ${name} version and build installed on this host.`,
        ...backportAction(distribution),
        `If affected, apply the vendor fix or mitigation for ${cve} without delay (see the KEV entry for required actions).`,
        'If the host is not affected (backport, feature not in use), record the evidence and resolve the finding manually.',
      ],
      references,
    };
  },
};

export const softwareRules: readonly Rule[] = [soft001, soft002];
