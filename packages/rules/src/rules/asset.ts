import type {
  Advisory,
  AssetContext,
  CheckedComponent,
  DiscoveryObservation,
  FindingCandidate,
  Rule,
} from '../types.ts';
import { isWithinDomain, normaliseName } from './dns.ts';

/*
 * Asset inventory rules from passive discovery (design §7). Discovery observations (one per
 * discovered hostname, produced from Milestone 9) are compared with the domain's known assets.
 * Passive discovery proves neither ownership nor liveness and never expands scan scope: these rules
 * only ask a human to review the inventory.
 */

const successfulHostnames = (records: readonly DiscoveryObservation[], apex: string) =>
  new Set(
    records
      .filter((r) => r.resultStatus === 'success')
      .map((r) => normaliseName(r.hostname))
      .filter((h) => isWithinDomain(h, apex)),
  );

/** An asset somebody has decided on (approved into scope, rejected, or suspended). */
const isDecided = (a: AssetContext) => a.status !== 'pending';

const ASSET_REFERENCES = [
  'https://www.rfc-editor.org/rfc/rfc6962',
  'https://www.cisa.gov/news-events/directives/bod-23-01-improving-asset-visibility-and-vulnerability-detection-federal-networks',
];

// --- ASSET-001 Newly discovered unapproved candidate asset ----------------------------------

export const asset001: Rule = {
  id: 'ASSET-001',
  version: 1,
  category: 'asset',
  title: 'Newly discovered unapproved candidate asset',
  requires: ['discovery'],
  requiresChecks: ['discovery'],
  defaultSeverity: 'informational',
  defaultConfidence: 'medium',
  evidenceRequirements:
    'Successful discovery observations (hostnames beneath the domain, exact label boundary) and the ' +
    "domain's asset list.",
  detection:
    'A discovered hostname is not a known asset, or is a pending candidate that nobody has approved ' +
    'or rejected yet. One finding per hostname (component = the hostname).',
  resolution:
    'The hostname has been approved, rejected or suspended in the asset inventory (evaluated on any ' +
    'successful discovery run).',
  evaluate(input) {
    const apex = normaliseName(input.context.domain.fqdn);
    const discovered = successfulHostnames(input.current.discovery, apex);
    const assets = new Map(input.context.assets.map((a) => [normaliseName(a.hostname), a]));
    const findings: FindingCandidate[] = [];
    const checked: CheckedComponent[] = [];

    for (const host of [...discovered].sort()) {
      const known = assets.get(host);
      if (known && isDecided(known)) continue; // listed as checked below
      const sources = [
        ...new Set(
          input.current.discovery
            .filter((r) => r.resultStatus === 'success' && normaliseName(r.hostname) === host)
            .map((r) => r.source),
        ),
      ].sort();
      const firstSeen = input.current.discovery
        .filter((r) => r.resultStatus === 'success' && normaliseName(r.hostname) === host)
        .map((r) => r.observedAt)
        .sort()[0];
      findings.push({
        hostname: host,
        component: host,
        title: `Unreviewed candidate asset ${host}`,
        description:
          `${host} was found by passive discovery (${sources.join(', ')}) but is not an approved asset ` +
          'of the domain. Passive sources show that the name was used at some point; they do not prove ' +
          'it is live, owned by your organisation, or in scope. It will not be scanned unless approved.',
        severity: 'informational',
        confidence: 'medium',
        exposure: 'public_record',
        evidence: {
          hostname: host,
          sources,
          firstObservedAt: firstSeen ?? null,
          assetStatus: known?.status ?? null,
          assetId: known?.assetId ?? null,
        },
      });
    }
    for (const [host, a] of [...assets].sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0))) {
      if (isDecided(a) && isWithinDomain(host, apex))
        checked.push({ hostname: host, component: host });
    }
    return { findings, checked };
  },
  advisory(finding): Advisory {
    return {
      title: `Review the candidate asset ${finding.hostname}`,
      summary:
        'A hostname under the domain appeared in a passive source (for example a Certificate ' +
        'Transparency log) and is not in the approved inventory.',
      businessImpact:
        'Unknown hosts are not monitored: forgotten services, shadow IT or third-party sites using the ' +
        'domain can go unpatched or be misconfigured without anyone noticing.',
      recommendedActions: [
        'Identify the owner of the hostname (DNS records, certificate details, team inventories).',
        'If it belongs to your organisation and you are authorised to scan it, approve it so it is monitored.',
        'If it is not yours or no longer used, reject it and remove stale DNS records and certificates.',
        "Never approve third-party hosting/CDN addresses for active scanning without the provider's permission.",
      ],
      references: ASSET_REFERENCES,
    };
  },
};

// --- ASSET-002 Previously monitored asset missing from a successful discovery run ------------

export const asset002: Rule = {
  id: 'ASSET-002',
  version: 1,
  category: 'asset',
  title: 'Previously monitored asset missing from a successful discovery run',
  requires: ['discovery'],
  requiresChecks: ['discovery'],
  defaultSeverity: 'medium',
  defaultConfidence: 'low',
  evidenceRequirements:
    'A complete discovery run in the current job (every discovery observation successful) and the ' +
    'hostnames from the previous successful discovery run.',
  detection:
    'An approved, monitored asset was in the previous discovery run but not in the current one. ' +
    'Confidence is low: passive sources age out and vary, so absence is a prompt to check, not proof.',
  resolution:
    'The asset appears again in a complete discovery run, or it is no longer approved and monitored.',
  evaluate(input) {
    const apex = normaliseName(input.context.domain.fqdn);
    // Any failed or partial source makes the run incomplete: absence then means nothing.
    if (input.current.discovery.some((r) => r.resultStatus !== 'success')) {
      return { findings: [], checked: [] };
    }
    const current = successfulHostnames(input.current.discovery, apex);
    const previous = successfulHostnames(input.previous.discovery, apex);
    const findings: FindingCandidate[] = [];
    const checked: CheckedComponent[] = [];
    const assets = [...input.context.assets]
      .map((a) => ({ ...a, hostname: normaliseName(a.hostname) }))
      .filter((a) => isWithinDomain(a.hostname, apex))
      .sort((x, y) => (x.hostname < y.hostname ? -1 : x.hostname > y.hostname ? 1 : 0));

    for (const a of assets) {
      const component = { hostname: a.hostname, component: 'discovery' };
      const monitored = a.status === 'approved' && a.monitoringEnabled;
      if (!monitored || current.has(a.hostname)) {
        checked.push(component);
        continue;
      }
      if (!previous.has(a.hostname)) continue; // never seen by discovery: nothing to compare
      findings.push({
        hostname: a.hostname,
        component: 'discovery',
        title: `Monitored asset ${a.hostname} missing from discovery`,
        description:
          `${a.hostname} is an approved, monitored asset that the previous discovery run found but the ` +
          'latest complete run did not. It may have been decommissioned, renamed, or simply aged out of ' +
          'the passive source; the inventory should be checked so monitoring reflects reality.',
        severity: 'medium',
        confidence: 'low',
        exposure: 'public_record',
        evidence: {
          hostname: a.hostname,
          assetId: a.assetId,
          currentRunHostnames: current.size,
          previousRunHostnames: previous.size,
          currentScanJobId: input.context.scanJobId,
          previousScanJobId: input.previous.discovery[0]?.scanJobId ?? null,
        },
      });
    }
    return { findings, checked };
  },
  advisory(finding): Advisory {
    return {
      title: `Confirm the status of ${finding.hostname}`,
      summary:
        'A monitored asset is no longer reported by passive discovery. The asset inventory may be out ' +
        'of date.',
      businessImpact:
        'Decommissioned hosts left in the inventory waste monitoring effort, while DNS records left ' +
        'behind for removed services can become dangling and be claimed by others.',
      recommendedActions: [
        'Check whether the host still exists and still resolves (see the DNS observations of the latest scan).',
        'If it was decommissioned: remove its DNS records, revoke its certificates and suspend the asset.',
        'If it is still in service: keep monitoring; no change is required.',
      ],
      references: ASSET_REFERENCES,
    };
  },
};

export const assetRules: readonly Rule[] = [asset001, asset002];
