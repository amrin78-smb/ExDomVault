import type {
  AdministrativeService,
  CheckedComponent,
  Confidence,
  PortObservation,
  Rule,
  RuleOutcome,
} from '../types.ts';

/**
 * Exposure rules (EXP-001, EXP-002). An open port is an observation, not a vulnerability: EXP-001
 * signals a change, EXP-002 applies the explicit exposure policy (`context.administrativeServices`).
 *
 * - Component: `<ip>:<port>`, IPv6 in brackets (`[2001:db8::1]:22`) so the port is unambiguous.
 * - Hostname: the domain FQDN — port observations are per address and carry no hostname, and a
 *   hostname derived from other observations would make the fingerprint unstable.
 * - Raised only from `success` port observations with state `open` (TCP connect scan).
 * - `checked` (resolvable) only for `success` observations with state `closed` or `filtered`: the
 *   address did not accept a connection in a successful scan. Ports not scanned in this job are
 *   neither raised nor resolved.
 */

const REFS = {
  cisControls: 'https://www.cisecurity.org/controls/cis-controls-list',
  nist80041: 'https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final',
  owaspAttackSurface:
    'https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html',
  cisaKev: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
  cloudflareAccess: 'https://developers.cloudflare.com/cloudflare-one/applications/',
} as const;

/** Canonical address text: lowercase (the worker already sends Python's compressed form). */
function normalizeIp(ip: string): string {
  return ip.trim().toLowerCase();
}

/** `<ip>:<port>`, with IPv6 bracketed (exported for tests). */
export function portComponent(ip: string, port: number): string {
  const addr = normalizeIp(ip);
  return addr.includes(':') ? `[${addr}]:${port}` : `${addr}:${port}`;
}

function successful(ports: readonly PortObservation[]): PortObservation[] {
  return ports.filter((p) => p.resultStatus === 'success');
}

function evidenceString(o: PortObservation, key: string): string | null {
  const v = o.evidence[key];
  return typeof v === 'string' && v.length > 0 ? v : null;
}

function portSummary(o: PortObservation) {
  return {
    ipAddress: normalizeIp(o.ipAddress),
    port: o.port,
    protocol: o.protocol,
    state: o.state,
    service: o.service,
    product: evidenceString(o, 'product'),
    version: evidenceString(o, 'version'),
    serviceMethod: evidenceString(o, 'serviceMethod'),
    reason: evidenceString(o, 'reason'),
    method: evidenceString(o, 'method'),
    observedAt: o.observedAt,
    scanJobId: o.scanJobId,
  };
}

function adminServiceFor(
  services: readonly AdministrativeService[],
  port: number,
): AdministrativeService | undefined {
  return services.find((s) => s.port === port);
}

function closedOrFiltered(o: PortObservation, hostname: string): CheckedComponent | null {
  return o.state === 'closed' || o.state === 'filtered'
    ? { hostname, component: portComponent(o.ipAddress, o.port) }
    : null;
}

// --- EXP-001 Newly exposed TCP port -----------------------------------------------------------

export const exp001: Rule = {
  id: 'EXP-001',
  version: 1,
  category: 'exposure',
  title: 'Newly exposed TCP port',
  requires: ['port'],
  requiresChecks: ['tcp_ports'],
  defaultSeverity: 'low',
  defaultConfidence: 'high',
  evidenceRequirements:
    'Successful `port` observations of the current job, and successful `port` observations of the same address from an earlier successful job (`previous`) as the baseline.',
  detection:
    'A port is open now on an address that has a baseline (a successful earlier port observation of that address), and the same address+port was absent, closed or filtered in the baseline. The first scan of an address establishes the baseline and raises nothing. Low; informational when the port is also an administrative service (EXP-002 carries the severity).',
  resolution:
    'A successful observation shows the address+port closed or filtered. While the port stays open the finding stays active (it records the change until reviewed).',
  manualResolution: true,
  evaluate(input) {
    const { context } = input;
    const hostname = context.domain.fqdn;
    const baseline = new Map<string, Map<number, PortObservation['state']>>();
    for (const p of successful(input.previous.ports)) {
      const ip = normalizeIp(p.ipAddress);
      let ports = baseline.get(ip);
      if (!ports) baseline.set(ip, (ports = new Map()));
      ports.set(p.port, p.state);
    }

    const out: RuleOutcome = { findings: [], checked: [] };
    for (const o of successful(input.current.ports)) {
      const checked = closedOrFiltered(o, hostname);
      if (checked) {
        out.checked.push(checked);
        continue;
      }
      if (o.state !== 'open') continue;
      const ip = normalizeIp(o.ipAddress);
      const prev = baseline.get(ip);
      if (!prev) continue; // first scan of this address: baseline only
      // Only a port the previous scan actually checked (closed/filtered) can be "newly" open: a port
      // another profile never probed has no baseline.
      const prevState = prev.get(o.port);
      if (prevState === undefined || prevState === 'open') continue;
      const admin = adminServiceFor(context.administrativeServices, o.port);
      const component = portComponent(ip, o.port);
      out.findings.push({
        hostname,
        component,
        title: `TCP port ${o.port} newly reachable on ${ip}`,
        description: `Port ${o.port}/tcp on ${ip} accepted connections in this scan${o.service ? ` (service: ${o.service})` : ''}; in the previous scan of this address it was ${prevState}. A newly reachable service changes the external attack surface and should be confirmed as intended. An open port alone is not a vulnerability.`,
        severity: admin ? 'informational' : 'low',
        confidence: 'high',
        exposure: 'network_service',
        evidence: {
          ...portSummary(o),
          previousState: prevState,
          ...(admin ? { administrativeService: admin.service } : {}),
        },
      });
    }
    return out;
  },
  advisory(f) {
    return {
      title: 'Confirm the newly exposed port is intended',
      summary: `${f.component}/tcp became reachable from the internet since the previous scan.`,
      businessImpact:
        'Unplanned exposure is a common way services end up reachable without the hardening, patching or monitoring expected of internet-facing systems.',
      recommendedActions: [
        'Identify the owner of the service and confirm the exposure is intentional (change ticket, deployment).',
        'If unintended, close it at the host firewall or cloud security group and re-scan.',
        'If intended, make sure it is patched, authenticated and monitored, then acknowledge the finding.',
      ],
      references: [REFS.cisControls, REFS.owaspAttackSurface, REFS.nist80041],
    };
  },
};

// --- EXP-002 Public administrative service ----------------------------------------------------

/** Nmap service names / product keywords that confirm the default policy's services. */
const SERVICE_ALIASES: Record<number, readonly string[]> = {
  21: ['ftp'],
  22: ['ssh'],
  23: ['telnet'],
  111: ['rpcbind', 'portmap'],
  135: ['msrpc', 'microsoft windows rpc'],
  139: ['netbios-ssn', 'netbios'],
  445: ['microsoft-ds', 'smb', 'samba'],
  873: ['rsync'],
  1433: ['ms-sql-s', 'microsoft sql server'],
  1521: ['oracle', 'oracle-tns'],
  2049: ['nfs'],
  2375: ['docker'],
  2376: ['docker'],
  3306: ['mysql', 'mariadb'],
  3389: ['ms-wbt-server', 'rdp', 'terminal services'],
  5432: ['postgresql'],
  5601: ['kibana'],
  5900: ['vnc'],
  5984: ['couchdb'],
  6379: ['redis'],
  6443: ['kubernetes'],
  9200: ['elasticsearch'],
  10250: ['kubelet', 'kubernetes'],
  11211: ['memcache', 'memcached'],
  15672: ['rabbitmq'],
  27017: ['mongodb', 'mongod'],
};

/**
 * Confidence that the open port runs the policy's service: high when Nmap probed the service
 * (serviceMethod `probed`) and its name/product matches; medium otherwise (port number only).
 * Exported for tests.
 */
export function serviceConfidence(o: PortObservation, admin: AdministrativeService): Confidence {
  if (evidenceString(o, 'serviceMethod') !== 'probed') return 'medium';
  const seen = [o.service, evidenceString(o, 'product')]
    .filter((v): v is string => v !== null)
    .map((v) => v.toLowerCase());
  if (seen.length === 0) return 'medium';
  const aliases = [
    ...(SERVICE_ALIASES[admin.port] ?? []),
    (admin.service.toLowerCase().split(/[\s(]/)[0] ?? '').trim(),
  ].filter((a) => a.length > 0);
  return seen.some((s) => aliases.some((a) => s.includes(a))) ? 'high' : 'medium';
}

export const exp002: Rule = {
  id: 'EXP-002',
  version: 1,
  category: 'exposure',
  title: 'Public administrative service violating the exposure policy',
  requires: ['port'],
  requiresChecks: ['tcp_ports'],
  defaultSeverity: 'high',
  defaultConfidence: 'medium',
  evidenceRequirements:
    'Successful `port` observations (state) and, when the profile runs `service_identification`, the Nmap service/product in evidence.',
  detection:
    "An open port matches an entry of the exposure policy (`administrativeServices`: port → service, severity). Severity is the policy entry's severity. Confidence high when Nmap's probe identified the matching service, medium when only the port number matches. Accepted exceptions are handled as accepted risk on the finding.",
  resolution: 'A successful observation shows the address+port closed or filtered.',
  evaluate(input) {
    const { context } = input;
    const hostname = context.domain.fqdn;
    const out: RuleOutcome = { findings: [], checked: [] };
    for (const o of successful(input.current.ports)) {
      const admin = adminServiceFor(context.administrativeServices, o.port);
      if (!admin) continue;
      const checked = closedOrFiltered(o, hostname);
      if (checked) {
        out.checked.push(checked);
        continue;
      }
      if (o.state !== 'open') continue;
      const ip = normalizeIp(o.ipAddress);
      const confidence = serviceConfidence(o, admin);
      out.findings.push({
        hostname,
        component: portComponent(ip, o.port),
        title: `${admin.service} (port ${o.port}) reachable from the internet on ${ip}`,
        description: `Port ${o.port}/tcp on ${ip}, the default port for ${admin.service}, accepted connections from the internet${o.service ? ` (identified as ${o.service}${evidenceString(o, 'product') ? `, ${evidenceString(o, 'product')}` : ''})` : ''}. The exposure policy says ${admin.service} should not be publicly reachable. This is an exposure that increases risk; it is not evidence that the service has been accessed or compromised.`,
        severity: admin.severity,
        confidence,
        exposure: 'network_service',
        evidence: {
          ...portSummary(o),
          policy: { port: admin.port, service: admin.service, severity: admin.severity },
        },
      });
    }
    return out;
  },
  advisory(f) {
    const policy = f.evidence['policy'] as { service?: string } | undefined;
    const service = policy?.service ?? 'administrative service';
    return {
      title: `Remove public access to ${service}`,
      summary: `${service} on ${f.component} is reachable from the internet, contrary to the exposure policy.`,
      businessImpact:
        'Internet-reachable administrative and data services are routinely targeted by automated password guessing and exploitation of known vulnerabilities; exposure of data stores can lead to data loss if authentication is weak or missing.',
      recommendedActions: [
        'Restrict the port at the firewall or cloud security group to known management networks, or close it.',
        'Put administrative access behind a VPN, bastion host or identity-aware proxy instead of exposing it directly.',
        'If the exposure is required, enforce strong authentication, keep the software patched, monitor access logs, and record an accepted-risk decision with a review date.',
      ],
      references: [REFS.cisControls, REFS.nist80041, REFS.cisaKev, REFS.cloudflareAccess],
    };
  },
};

export const exposureRules: readonly Rule[] = [exp001, exp002];
