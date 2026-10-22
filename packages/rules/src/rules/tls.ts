import type {
  CheckedComponent,
  EvaluationContext,
  EvaluationInput,
  FindingCandidate,
  Rule,
  RuleOutcome,
  Severity,
  TlsObservation,
} from '../types.ts';

/**
 * TLS rules (design §8: TLS-001 … TLS-004, plus TLS-005 untrusted chain).
 *
 * Shared conventions:
 * - Observations are grouped per hostname + port; the component is the port (`443`), so a finding
 *   is one per hostname/port however many addresses serve it. Evidence lists the addresses.
 * - A finding is raised only from SUCCESSFUL observations (the certificate was read and parsed).
 * - A hostname/port is listed in `checked` (may resolve) only when EVERY current observation for it
 *   succeeded: a failed address could still be serving the problem certificate.
 * - The worker currently records `tls_certificate` only; `tls_configuration` (per-version
 *   handshakes) is not implemented, so TLS-004 relies on the negotiated version.
 */

const DAY_MS = 86_400_000;
const EXPIRY_WINDOW_DAYS = 14;
const EXPIRY_HIGH_DAYS = 3;
const TLS_CHECKS = ['tls_certificate', 'tls_configuration'] as const;

const REFS = {
  mozilla: 'https://wiki.mozilla.org/Security/Server_Side_TLS',
  mozillaConfig: 'https://ssl-config.mozilla.org/',
  cabf: 'https://cabforum.org/working-groups/server/baseline-requirements/documents/',
  rfc6125: 'https://www.rfc-editor.org/rfc/rfc6125',
  rfc8996: 'https://www.rfc-editor.org/rfc/rfc8996',
  owaspTls:
    'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html',
} as const;

interface TlsGroup {
  hostname: string;
  port: number;
  all: TlsObservation[];
  success: TlsObservation[];
  complete: boolean;
}

function groupTls(observations: readonly TlsObservation[]): TlsGroup[] {
  const groups = new Map<string, TlsGroup>();
  for (const o of observations) {
    const key = `${o.hostname}|${o.port}`;
    let g = groups.get(key);
    if (!g) {
      g = { hostname: o.hostname, port: o.port, all: [], success: [], complete: true };
      groups.set(key, g);
    }
    g.all.push(o);
    if (o.resultStatus === 'success') g.success.push(o);
    else g.complete = false;
  }
  return [...groups.values()];
}

function time(value: string | null): number | null {
  if (value === null) return null;
  const t = Date.parse(value);
  return Number.isNaN(t) ? null : t;
}

function certSummary(o: TlsObservation) {
  return {
    ipAddress: o.ipAddress,
    notBefore: o.notBefore,
    notAfter: o.notAfter,
    issuer: o.issuer,
    subject: o.subject,
    subjectAltNames: o.subjectAltNames,
    fingerprintSha256: o.fingerprintSha256,
    protocolVersion: o.protocolVersion,
    trusted: o.evidence['trusted'] ?? null,
    verifyError: verifyError(o),
    observedAt: o.observedAt,
  };
}

function verifyError(o: TlsObservation): string | null {
  const v = o.evidence['verifyError'];
  return typeof v === 'string' && v.length > 0 ? v : null;
}

/**
 * Classifies the worker's OpenSSL verification message. Only the first error OpenSSL hits is
 * reported, so an untrusted chain normally masks expiry/hostname problems (which TLS-001/002/003
 * detect from the certificate fields independently).
 */
export type VerifyErrorClass = 'hostname' | 'expired' | 'not_yet_valid' | 'chain' | 'handshake';

export function classifyVerifyError(message: string): VerifyErrorClass {
  const m = message.toLowerCase();
  if (m.startsWith('handshake_failed')) return 'handshake';
  if (m.includes('hostname mismatch') || m.includes('ip address mismatch')) return 'hostname';
  if (m.includes('has expired')) return 'expired';
  if (m.includes('not yet valid')) return 'not_yet_valid';
  return 'chain';
}

const KNOWN_CHAIN_ERRORS = [
  'self-signed',
  'self signed',
  'unable to get local issuer',
  'unable to get issuer',
  'unable to verify the first certificate',
  'certificate chain too long',
  'invalid ca certificate',
  'certificate revoked',
  'certificate signature failure',
];

function isKnownChainError(message: string): boolean {
  const m = message.toLowerCase();
  return KNOWN_CHAIN_ERRORS.some((k) => m.includes(k));
}

function hostLabel(f: FindingCandidate) {
  return `${f.hostname}:${f.component}`;
}

function finding(
  group: TlsGroup,
  fields: Pick<FindingCandidate, 'title' | 'description' | 'severity' | 'confidence'>,
  evidence: Record<string, unknown>,
): FindingCandidate {
  return {
    hostname: group.hostname,
    component: String(group.port),
    exposure: 'web',
    ...fields,
    evidence: { hostname: group.hostname, port: group.port, ...evidence },
  };
}

function checkedOf(group: TlsGroup): CheckedComponent[] {
  return group.complete && group.success.length > 0
    ? [{ hostname: group.hostname, component: String(group.port) }]
    : [];
}

/** Runs `detect` per group; it returns a finding or null (null + complete group = resolvable). */
function perGroup(
  input: EvaluationInput,
  detect: (group: TlsGroup, ctx: EvaluationContext) => FindingCandidate | null | 'insufficient',
): RuleOutcome {
  const out: RuleOutcome = { findings: [], checked: [] };
  for (const group of groupTls(input.current.tls)) {
    if (group.success.length === 0) continue;
    const res = detect(group, input.context);
    if (res === 'insufficient') continue;
    if (res) out.findings.push(res);
    else out.checked.push(...checkedOf(group));
  }
  return out;
}

const baseRule = {
  version: 1,
  category: 'tls',
  requires: ['tls'],
  requiresChecks: TLS_CHECKS,
} as const satisfies Partial<Rule>;

// --- TLS-001 ----------------------------------------------------------------------------------

export const tls001: Rule = {
  ...baseRule,
  id: 'TLS-001',
  title: 'Expired or not-yet-valid TLS certificate',
  defaultSeverity: 'high',
  defaultConfidence: 'high',
  evidenceRequirements:
    'Successful `tls` observations (certificate read and parsed) for the hostname and port, with notBefore/notAfter.',
  detection:
    'Any address serving the hostname presents a certificate whose notAfter is before the evaluation time (expired) or whose notBefore is after it (not yet valid). One finding per hostname and port; evidence lists the affected addresses.',
  resolution:
    'Every current observation for the hostname and port succeeded and every certificate is inside its validity period.',
  evaluate(input) {
    const now = Date.parse(input.context.now);
    return perGroup(input, (group) => {
      const expired: TlsObservation[] = [];
      const notYetValid: TlsObservation[] = [];
      let evaluated = 0;
      for (const o of group.success) {
        const nb = time(o.notBefore);
        const na = time(o.notAfter);
        if (nb === null || na === null) continue;
        evaluated++;
        if (na < now) expired.push(o);
        else if (nb > now) notYetValid.push(o);
      }
      if (expired.length === 0 && notYetValid.length === 0) {
        return evaluated === group.success.length ? null : 'insufficient';
      }
      const isExpired = expired.length > 0;
      const affected = isExpired ? expired : notYetValid;
      const ips = affected.map((o) => o.ipAddress);
      const host = `${group.hostname}:${group.port}`;
      return finding(
        group,
        {
          title: isExpired
            ? `Expired TLS certificate on ${host}`
            : `TLS certificate not yet valid on ${host}`,
          description: isExpired
            ? `The certificate presented for ${host} (address ${ips.join(', ')}) expired on ${affected[0]?.notAfter}. Browsers and API clients reject expired certificates, so visitors see security warnings or cannot connect. This is a certificate management issue, not evidence of compromise.`
            : `The certificate presented for ${host} (address ${ips.join(', ')}) is not valid until ${affected[0]?.notBefore}. Clients reject it until then, which usually indicates a premature deployment or a server clock problem.`,
          severity: 'high',
          confidence: 'high',
        },
        {
          condition: isExpired ? 'expired' : 'not_yet_valid',
          evaluatedAt: input.context.now,
          affectedAddresses: ips,
          certificates: affected.map(certSummary),
          ...(isExpired && notYetValid.length > 0
            ? { notYetValidAddresses: notYetValid.map((o) => o.ipAddress) }
            : {}),
        },
      );
    });
  },
  advisory(f) {
    const notYet = f.evidence['condition'] === 'not_yet_valid';
    return {
      title: notYet ? 'Deploy a currently valid certificate' : 'Renew the expired certificate',
      summary: notYet
        ? `${hostLabel(f)} presents a certificate whose validity period has not started.`
        : `${hostLabel(f)} presents an expired certificate.`,
      businessImpact:
        'Visitors receive browser security warnings or cannot connect; automated clients fail. Users trained to click through warnings become easier to deceive.',
      recommendedActions: notYet
        ? [
            'Check the server clock (NTP) and the certificate notBefore date.',
            'Deploy the previous valid certificate until the new one becomes valid.',
            'Confirm every listed address serves the same, valid certificate.',
          ]
        : [
            'Issue and install a renewed certificate on every listed address (and any load balancer or CDN edge).',
            'Automate renewal (e.g. ACME) and alert at least 30 days before expiry.',
            'Reload or restart the TLS terminator so it serves the new certificate, then re-scan.',
          ],
      references: [REFS.mozilla, REFS.cabf],
    };
  },
};

// --- TLS-002 ----------------------------------------------------------------------------------

export const tls002: Rule = {
  ...baseRule,
  id: 'TLS-002',
  title: 'Certificate hostname mismatch',
  defaultSeverity: 'medium',
  defaultConfidence: 'high',
  evidenceRequirements:
    'Successful `tls` observations with `hostnameMatches` (RFC 6125 matching against dNSName SANs, computed by the worker).',
  detection:
    'Any address serving the hostname presents a certificate whose subjectAltNames do not cover the hostname (hostnameMatches = false). Medium; high when the chain is also untrusted for another reason (self-signed, unknown CA).',
  resolution:
    'Every current observation for the hostname and port succeeded and every certificate matches the hostname.',
  evaluate(input) {
    return perGroup(input, (group) => {
      if (group.success.some((o) => o.hostnameMatches === null)) {
        // Unknown match status on some address: raise only from definite mismatches.
        if (!group.success.some((o) => o.hostnameMatches === false)) return 'insufficient';
      }
      const mismatched = group.success.filter((o) => o.hostnameMatches === false);
      if (mismatched.length === 0) return null;
      const alsoUntrusted = mismatched.some((o) => {
        const err = verifyError(o);
        return (
          o.evidence['trusted'] === false && err !== null && classifyVerifyError(err) === 'chain'
        );
      });
      const host = `${group.hostname}:${group.port}`;
      return finding(
        group,
        {
          title: `TLS certificate does not match ${group.hostname}`,
          description: `The certificate presented for ${host} (address ${mismatched.map((o) => o.ipAddress).join(', ')}) does not list ${group.hostname} in its subject alternative names${alsoUntrusted ? ', and its chain is not trusted' : ''}. Clients reject the connection or show a warning. This often means the host is served by shared hosting or a default virtual host; it is a configuration issue, not evidence of interception.`,
          severity: alsoUntrusted ? 'high' : 'medium',
          confidence: 'high',
        },
        {
          affectedAddresses: mismatched.map((o) => o.ipAddress),
          alsoUntrusted,
          certificates: mismatched.map(certSummary),
        },
      );
    });
  },
  advisory(f) {
    return {
      title: 'Serve a certificate that covers the hostname',
      summary: `${hostLabel(f)} presents a certificate that does not include the hostname.`,
      businessImpact:
        'Visitors see certificate warnings or cannot connect; users who learn to ignore warnings are easier to target with real interception attempts.',
      recommendedActions: [
        `Issue a certificate whose subjectAltName includes ${f.hostname} (wildcards cover exactly one label).`,
        'Check SNI and virtual host configuration on every listed address so the right certificate is selected.',
        'If the hostname is no longer used, remove its DNS records instead of leaving it pointed at a shared server.',
      ],
      references: [REFS.rfc6125, REFS.cabf, REFS.mozilla],
    };
  },
};

// --- TLS-003 ----------------------------------------------------------------------------------

export const tls003: Rule = {
  ...baseRule,
  id: 'TLS-003',
  title: 'Certificate expiry within 14 days',
  defaultSeverity: 'medium',
  defaultConfidence: 'high',
  evidenceRequirements: 'Successful `tls` observations with notAfter.',
  detection: `A currently valid certificate (notAfter not before the evaluation time) expires within ${EXPIRY_WINDOW_DAYS} days (0 ≤ remaining ≤ ${EXPIRY_WINDOW_DAYS} days, inclusive). Medium; high when ${EXPIRY_HIGH_DAYS} days or fewer remain. Already-expired certificates are TLS-001.`,
  resolution: `Every current observation for the hostname and port succeeded and every currently valid certificate has more than ${EXPIRY_WINDOW_DAYS} days remaining (an expired one moves to TLS-001).`,
  evaluate(input) {
    const now = Date.parse(input.context.now);
    return perGroup(input, (group) => {
      const soon: { o: TlsObservation; days: number }[] = [];
      for (const o of group.success) {
        const na = time(o.notAfter);
        if (na === null) return 'insufficient';
        if (na < now) continue;
        const days = (na - now) / DAY_MS;
        if (days <= EXPIRY_WINDOW_DAYS) soon.push({ o, days });
      }
      soon.sort((a, b) => a.days - b.days);
      const soonest = soon[0];
      if (!soonest) return null;
      const minDays = soonest.days;
      const whole = Math.floor(minDays);
      const host = `${group.hostname}:${group.port}`;
      return finding(
        group,
        {
          title: `TLS certificate for ${host} expires within ${EXPIRY_WINDOW_DAYS} days`,
          description: `The certificate presented for ${host} (address ${soon.map((s) => s.o.ipAddress).join(', ')}) expires on ${soonest.o.notAfter} (${whole} day${whole === 1 ? '' : 's'} remaining). If it is not renewed in time, clients will reject the connection.`,
          severity: expirySeverity(minDays) ?? 'medium',
          confidence: 'high',
        },
        {
          evaluatedAt: input.context.now,
          daysRemaining: whole,
          affectedAddresses: soon.map((s) => s.o.ipAddress),
          certificates: soon.map((s) => certSummary(s.o)),
        },
      );
    });
  },
  advisory(f) {
    return {
      title: 'Renew the certificate before it expires',
      summary: `${hostLabel(f)} presents a certificate that expires soon.`,
      businessImpact:
        'An expired certificate causes browser warnings and failed API connections, interrupting the service.',
      recommendedActions: [
        'Renew and deploy the certificate on every listed address now.',
        'If renewal is automated (ACME), check why it has not run: failed challenges, rate limits or a stopped renewal job.',
        'Alert on certificates with fewer than 30 days remaining.',
      ],
      references: [REFS.mozilla, REFS.cabf],
    };
  },
};

// --- TLS-004 ----------------------------------------------------------------------------------

const WEAK_PROTOCOLS = new Set(['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0', 'TLSv1.1']);
const STRONG_PROTOCOLS = new Set(['TLSv1.2', 'TLSv1.3']);

export const tls004: Rule = {
  ...baseRule,
  id: 'TLS-004',
  title: 'Weak or unsupported TLS configuration',
  defaultSeverity: 'medium',
  defaultConfidence: 'medium',
  evidenceRequirements:
    'Successful `tls` observations with protocolVersion (the version negotiated by the worker). Per-version enumeration (`tls_configuration`) is not implemented by the worker yet.',
  detection:
    'The negotiated protocol is SSLv2, SSLv3, TLS 1.0 or TLS 1.1 (deprecated by RFC 8996). Only the negotiated version is known, so a server that also accepts old versions but prefers TLS 1.2+ is not detected (confidence medium). The worker requires TLS 1.2+ for its handshake, so a server offering only old versions currently fails the handshake (error observation) instead of producing evidence here.',
  resolution:
    'Every current observation for the hostname and port succeeded and negotiated TLS 1.2 or TLS 1.3.',
  evaluate(input) {
    return perGroup(input, (group) => {
      const weak = group.success.filter(
        (o) => o.protocolVersion !== null && WEAK_PROTOCOLS.has(o.protocolVersion),
      );
      if (weak.length > 0) {
        const host = `${group.hostname}:${group.port}`;
        const versions = [...new Set(weak.map((o) => o.protocolVersion))];
        return finding(
          group,
          {
            title: `Deprecated TLS version negotiated on ${host}`,
            description: `${host} (address ${weak.map((o) => o.ipAddress).join(', ')}) negotiated ${versions.join(', ')}, which is deprecated (RFC 8996) and lacks modern protections. This is a configuration weakness, not evidence that traffic was intercepted.`,
            severity: 'medium',
            confidence: 'medium',
          },
          {
            negotiatedVersions: versions,
            affectedAddresses: weak.map((o) => o.ipAddress),
            method: 'negotiated_version_only',
          },
        );
      }
      const known = group.success.every(
        (o) => o.protocolVersion !== null && STRONG_PROTOCOLS.has(o.protocolVersion),
      );
      return known ? null : 'insufficient';
    });
  },
  advisory(f) {
    return {
      title: 'Disable deprecated TLS protocol versions',
      summary: `${hostLabel(f)} negotiates a deprecated TLS protocol version.`,
      businessImpact:
        'Old protocol versions have known cryptographic weaknesses and fail compliance requirements (e.g. PCI DSS); modern clients increasingly refuse them.',
      recommendedActions: [
        'Allow only TLS 1.2 and TLS 1.3 on the server, load balancer and CDN.',
        "Apply the Mozilla 'intermediate' configuration for your server software.",
        'Re-scan to confirm TLS 1.2+ is negotiated on every address.',
      ],
      references: [REFS.rfc8996, REFS.mozilla, REFS.mozillaConfig, REFS.owaspTls],
    };
  },
};

// --- TLS-005 ----------------------------------------------------------------------------------

export const tls005: Rule = {
  ...baseRule,
  id: 'TLS-005',
  title: 'Untrusted certificate chain',
  defaultSeverity: 'medium',
  defaultConfidence: 'high',
  evidenceRequirements:
    'Successful `tls` observations with evidence.trusted and, when untrusted, evidence.verifyError (OpenSSL verification message).',
  detection:
    'evidence.trusted = false with a verifyError that is not only a hostname mismatch, expiry or not-yet-valid (those are TLS-002/TLS-001): self-signed certificate, unknown CA or incomplete chain. Confidence high for recognised chain errors, medium for other messages.',
  resolution:
    'Every current observation for the hostname and port succeeded, and each is trusted or fails only for a reason covered by TLS-001/TLS-002.',
  evaluate(input) {
    return perGroup(input, (group) => {
      const untrusted: TlsObservation[] = [];
      const errorSet = new Set<string>();
      for (const o of group.success) {
        const trusted = o.evidence['trusted'];
        if (trusted === true) continue;
        if (trusted !== false) return 'insufficient';
        const err = verifyError(o);
        if (err === null) return 'insufficient';
        if (classifyVerifyError(err) === 'chain') {
          untrusted.push(o);
          errorSet.add(err);
        }
      }
      if (untrusted.length === 0) return null;
      const host = `${group.hostname}:${group.port}`;
      const errors = [...errorSet];
      const known = errors.every(isKnownChainError);
      return finding(
        group,
        {
          title: `Untrusted TLS certificate chain on ${host}`,
          description: `The certificate presented for ${host} (address ${untrusted.map((o) => o.ipAddress).join(', ')}) could not be validated against the public trust store (${errors.join('; ')}). Typical causes are a self-signed certificate, a private CA or a missing intermediate certificate. Clients reject the connection or show a warning; this is a configuration issue, not evidence of interception.`,
          severity: 'medium',
          confidence: known ? 'high' : 'medium',
        },
        {
          verifyErrors: errors,
          affectedAddresses: untrusted.map((o) => o.ipAddress),
          certificates: untrusted.map(certSummary),
        },
      );
    });
  },
  advisory(f) {
    return {
      title: 'Serve a publicly trusted, complete certificate chain',
      summary: `${hostLabel(f)} presents a certificate chain that public clients do not trust.`,
      businessImpact:
        'Visitors see certificate warnings or cannot connect; API clients fail. Users trained to accept warnings are easier to deceive.',
      recommendedActions: [
        'Replace self-signed or private-CA certificates on public endpoints with certificates from a publicly trusted CA.',
        'Configure the server to send the full intermediate chain (leaf first, then intermediates; no root needed).',
        'Verify the result with an external TLS checker, then re-scan.',
      ],
      references: [REFS.cabf, REFS.mozilla, REFS.owaspTls],
    };
  },
};

export const tlsRules: readonly Rule[] = [tls001, tls002, tls003, tls004, tls005];

/** Exported for tests: severity of TLS-003 for a number of remaining days. */
export function expirySeverity(days: number): Severity | null {
  if (days < 0 || days > EXPIRY_WINDOW_DAYS) return null;
  return days <= EXPIRY_HIGH_DAYS ? 'high' : 'medium';
}
