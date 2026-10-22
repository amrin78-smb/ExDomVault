import type { FindingCandidate, HttpObservation, Rule, RuleOutcome, Severity } from '../types.ts';

/**
 * HTTP rules (HTTP-001 … HTTP-005).
 *
 * How the worker produces `http` observations (docs/worker-protocol.md, worker/app/http_checks.py):
 * per hostname it requests `https://<host>/`; only when that reached an address but got no HTTP
 * response does it also request `http://<host>/`. So a plain-HTTP observation exists only when HTTPS
 * did not answer. Redirects are followed only inside the job's domain; a refused redirect makes the
 * observation `partial` (the response that carried it is still real evidence).
 *
 * Hostname = the host of the requested URL (always the target hostname). Rules that must reason
 * about a failed HTTPS attempt (HTTP-001/002) declare `requires: []` so the evaluator does not skip
 * them when no observation is `success`; they apply the evidence checks themselves.
 */

const REFS = {
  rfc6797: 'https://www.rfc-editor.org/rfc/rfc6797',
  mozillaWeb: 'https://infosec.mozilla.org/guidelines/web_security',
  mozillaTls: 'https://wiki.mozilla.org/Security/Server_Side_TLS',
  owaspHeaders: 'https://owasp.org/www-project-secure-headers/',
  owaspHeadersCheat: 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html',
  owaspHsts:
    'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html',
  owaspFingerprint:
    'https://owasp.org/www-project-web-security-testing-guide/latest/4-Information_Gathering/02-Fingerprint_Web_Server',
  hstsPreload: 'https://hstspreload.org/',
} as const;

// --- helpers ---------------------------------------------------------------------------------

interface ParsedUrl {
  scheme: 'http' | 'https';
  host: string;
}

/** Minimal URL parsing (no DOM/Node URL in this pure package): scheme + lowercase host. */
export function parseUrl(url: string | null): ParsedUrl | null {
  if (!url) return null;
  const m = /^(https?):\/\/(\[[0-9a-f:.]+\]|[^/:?#@\s]+)(?::\d+)?(?:[/?#]|$)/i.exec(url);
  const scheme = m?.[1]?.toLowerCase();
  const host = m?.[2]?.toLowerCase().replace(/\.$/, '');
  if ((scheme !== 'http' && scheme !== 'https') || !host) return null;
  return { scheme, host };
}

function inDomain(host: string, fqdn: string): boolean {
  const d = fqdn.toLowerCase();
  return host === d || host.endsWith(`.${d}`);
}

interface Hop {
  url: string | null;
  ip: string | null;
  status: number | null;
  decision: string | null;
  error?: string;
}

function hops(o: HttpObservation): Hop[] {
  const raw = o.evidence['hops'];
  if (!Array.isArray(raw)) return [];
  return raw.map((h: unknown) => {
    const r = (h && typeof h === 'object' ? h : {}) as Record<string, unknown>;
    return {
      url: typeof r['url'] === 'string' ? r['url'] : null,
      ip: typeof r['ip'] === 'string' ? r['ip'] : null,
      status: typeof r['status'] === 'number' ? r['status'] : null,
      decision: typeof r['decision'] === 'string' ? r['decision'] : null,
      ...(typeof r['error'] === 'string' ? { error: r['error'] } : {}),
    };
  });
}

function responded(o: HttpObservation): boolean {
  return (o.resultStatus === 'success' || o.resultStatus === 'partial') && o.statusCode !== null;
}

function failedToRespond(o: HttpObservation): boolean {
  return (o.resultStatus === 'error' || o.resultStatus === 'timeout') && o.statusCode === null;
}

interface HostGroup {
  hostname: string;
  https: HttpObservation[];
  http: HttpObservation[];
}

function groupByHost(observations: readonly HttpObservation[]): HostGroup[] {
  const groups = new Map<string, HostGroup>();
  for (const o of observations) {
    const u = parseUrl(o.url);
    if (!u) continue;
    let g = groups.get(u.host);
    if (!g) {
      g = { hostname: u.host, https: [], http: [] };
      groups.set(u.host, g);
    }
    g[u.scheme].push(o);
  }
  return [...groups.values()];
}

function obsSummary(o: HttpObservation) {
  return {
    url: o.url,
    ipAddress: o.ipAddress,
    resultStatus: o.resultStatus,
    statusCode: o.statusCode,
    finalUrl: o.finalUrl,
    redirectCount: o.redirectCount,
    hstsEnabled: o.hstsEnabled,
    hops: hops(o),
    observedAt: o.observedAt,
  };
}

function web(
  hostname: string,
  component: string,
  fields: Pick<FindingCandidate, 'title' | 'description' | 'severity' | 'confidence' | 'evidence'>,
): FindingCandidate {
  return { hostname, component, exposure: 'web', ...fields };
}

const AVAILABILITY_CHECKS = ['http_availability', 'http_headers'] as const;

// --- HTTP-001 HTTPS not available ------------------------------------------------------------

export const http001: Rule = {
  id: 'HTTP-001',
  version: 1,
  category: 'http',
  title: 'Website served without HTTPS',
  requires: [],
  requiresChecks: AVAILABILITY_CHECKS,
  defaultSeverity: 'medium',
  defaultConfidence: 'high',
  evidenceRequirements:
    'For the hostname: the `https://<host>/` observation and, when HTTPS gave no response, the `http://<host>/` observation of the same job. A response is a status code on a `success` or `partial` observation (a refused redirect does not undo the response that carried it). Declares no required kinds because the triggering evidence is a failed HTTPS attempt.',
  detection:
    '`https://<host>/` reached an address but got no HTTP response (error/timeout, no status code) while `http://<host>/` returned an HTTP status (including a redirect to another domain). If neither answered, there is no finding (not a web host).',
  resolution: '`https://<host>/` returned an HTTP status in the current job.',
  evaluate(input) {
    const out: RuleOutcome = { findings: [], checked: [] };
    for (const g of groupByHost(input.current.http)) {
      if (g.https.some(responded)) {
        out.checked.push({ hostname: g.hostname, component: 'https' });
        continue;
      }
      const httpsFailed = g.https.filter(failedToRespond);
      const plain = g.http.filter(responded);
      const failure = httpsFailed[0];
      const answer = plain[0];
      if (!failure || !answer) continue;
      out.findings.push(
        web(g.hostname, 'https', {
          title: `${g.hostname} answers over plain HTTP but not HTTPS`,
          description: `A request to https://${g.hostname}/ (address ${failure.ipAddress}) got no HTTP response (${failure.resultStatus}), while http://${g.hostname}/ answered with status ${answer.statusCode}. Visitors and links reach the site only unencrypted, so content and any submitted data can be read or altered on the network path. This describes the transport configuration; it is not evidence of interception.`,
          severity: 'medium',
          confidence: 'high',
          evidence: {
            https: httpsFailed.map(obsSummary),
            http: plain.map(obsSummary),
          },
        }),
      );
    }
    return out;
  },
  advisory(f) {
    return {
      title: 'Serve the site over HTTPS',
      summary: `${f.hostname} answers over plain HTTP but HTTPS does not respond.`,
      businessImpact:
        'Traffic, cookies and form data travel unencrypted and can be read or modified on the network; browsers label the site "Not secure".',
      recommendedActions: [
        'Enable HTTPS (port 443) with a publicly trusted certificate (e.g. via ACME) on the server, load balancer or CDN.',
        'Then redirect all plain-HTTP requests to HTTPS with a 301 and enable HSTS.',
        'If the hostname only forwards to another domain, terminate HTTPS for it too (or remove it if unused), so the redirect itself is protected.',
      ],
      references: [REFS.mozillaWeb, REFS.mozillaTls, REFS.rfc6797],
    };
  },
};

// --- HTTP-002 HTTP does not redirect to HTTPS -------------------------------------------------

export const http002: Rule = {
  id: 'HTTP-002',
  version: 1,
  category: 'http',
  title: 'HTTP does not redirect to HTTPS',
  requires: [],
  requiresChecks: AVAILABILITY_CHECKS,
  defaultSeverity: 'low',
  defaultConfidence: 'high',
  evidenceRequirements:
    '`http://<host>/` observation whose first hop returned a status (evidence.hops[0].status). The worker only requests plain HTTP when HTTPS gave no response, so this rule is evaluated only for such hosts.',
  detection:
    'The first plain-HTTP response is 2xx (content served over HTTP), or the in-domain redirect chain ends in a 2xx response on an http:// URL. A redirect to https://, or to another domain (refused as redirect_out_of_scope — the hostname forwards elsewhere), is not flagged.',
  resolution:
    'The first plain-HTTP response is a redirect (3xx) or a non-2xx status, or the chain ends on HTTPS.',
  evaluate(input) {
    const out: RuleOutcome = { findings: [], checked: [] };
    for (const g of groupByHost(input.current.http)) {
      for (const o of g.http) {
        if (!responded(o)) continue;
        const h = hops(o);
        const first = h[0];
        const firstStatus = first ? first.status : o.redirectCount === 0 ? o.statusCode : null;
        if (firstStatus === null) continue;
        const final = parseUrl(o.finalUrl);
        const endsOnPlainHttp =
          o.resultStatus === 'success' &&
          o.statusCode !== null &&
          o.statusCode >= 200 &&
          o.statusCode < 300 &&
          final?.scheme === 'http' &&
          inDomain(final.host, input.context.domain.fqdn);
        if ((firstStatus >= 200 && firstStatus < 300) || endsOnPlainHttp) {
          out.findings.push(
            web(g.hostname, 'http-redirect', {
              title: `${g.hostname} serves content over plain HTTP without redirecting to HTTPS`,
              description: `http://${g.hostname}/ returned status ${o.statusCode}${o.redirectCount > 0 ? ` after ${o.redirectCount} redirect(s) ending at ${o.finalUrl}` : ''} instead of redirecting to HTTPS. Visitors who type the name or follow old links stay on an unencrypted connection.`,
              severity: 'low',
              confidence: 'high',
              evidence: { http: obsSummary(o) },
            }),
          );
        } else {
          out.checked.push({ hostname: g.hostname, component: 'http-redirect' });
        }
      }
    }
    return out;
  },
  advisory(f) {
    return {
      title: 'Redirect plain HTTP to HTTPS',
      summary: `${f.hostname} serves content over plain HTTP.`,
      businessImpact:
        'Users reaching the site by typing the name or via old links use an unencrypted connection that can be read or modified.',
      recommendedActions: [
        'Make sure HTTPS is available first (see HTTP-001 if reported).',
        'Answer every plain-HTTP request with a 301 redirect to the same path on https://.',
        'Enable HSTS once HTTPS works everywhere so browsers skip plain HTTP entirely.',
      ],
      references: [REFS.mozillaWeb, REFS.rfc6797, REFS.owaspHsts],
    };
  },
};

// --- HTTP-003 HSTS missing --------------------------------------------------------------------

export const http003: Rule = {
  id: 'HTTP-003',
  version: 1,
  category: 'http',
  title: 'HSTS not enabled',
  requires: ['http'],
  requiresChecks: AVAILABILITY_CHECKS,
  defaultSeverity: 'low',
  defaultConfidence: 'high',
  evidenceRequirements:
    'A `success` `https://<host>/` observation whose final response is HTTPS, with hstsEnabled (Strict-Transport-Security with max-age > 0 on the final response).',
  detection:
    'The final HTTPS response has no valid Strict-Transport-Security header (hstsEnabled = false). Hosts without HTTPS are covered by HTTP-001 instead. The header is read from the final response of the in-domain redirect chain.',
  resolution: 'A successful HTTPS observation shows hstsEnabled = true.',
  evaluate(input) {
    const out: RuleOutcome = { findings: [], checked: [] };
    for (const g of groupByHost(input.current.http)) {
      for (const o of g.https) {
        if (o.resultStatus !== 'success' || o.hstsEnabled === null) continue;
        if (parseUrl(o.finalUrl)?.scheme !== 'https') continue;
        if (o.hstsEnabled) {
          out.checked.push({ hostname: g.hostname, component: 'hsts' });
          continue;
        }
        const sh = o.evidence['securityHeaders'];
        const hstsValue =
          sh && typeof sh === 'object'
            ? ((sh as Record<string, unknown>)['strict-transport-security'] ?? null)
            : undefined;
        out.findings.push(
          web(g.hostname, 'hsts', {
            title: `HSTS not enabled on ${g.hostname}`,
            description: `The HTTPS response from ${o.finalUrl} has no valid Strict-Transport-Security header. Without HSTS, a browser may still make a first plain-HTTP request (typed name, old link), which a network attacker could intercept to downgrade the connection. This is a missing hardening measure, not evidence of an attack.`,
            severity: 'low',
            confidence: 'high',
            evidence: {
              https: obsSummary(o),
              ...(hstsValue !== undefined ? { strictTransportSecurity: hstsValue } : {}),
            },
          }),
        );
      }
    }
    return out;
  },
  advisory(f) {
    return {
      title: 'Enable HTTP Strict Transport Security',
      summary: `${f.hostname} does not send a valid Strict-Transport-Security header.`,
      businessImpact:
        'Visitors can be downgraded to plain HTTP on hostile networks (SSL stripping) before the redirect to HTTPS happens.',
      recommendedActions: [
        'Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all HTTPS responses (start with a short max-age, then increase).',
        'Only add includeSubDomains once every subdomain serves HTTPS; consider HSTS preload afterwards.',
        'Keep the redirect from HTTP to HTTPS in place.',
      ],
      references: [REFS.rfc6797, REFS.owaspHsts, REFS.mozillaWeb, REFS.hstsPreload],
    };
  },
};

// --- HTTP-004 Missing security headers --------------------------------------------------------

export type SecurityHeader =
  'content-security-policy' | 'x-content-type-options' | 'x-frame-options' | 'referrer-policy';

function headerValue(headers: Record<string, unknown>, name: string): string | null {
  const v = headers[name];
  return typeof v === 'string' && v.trim().length > 0 ? v.trim() : null;
}

/** The recommended headers missing from a captured `securityHeaders` map (exported for tests). */
export function missingSecurityHeaders(headers: Record<string, unknown>): SecurityHeader[] {
  const missing: SecurityHeader[] = [];
  const csp = headerValue(headers, 'content-security-policy');
  if (!csp) missing.push('content-security-policy');
  const xcto = headerValue(headers, 'x-content-type-options');
  if (!xcto || !/\bnosniff\b/i.test(xcto)) missing.push('x-content-type-options');
  const frameAncestors = csp !== null && /(^|;)\s*frame-ancestors\s/i.test(csp);
  if (!headerValue(headers, 'x-frame-options') && !frameAncestors) missing.push('x-frame-options');
  if (!headerValue(headers, 'referrer-policy')) missing.push('referrer-policy');
  return missing;
}

function securityHeaders(o: HttpObservation): Record<string, unknown> | null {
  const sh = o.evidence['securityHeaders'];
  return sh && typeof sh === 'object' && !Array.isArray(sh)
    ? (sh as Record<string, unknown>)
    : null;
}

export const http004: Rule = {
  id: 'HTTP-004',
  version: 1,
  category: 'http',
  title: 'Recommended security headers missing',
  requires: ['http'],
  requiresChecks: ['http_headers'],
  defaultSeverity: 'informational',
  defaultConfidence: 'high',
  evidenceRequirements:
    'A `success` http observation with final status 200 and evidence.securityHeaders (captured only when the profile runs `http_headers`). HTTPS observations are preferred over plain HTTP.',
  detection:
    'Any of Content-Security-Policy, X-Content-Type-Options: nosniff, X-Frame-Options (or CSP frame-ancestors) or Referrer-Policy is missing on the final 200 response. One finding per hostname listing the missing headers. Low when framing protection is missing (neither X-Frame-Options nor frame-ancestors), otherwise informational.',
  resolution: 'A qualifying observation shows all four headers present.',
  evaluate(input) {
    const out: RuleOutcome = { findings: [], checked: [] };
    for (const g of groupByHost(input.current.http)) {
      const qualifying = [...g.https, ...g.http].find(
        (o) => o.resultStatus === 'success' && o.statusCode === 200 && securityHeaders(o) !== null,
      );
      const headers = qualifying ? securityHeaders(qualifying) : null;
      if (!qualifying || !headers) continue;
      const missing = missingSecurityHeaders(headers);
      if (missing.length === 0) {
        out.checked.push({ hostname: g.hostname, component: 'headers' });
        continue;
      }
      const severity: Severity = missing.includes('x-frame-options') ? 'low' : 'informational';
      out.findings.push(
        web(g.hostname, 'headers', {
          title: `Recommended security headers missing on ${g.hostname}`,
          description: `The response from ${qualifying.finalUrl ?? qualifying.url} does not set: ${missing.join(', ')}. These headers are defence-in-depth measures that limit the impact of content injection, MIME sniffing and framing (clickjacking). Their absence is a hardening gap, not a confirmed vulnerability.`,
          severity,
          confidence: 'high',
          evidence: {
            missing,
            url: qualifying.url,
            finalUrl: qualifying.finalUrl,
            statusCode: qualifying.statusCode,
            securityHeaders: headers,
          },
        }),
      );
    }
    return out;
  },
  advisory(f) {
    const missing = Array.isArray(f.evidence['missing']) ? (f.evidence['missing'] as string[]) : [];
    const actions: Record<string, string> = {
      'content-security-policy':
        "Define a Content-Security-Policy (start with `default-src 'self'` in Report-Only mode, then enforce).",
      'x-content-type-options': 'Send `X-Content-Type-Options: nosniff`.',
      'x-frame-options':
        "Prevent framing with CSP `frame-ancestors 'self'` (or `X-Frame-Options: DENY`/`SAMEORIGIN`).",
      'referrer-policy': 'Send `Referrer-Policy: strict-origin-when-cross-origin` (or stricter).',
    };
    return {
      title: 'Add recommended HTTP security headers',
      summary: `${f.hostname} is missing ${missing.join(', ') || 'recommended security headers'}.`,
      businessImpact:
        'Missing headers remove browser-side protections that limit the impact of cross-site scripting, clickjacking and information leakage through referrers.',
      recommendedActions: [
        ...missing.map((m) => actions[m]).filter((a): a is string => a !== undefined),
        'Set the headers at the web server, application or CDN so every HTML response carries them.',
      ],
      references: [REFS.owaspHeaders, REFS.owaspHeadersCheat, REFS.mozillaWeb],
    };
  },
};

// --- HTTP-005 Software version disclosure -----------------------------------------------------

const VERSION_PATTERN = /\b\d+\.\d+(?:\.\d+)*\b/;

/** True when a header value contains a dotted version number (exported for tests). */
export function disclosesVersion(value: string | null): boolean {
  return value !== null && VERSION_PATTERN.test(value);
}

function headerField(o: HttpObservation, key: 'server' | 'xPoweredBy'): string | null | undefined {
  if (!(key in o.evidence)) return undefined;
  const v = o.evidence[key];
  return typeof v === 'string' ? v : null;
}

export const http005: Rule = {
  id: 'HTTP-005',
  version: 1,
  category: 'http',
  title: 'Software version disclosed in HTTP headers',
  requires: ['http'],
  requiresChecks: ['http_headers'],
  defaultSeverity: 'informational',
  defaultConfidence: 'high',
  evidenceRequirements:
    'An http observation with a response and evidence.server / evidence.xPoweredBy captured (profile runs `http_headers`). Raised from `success` or `partial` (the header came from a real response); resolved only from `success`.',
  detection:
    'The Server or X-Powered-By header contains a dotted version number (e.g. `Apache/2.4.41`, `PHP/8.1.2`). Informational: this is disclosure, not a confirmed vulnerability.',
  resolution: 'A successful observation shows neither header carries a version number.',
  evaluate(input) {
    const out: RuleOutcome = { findings: [], checked: [] };
    for (const g of groupByHost(input.current.http)) {
      const disclosures: { url: string; server: string | null; xPoweredBy: string | null }[] = [];
      let cleanSuccess = false;
      for (const o of [...g.https, ...g.http]) {
        if (!responded(o)) continue;
        const server = headerField(o, 'server');
        const xpb = headerField(o, 'xPoweredBy');
        if (server === undefined && xpb === undefined) continue;
        if (disclosesVersion(server ?? null) || disclosesVersion(xpb ?? null)) {
          disclosures.push({
            url: o.finalUrl ?? o.url,
            server: server ?? null,
            xPoweredBy: xpb ?? null,
          });
        } else if (o.resultStatus === 'success') {
          cleanSuccess = true;
        }
      }
      if (disclosures.length > 0) {
        const values = disclosures
          .flatMap((d) => [d.server, d.xPoweredBy])
          .filter((v): v is string => v !== null && disclosesVersion(v));
        out.findings.push(
          web(g.hostname, 'version-disclosure', {
            title: `Software version disclosed by ${g.hostname}`,
            description: `HTTP response headers reveal software versions (${[...new Set(values)].join('; ')}). This is information disclosure that helps an attacker look up known issues for that version; it does not confirm that the version is vulnerable or that the server was attacked.`,
            severity: 'informational',
            confidence: 'high',
            evidence: { responses: disclosures },
          }),
        );
      } else if (cleanSuccess) {
        out.checked.push({ hostname: g.hostname, component: 'version-disclosure' });
      }
    }
    return out;
  },
  advisory(f) {
    return {
      title: 'Stop advertising software versions',
      summary: `${f.hostname} reveals software versions in its HTTP headers.`,
      businessImpact:
        'Version strings make it cheaper to find known vulnerabilities for the exact software in use. Disclosure alone is not a vulnerability; patching matters more than hiding.',
      recommendedActions: [
        'Confirm the disclosed software is on a supported, patched version.',
        'Suppress version details (e.g. nginx `server_tokens off`, Apache `ServerTokens Prod` / `ServerSignature Off`, PHP `expose_php = Off`).',
        'Remove X-Powered-By at the application or reverse proxy.',
      ],
      references: [REFS.owaspFingerprint, REFS.owaspHeadersCheat],
    };
  },
};

export const httpRules: readonly Rule[] = [http001, http002, http003, http004, http005];
