import type {
  Advisory,
  CheckedComponent,
  DnsRecordSetObservation,
  FindingCandidate,
  Rule,
  RuleOutcome,
} from '../types.ts';
import { decodeTxt, mailState, normaliseName, successfulRecord } from './dns.ts';

/*
 * Deeper e-mail security rules (Milestone 15), passive DNS only. The worker queries, at the apex:
 * `_mta-sts.<apex>` and `_smtp._tls.<apex>` TXT only when the apex MX lists a real exchanger, and
 * `<selector>._domainkey.<apex>` TXT for a fixed list of common DKIM selectors plus
 * `default._bimi.<apex>` TXT for every apex (sending does not need an MX). The MTA-STS policy file
 * (https://mta-sts.<apex>/.well-known/mta-sts.txt) is never fetched: only the DNS record is checked.
 * BIMI is displayed in the UI but produces no finding (it is a brand feature, not a control).
 *
 * As for every DNS rule, only `success` observations are evidence: a failed, timed-out or missing
 * lookup neither raises nor resolves.
 */

const apexOf = (input: { context: { domain: { fqdn: string } } }) =>
  normaliseName(input.context.domain.fqdn);

const none = (): RuleOutcome => ({ findings: [], checked: [] });

/** `key=value` tags of a `;`-separated record (first occurrence wins, keys lowercased). */
export function parseTags(record: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const part of record.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim().toLowerCase();
    if (key && !(key in tags)) tags[key] = part.slice(eq + 1).trim();
  }
  return tags;
}

const RFC = {
  mtaSts: 'https://www.rfc-editor.org/rfc/rfc8461',
  tlsRpt: 'https://www.rfc-editor.org/rfc/rfc8460',
  dkim: 'https://www.rfc-editor.org/rfc/rfc6376',
  dkimKeys: 'https://www.rfc-editor.org/rfc/rfc8301',
  ncscEmail: 'https://www.ncsc.gov.uk/collection/email-security-and-anti-spoofing',
} as const;

// --- MTA-STS (RFC 8461 §3.1) ----------------------------------------------------------------

export type MtaStsProblem = 'missing' | 'multiple' | 'invalid_id';

/** Analyse the TXT values at `_mta-sts.<apex>`: null when exactly one valid record exists. */
export function analyseMtaSts(values: readonly string[]): {
  problem: MtaStsProblem | null;
  records: string[];
  id: string | null;
} {
  // Records that do not begin with "v=STSv1;" are discarded (RFC 8461 §3.1).
  const records = values.map(decodeTxt).filter((t) => /^v=STSv1\s*(;|$)/.test(t.trim()));
  if (records.length === 0) return { problem: 'missing', records, id: null };
  if (records.length > 1) return { problem: 'multiple', records, id: null };
  const id = parseTags(records[0] ?? '').id ?? null;
  if (!id || !/^[A-Za-z0-9]{1,32}$/.test(id)) return { problem: 'invalid_id', records, id };
  return { problem: null, records, id };
}

const mtaStsName = (apex: string) => `_mta-sts.${apex}`;

export const email001: Rule = {
  id: 'EMAIL-001',
  version: 1,
  category: 'email',
  title: 'No MTA-STS policy for a mail domain',
  requires: ['dns'],
  requiresChecks: ['dns'],
  defaultSeverity: 'low',
  defaultConfidence: 'high',
  evidenceRequirements:
    'Successful apex MX lookup listing a real exchanger and a successful TXT lookup at _mta-sts.<apex> ' +
    '(NXDOMAIN/NODATA count as "no record"). Only the DNS record is checked; the HTTPS policy file is never fetched.',
  detection:
    'The domain receives mail (MX present, not a null MX) but no TXT record at _mta-sts.<apex> begins ' +
    'with v=STSv1. Malformed or duplicate records are EMAIL-002.',
  resolution:
    'A v=STSv1 record is published at _mta-sts.<apex>, or the apex MX lookup shows the domain no longer receives mail.',
  evaluate(input) {
    const apex = apexOf(input);
    const component = { hostname: apex, component: 'mta-sts' };
    const mail = mailState(input.current.dns, apex);
    if (mail === 'unknown') return none();
    if (mail === 'no_mail') return { findings: [], checked: [component] };
    const txt = successfulRecord(input.current.dns, mtaStsName(apex), 'TXT');
    if (!txt) return none();
    if (analyseMtaSts(txt.values).problem !== 'missing')
      return { findings: [], checked: [component] };
    return {
      findings: [
        {
          hostname: apex,
          component: 'mta-sts',
          title: `No MTA-STS policy for ${apex}`,
          description:
            `${apex} receives mail but publishes no MTA-STS record at ${mtaStsName(apex)}. Without ` +
            'MTA-STS (or DANE), sending servers fall back to opportunistic TLS, so an on-path attacker ' +
            'can strip encryption or redirect inbound mail. This is a hardening gap, not evidence of interception.',
          severity: 'low',
          confidence: 'high',
          exposure: 'public_record',
          evidence: {
            queriedName: mtaStsName(apex),
            txtValues: txt.values,
            rcode: txt.evidence.rcode ?? null,
            mail,
            policyFileChecked: false,
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
      title: `Publish an MTA-STS policy for ${apex}`,
      summary:
        'MTA-STS lets a receiving domain require authenticated TLS for inbound SMTP, so senders refuse ' +
        'to deliver over downgraded or spoofed connections.',
      businessImpact:
        'Inbound mail can be read or redirected by an attacker able to tamper with the network path or DNS ' +
        'responses seen by sending servers.',
      recommendedActions: [
        `Host the policy at https://mta-sts.${apex}/.well-known/mta-sts.txt listing your MX hosts, starting with "mode: testing".`,
        `Publish TXT "v=STSv1; id=<version>" at _mta-sts.${apex} (change id whenever the policy changes).`,
        'Publish a TLS-RPT record to receive failure reports, then move the policy to "mode: enforce".',
        'Make sure every MX host presents a valid certificate for its name.',
      ],
      references: [RFC.mtaSts, RFC.tlsRpt, RFC.ncscEmail],
    };
  },
};

export const email002: Rule = {
  id: 'EMAIL-002',
  version: 1,
  category: 'email',
  title: 'MTA-STS record malformed',
  requires: ['dns'],
  requiresChecks: ['dns'],
  defaultSeverity: 'low',
  defaultConfidence: 'high',
  evidenceRequirements:
    'Successful apex MX lookup listing a real exchanger and a successful TXT lookup at _mta-sts.<apex>.',
  detection:
    'More than one TXT record at _mta-sts.<apex> begins with v=STSv1, or the single record has no valid ' +
    'id= (1–32 letters or digits). Senders then treat the domain as having no MTA-STS policy (RFC 8461 §3.1).',
  resolution:
    'Exactly one well-formed v=STSv1 record (or none — EMAIL-001 then applies), or the domain no longer receives mail.',
  evaluate(input) {
    const apex = apexOf(input);
    const component = { hostname: apex, component: 'mta-sts-record' };
    const mail = mailState(input.current.dns, apex);
    if (mail === 'unknown') return none();
    if (mail === 'no_mail') return { findings: [], checked: [component] };
    const txt = successfulRecord(input.current.dns, mtaStsName(apex), 'TXT');
    if (!txt) return none();
    const analysis = analyseMtaSts(txt.values);
    if (analysis.problem === null || analysis.problem === 'missing') {
      return { findings: [], checked: [component] };
    }
    const detail =
      analysis.problem === 'multiple'
        ? `${analysis.records.length} v=STSv1 records are published`
        : 'the record has no valid id= value (1–32 letters or digits)';
    return {
      findings: [
        {
          hostname: apex,
          component: 'mta-sts-record',
          title: `MTA-STS record for ${apex} is malformed`,
          description:
            `At ${mtaStsName(apex)} ${detail}. Sending servers ignore an invalid record, so the ` +
            'MTA-STS policy is not applied and inbound mail falls back to opportunistic TLS.',
          severity: 'low',
          confidence: 'high',
          exposure: 'public_record',
          evidence: {
            queriedName: mtaStsName(apex),
            problem: analysis.problem,
            records: analysis.records,
            id: analysis.id,
            observedAt: txt.observedAt,
          },
        },
      ],
      checked: [],
    };
  },
  advisory(finding): Advisory {
    return {
      title: `Fix the MTA-STS record for ${finding.hostname}`,
      summary:
        'The MTA-STS DNS record must be a single TXT record "v=STSv1; id=<1–32 alphanumerics>".',
      businessImpact: 'Until it is valid, senders apply no MTA-STS protection to inbound mail.',
      recommendedActions: [
        `Keep exactly one TXT record at _mta-sts.${finding.hostname} starting with "v=STSv1;".`,
        'Give it an id= of 1–32 letters or digits, e.g. a date stamp such as 20261029T0000; change it whenever the policy file changes.',
        `Verify the policy file at https://mta-sts.${finding.hostname}/.well-known/mta-sts.txt is reachable over HTTPS.`,
      ],
      references: [RFC.mtaSts],
    };
  },
};

// --- TLS-RPT (RFC 8460 §3) ------------------------------------------------------------------

export type TlsRptProblem = 'missing' | 'multiple' | 'invalid_rua';

export function analyseTlsRpt(values: readonly string[]): {
  problem: TlsRptProblem | null;
  records: string[];
} {
  const records = values.map(decodeTxt).filter((t) => /^v=TLSRPTv1\s*(;|$)/.test(t.trim()));
  if (records.length === 0) return { problem: 'missing', records };
  if (records.length > 1) return { problem: 'multiple', records };
  const rua = parseTags(records[0] ?? '').rua ?? '';
  const uris = rua
    .split(',')
    .map((u) => u.trim())
    .filter(Boolean);
  const valid =
    uris.length > 0 && uris.every((u) => /^(mailto:[^\s@]+@[^\s@]+|https:\/\/\S+)$/i.test(u));
  return { problem: valid ? null : 'invalid_rua', records };
}

const tlsRptName = (apex: string) => `_smtp._tls.${apex}`;

export const email003: Rule = {
  id: 'EMAIL-003',
  version: 1,
  category: 'email',
  title: 'No TLS reporting (TLS-RPT) for a mail domain',
  requires: ['dns'],
  requiresChecks: ['dns'],
  defaultSeverity: 'informational',
  defaultConfidence: 'high',
  evidenceRequirements:
    'Successful apex MX lookup listing a real exchanger and a successful TXT lookup at _smtp._tls.<apex>.',
  detection:
    'The domain receives mail but has no usable TLS-RPT record: none beginning with v=TLSRPTv1, more than ' +
    'one, or a record without a valid rua= (mailto: or https: URIs).',
  resolution:
    'Exactly one v=TLSRPTv1 record with a valid rua= is published, or the domain no longer receives mail.',
  evaluate(input) {
    const apex = apexOf(input);
    const component = { hostname: apex, component: 'tls-rpt' };
    const mail = mailState(input.current.dns, apex);
    if (mail === 'unknown') return none();
    if (mail === 'no_mail') return { findings: [], checked: [component] };
    const txt = successfulRecord(input.current.dns, tlsRptName(apex), 'TXT');
    if (!txt) return none();
    const analysis = analyseTlsRpt(txt.values);
    if (analysis.problem === null) return { findings: [], checked: [component] };
    const detail = {
      missing: `No TLS-RPT record is published at ${tlsRptName(apex)}.`,
      multiple: `${analysis.records.length} TLS-RPT records are published at ${tlsRptName(apex)}; senders ignore them.`,
      invalid_rua: `The TLS-RPT record at ${tlsRptName(apex)} has no valid rua= reporting address.`,
    }[analysis.problem];
    return {
      findings: [
        {
          hostname: apex,
          component: 'tls-rpt',
          title: `No TLS reporting (TLS-RPT) for ${apex}`,
          description:
            `${detail} TLS-RPT asks sending servers to report failed TLS deliveries to the domain, which ` +
            'is how MTA-STS or DANE problems (and downgrade attempts) become visible.',
          severity: 'informational',
          confidence: 'high',
          exposure: 'public_record',
          evidence: {
            queriedName: tlsRptName(apex),
            problem: analysis.problem,
            records: analysis.records,
            rcode: txt.evidence.rcode ?? null,
            observedAt: txt.observedAt,
          },
        },
      ],
      checked: [],
    };
  },
  advisory(finding): Advisory {
    return {
      title: `Publish a TLS-RPT record for ${finding.hostname}`,
      summary:
        'TLS-RPT gives the domain daily reports of TLS failures seen by sending mail servers.',
      businessImpact:
        'Without reports, MTA-STS/DANE misconfigurations and TLS downgrade attempts go unnoticed.',
      recommendedActions: [
        `Publish one TXT record at _smtp._tls.${finding.hostname}: "v=TLSRPTv1; rua=mailto:<reporting address>".`,
        'Route the reports to a mailbox or a reporting service that someone reviews.',
      ],
      references: [RFC.tlsRpt, RFC.mtaSts],
    };
  },
};

// --- DKIM (RFC 6376 §3.6.1) -----------------------------------------------------------------

const DKIM_LABEL = '._domainkey.';

/** The selector of a `<selector>._domainkey.<apex>` name, or null. */
export function dkimSelector(hostname: string, apex: string): string | null {
  const name = normaliseName(hostname);
  const suffix = `${DKIM_LABEL}${apex}`;
  if (!name.endsWith(suffix)) return null;
  const selector = name.slice(0, -suffix.length);
  return selector && !selector.includes('.') ? selector : null;
}

export interface DkimKey {
  /** Key type (`k=`, default `rsa`). */
  keyType: string;
  /** True when `p=` is empty (RFC 6376 §3.6.1: the key has been revoked). */
  revoked: boolean;
  /** RSA modulus size in bits; null for other key types or an unparseable key. */
  bits: number | null;
}

/** DKIM key records among TXT values (those with a `p=` tag and, if present, `v=DKIM1`). */
export function dkimKeys(values: readonly string[]): DkimKey[] {
  const keys: DkimKey[] = [];
  for (const raw of values.map(decodeTxt)) {
    const tags = parseTags(raw);
    if (!('p' in tags)) continue;
    if (tags.v !== undefined && tags.v !== 'DKIM1') continue;
    const keyType = (tags.k ?? 'rsa').toLowerCase();
    const p = (tags.p ?? '').replace(/\s+/g, '');
    keys.push({
      keyType,
      revoked: p.length === 0,
      bits: p.length > 0 && keyType === 'rsa' ? rsaModulusBits(p) : null,
    });
  }
  return keys;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** Standard base64 → bytes (padding optional); null when invalid. */
export function base64Bytes(text: string): Uint8Array | null {
  const clean = text.replace(/=+$/, '');
  if (!/^[A-Za-z0-9+/]*$/.test(clean) || clean.length % 4 === 1) return null;
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of clean) {
    buffer = (buffer << 6) | B64.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

interface Der {
  tag: number;
  start: number;
  end: number;
}

function derAt(bytes: Uint8Array, offset: number): Der | null {
  const tag = bytes[offset];
  let lenByte = bytes[offset + 1];
  if (tag === undefined || lenByte === undefined) return null;
  let pos = offset + 2;
  let length = lenByte;
  if (lenByte & 0x80) {
    const n = lenByte & 0x7f;
    if (n === 0 || n > 3) return null;
    length = 0;
    for (let i = 0; i < n; i += 1) {
      lenByte = bytes[pos + i];
      if (lenByte === undefined) return null;
      length = length * 256 + lenByte;
    }
    pos += n;
  }
  if (pos + length > bytes.length) return null;
  return { tag, start: pos, end: pos + length };
}

/**
 * RSA modulus size of a DKIM `p=` value: SubjectPublicKeyInfo (RFC 6376) or, as some signers
 * publish, a bare PKCS#1 RSAPublicKey. Null when the key cannot be parsed.
 */
export function rsaModulusBits(p: string): number | null {
  const bytes = base64Bytes(p);
  if (!bytes) return null;
  let seq = derAt(bytes, 0);
  if (!seq || seq.tag !== 0x30) return null;
  let first = derAt(bytes, seq.start);
  if (!first) return null;
  if (first.tag === 0x30) {
    // SPKI: SEQUENCE { AlgorithmIdentifier, BIT STRING { RSAPublicKey } }
    const bitString = derAt(bytes, first.end);
    if (!bitString || bitString.tag !== 0x03) return null;
    seq = derAt(bytes, bitString.start + 1); // skip the unused-bits byte
    if (!seq || seq.tag !== 0x30) return null;
    first = derAt(bytes, seq.start);
    if (!first) return null;
  }
  if (first.tag !== 0x02) return null; // modulus INTEGER
  let i = first.start;
  while (i < first.end && bytes[i] === 0) i += 1;
  if (i >= first.end) return null;
  const top = bytes[i] ?? 0;
  return (first.end - i - 1) * 8 + (32 - Math.clz32(top));
}

/** DKIM selector observations of the current job (any status), keyed by selector. */
function dkimObservations(records: readonly DnsRecordSetObservation[], apex: string) {
  const out = new Map<string, DnsRecordSetObservation[]>();
  for (const r of records) {
    if (r.recordType !== 'TXT') continue;
    const selector = dkimSelector(r.hostname, apex);
    if (!selector) continue;
    const list = out.get(selector);
    if (list) list.push(r);
    else out.set(selector, [r]);
  }
  return out;
}

export const email004: Rule = {
  id: 'EMAIL-004',
  version: 1,
  category: 'email',
  title: 'No DKIM key found at common selectors',
  requires: ['dns'],
  requiresChecks: ['dns'],
  defaultSeverity: 'informational',
  defaultConfidence: 'low',
  evidenceRequirements:
    'Successful apex MX lookup listing a real exchanger, and successful TXT lookups for every DKIM ' +
    'selector the worker queried (<selector>._domainkey.<apex>, a fixed list of common selectors; ' +
    'CNAME-delegated selectors are followed by the resolver). Any failed selector lookup skips the rule.',
  detection:
    'The domain has MX records but none of the queried common selectors publishes a DKIM key (a TXT ' +
    'record with a non-empty p=). DKIM selectors cannot be enumerated through DNS, so a domain using a ' +
    'custom or dated selector (e.g. Mimecast) is reported here although it signs mail: confidence is low.',
  resolution:
    'A DKIM key is found at one of the queried selectors, or the domain no longer receives mail.',
  evaluate(input) {
    const apex = apexOf(input);
    const component = { hostname: apex, component: 'dkim' };
    const mail = mailState(input.current.dns, apex);
    if (mail === 'unknown') return none();
    if (mail === 'no_mail') return { findings: [], checked: [component] };
    const bySelector = dkimObservations(input.current.dns, apex);
    if (bySelector.size === 0) return none();
    const all = [...bySelector.values()].flat();
    if (all.some((r) => r.resultStatus !== 'success')) return none();
    const found = [...bySelector.entries()]
      .filter(([, obs]) => obs.some((o) => dkimKeys(o.values).some((k) => !k.revoked)))
      .map(([selector]) => selector);
    if (found.length > 0) return { findings: [], checked: [component] };
    const selectors = [...bySelector.keys()].sort();
    return {
      findings: [
        {
          hostname: apex,
          component: 'dkim',
          title: `No DKIM key found for ${apex} at common selectors`,
          description:
            `${apex} receives mail, but none of the ${selectors.length} commonly used DKIM selectors ` +
            'queried publishes a DKIM public key. DKIM selectors cannot be listed through DNS, so the ' +
            'domain may still sign mail with a selector that was not checked; confirm with the mail ' +
            'administrator. Without DKIM, DMARC can only rely on SPF alignment, which breaks on forwarding.',
          severity: 'informational',
          confidence: 'low',
          exposure: 'public_record',
          evidence: { selectorsQueried: selectors, mail, observedAt: all[0]?.observedAt ?? null },
        },
      ],
      checked: [],
    };
  },
  advisory(finding): Advisory {
    return {
      title: `Confirm DKIM signing for ${finding.hostname}`,
      summary:
        'DKIM signs outgoing mail so receivers can verify it was sent by an authorised system and not altered.',
      businessImpact:
        'Unsigned mail is more likely to be rejected or filtered, and DMARC cannot pass for forwarded mail.',
      recommendedActions: [
        'Ask the mail administrator which DKIM selectors are in use; if one exists, no action is needed (accept the finding).',
        'Otherwise enable DKIM signing in each sending service (mail platform, marketing and ticketing tools) and publish the provided keys.',
        'Use RSA keys of at least 2048 bits (or Ed25519 alongside RSA).',
      ],
      references: [RFC.dkim, RFC.dkimKeys, RFC.ncscEmail],
    };
  },
};

export const email005: Rule = {
  id: 'EMAIL-005',
  version: 1,
  category: 'email',
  title: 'Weak or revoked DKIM key',
  requires: ['dns'],
  requiresChecks: ['dns'],
  defaultSeverity: 'medium',
  defaultConfidence: 'high',
  evidenceRequirements:
    'Successful TXT lookup at <selector>._domainkey.<apex> for one of the common selectors the worker queries.',
  detection:
    'A published DKIM RSA key has a modulus shorter than 1024 bits (medium: such keys can be factored ' +
    'and RFC 8301 forbids verifying them), or the key record has an empty p= (informational: the key ' +
    'was revoked; harmless, reported as clean-up). One finding per selector.',
  resolution:
    'The selector publishes an RSA key of at least 1024 bits or a non-RSA key, or no longer publishes a key record.',
  evaluate(input) {
    const apex = apexOf(input);
    const findings: FindingCandidate[] = [];
    const checked: CheckedComponent[] = [];
    const bySelector = dkimObservations(input.current.dns, apex);
    for (const selector of [...bySelector.keys()].sort()) {
      const name = `${selector}${DKIM_LABEL}${apex}`;
      const txt = successfulRecord(input.current.dns, name, 'TXT');
      if (!txt) continue;
      const component = { hostname: apex, component: `dkim:${selector}` };
      const keys = dkimKeys(txt.values);
      if (keys.some((k) => k.keyType === 'rsa' && !k.revoked && k.bits === null)) continue;
      const weak = keys.filter((k) => k.keyType === 'rsa' && k.bits !== null && k.bits < 1024);
      const revoked = keys.length > 0 && keys.every((k) => k.revoked);
      if (weak.length === 0 && !revoked) {
        checked.push(component);
        continue;
      }
      const bits = weak.length > 0 ? Math.min(...weak.map((k) => k.bits ?? 0)) : null;
      findings.push({
        hostname: apex,
        component: `dkim:${selector}`,
        title:
          bits !== null
            ? `Weak ${bits}-bit DKIM key for ${apex} (selector ${selector})`
            : `Revoked DKIM key published for ${apex} (selector ${selector})`,
        description:
          bits !== null
            ? `The DKIM key at ${name} is a ${bits}-bit RSA key. Keys this short can be factored, ` +
              'which would let a third party sign mail as the domain; receivers following RFC 8301 ' +
              'treat such signatures as failed.'
            : `The DKIM record at ${name} has an empty p= tag, meaning the key was revoked. This is ` +
              'harmless but can be removed once no mail signed with it is in transit.',
        severity: bits !== null ? 'medium' : 'informational',
        confidence: 'high',
        exposure: 'public_record',
        evidence: {
          queriedName: name,
          selector,
          keys,
          canonicalName: txt.evidence.canonicalName ?? null,
          observedAt: txt.observedAt,
        },
      });
    }
    return { findings, checked };
  },
  advisory(finding): Advisory {
    const selector = String(finding.evidence.selector ?? '<selector>');
    const weak = finding.severity !== 'informational';
    return {
      title: weak
        ? `Replace the weak DKIM key for ${finding.hostname}`
        : `Remove the revoked DKIM record for ${finding.hostname}`,
      summary: weak
        ? 'DKIM RSA keys shorter than 1024 bits are considered breakable and are not accepted by modern receivers.'
        : 'An empty p= marks a revoked DKIM key; the record is no longer used for verification.',
      businessImpact: weak
        ? 'A factored key lets anyone sign mail that passes DKIM for the domain; meanwhile legitimate mail signed with it fails DKIM.'
        : 'None directly; removing stale records keeps the DNS zone easy to audit.',
      recommendedActions: weak
        ? [
            'Generate a new 2048-bit RSA key pair in the sending service, publish it under a new selector, and switch signing to it.',
            `Then revoke the old key by publishing an empty p= at ${selector}._domainkey.${finding.hostname}, and later remove the record.`,
          ]
        : [
            `Delete the TXT record at ${selector}._domainkey.${finding.hostname} once no mail signed with the old key can still be in transit (a few days).`,
          ],
      references: [RFC.dkim, RFC.dkimKeys],
    };
  },
};

export const emailRules: readonly Rule[] = [email001, email002, email003, email004, email005];
