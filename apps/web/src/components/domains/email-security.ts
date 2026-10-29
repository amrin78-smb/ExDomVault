import type { DnsRecordSet } from '@exdomainvault/shared';

/**
 * E-mail security summary computed from the DNS record sets the passive check collects (apex MX/TXT,
 * `_dmarc`, and from Milestone 15 `_mta-sts`, `_smtp._tls`, `default._bimi` and common DKIM
 * selectors). Display only: findings come from the server-side rules, never from this summary.
 */

export type EmailControlState = 'present' | 'missing' | 'not_checked' | 'failed';

export interface EmailControl {
  label: string;
  state: EmailControlState;
  detail: string;
}

/** Joins the character strings of a TXT value in presentation format (`"a" "b"` → `ab`). */
export function txtText(value: string): string {
  const v = value.trim();
  if (!v.startsWith('"')) return v;
  const parts = [...v.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1] ?? '');
  return parts.join('').replace(/\\(["\\])/g, '$1');
}

function latest(records: DnsRecordSet[], hostname: string, type: string) {
  let best: DnsRecordSet | undefined;
  for (const r of records) {
    if (r.hostname !== hostname || r.recordType !== type) continue;
    if (!best || r.observedAt > best.observedAt) best = r;
  }
  return best;
}

/** Looks up a TXT record set and returns the decoded values matching `prefix` (case-sensitive). */
function txtControl(
  records: DnsRecordSet[],
  label: string,
  name: string,
  prefix: RegExp,
  checkedWhen: boolean,
  notCheckedDetail: string,
): EmailControl {
  const set = latest(records, name, 'TXT');
  if (!set) {
    return {
      label,
      state: 'not_checked',
      detail: checkedWhen ? 'Not collected yet' : notCheckedDetail,
    };
  }
  if (set.resultStatus !== 'success') return { label, state: 'failed', detail: 'Lookup failed' };
  const matches = set.values.map(txtText).filter((t) => prefix.test(t));
  if (matches.length === 0) return { label, state: 'missing', detail: `No record at ${name}` };
  return { label, state: 'present', detail: matches.join(' | ') };
}

export function emailSecurity(records: DnsRecordSet[], apex: string): EmailControl[] {
  const mx = latest(records, apex, 'MX');
  const exchangers = (mx?.values ?? []).filter((v) => {
    const parts = v.trim().split(/\s+/);
    return parts.length >= 2 && parts[1] !== '.';
  });
  const receives = mx?.resultStatus === 'success' && exchangers.length > 0;
  const mxControl: EmailControl = !mx
    ? { label: 'Mail exchangers (MX)', state: 'not_checked', detail: 'Not collected yet' }
    : mx.resultStatus !== 'success'
      ? { label: 'Mail exchangers (MX)', state: 'failed', detail: 'Lookup failed' }
      : receives
        ? { label: 'Mail exchangers (MX)', state: 'present', detail: exchangers.join(', ') }
        : {
            label: 'Mail exchangers (MX)',
            state: 'missing',
            detail: mx.values.includes('0 .')
              ? 'Null MX: the domain accepts no mail'
              : 'No MX: the domain does not receive mail',
          };
  const noMail = 'Only checked for domains that receive mail';

  const dkimSets = records.filter(
    (r) => r.recordType === 'TXT' && r.hostname.endsWith(`._domainkey.${apex}`),
  );
  const dkimWithKey = dkimSets
    .filter((r) => r.resultStatus === 'success')
    .filter((r) => r.values.map(txtText).some((t) => /(^|;)\s*p=\s*[A-Za-z0-9+/]/.test(t)))
    .map((r) => r.hostname.slice(0, -`._domainkey.${apex}`.length))
    .sort();
  const dkim: EmailControl =
    dkimSets.length === 0
      ? { label: 'DKIM', state: 'not_checked', detail: 'Not collected yet' }
      : dkimWithKey.length > 0
        ? { label: 'DKIM', state: 'present', detail: `Key at selector ${dkimWithKey.join(', ')}` }
        : dkimSets.some((r) => r.resultStatus !== 'success')
          ? { label: 'DKIM', state: 'failed', detail: 'Some selector lookups failed' }
          : {
              label: 'DKIM',
              state: 'missing',
              detail: `No key at the ${dkimSets.length} common selectors checked (custom selectors cannot be discovered)`,
            };

  return [
    mxControl,
    txtControl(records, 'SPF', apex, /^v=spf1(\s|$)/i, true, ''),
    txtControl(records, 'DMARC', `_dmarc.${apex}`, /^v=DMARC1\s*(;|$)/i, true, ''),
    dkim,
    txtControl(records, 'MTA-STS', `_mta-sts.${apex}`, /^v=STSv1\s*(;|$)/, receives, noMail),
    txtControl(records, 'TLS-RPT', `_smtp._tls.${apex}`, /^v=TLSRPTv1\s*(;|$)/, receives, noMail),
    txtControl(records, 'BIMI', `default._bimi.${apex}`, /^v=BIMI1\s*(;|$)/i, receives, noMail),
  ];
}
