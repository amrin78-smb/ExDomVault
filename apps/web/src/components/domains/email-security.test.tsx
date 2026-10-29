import type { DnsRecordSet } from '@exdomainvault/shared';
import { render, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { openDomainCards } from '../../testing/domain-cards.ts';
import { DnsRecordsCard } from './DnsRecordsCard.tsx';
import { EmailSecurityCard } from './EmailSecurityCard.tsx';
import { emailSecurity, txtText } from './email-security.ts';
import { MemoryRouter } from 'react-router';

const APEX = 'example.com';
const JOB = '7d1f8c2e-3b4a-4c5d-9e6f-0a1b2c3d4e5f';

const rec = (
  hostname: string,
  recordType: DnsRecordSet['recordType'],
  values: string[],
  resultStatus: DnsRecordSet['resultStatus'] = 'success',
): DnsRecordSet => ({
  hostname,
  recordType,
  ttl: values.length ? 300 : null,
  values,
  resultStatus,
  observedAt: '2026-10-29T09:00:00.000Z',
  scanJobId: JOB,
});

const byLabel = (records: DnsRecordSet[]) =>
  Object.fromEntries(emailSecurity(records, APEX).map((c) => [c.label, c]));

describe('emailSecurity', () => {
  it('summarises a well-configured mail domain', () => {
    const c = byLabel([
      rec(APEX, 'MX', ['10 mx1.example.com.']),
      rec(APEX, 'TXT', ['"v=spf1 include:_spf.example.net -all"']),
      rec(`_dmarc.${APEX}`, 'TXT', ['"v=DMARC1; p=reject"']),
      rec(`selector1._domainkey.${APEX}`, 'TXT', ['"v=DKIM1; k=rsa; p=MIIBIjAN" "BgkqhkiG"']),
      rec(`google._domainkey.${APEX}`, 'TXT', []),
      rec(`_mta-sts.${APEX}`, 'TXT', ['"v=STSv1; id=2026"']),
      rec(`_smtp._tls.${APEX}`, 'TXT', ['"v=TLSRPTv1; rua=mailto:tls@example.com"']),
      rec(`default._bimi.${APEX}`, 'TXT', []),
    ]);
    expect(c['Mail exchangers (MX)']).toMatchObject({ state: 'present' });
    expect(c['DKIM']).toMatchObject({ state: 'present', detail: 'Key at selector selector1' });
    expect(c['MTA-STS']).toMatchObject({ state: 'present', detail: 'v=STSv1; id=2026' });
    expect(c['TLS-RPT']?.state).toBe('present');
    expect(c['BIMI']?.state).toBe('missing');
  });

  it('marks receiving-side controls as not checked for a null-MX domain', () => {
    const c = byLabel([
      rec(APEX, 'MX', ['0 .']),
      rec(`s1._domainkey.${APEX}`, 'TXT', []),
      rec(`s2._domainkey.${APEX}`, 'TXT', [], 'timeout'),
    ]);
    expect(c['Mail exchangers (MX)']).toMatchObject({ state: 'missing' });
    expect(c['Mail exchangers (MX)']?.detail).toMatch(/Null MX/);
    expect(c['MTA-STS']).toMatchObject({ state: 'not_checked' });
    expect(c['MTA-STS']?.detail).toMatch(/receive mail/);
    expect(c['DKIM']?.state).toBe('failed');
  });

  it('decodes TXT presentation format', () => {
    expect(txtText('"v=spf1 " "-all"')).toBe('v=spf1 -all');
    expect(txtText('"a\\"b"')).toBe('a"b');
    expect(txtText('plain')).toBe('plain');
  });
});

describe('cards', () => {
  beforeEach(openDomainCards);

  it('renders the e-mail security card', () => {
    render(
      <EmailSecurityCard
        apex={APEX}
        state={{
          status: 'success',
          data: {
            dns: [rec(APEX, 'MX', ['10 mx1.example.com.']), rec(`_mta-sts.${APEX}`, 'TXT', [])],
          },
        }}
      />,
    );
    expect(screen.getByText('E-mail security')).toBeInTheDocument();
    const list = screen.getByText('MTA-STS').closest('div') as HTMLElement;
    expect(within(list).getByText('Not published')).toBeInTheDocument();
    expect(screen.getByText(/MTA-STS policy file is not fetched/)).toBeInTheDocument();
  });

  it('hides empty DKIM selector probes from the DNS records card', () => {
    render(
      <MemoryRouter>
        <DnsRecordsCard
          apex={APEX}
          state={{
            status: 'success',
            data: {
              dns: [
                rec(APEX, 'A', ['192.0.2.1']),
                rec(`google._domainkey.${APEX}`, 'TXT', []),
                rec(`s1._domainkey.${APEX}`, 'TXT', ['"v=DKIM1; p=MIGf"']),
              ],
            },
          }}
        />
      </MemoryRouter>,
    );
    expect(screen.queryByText(`google._domainkey.${APEX}`)).not.toBeInTheDocument();
    expect(screen.getByText(`s1._domainkey.${APEX}`)).toBeInTheDocument();
  });
});
