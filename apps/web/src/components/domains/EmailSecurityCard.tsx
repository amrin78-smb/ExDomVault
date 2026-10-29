import type { DnsRecordSet } from '@exdomainvault/shared';
import { Mail } from 'lucide-react';
import type { AsyncState } from '../../lib/use-async.ts';
import { Card } from '../ui/Card.tsx';
import { EmptyState } from '../ui/EmptyState.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';
import { emailSecurity, type EmailControlState } from './email-security.ts';
import { FactBadge } from './TlsCard.tsx';

/**
 * E-mail security at a glance, computed from the DNS record sets the passive check already collects
 * (apex MX/TXT, `_dmarc`, and from Milestone 15 `_mta-sts`, `_smtp._tls`, `default._bimi` and common
 * DKIM selectors). Display only: findings come from the server-side rules (DNS-003/004/007,
 * EMAIL-001…005), never from this summary.
 */

const STATE_TEXT: Record<EmailControlState, string> = {
  present: 'Published',
  missing: 'Not published',
  not_checked: 'Not checked',
  failed: 'Lookup failed',
};

export function EmailSecurityCard({
  apex,
  state,
}: {
  apex: string;
  state: AsyncState<{ dns: DnsRecordSet[] }>;
}) {
  const controls = state.status === 'success' ? emailSecurity(state.data.dns, apex) : [];
  const published = controls.filter((c) => c.state === 'present').length;
  const summary =
    state.status === 'loading'
      ? undefined
      : state.status === 'error'
        ? 'Could not load'
        : state.data.dns.length === 0
          ? 'None collected yet'
          : `${published} of ${controls.length} published`;
  return (
    <Card title="E-mail security" collapsible="domain.email" defaultOpen={false} summary={summary}>
      {state.status === 'loading' && (
        <p className="text-sm text-fg-subtle" role="status">
          Loading DNS records…
        </p>
      )}
      {state.status === 'error' && (
        <ErrorAlert error={state.error} title="Could not load DNS records" />
      )}
      {state.status === 'success' &&
        (state.data.dns.length === 0 ? (
          <EmptyState title="No DNS records collected yet" icon={Mail}>
            E-mail security records appear here after a passive scan of this domain.
          </EmptyState>
        ) : (
          <div className="space-y-3">
            <dl className="divide-y divide-line-soft text-sm">
              {controls.map((c) => (
                <div key={c.label} className="grid gap-1 py-2 sm:grid-cols-[9rem_1fr]">
                  <dt className="font-medium text-fg">{c.label}</dt>
                  <dd className="min-w-0 space-y-1">
                    <FactBadge
                      ok={c.state === 'present' ? true : c.state === 'missing' ? false : null}
                    >
                      {STATE_TEXT[c.state]}
                    </FactBadge>
                    <p className="break-all font-mono text-xs text-fg-muted">{c.detail}</p>
                  </dd>
                </div>
              ))}
            </dl>
            <p className="text-xs text-fg-subtle">
              From public DNS only: the MTA-STS policy file is not fetched, and DKIM is checked at
              common selector names. Findings about these records are listed in the Findings card.
            </p>
          </div>
        ))}
    </Card>
  );
}
