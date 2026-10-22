import type { DomainDetailResponse } from '@exdomainvault/shared';
import { AlertTriangle, ArrowLeft, Construction } from 'lucide-react';
import { useState } from 'react';
import { Link, useParams } from 'react-router';
import { CriticalityLabel, VerificationBadge } from '../../components/domains/DomainBadges.tsx';
import { DomainScansCard } from '../../components/domains/DomainScansCard.tsx';
import { DomainSettingsCard } from '../../components/domains/DomainSettingsCard.tsx';
import { VerificationPanel } from '../../components/domains/VerificationPanel.tsx';
import { Card } from '../../components/ui/Card.tsx';
import { EmptyState } from '../../components/ui/EmptyState.tsx';
import { ErrorAlert } from '../../components/ui/ErrorAlert.tsx';
import { api } from '../../lib/api.ts';
import { formatDate, formatDateTime } from '../../lib/format.ts';
import { useAsync } from '../../lib/use-async.ts';

const REGISTRATION_STATUS_TEXT = {
  unknown: 'Not collected yet. Registration (RDAP) data is gathered once monitoring runs.',
  available: null,
  redacted: 'The registry redacts this registration data for privacy.',
  unavailable: 'The registry did not provide registration data.',
} as const;

export function DomainDetailPage() {
  const { id = '' } = useParams();
  const state = useAsync((signal) => api.domains.get(id, { signal }), [id]);
  // Results of changes made on this page, applied without refetching so one-time values survive.
  const [override, setOverride] = useState<{ id: string; detail: DomainDetailResponse } | null>(
    null,
  );

  if (state.status === 'loading') {
    return (
      <p className="py-8 text-center text-sm text-slate-500" role="status">
        Loading domain…
      </p>
    );
  }
  if (state.status === 'error') {
    return (
      <>
        <BackLink />
        <ErrorAlert error={state.error} title="Could not load this domain" />
      </>
    );
  }

  const detail = override?.id === id ? override.detail : state.data;
  const { domain, verification } = detail;
  const apply = (next: DomainDetailResponse) => setOverride({ id, detail: next });
  const registrationNote = REGISTRATION_STATUS_TEXT[domain.registrationDataStatus];

  return (
    <>
      <BackLink />
      <div className="mb-6">
        <h1 className="break-all font-mono text-xl font-semibold tracking-tight text-slate-900">
          {domain.fqdn}
        </h1>
        {domain.unicodeFqdn !== domain.fqdn && (
          <p className="mt-1 text-sm text-slate-600">
            Displayed as <span className="font-medium">{domain.unicodeFqdn}</span>
          </p>
        )}
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <VerificationBadge
            status={domain.verificationStatus}
            method={domain.verificationMethod}
          />
          <CriticalityLabel criticality={domain.criticality} />
          <span className="text-xs text-slate-500">Added {formatDate(domain.createdAt)}</span>
        </div>
        {domain.warnings.includes('mixed_script') && (
          <div
            role="note"
            className="mt-3 flex gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900"
          >
            <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden />
            This name mixes writing systems (for example Latin and Cyrillic), a technique used in
            look-alike domains. Confirm the A-label above is the domain you intend to monitor.
          </div>
        )}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <VerificationPanel domain={domain} challenge={verification} onChanged={apply} />
        <DomainSettingsCard
          key={domain.updatedAt}
          domain={domain}
          onSaved={(d) => apply({ domain: d, verification })}
        />

        <Card title="Registration">
          {registrationNote ? (
            <p className="text-sm text-slate-600">{registrationNote}</p>
          ) : (
            <dl className="grid gap-3 text-sm sm:grid-cols-3">
              <div>
                <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">
                  Registrar
                </dt>
                <dd className="mt-1">{domain.registrar ?? 'Not provided'}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">
                  Registered
                </dt>
                <dd className="mt-1">
                  {domain.registeredAt ? formatDate(domain.registeredAt) : 'Not provided'}
                </dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">
                  Expires
                </dt>
                <dd className="mt-1">
                  {domain.expiresAt ? formatDateTime(domain.expiresAt) : 'Not provided'}
                </dd>
              </div>
            </dl>
          )}
        </Card>

        <DomainScansCard domain={domain} />

        <Card title="DNS, certificates, assets and findings">
          <EmptyState title="Nothing collected yet" icon={Construction}>
            DNS records, nameservers, certificate status, discovered assets and findings appear here
            once the scanning worker reports results (Milestones 5–9).
          </EmptyState>
        </Card>
      </div>
    </>
  );
}

function BackLink() {
  return (
    <Link
      to="/domains"
      className="mb-4 inline-flex items-center gap-1 text-sm text-slate-600 hover:text-slate-900"
    >
      <ArrowLeft className="size-4" aria-hidden />
      Domains
    </Link>
  );
}
