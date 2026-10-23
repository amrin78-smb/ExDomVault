import type { DomainDetailResponse } from '@exdomainvault/shared';
import { AlertTriangle, ArrowLeft } from 'lucide-react';
import { useState } from 'react';
import { Link, useParams } from 'react-router';
import { DomainAssetsCard } from '../../components/assets/DomainAssetsCard.tsx';
import { DnsRecordsCard } from '../../components/domains/DnsRecordsCard.tsx';
import { CriticalityLabel, VerificationBadge } from '../../components/domains/DomainBadges.tsx';
import { DomainScansCard } from '../../components/domains/DomainScansCard.tsx';
import { DomainSettingsCard } from '../../components/domains/DomainSettingsCard.tsx';
import { HttpCard } from '../../components/domains/HttpCard.tsx';
import { PortsCard } from '../../components/domains/PortsCard.tsx';
import { RegistrationCard } from '../../components/domains/RegistrationCard.tsx';
import { TlsCard } from '../../components/domains/TlsCard.tsx';
import { VerificationPanel } from '../../components/domains/VerificationPanel.tsx';
import { DomainFindingsCard } from '../../components/findings/DomainFindingsCard.tsx';
import { DomainSoftwareCard } from '../../components/software/DomainSoftwareCard.tsx';
import { ErrorAlert } from '../../components/ui/ErrorAlert.tsx';
import { api } from '../../lib/api.ts';
import { formatDate } from '../../lib/format.ts';
import { useAsync } from '../../lib/use-async.ts';

export function DomainDetailPage() {
  const { id = '' } = useParams();
  const state = useAsync((signal) => api.domains.get(id, { signal }), [id]);
  // Loaded independently so a failure here never hides the rest of the domain page.
  const observations = useAsync((signal) => api.domains.observations(id, { signal }), [id]);
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

        <RegistrationCard domain={domain} state={observations} />

        <DomainScansCard domain={domain} />

        <DomainFindingsCard domain={domain} />

        <DnsRecordsCard apex={domain.fqdn} state={observations} />

        <TlsCard state={observations} />

        <HttpCard state={observations} />

        <PortsCard state={observations} />

        <DomainSoftwareCard domain={domain} />

        <DomainAssetsCard domain={domain} />
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
