import type {
  CreateChallengeResponse,
  Domain,
  DomainDetailResponse,
  VerificationChallenge,
  VerifyDomainResponse,
} from '@exdomainvault/shared';
import { Check, Copy, RefreshCw, ShieldCheck } from 'lucide-react';
import { useState } from 'react';
import { api } from '../../lib/api.ts';
import { formatDateTime } from '../../lib/format.ts';
import { usePermission } from '../../lib/session.ts';
import { Button } from '../ui/Button.tsx';
import { Card } from '../ui/Card.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';

const FAILURE_LABELS: Record<string, string> = {
  record_not_found: 'No TXT record found',
  value_mismatch: 'TXT record found, but the value did not match',
  dns_error: 'DNS lookup failed',
  expired: 'Expired',
};

function CopyField({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard unavailable (permissions or insecure context): the value stays selectable.
    }
  };
  return (
    <div>
      <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-1 flex items-start gap-2">
        <code className="min-w-0 flex-1 break-all rounded bg-slate-100 px-2 py-1 font-mono text-xs text-slate-800">
          {value}
        </code>
        <Button onClick={copy} aria-label={`Copy ${label.toLowerCase()}`}>
          {copied ? (
            <Check className="size-4" aria-hidden />
          ) : (
            <Copy className="size-4" aria-hidden />
          )}
        </Button>
      </dd>
    </div>
  );
}

/**
 * DNS TXT ownership verification. The record value is only available in the response that created
 * it (the server keeps a hash), so it is shown once and must be copied then.
 */
export function VerificationPanel({
  domain,
  challenge,
  onChanged,
}: {
  domain: Domain;
  challenge: VerificationChallenge | null;
  onChanged: (detail: DomainDetailResponse) => void;
}) {
  const canVerify = usePermission('domains:verify');
  const [issued, setIssued] = useState<CreateChallengeResponse | null>(null);
  const [result, setResult] = useState<VerifyDomainResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const run = async (action: () => Promise<DomainDetailResponse>) => {
    setBusy(true);
    setError(null);
    try {
      onChanged(await action());
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setBusy(false);
    }
  };

  const start = () =>
    run(async () => {
      setResult(null);
      const created = await api.domains.startVerification(domain.id);
      setIssued(created);
      return {
        domain: { ...domain, verificationStatus: 'pending' as const },
        verification: created.challenge,
      };
    });
  const check = () =>
    run(async () => {
      const r = await api.domains.verify(domain.id);
      setResult(r);
      if (r.outcome === 'verified') setIssued(null);
      return { domain: r.domain, verification: r.verification };
    });

  if (domain.verificationStatus === 'verified') {
    return (
      <Card title="Ownership verification">
        <p className="flex items-center gap-2 text-sm text-emerald-800">
          <ShieldCheck className="size-4" aria-hidden />
          Verified {domain.verifiedAt ? `on ${formatDateTime(domain.verifiedAt)}` : ''} by DNS TXT
          record.
        </p>
        {result?.outcome === 'verified' && (
          <p className="mt-2 text-sm text-slate-600" role="status">
            {result.message} You can remove the TXT record now.
          </p>
        )}
        <p className="mt-3 text-xs text-slate-500">
          Verification proves control of this domain&apos;s DNS. It does not approve subdomains, IP
          addresses, or hosting, CDN or cloud providers for scanning; those need separate approval.
        </p>
      </Card>
    );
  }

  const pending = challenge?.status === 'pending' ? challenge : null;
  const recordName = issued?.record.name ?? pending?.recordName;

  return (
    <Card title="Ownership verification">
      <div className="space-y-4 text-sm">
        {!pending && !issued && (
          <p className="text-slate-600">
            {challenge?.status === 'expired'
              ? 'The last verification value expired before it was confirmed.'
              : 'This domain has not been verified.'}{' '}
            Verify ownership by publishing a DNS TXT record. Monitoring and scanning stay off until
            the domain is verified.
          </p>
        )}

        {issued && (
          <div className="rounded-md border border-amber-200 bg-amber-50 p-3">
            <p className="mb-3 text-amber-900">
              Publish this TXT record in the DNS for{' '}
              <strong className="font-mono">{domain.fqdn}</strong>, then select <em>Check now</em>.{' '}
              <strong>Copy the value now: it is shown only once.</strong>
            </p>
            <dl className="space-y-3">
              <CopyField label="Name" value={issued.record.name} />
              <div>
                <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">Type</dt>
                <dd className="mt-1 font-mono text-xs">TXT</dd>
              </div>
              <CopyField label="Value" value={issued.record.value} />
            </dl>
          </div>
        )}

        {pending && (
          <dl className="grid gap-3 sm:grid-cols-3">
            {!issued && recordName && (
              <div className="sm:col-span-3">
                <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">
                  TXT record name
                </dt>
                <dd className="mt-1 font-mono text-xs">{recordName}</dd>
              </div>
            )}
            <div>
              <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">
                Expires
              </dt>
              <dd className="mt-1">{formatDateTime(pending.expiresAt)}</dd>
            </div>
            <div>
              <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">
                Last checked
              </dt>
              <dd className="mt-1">
                {pending.lastCheckedAt ? formatDateTime(pending.lastCheckedAt) : 'Not yet'}
              </dd>
            </div>
            <div>
              <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">
                Last result
              </dt>
              <dd className="mt-1">
                {pending.failureReason
                  ? (FAILURE_LABELS[pending.failureReason] ?? pending.failureReason)
                  : '—'}
              </dd>
            </div>
          </dl>
        )}

        {pending && !issued && canVerify && (
          <p className="text-xs text-slate-500">
            The value was shown when verification started. If you no longer have it, generate a new
            one (the old value stops working).
          </p>
        )}

        {result && result.outcome !== 'verified' && (
          <p role="status" className="rounded-md bg-slate-100 px-3 py-2 text-slate-700">
            {result.message}
          </p>
        )}
        {error && <ErrorAlert error={error} />}

        {canVerify && (
          <div className="flex flex-wrap gap-2">
            {(pending || issued) && (
              <Button variant="primary" onClick={check} disabled={busy}>
                <RefreshCw className="size-4" aria-hidden />
                Check now
              </Button>
            )}
            <Button
              variant={pending || issued ? 'secondary' : 'primary'}
              onClick={start}
              disabled={busy}
            >
              {pending || issued ? 'Generate new value' : 'Start verification'}
            </Button>
          </div>
        )}
      </div>
    </Card>
  );
}
