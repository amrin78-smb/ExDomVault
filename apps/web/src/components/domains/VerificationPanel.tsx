import type {
  Domain,
  DomainDetailResponse,
  VerificationChallenge,
  VerifyDomainResponse,
} from '@exdomainvault/shared';
import {
  ATTESTATION_DEFAULT_MONTHS,
  type AuthorisationInput,
  type CreateChallengeResponse,
} from '@exdomainvault/shared';
import { Check, Copy, RefreshCw, ShieldCheck, UserCheck } from 'lucide-react';
import { useState } from 'react';
import { api } from '../../lib/api.ts';
import { addMonthsIso, formatDate, formatDateTime } from '../../lib/format.ts';
import { AuthorisationFields } from './AuthorisationFields.tsx';
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
      <dt className="text-xs font-medium uppercase tracking-wide text-fg-subtle">{label}</dt>
      <dd className="mt-1 flex items-start gap-2">
        <code className="min-w-0 flex-1 break-all rounded bg-surface-3 px-2 py-1 font-mono text-xs text-fg">
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

/** One line for the collapsed card, e.g. "Authorised (admin) · review by 22 Oct 2027". */
function verificationSummary(domain: Domain, challenge: VerificationChallenge | null): string {
  const expires = domain.verificationExpiresAt ? formatDate(domain.verificationExpiresAt) : null;
  switch (domain.verificationStatus) {
    case 'verified':
      return domain.verificationMethod === 'admin_attestation'
        ? `Authorised (admin)${expires ? ` · review by ${expires}` : ''}`
        : `Verified by DNS${expires ? ` · expires ${expires}` : ''}`;
    case 'pending':
      return challenge?.status === 'pending'
        ? `Pending DNS check · value expires ${formatDate(challenge.expiresAt)}`
        : 'Pending';
    case 'revoked':
      return 'Revoked · active scanning not allowed';
    default:
      return challenge?.status === 'expired'
        ? 'Not verified · last attempt expired'
        : 'Not verified';
  }
}

/**
 * Ownership verification: DNS TXT proof, or an administrator authorisation where the DNS cannot be
 * edited. For DNS, the record value is only available in the response that created
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
  const [authorising, setAuthorising] = useState(false);
  const [authInput, setAuthInput] = useState<AuthorisationInput>(() => ({
    reason: '',
    reference: '',
    reviewBy: addMonthsIso(ATTESTATION_DEFAULT_MONTHS),
  }));
  const [revoking, setRevoking] = useState(false);
  const [revokeReason, setRevokeReason] = useState('');

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

  const authorise = () =>
    run(async () => {
      const detail = await api.domains.authorise(domain.id, authInput);
      setIssued(null);
      setResult(null);
      setAuthorising(false);
      return detail;
    });
  const revoke = () =>
    run(async () => {
      const detail = await api.domains.revoke(domain.id, revokeReason);
      setRevoking(false);
      setRevokeReason('');
      return detail;
    });

  if (domain.verificationStatus === 'verified') {
    const attested = domain.verificationMethod === 'admin_attestation';
    return (
      <Card
        title="Ownership verification"
        collapsible="domain.verification"
        defaultOpen={false}
        summary={verificationSummary(domain, challenge)}
      >
        <div className="space-y-3 text-sm">
          <p
            className={`flex items-center gap-2 ${attested ? 'text-sky-800' : 'text-emerald-800'}`}
          >
            {attested ? (
              <UserCheck className="size-4" aria-hidden />
            ) : (
              <ShieldCheck className="size-4" aria-hidden />
            )}
            {attested ? 'Authorised by an administrator' : 'Verified by DNS TXT record'}
            {domain.verifiedAt ? ` on ${formatDateTime(domain.verifiedAt)}` : ''}.
          </p>
          {attested && challenge?.method === 'admin_attestation' && (
            <dl className="grid gap-3 sm:grid-cols-3">
              <div className="sm:col-span-3">
                <dt className="text-xs font-medium uppercase tracking-wide text-fg-subtle">
                  Reason
                </dt>
                <dd className="mt-1 whitespace-pre-line">{challenge.reason}</dd>
              </div>
              <div className="sm:col-span-2">
                <dt className="text-xs font-medium uppercase tracking-wide text-fg-subtle">
                  Reference
                </dt>
                <dd className="mt-1">{challenge.reference ?? '—'}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase tracking-wide text-fg-subtle">
                  Review by
                </dt>
                <dd className="mt-1">
                  {domain.verificationExpiresAt ? formatDate(domain.verificationExpiresAt) : '—'}
                </dd>
              </div>
            </dl>
          )}
          {result?.outcome === 'verified' && (
            <p className="text-fg-muted" role="status">
              {result.message}
            </p>
          )}
          <p className="text-xs text-fg-subtle">
            {attested
              ? 'An administrator has recorded that the organisation owns this domain and authorises active scanning. This is weaker evidence than DNS proof and lapses on the review date unless renewed. '
              : "DNS proof shows control of this domain's zone. "}
            It does not approve subdomains, IP addresses, or hosting, CDN or cloud providers for
            scanning; those need separate approval.
          </p>
          {error && <ErrorAlert error={error} />}
          {canVerify && !revoking && (
            <Button variant="secondary" onClick={() => setRevoking(true)} disabled={busy}>
              Revoke verification
            </Button>
          )}
          {canVerify && revoking && (
            <div
              role="alertdialog"
              aria-label="Confirm revocation"
              className="space-y-2 rounded-md border border-red-200 bg-red-50 p-3"
            >
              <label className="block text-sm font-medium text-fg-2">
                Why is this verification being revoked?
                <textarea
                  className="mt-1 w-full rounded-md border border-line-strong px-2.5 py-1.5 text-sm"
                  rows={2}
                  value={revokeReason}
                  onChange={(e) => setRevokeReason(e.target.value)}
                  maxLength={500}
                />
              </label>
              <p className="text-xs text-red-800">
                Active scanning of this domain will no longer be allowed until it is verified again.
              </p>
              <div className="flex gap-2">
                <Button
                  variant="danger"
                  onClick={revoke}
                  disabled={busy || revokeReason.trim().length < 10}
                >
                  Revoke
                </Button>
                <Button onClick={() => setRevoking(false)} disabled={busy}>
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </div>
      </Card>
    );
  }

  const pending = challenge?.status === 'pending' ? challenge : null;
  const recordName = issued?.record.name ?? pending?.recordName;

  return (
    <Card
      title="Ownership verification"
      collapsible="domain.verification"
      defaultOpen={false}
      summary={verificationSummary(domain, challenge)}
    >
      <div className="space-y-4 text-sm">
        {!pending && !issued && (
          <p className="text-fg-muted">
            {domain.verificationStatus === 'revoked'
              ? 'Verification of this domain was revoked.'
              : challenge?.status === 'expired'
                ? challenge.method === 'admin_attestation'
                  ? 'The administrator authorisation passed its review date.'
                  : 'The last verification value expired before it was confirmed.'
                : 'This domain has not been verified.'}{' '}
            Passive monitoring works without verification. Active scanning needs either a DNS TXT
            record or, where you cannot edit the DNS, an administrator authorisation.
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
                <dt className="text-xs font-medium uppercase tracking-wide text-fg-subtle">Type</dt>
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
                <dt className="text-xs font-medium uppercase tracking-wide text-fg-subtle">
                  TXT record name
                </dt>
                <dd className="mt-1 font-mono text-xs">{recordName}</dd>
              </div>
            )}
            <div>
              <dt className="text-xs font-medium uppercase tracking-wide text-fg-subtle">
                Expires
              </dt>
              <dd className="mt-1">{formatDateTime(pending.expiresAt)}</dd>
            </div>
            <div>
              <dt className="text-xs font-medium uppercase tracking-wide text-fg-subtle">
                Last checked
              </dt>
              <dd className="mt-1">
                {pending.lastCheckedAt ? formatDateTime(pending.lastCheckedAt) : 'Not yet'}
              </dd>
            </div>
            <div>
              <dt className="text-xs font-medium uppercase tracking-wide text-fg-subtle">
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
          <p className="text-xs text-fg-subtle">
            The value was shown when verification started. If you no longer have it, generate a new
            one (the old value stops working).
          </p>
        )}

        {result && result.outcome !== 'verified' && (
          <p role="status" className="rounded-md bg-surface-3 px-3 py-2 text-fg-2">
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
              {pending || issued ? 'Generate new value' : 'Verify with DNS TXT record'}
            </Button>
            {!authorising && (
              <Button onClick={() => setAuthorising(true)} disabled={busy}>
                <UserCheck className="size-4" aria-hidden />
                Authorise without DNS
              </Button>
            )}
          </div>
        )}

        {canVerify && authorising && (
          <form
            aria-label="Authorise without DNS"
            className="space-y-3 rounded-md border border-sky-200 bg-sky-50 p-3"
            onSubmit={(e) => {
              e.preventDefault();
              void authorise();
            }}
          >
            <p className="text-fg-2">
              Use this when the organisation owns the domain but its DNS is managed elsewhere (for
              example by the registrar). Your name, reason and reference are recorded in the audit
              log, and the authorisation lapses on the review date.
            </p>
            <AuthorisationFields value={authInput} onChange={setAuthInput} />
            <div className="flex gap-2">
              <Button
                type="submit"
                variant="primary"
                disabled={busy || authInput.reason.trim().length < 10}
              >
                Authorise {domain.fqdn}
              </Button>
              <Button onClick={() => setAuthorising(false)} disabled={busy}>
                Cancel
              </Button>
            </div>
          </form>
        )}
      </div>
    </Card>
  );
}
