import type { ObservationResult, TlsSnapshot } from '@exdomainvault/shared';
import { Check, Lock, X } from 'lucide-react';
import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { formatDate, formatDateTime } from '../../lib/format.ts';
import type { AsyncState } from '../../lib/use-async.ts';
import { Card } from '../ui/Card.tsx';
import { EmptyState } from '../ui/EmptyState.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';

const DAY_MS = 86_400_000;
const EXPIRY_WARNING_DAYS = 30;

/** Plain-language outcome of an active check that did not fully succeed. */
const ACTIVE_RESULT_NOTES: Record<Exclude<ObservationResult, 'success'>, string> = {
  partial: 'partial result',
  error: 'check failed',
  timeout: 'check timed out',
  skipped: 'not checked',
};

/** Outcome of a check that did not fully succeed, e.g. "TLS check timed out."; nothing on success. */
export function ResultNote({ status, prefix }: { status: ObservationResult; prefix?: string }) {
  if (status === 'success') return null;
  const note = ACTIVE_RESULT_NOTES[status];
  return (
    <span className="block text-xs italic text-slate-500">
      {prefix ? `${prefix} ${note}.` : note}
    </span>
  );
}

/** Neutral (non-severity) yes/no badge for a property of an observation. */
export function FactBadge({ ok, children }: { ok: boolean | null; children: ReactNode }) {
  const Icon = ok ? Check : X;
  return (
    <span className="inline-flex items-center gap-1 rounded border border-slate-300 bg-slate-50 px-1.5 py-0.5 text-xs font-medium text-slate-700">
      {ok !== null && <Icon className="size-3" aria-hidden />}
      {children}
    </span>
  );
}

export function ObservedLink({ at, scanJobId }: { at: string; scanJobId: string }) {
  return (
    <Link to={`/scans/${scanJobId}`} className="text-sky-800 hover:underline">
      {formatDateTime(at)}
    </Link>
  );
}

function sortByHostname(items: TlsSnapshot[]): TlsSnapshot[] {
  return [...items].sort(
    (a, b) =>
      a.hostname.localeCompare(b.hostname) ||
      a.ipAddress.localeCompare(b.ipAddress) ||
      a.port - b.port,
  );
}

/** Latest TLS certificate per (hostname, address, port) from browser-like handshakes. */
export function TlsCard({
  state,
  now = new Date(),
}: {
  state: AsyncState<{ tls: TlsSnapshot[] }>;
  now?: Date;
}) {
  return (
    <Card title="TLS certificates" className="lg:col-span-2">
      {state.status === 'loading' && (
        <p className="text-sm text-slate-500" role="status">
          Loading certificates…
        </p>
      )}
      {state.status === 'error' && (
        <ErrorAlert error={state.error} title="Could not load TLS observations" />
      )}
      {state.status === 'success' &&
        (state.data.tls.length === 0 ? (
          <EmptyState title="No certificates collected yet" icon={Lock}>
            Certificates appear here after an active scan of this verified domain. The scan makes
            one TLS handshake per address, as a browser would.
          </EmptyState>
        ) : (
          <div className="space-y-5">
            {sortByHostname(state.data.tls).map((s) => (
              <TlsEntry key={`${s.hostname}|${s.ipAddress}|${s.port}`} snapshot={s} now={now} />
            ))}
          </div>
        ))}
    </Card>
  );
}

function TlsEntry({ snapshot: s, now }: { snapshot: TlsSnapshot; now: Date }) {
  const headingId = `tls-${s.hostname}-${s.ipAddress}-${s.port}`;
  const trusted = typeof s.evidence.trusted === 'boolean' ? s.evidence.trusted : null;
  const verifyError = typeof s.evidence.verifyError === 'string' ? s.evidence.verifyError : null;
  const hasCert = s.notAfter !== null || s.subject !== null || s.fingerprintSha256 !== null;

  return (
    <section aria-labelledby={headingId} className="space-y-2 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <h3 id={headingId} className="break-all font-mono text-sm font-semibold text-slate-800">
          {s.hostname}
          {s.port !== 443 ? `:${s.port}` : ''}
        </h3>
        {s.hostnameMatches !== null && (
          <FactBadge ok={s.hostnameMatches}>
            {s.hostnameMatches ? 'Hostname matches' : 'Hostname mismatch'}
          </FactBadge>
        )}
        {trusted !== null && (
          <FactBadge ok={trusted}>{trusted ? 'Trusted chain' : 'Not trusted'}</FactBadge>
        )}
      </div>
      <ResultNote status={s.resultStatus} prefix="TLS" />
      {verifyError && (
        <p className="text-xs text-slate-600">
          Verification error: <span className="font-mono">{verifyError}</span>
        </p>
      )}
      {hasCert && (
        <dl className="grid gap-3 sm:grid-cols-2">
          <Field label="Subject">{s.subject ?? 'Not provided'}</Field>
          <Field label="Issuer">{s.issuer ?? 'Not provided'}</Field>
          <Field label="Valid from">{s.notBefore ? formatDate(s.notBefore) : '—'}</Field>
          <Field label="Valid to">
            {s.notAfter ? <CertExpiry iso={s.notAfter} now={now} /> : '—'}
          </Field>
          <Field label="Protocol">{s.protocolVersion ?? '—'}</Field>
          <Field label="Connected to">
            <span className="font-mono text-xs">{s.ipAddress}</span>
          </Field>
          {s.fingerprintSha256 && (
            <div className="sm:col-span-2">
              <Field label="SHA-256 fingerprint">
                <span className="break-all font-mono text-xs">{s.fingerprintSha256}</span>
              </Field>
            </div>
          )}
          {s.subjectAltNames.length > 0 && (
            <div className="sm:col-span-2">
              <details>
                <summary className="cursor-pointer text-xs font-medium text-slate-600">
                  {s.subjectAltNames.length} subject alternative name
                  {s.subjectAltNames.length === 1 ? '' : 's'}
                </summary>
                <ul className="mt-1 space-y-0.5 font-mono text-xs text-slate-800">
                  {s.subjectAltNames.map((n) => (
                    <li key={n} className="break-all">
                      {n}
                    </li>
                  ))}
                </ul>
              </details>
            </div>
          )}
        </dl>
      )}
      <p className="text-xs text-slate-500">
        Observed <ObservedLink at={s.observedAt} scanJobId={s.scanJobId} />
      </p>
    </section>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-1 break-words">{children}</dd>
    </div>
  );
}

/** Certificate expiry plus days left: amber within 30 days, red once expired. */
function CertExpiry({ iso, now }: { iso: string; now: Date }) {
  const days = Math.floor((new Date(iso).getTime() - now.getTime()) / DAY_MS);
  let text: string;
  let tone = 'text-slate-500';
  if (days < 0) {
    const ago = -days;
    text = `expired ${ago} day${ago === 1 ? '' : 's'} ago`;
    tone = 'rounded bg-red-50 px-1.5 py-0.5 font-medium text-red-800';
  } else {
    text = days === 0 ? 'expires today' : `${days} day${days === 1 ? '' : 's'} left`;
    if (days <= EXPIRY_WARNING_DAYS) {
      tone = 'rounded bg-amber-50 px-1.5 py-0.5 font-medium text-amber-900';
    }
  }
  return (
    <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
      <span>{formatDate(iso)}</span>
      <span className={`text-xs ${tone}`} data-testid="cert-expiry">
        {text}
      </span>
    </span>
  );
}
