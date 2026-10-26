import type { Domain, RegistrationSnapshot } from '@exdomainvault/shared';
import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { formatDate, formatDateTime } from '../../lib/format.ts';
import type { AsyncState } from '../../lib/use-async.ts';
import { Card } from '../ui/Card.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';
import { RESULT_NOTES } from './observation-status.ts';

const DAY_MS = 86_400_000;
const EXPIRY_WARNING_DAYS = 30;

const NOT_COLLECTED =
  'Not collected yet. Registration (RDAP) data is gathered by a passive scan; monitoring schedules one daily for monitored domains.';

const DOMAIN_STATUS_TEXT = {
  unknown: NOT_COLLECTED,
  available: null,
  redacted: 'The registry withholds registration details for privacy.',
  unavailable: 'No registration data could be obtained.',
} as const;

const SNAPSHOT_STATUS_TEXT = {
  available: null,
  redacted: DOMAIN_STATUS_TEXT.redacted,
  unavailable: DOMAIN_STATUS_TEXT.unavailable,
} as const;

interface RegistrationFields {
  registrar: string | null;
  registeredAt: string | null;
  expiresAt: string | null;
  nameservers?: string[];
}

/** Registration (RDAP) details: the latest observation, falling back to the domain's own fields. */
export function RegistrationCard({
  domain,
  state,
  now = new Date(),
}: {
  domain: Domain;
  state: AsyncState<{ registration: RegistrationSnapshot | null }>;
  now?: Date;
}) {
  return (
    <Card
      title="Registration"
      collapsible="domain.registration"
      defaultOpen={false}
      summary={registrationSummary(domain, state, now)}
    >
      {state.status === 'loading' && (
        <p className="text-sm text-fg-subtle" role="status">
          Loading registration…
        </p>
      )}
      {state.status === 'error' && (
        <ErrorAlert error={state.error} title="Could not load registration observations" />
      )}
      {state.status === 'success' &&
        (state.data.registration ? (
          <SnapshotView snapshot={state.data.registration} now={now} />
        ) : (
          <DomainFallback domain={domain} now={now} />
        ))}
    </Card>
  );
}

const SUMMARY_STATUS_TEXT = {
  unknown: 'Not collected yet',
  redacted: 'Withheld by the registry',
  unavailable: 'No data obtained',
} as const;

function registrationSummary(
  domain: Domain,
  state: AsyncState<{ registration: RegistrationSnapshot | null }>,
  now: Date,
): string | undefined {
  if (state.status === 'loading') return undefined;
  if (state.status === 'error') return 'Could not load';
  const snapshot = state.data.registration;
  const fields: RegistrationFields = snapshot ?? domain;
  const status = snapshot ? snapshot.dataStatus : domain.registrationDataStatus;
  if (!fields.registrar && !fields.expiresAt) {
    return status === 'available' ? 'No details provided' : SUMMARY_STATUS_TEXT[status];
  }
  const parts: string[] = [];
  if (fields.registrar) parts.push(fields.registrar);
  if (fields.expiresAt) {
    const days = Math.floor((new Date(fields.expiresAt).getTime() - now.getTime()) / DAY_MS);
    const date = formatDate(fields.expiresAt);
    const plural = (n: number) => `${n} day${n === 1 ? '' : 's'}`;
    parts.push(
      days < 0
        ? `expired ${date} (${plural(-days)} ago)`
        : `expires ${date} (${days === 0 ? 'today' : `in ${plural(days)}`})`,
    );
  }
  return parts.join(' · ');
}

function SnapshotView({ snapshot: s, now }: { snapshot: RegistrationSnapshot; now: Date }) {
  const statusText = SNAPSHOT_STATUS_TEXT[s.dataStatus];
  const resultNote = s.resultStatus === 'success' ? null : RESULT_NOTES[s.resultStatus];
  const hasFields = s.registrar !== null || s.registeredAt !== null || s.expiresAt !== null;
  return (
    <div className="space-y-3 text-sm">
      {statusText && <p className="text-fg-muted">{statusText}</p>}
      {resultNote && <p className="text-xs italic text-fg-subtle">RDAP {resultNote}.</p>}
      {(s.dataStatus === 'available' || hasFields) && (
        <RegistrationFieldsList fields={s} now={now} />
      )}
      <p className="text-xs text-fg-subtle">
        Observed{' '}
        <Link to={`/scans/${s.scanJobId}`} className="text-sky-800 hover:underline">
          {formatDateTime(s.observedAt)}
        </Link>
      </p>
    </div>
  );
}

function DomainFallback({ domain, now }: { domain: Domain; now: Date }) {
  const note = DOMAIN_STATUS_TEXT[domain.registrationDataStatus];
  if (note) return <p className="text-sm text-fg-muted">{note}</p>;
  return <RegistrationFieldsList fields={domain} now={now} />;
}

function RegistrationFieldsList({ fields, now }: { fields: RegistrationFields; now: Date }) {
  return (
    <dl className="grid gap-3 text-sm sm:grid-cols-3">
      <Field label="Registrar">{fields.registrar ?? 'Not provided'}</Field>
      <Field label="Registered">
        {fields.registeredAt ? formatDate(fields.registeredAt) : 'Not provided'}
      </Field>
      <Field label="Expires">
        {fields.expiresAt ? <Expiry iso={fields.expiresAt} now={now} /> : 'Not provided'}
      </Field>
      {fields.nameservers && (
        <div className="sm:col-span-3">
          <dt className="text-xs font-medium uppercase tracking-wide text-fg-subtle">
            Nameservers
          </dt>
          <dd className="mt-1">
            {fields.nameservers.length === 0 ? (
              'Not provided'
            ) : (
              <ul className="space-y-0.5 font-mono text-xs text-fg">
                {fields.nameservers.map((ns) => (
                  <li key={ns} className="break-all">
                    {ns}
                  </li>
                ))}
              </ul>
            )}
          </dd>
        </div>
      )}
    </dl>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs font-medium uppercase tracking-wide text-fg-subtle">{label}</dt>
      <dd className="mt-1">{children}</dd>
    </div>
  );
}

/** Expiry date plus days remaining. Neutral (non-severity) emphasis when close or past. */
function Expiry({ iso, now }: { iso: string; now: Date }) {
  const days = Math.floor((new Date(iso).getTime() - now.getTime()) / DAY_MS);
  let text: string;
  let tone = 'text-fg-subtle';
  if (days < 0) {
    const ago = -days;
    text = `expired ${ago} day${ago === 1 ? '' : 's'} ago`;
    tone = 'rounded bg-red-50 px-1.5 py-0.5 font-medium text-red-800';
  } else {
    text = days === 0 ? 'expires today' : `in ${days} day${days === 1 ? '' : 's'}`;
    if (days <= EXPIRY_WARNING_DAYS) {
      tone = 'rounded bg-amber-50 px-1.5 py-0.5 font-medium text-amber-900';
    }
  }
  return (
    <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
      <span>{formatDate(iso)}</span>
      <span className={`text-xs ${tone}`} data-testid="expiry-countdown">
        {text}
      </span>
    </span>
  );
}
