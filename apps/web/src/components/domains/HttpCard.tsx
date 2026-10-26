import type { HttpSnapshot } from '@exdomainvault/shared';
import { Globe } from 'lucide-react';
import { ScheduledScansHint } from '../settings/ScheduledScansHint.tsx';
import type { AsyncState } from '../../lib/use-async.ts';
import { Card } from '../ui/Card.tsx';
import { useShowAll } from '../ui/ShowAllButton.tsx';
import { EmptyState } from '../ui/EmptyState.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';
import { FactBadge, ObservedLink, ResultNote } from './TlsCard.tsx';

/** Security headers the worker records (docs/worker-protocol.md, `http` evidence). */
const SECURITY_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-content-type-options',
  'x-frame-options',
  'referrer-policy',
  'permissions-policy',
] as const;

const DECISION_TEXT: Record<string, string> = {
  followed: 'redirect followed',
  final: 'final response',
};

interface Hop {
  url: string;
  ip: string | null;
  status: number | null;
  decision: string;
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * Header values from evidence. Accepts a nested `securityHeaders`/`headers` object or header names as
 * top-level keys; a header counts as present only when a non-empty string value was recorded.
 */
function headerSource(evidence: Record<string, unknown>): Record<string, unknown> {
  if (isRecord(evidence.securityHeaders)) return evidence.securityHeaders;
  if (isRecord(evidence.headers)) return evidence.headers;
  return evidence;
}

const text = (v: unknown): string | null => (typeof v === 'string' && v !== '' ? v : null);

function hops(evidence: Record<string, unknown>): Hop[] {
  if (!Array.isArray(evidence.hops)) return [];
  return evidence.hops.filter(isRecord).map((h) => ({
    url: text(h.url) ?? '',
    ip: text(h.ip),
    status: typeof h.status === 'number' ? h.status : null,
    decision: text(h.decision) ?? 'unknown',
  }));
}

function httpSummary(state: AsyncState<{ http: HttpSnapshot[] }>): string | undefined {
  if (state.status === 'loading') return undefined;
  if (state.status === 'error') return 'Could not load';
  const n = state.data.http.length;
  if (n === 0) return 'None collected yet';
  const hsts = state.data.http.filter((s) => s.hstsEnabled === true).length;
  return `${n} URL${n === 1 ? '' : 's'} · HSTS on ${hsts}`;
}

/** Latest HTTP response per starting URL, from browser-like requests with validated redirects. */
export function HttpCard({ state }: { state: AsyncState<{ http: HttpSnapshot[] }> }) {
  return (
    <Card
      title="HTTP"
      className="lg:col-span-2"
      collapsible="domain.http"
      defaultOpen={false}
      summary={httpSummary(state)}
    >
      {state.status === 'loading' && (
        <p className="text-sm text-fg-subtle" role="status">
          Loading HTTP observations…
        </p>
      )}
      {state.status === 'error' && (
        <ErrorAlert error={state.error} title="Could not load HTTP observations" />
      )}
      {state.status === 'success' &&
        (state.data.http.length === 0 ? (
          <EmptyState title="No HTTP responses collected yet" icon={Globe}>
            HTTP responses appear here after an active scan of this verified domain. Each request is
            an ordinary page load; every redirect is checked against scope before it is followed.
            <ScheduledScansHint />
          </EmptyState>
        ) : (
          <HttpList items={state.data.http} />
        ))}
    </Card>
  );
}

function HttpList({ items }: { items: HttpSnapshot[] }) {
  const sorted = [...items].sort((a, b) => a.url.localeCompare(b.url));
  const { shown, toggle } = useShowAll(sorted, { limit: 5, noun: 'URLs' });
  return (
    <div className="space-y-6">
      {shown.map((s) => (
        <HttpEntry key={s.url} snapshot={s} />
      ))}
      {toggle}
    </div>
  );
}

function HttpEntry({ snapshot: s }: { snapshot: HttpSnapshot }) {
  const headingId = `http-${s.url}`;
  const source = headerSource(s.evidence);
  const connected = s.statusCode !== null;
  const server = text(source.server) ?? text(s.evidence.server);
  const poweredBy =
    text(s.evidence.xPoweredBy) ??
    text(source['x-powered-by']) ??
    text(s.evidence['x-powered-by']) ??
    text(s.evidence.poweredBy);
  const hopList = hops(s.evidence);

  return (
    <section aria-labelledby={headingId} className="space-y-3 text-sm">
      <h3 id={headingId} className="break-all font-mono text-sm font-semibold text-fg">
        {s.url}
        {s.finalUrl && s.finalUrl !== s.url && (
          <span className="font-normal text-fg-muted"> → {s.finalUrl}</span>
        )}
      </h3>
      <ResultNote status={s.resultStatus} prefix="HTTP" />
      <div className="flex flex-wrap items-center gap-2 text-xs text-fg-muted">
        <span>
          Status <span className="font-mono text-fg">{s.statusCode ?? '—'}</span>
        </span>
        <span>
          {s.redirectCount} redirect{s.redirectCount === 1 ? '' : 's'}
        </span>
        {s.hstsEnabled !== null && (
          <FactBadge ok={s.hstsEnabled}>
            {s.hstsEnabled ? 'HSTS enabled' : 'HSTS missing'}
          </FactBadge>
        )}
        <span>
          First hop <span className="font-mono">{s.ipAddress}</span>
        </span>
      </div>

      {connected && (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs" aria-label={`Security headers of ${s.url}`}>
            <thead className="border-b border-line uppercase tracking-wide text-fg-subtle">
              <tr>
                <th scope="col" className="py-1.5 pr-3 font-medium">
                  Security header
                </th>
                <th scope="col" className="py-1.5 font-medium">
                  Value
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line-soft">
              {SECURITY_HEADERS.map((name) => {
                const value = text(source[name]);
                return (
                  <tr key={name} className="align-top">
                    <th scope="row" className="py-1.5 pr-3 font-mono font-normal text-fg">
                      {name}
                    </th>
                    <td className="py-1.5">
                      {value ? (
                        <span className="break-all font-mono text-fg-2">{value}</span>
                      ) : (
                        <span className="text-fg-subtle">Missing</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {(server || poweredBy) && (
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-fg-subtle">
            Disclosed software (not verified)
          </p>
          <dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-3 text-xs">
            {server && (
              <>
                <dt className="font-mono text-fg-subtle">server</dt>
                <dd className="break-all text-fg">{server}</dd>
              </>
            )}
            {poweredBy && (
              <>
                <dt className="font-mono text-fg-subtle">x-powered-by</dt>
                <dd className="break-all text-fg">{poweredBy}</dd>
              </>
            )}
          </dl>
        </div>
      )}

      {hopList.length > 0 && (
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-fg-subtle">Requests</p>
          <ol aria-label={`Requests for ${s.url}`} className="mt-1 space-y-1 text-xs">
            {hopList.map((h, i) => (
              <li key={`${i}:${h.url}`} className="flex flex-wrap gap-x-2">
                <span className="break-all font-mono text-fg">{h.url}</span>
                {h.ip && <span className="font-mono text-fg-subtle">{h.ip}</span>}
                {h.status !== null && <span className="text-fg-muted">{h.status}</span>}
                <span className="text-fg-muted">
                  {DECISION_TEXT[h.decision] ?? `${h.decision} — not followed`}
                </span>
              </li>
            ))}
          </ol>
        </div>
      )}

      <p className="text-xs text-fg-subtle">
        Observed <ObservedLink at={s.observedAt} scanJobId={s.scanJobId} />
      </p>
    </section>
  );
}
