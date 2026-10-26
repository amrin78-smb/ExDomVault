import { DNS_RECORD_TYPES, type DnsRecordSet } from '@exdomainvault/shared';
import { Network } from 'lucide-react';
import { Link } from 'react-router';
import { formatDateTime } from '../../lib/format.ts';
import type { AsyncState } from '../../lib/use-async.ts';
import { Card } from '../ui/Card.tsx';
import { useShowAll } from '../ui/ShowAllButton.tsx';
import { EmptyState } from '../ui/EmptyState.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';
import { RESULT_NOTES } from './observation-status.ts';

const TYPE_ORDER = new Map<string, number>(DNS_RECORD_TYPES.map((t, i) => [t, i]));

/** Groups record sets by hostname: the domain apex first, then other names alphabetically. */
function groupByHostname(
  records: DnsRecordSet[],
  apex: string,
): { hostname: string; records: DnsRecordSet[] }[] {
  const groups = new Map<string, DnsRecordSet[]>();
  for (const r of records) {
    const list = groups.get(r.hostname);
    if (list) list.push(r);
    else groups.set(r.hostname, [r]);
  }
  const apexName = apex.toLowerCase();
  return [...groups.entries()]
    .sort(([a], [b]) => {
      if (a === apexName) return -1;
      if (b === apexName) return 1;
      return a.localeCompare(b);
    })
    .map(([hostname, list]) => ({
      hostname,
      records: [...list].sort(
        (a, b) => (TYPE_ORDER.get(a.recordType) ?? 99) - (TYPE_ORDER.get(b.recordType) ?? 99),
      ),
    }));
}

function latest(records: DnsRecordSet[]): DnsRecordSet | undefined {
  return records.reduce<DnsRecordSet | undefined>(
    (best, r) => (!best || r.observedAt > best.observedAt ? r : best),
    undefined,
  );
}

/** Latest DNS record set per (hostname, type) as reported by scans. Evidence only. */
export function DnsRecordsCard({
  apex,
  state,
}: {
  apex: string;
  state: AsyncState<{ dns: DnsRecordSet[] }>;
}) {
  return (
    <Card
      title="DNS records"
      className="lg:col-span-2"
      collapsible="domain.dns"
      defaultOpen={false}
      summary={dnsSummary(state)}
    >
      {state.status === 'loading' && (
        <p className="text-sm text-fg-subtle" role="status">
          Loading DNS records…
        </p>
      )}
      {state.status === 'error' && (
        <ErrorAlert error={state.error} title="Could not load DNS records" />
      )}
      {state.status === 'success' && <DnsRecords apex={apex} records={state.data.dns} />}
    </Card>
  );
}

function dnsSummary(state: AsyncState<{ dns: DnsRecordSet[] }>): string | undefined {
  if (state.status === 'loading') return undefined;
  if (state.status === 'error') return 'Could not load';
  const n = state.data.dns.length;
  if (n === 0) return 'None collected yet';
  const names = new Set(state.data.dns.map((r) => r.hostname)).size;
  return `${n} record set${n === 1 ? '' : 's'} on ${names} name${names === 1 ? '' : 's'}`;
}

function DnsRecords({ apex, records }: { apex: string; records: DnsRecordSet[] }) {
  const groups = groupByHostname(records, apex);
  const { shown, toggle } = useShowAll(groups, { limit: 5, noun: 'hostnames' });
  if (records.length === 0) {
    return (
      <EmptyState title="No DNS records collected yet" icon={Network}>
        DNS records appear here after a passive scan of this domain. Use the Scans card to request
        one.
      </EmptyState>
    );
  }
  const newest = latest(records);

  return (
    <div className="space-y-5">
      {newest && (
        <p className="text-xs text-fg-subtle">
          Most recent observation{' '}
          <Link to={`/scans/${newest.scanJobId}`} className="text-sky-800 hover:underline">
            {formatDateTime(newest.observedAt)}
          </Link>
        </p>
      )}
      {shown.map((g) => {
        const headingId = `dns-${g.hostname}`;
        return (
          <section key={g.hostname} aria-labelledby={headingId}>
            <h3 id={headingId} className="mb-2 break-all font-mono text-sm font-semibold text-fg">
              {g.hostname}
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm" aria-labelledby={headingId}>
                <thead className="border-b border-line text-xs uppercase tracking-wide text-fg-subtle">
                  <tr>
                    <th scope="col" className="w-20 py-2 pr-3 font-medium">
                      Type
                    </th>
                    <th scope="col" className="py-2 pr-3 font-medium">
                      Values
                    </th>
                    <th scope="col" className="w-20 py-2 pr-3 font-medium">
                      TTL
                    </th>
                    <th scope="col" className="w-48 py-2 font-medium">
                      Observed
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line-soft">
                  {g.records.map((r) => (
                    <DnsRow key={r.recordType} record={r} />
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        );
      })}
      {toggle}
    </div>
  );
}

function DnsRow({ record: r }: { record: DnsRecordSet }) {
  const note = r.resultStatus === 'success' ? null : RESULT_NOTES[r.resultStatus];
  return (
    <tr className="align-top">
      <th scope="row" className="py-2 pr-3 font-mono font-medium text-fg">
        {r.recordType}
      </th>
      <td className="py-2 pr-3">
        {r.values.length > 0 && (
          <ul className="space-y-0.5 font-mono text-xs text-fg">
            {r.values.map((v, i) => (
              <li key={`${i}:${v}`} className="break-all whitespace-pre-wrap">
                {v}
              </li>
            ))}
          </ul>
        )}
        {r.values.length === 0 && !note && <span className="text-fg-subtle">No records</span>}
        {note && <p className="text-xs italic text-fg-subtle">{note}</p>}
      </td>
      <td className="py-2 pr-3 tabular-nums text-fg-2">{r.ttl ?? '—'}</td>
      <td className="py-2 text-xs text-fg-muted">
        <Link to={`/scans/${r.scanJobId}`} className="hover:underline">
          {formatDateTime(r.observedAt)}
        </Link>
      </td>
    </tr>
  );
}
