import type { PortSnapshot } from '@exdomainvault/shared';
import { Server } from 'lucide-react';
import type { AsyncState } from '../../lib/use-async.ts';
import { Card } from '../ui/Card.tsx';
import { EmptyState } from '../ui/EmptyState.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';
import { ObservedLink, ResultNote } from './TlsCard.tsx';

const EXPLANATION =
  'Ports are probed only on addresses inside networks an administrator has approved in Settings. Addresses at hosting, CDN or cloud providers are never probed.';

function groupByIp(ports: PortSnapshot[]): { ip: string; ports: PortSnapshot[] }[] {
  const groups = new Map<string, PortSnapshot[]>();
  for (const p of ports) {
    const list = groups.get(p.ipAddress);
    if (list) list.push(p);
    else groups.set(p.ipAddress, [p]);
  }
  return [...groups.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([ip, list]) => ({ ip, ports: [...list].sort((a, b) => a.port - b.port) }));
}

const str = (v: unknown) => (typeof v === 'string' && v !== '' ? v : null);

function portsSummary(state: AsyncState<{ ports: PortSnapshot[] }>): string | undefined {
  if (state.status === 'loading') return undefined;
  if (state.status === 'error') return 'Could not load';
  if (state.data.ports.length === 0) return 'None probed';
  const open = state.data.ports.filter((p) => p.state === 'open');
  const ips = new Set(open.map((p) => p.ipAddress)).size;
  if (open.length === 0) {
    const n = state.data.ports.length;
    return `${n} probed, none open`;
  }
  return `${open.length} open on ${ips} address${ips === 1 ? '' : 'es'}`;
}

/** Latest state per (address, port) from probes of approved networks. */
export function PortsCard({ state }: { state: AsyncState<{ ports: PortSnapshot[] }> }) {
  return (
    <Card
      title="Ports"
      collapsible="domain.ports"
      defaultOpen={false}
      summary={portsSummary(state)}
    >
      {state.status === 'loading' && (
        <p className="text-sm text-fg-subtle" role="status">
          Loading ports…
        </p>
      )}
      {state.status === 'error' && (
        <ErrorAlert error={state.error} title="Could not load port observations" />
      )}
      {state.status === 'success' &&
        (state.data.ports.length === 0 ? (
          <EmptyState title="No ports probed" icon={Server}>
            {EXPLANATION}
          </EmptyState>
        ) : (
          <div className="space-y-4 text-sm">
            <p className="text-xs text-fg-subtle">{EXPLANATION}</p>
            {groupByIp(state.data.ports).map((g) => {
              const headingId = `ports-${g.ip}`;
              return (
                <section key={g.ip} aria-labelledby={headingId}>
                  <h3
                    id={headingId}
                    className="mb-1 break-all font-mono text-sm font-semibold text-fg"
                  >
                    {g.ip}
                  </h3>
                  <table className="w-full text-left text-xs" aria-labelledby={headingId}>
                    <thead className="border-b border-line uppercase tracking-wide text-fg-subtle">
                      <tr>
                        <th scope="col" className="w-20 py-1.5 pr-3 font-medium">
                          Port
                        </th>
                        <th scope="col" className="w-20 py-1.5 pr-3 font-medium">
                          State
                        </th>
                        <th scope="col" className="py-1.5 pr-3 font-medium">
                          Service
                        </th>
                        <th scope="col" className="py-1.5 font-medium">
                          Observed
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line-soft">
                      {g.ports.map((p) => (
                        <PortRow key={p.port} port={p} />
                      ))}
                    </tbody>
                  </table>
                </section>
              );
            })}
          </div>
        ))}
    </Card>
  );
}

function PortRow({ port: p }: { port: PortSnapshot }) {
  const product = [str(p.evidence.product), str(p.evidence.version)].filter(Boolean).join(' ');
  return (
    <tr className="align-top">
      <th scope="row" className="py-1.5 pr-3 font-mono font-medium text-fg">
        {p.port}/{p.protocol}
      </th>
      <td className="py-1.5 pr-3 text-fg-2">{p.state}</td>
      <td className="py-1.5 pr-3 text-fg-2">
        {p.service ?? '—'}
        {product && <span className="block text-fg-subtle">{product} (not verified)</span>}
        <ResultNote status={p.resultStatus} />
      </td>
      <td className="py-1.5 text-fg-muted">
        <ObservedLink at={p.observedAt} scanJobId={p.scanJobId} />
      </td>
    </tr>
  );
}
