import type { PortItem, PortsResponse } from '@exdomainvault/shared';
import { DoorOpen, ShieldX } from 'lucide-react';
import { Link } from 'react-router';
import { CountryFlag } from '../../components/inventory/CountryFlag.tsx';
import {
  DomainFilter,
  SearchForm,
  SelectFilter,
  inputClass,
} from '../../components/inventory/FilterControls.tsx';
import { HostnameChips } from '../../components/inventory/HostnameChips.tsx';
import { InfoNote } from '../../components/inventory/InfoNote.tsx';
import {
  ListBody,
  TableFrame,
  linkClass,
  tdClass,
  thClass,
  theadRowClass,
} from '../../components/inventory/ListBody.tsx';
import { RelativeTime } from '../../components/inventory/RelativeTime.tsx';
import { StatusTabs } from '../../components/inventory/StatusTabs.tsx';
import { useListParams } from '../../components/inventory/use-list-params.ts';
import { ScheduledScansHint } from '../../components/settings/ScheduledScansHint.tsx';
import { Card } from '../../components/ui/Card.tsx';
import { PageHeader } from '../../components/ui/PageHeader.tsx';
import { api } from '../../lib/api.ts';
import { useAsync } from '../../lib/use-async.ts';
import { useRefreshableAsync } from '../../lib/use-refreshable-async.ts';

const STATES = [
  { value: 'open', label: 'Open' },
  { value: 'filtered', label: 'Filtered' },
  { value: 'closed', label: 'Closed' },
  { value: 'all', label: 'All' },
] as const;
const DEFAULT_STATE = 'open';
const DEFAULT_SORT = 'port';
const SORTS = [
  { value: 'port', label: 'Port number' },
  { value: 'ip', label: 'IP address' },
  { value: 'last_observed', label: 'Most recently observed' },
];
const FILTER_KEYS = ['port', 'domainId', 'q'] as const;

const STATE_STYLES: Record<PortItem['state'], string> = {
  open: 'bg-emerald-50 text-emerald-800 ring-emerald-600/25',
  filtered: 'bg-surface-3 text-fg-muted ring-line-strong',
  closed: 'bg-surface-3 text-fg-subtle ring-line',
};

const tabCount = (counts: PortsResponse['counts'] | undefined, state: string) =>
  counts === undefined
    ? undefined
    : state === 'all'
      ? counts.open + counts.filtered + counts.closed
      : counts[state as keyof PortsResponse['counts']];

export function PortsPage() {
  const { params, get, setParam } = useListParams();
  const state = get('state') ?? DEFAULT_STATE;
  const query = {
    state: state === DEFAULT_STATE ? undefined : state,
    port: get('port'),
    domainId: get('domainId'),
    q: get('q'),
    sort: get('sort'),
    page: get('page'),
  };
  const list = useRefreshableAsync(
    (signal) => api.inventory.ports(query, { signal }),
    [params.toString()],
  );
  const surface = useAsync((signal) => api.inventory.attackSurface({ signal }), []);
  const filtered = FILTER_KEYS.some((k) => params.get(k));
  const data = list.state.status === 'success' ? list.state.data : undefined;
  const domainId = get('domainId') ?? '';
  const services = surface.status === 'success' ? surface.data.exposedServices : [];

  return (
    <>
      <PageHeader
        title="Open Ports"
        description="The latest state of every port probed on your approved networks, with the hostnames resolving to each address and whether the exposure policy allows it."
      />
      <div className="space-y-6">
        <InfoNote label="Where port data comes from">
          Ports are only probed on approved networks (Standard/Deep scans). Third-party hosting, CDN
          and cloud addresses are never probed unless an administrator approves the network.
        </InfoNote>

        {services.length > 0 && (
          <section
            aria-labelledby="top-services"
            className="rounded-xl border border-line bg-surface p-4 shadow-card"
          >
            <h2
              id="top-services"
              className="text-xs font-medium uppercase tracking-wider text-fg-subtle"
            >
              Most exposed services
              <span className="ml-2 font-normal normal-case tracking-normal">
                open ports across all current addresses (not filtered)
              </span>
            </h2>
            <ul className="mt-3 flex flex-wrap gap-2">
              {services.map((s) => (
                <li key={s.port}>
                  <button
                    type="button"
                    onClick={() => setParam('port', String(s.port))}
                    className="inline-flex items-center gap-2 rounded-lg border border-line bg-surface-2 px-2.5 py-1 text-sm hover:border-accent"
                    aria-label={`Filter port ${s.port}${s.service ? ` (${s.service})` : ''}: ${s.ips} addresses`}
                  >
                    <span className="font-mono text-fg">{s.port}</span>
                    {s.service && <span className="text-fg-muted">{s.service}</span>}
                    <span className="rounded-full bg-surface-3 px-1.5 text-xs tabular-nums text-fg-subtle">
                      {s.ips}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </section>
        )}

        <Card>
          <StatusTabs
            label="Port state"
            value={state}
            onChange={(v) => setParam('state', v === DEFAULT_STATE ? '' : v)}
            tabs={STATES.map((s) => ({ ...s, count: tabCount(data?.counts, s.value) }))}
          />
          <div className="my-4 flex flex-wrap items-end gap-3">
            <SearchForm
              id="port-search"
              label="Search ports"
              placeholder="IP, hostname or service"
              value={get('q') ?? ''}
              onSearch={(v) => setParam('q', v)}
            />
            <PortNumberFilter value={get('port') ?? ''} onChange={(v) => setParam('port', v)} />
            <DomainFilter
              value={domainId}
              fallbackLabel={data?.items.find((p) => p.domain?.id === domainId)?.domain?.fqdn}
              onChange={(v) => setParam('domainId', v)}
            />
            <SelectFilter
              label="Sort by"
              value={get('sort') ?? DEFAULT_SORT}
              options={SORTS}
              onChange={(v) => setParam('sort', v === DEFAULT_SORT ? '' : v)}
            />
          </div>

          <ListBody
            list={list}
            noun="ports"
            columns={7}
            onPage={(p) => setParam('page', String(p))}
            empty={
              filtered || state !== DEFAULT_STATE
                ? {
                    title: 'No ports match these filters',
                    icon: DoorOpen,
                    body: 'Try another state tab or clear the filters.',
                  }
                : {
                    title: 'No open ports observed',
                    icon: DoorOpen,
                    body: (
                      <>
                        Ports are probed by <strong>Standard</strong> and <strong>Deep</strong>{' '}
                        scans, and only on addresses inside an approved network (
                        <Link to="/settings" className={linkClass}>
                          Settings → Workers and networks
                        </Link>
                        ). Run a scan from a{' '}
                        <Link to="/domains" className={linkClass}>
                          domain page
                        </Link>{' '}
                        once a network is approved.
                        <ScheduledScansHint />
                      </>
                    ),
                  }
            }
          >
            {(page) => <PortsTable items={page.items} />}
          </ListBody>
        </Card>
      </div>
    </>
  );
}

function PortNumberFilter({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <label className="text-xs text-fg-muted">
      <span className="mb-1 block">Port</span>
      <input
        type="number"
        inputMode="numeric"
        min={1}
        max={65535}
        // Applied when the field loses focus or on Enter, so typing "443" is one request.
        key={value}
        defaultValue={value}
        placeholder="Any"
        onBlur={(e) => {
          const v = e.target.value.trim();
          if (v !== value && (v === '' || isPort(v))) onChange(v);
        }}
        onKeyDown={(e) => {
          if (e.key !== 'Enter') return;
          e.preventDefault();
          const v = e.currentTarget.value.trim();
          if (v === '' || isPort(v)) onChange(v);
        }}
        className={`${inputClass} w-24 px-2`}
      />
    </label>
  );
}

const isPort = (v: string) => /^\d{1,5}$/.test(v) && Number(v) >= 1 && Number(v) <= 65535;

function PortsTable({ items }: { items: PortItem[] }) {
  return (
    <TableFrame caption="Observed ports, latest observation per address, port and protocol">
      <thead>
        <tr className={theadRowClass}>
          <th scope="col" className={thClass}>
            IP address
          </th>
          <th scope="col" className={thClass}>
            Port
          </th>
          <th scope="col" className={thClass}>
            Service
          </th>
          <th scope="col" className={thClass}>
            Hostnames
          </th>
          <th scope="col" className={thClass}>
            Domain
          </th>
          <th scope="col" className={thClass}>
            Policy
          </th>
          <th scope="col" className={thClass}>
            First observed
          </th>
          <th scope="col" className={`${thClass} pr-0`}>
            Last observed
          </th>
        </tr>
      </thead>
      <tbody className="divide-y divide-line-soft">
        {items.map((p) => (
          <tr key={`${p.ipAddress}/${p.port}/${p.protocol}`}>
            <th scope="row" className={`${tdClass} text-left font-normal`}>
              <div className="font-mono text-fg">{p.ipAddress}</div>
              {p.country && <CountryFlag code={p.country} />}
            </th>
            <td className={`${tdClass} whitespace-nowrap`}>
              <span className="font-mono text-fg">{p.port}</span>
              <span className="text-fg-subtle">/{p.protocol}</span>
              {p.state !== 'open' && (
                <span
                  className={`ml-2 rounded-full px-1.5 py-0.5 text-xs ring-1 ring-inset ${STATE_STYLES[p.state]}`}
                >
                  {p.state}
                </span>
              )}
            </td>
            <td className={`${tdClass} text-fg-2`}>
              {p.service ?? <span className="text-fg-faint">Unidentified</span>}
            </td>
            <td className={tdClass}>
              <HostnameChips hostnames={p.hostnames} />
            </td>
            <td className={`${tdClass} whitespace-nowrap`}>
              {p.domain ? (
                <Link to={`/domains/${p.domain.id}`} className={`${linkClass} font-mono`}>
                  {p.domain.fqdn}
                </Link>
              ) : (
                <span className="text-fg-faint">—</span>
              )}
            </td>
            <td className={tdClass}>
              {p.policyViolation ? (
                <Link
                  to={`/findings?${new URLSearchParams({ ruleId: 'EXP-002', q: p.ipAddress }).toString()}`}
                  className="inline-flex items-center gap-1 whitespace-nowrap rounded-full bg-red-50 px-2 py-0.5 text-xs font-medium text-red-800 ring-1 ring-inset ring-red-600/25 hover:underline"
                >
                  <ShieldX className="size-3.5" aria-hidden />
                  Not allowed by exposure policy
                </Link>
              ) : (
                <span className="text-xs text-fg-subtle">No violation</span>
              )}
            </td>
            <td className={`${tdClass} text-xs text-fg-muted`}>
              <RelativeTime iso={p.firstObservedAt} />
            </td>
            <td className={`${tdClass} pr-0 text-xs text-fg-muted`}>
              <RelativeTime iso={p.lastObservedAt} />
            </td>
          </tr>
        ))}
      </tbody>
    </TableFrame>
  );
}
