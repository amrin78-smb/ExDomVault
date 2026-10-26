import {
  ASSET_ROLE_LABELS,
  type AttackSurfaceResponse,
  type HostingHint,
} from '@exdomainvault/shared';
import { Globe2 } from 'lucide-react';
import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { HOSTING_KIND_LABELS } from '../../components/assets/labels.ts';
import { LazyWorldMap } from '../../components/map/LazyWorldMap.tsx';
import { countryName, flagEmoji } from '../../components/map/country-names.ts';
import { Card } from '../../components/ui/Card.tsx';
import { EmptyState } from '../../components/ui/EmptyState.tsx';
import { LoadError } from '../../components/ui/LoadError.tsx';
import { PageHeader } from '../../components/ui/PageHeader.tsx';
import { ProportionBar } from '../../components/ui/ProportionBar.tsx';
import { StaleDataNotice } from '../../components/ui/StaleDataNotice.tsx';
import { StatCard } from '../../components/ui/StatCard.tsx';
import { api } from '../../lib/api.ts';
import { useRefreshableAsync } from '../../lib/use-refreshable-async.ts';

const pct = (n: number, total: number) => (total > 0 ? Math.round((n / total) * 100) : 0);
const plural = (n: number, word: string) => `${n.toLocaleString()} ${word}${n === 1 ? '' : 's'}`;

/**
 * Attack surface (Milestone 13): where approved assets are hosted and what they expose. Read-only
 * projection of data already collected (DNS, port observations, IP geolocation by the worker).
 */
export function AttackSurfacePage() {
  const { state, stale, refreshing, retry } = useRefreshableAsync(
    (signal) => api.inventory.attackSurface({ signal }),
    [],
  );

  return (
    <>
      <PageHeader
        title="Attack surface"
        description="Where your approved assets are hosted and what they expose, from the latest DNS and port observations."
      />
      {stale && (
        <StaleDataNotice
          loadedAt={stale.loadedAt}
          error={stale.error}
          onRetry={retry}
          retrying={refreshing}
        />
      )}
      {state.status === 'loading' && <LoadingSkeleton />}
      {state.status === 'error' && (
        <LoadError error={state.error} title="Could not load the attack surface" onRetry={retry} />
      )}
      {state.status === 'success' && <AttackSurface data={state.data} />}
    </>
  );
}

function LoadingSkeleton() {
  return (
    <div role="status" aria-label="Loading attack surface" className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="h-24 animate-pulse rounded-xl border border-line bg-surface" />
        ))}
      </div>
      <div className="h-96 animate-pulse rounded-xl border border-line bg-surface" />
    </div>
  );
}

function AttackSurface({ data }: { data: AttackSurfaceResponse }) {
  const { totals } = data;
  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Approved assets" value={totals.approvedAssets} hint="In scan scope" />
        <StatCard label="Current IPs" value={totals.currentIps} hint="From the latest DNS" />
        <StatCard label="Open ports" value={totals.openPorts} hint="On approved networks" />
        <StatCard
          label="Third-party hosted"
          value={totals.thirdPartyHosted}
          hint="CDN, cloud or SaaS detected"
        />
      </div>

      <CountryMapCard data={data} />

      <div className="grid gap-4 lg:grid-cols-2">
        <AssetTypesCard roles={data.assetRoles} />
        <HostingProvidersCard providers={data.hostingProviders} />
        <ExposedServicesCard services={data.exposedServices} />
        <CountriesCard countries={data.countries} />
      </div>
    </div>
  );
}

function CountryMapCard({ data }: { data: AttackSurfaceResponse }) {
  const geolocatedIps = data.continents.reduce((n, c) => n + c.ips, 0);
  return (
    <Card title="Assets by country">
      {data.countries.length === 0 ? (
        <EmptyState title="No country data yet" icon={Globe2}>
          Country data appears after the next scan — the worker adds it to DNS results.
          {data.unknownCountryIps > 0 && ` ${plural(data.unknownCountryIps, 'IP')} not geolocated.`}
        </EmptyState>
      ) : (
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_16rem]">
          <LazyWorldMap countries={data.countries} attribution={data.geoAttribution ?? undefined} />
          <div>
            <h3 className="text-xs font-medium uppercase tracking-wider text-fg-subtle">
              Assets by region
            </h3>
            <p className="mt-0.5 text-xs text-fg-subtle">Share of geolocated IPs</p>
            <ul className="mt-3 space-y-3" aria-label="Assets by region">
              {data.continents.map((c) => (
                <li key={c.continent}>
                  <div className="flex items-baseline justify-between gap-2 text-sm">
                    <span className="text-fg-2">{c.continent}</span>
                    <span className="tabular-nums text-fg">{pct(c.ips, geolocatedIps)}%</span>
                  </div>
                  <ProportionBar
                    percent={pct(c.ips, geolocatedIps)}
                    className="mt-1 h-1.5 w-full rounded-full bg-line"
                    fillClassName="fill-accent"
                  />
                  <div className="mt-0.5 text-xs tabular-nums text-fg-subtle">
                    {plural(c.assets, 'asset')} · {plural(c.ips, 'IP')}
                  </div>
                </li>
              ))}
            </ul>
            <p className="mt-4 border-t border-line-soft pt-3 text-xs text-fg-subtle">
              Not geolocated: {plural(data.unknownCountryIps, 'IP')}
            </p>
          </div>
        </div>
      )}
    </Card>
  );
}

function BarRow({
  label,
  value,
  max,
  to,
  extra,
  valueLabel,
}: {
  label: string;
  value: number;
  max: number;
  to?: string;
  extra?: ReactNode;
  valueLabel: string;
}) {
  return (
    <li>
      <div className="flex items-center justify-between gap-2 text-sm">
        <span className="flex min-w-0 items-center gap-2">
          {to ? (
            <Link to={to} className="truncate text-sky-800 hover:underline">
              {label}
            </Link>
          ) : (
            <span className="truncate text-fg-2">{label}</span>
          )}
          {extra}
        </span>
        <span className="shrink-0 tabular-nums text-fg" aria-label={valueLabel}>
          {value.toLocaleString()}
        </span>
      </div>
      <ProportionBar
        percent={max > 0 ? (value / max) * 100 : 0}
        className="mt-1 h-1.5 w-full rounded-full bg-line"
        fillClassName="fill-accent"
      />
    </li>
  );
}

function AssetTypesCard({ roles }: { roles: AttackSurfaceResponse['assetRoles'] }) {
  const sorted = [...roles].sort((a, b) => b.assets - a.assets);
  const max = Math.max(0, ...sorted.map((r) => r.assets));
  return (
    <Card title="Asset types">
      {max === 0 ? (
        <EmptyState title="No approved assets yet">
          Roles come from collected evidence (MX/NS records, open ports, HTTP responses).
        </EmptyState>
      ) : (
        <ul className="space-y-3">
          {sorted.map((r) => (
            <BarRow
              key={r.role}
              label={ASSET_ROLE_LABELS[r.role]}
              value={r.assets}
              max={max}
              to={`/assets?status=approved&role=${r.role}`}
              valueLabel={`${plural(r.assets, 'asset')}`}
            />
          ))}
        </ul>
      )}
    </Card>
  );
}

function KindChip({ kind }: { kind: HostingHint['kind'] }) {
  return (
    <span className="whitespace-nowrap rounded-full bg-violet-50 px-1.5 py-0.5 text-[11px] font-medium text-violet-800 ring-1 ring-inset ring-violet-600/20 dark:ring-violet-400/45">
      {HOSTING_KIND_LABELS[kind]}
    </span>
  );
}

function HostingProvidersCard({
  providers,
}: {
  providers: AttackSurfaceResponse['hostingProviders'];
}) {
  const max = Math.max(0, ...providers.map((p) => p.assets));
  return (
    <Card title="Hosting providers">
      {providers.length === 0 ? (
        <EmptyState title="No approved assets yet" />
      ) : (
        <ul className="space-y-3">
          {providers.map((p) => (
            <BarRow
              key={p.provider ?? '(none)'}
              label={p.provider ?? 'No third-party provider detected'}
              value={p.assets}
              max={max}
              extra={p.kind && <KindChip kind={p.kind} />}
              valueLabel={plural(p.assets, 'asset')}
            />
          ))}
        </ul>
      )}
    </Card>
  );
}

function ExposedServicesCard({ services }: { services: AttackSurfaceResponse['exposedServices'] }) {
  const max = Math.max(0, ...services.map((s) => s.ips));
  return (
    <Card title="Exposed services">
      {services.length === 0 ? (
        <EmptyState title="No open ports observed">
          Port checks run only against approved networks.
        </EmptyState>
      ) : (
        <ul className="space-y-3">
          {services.map((s) => (
            <BarRow
              key={s.port}
              label={`${s.port}${s.service ? ` · ${s.service}` : ''}`}
              value={s.ips}
              max={max}
              to={`/ports?port=${s.port}`}
              valueLabel={plural(s.ips, 'IP')}
            />
          ))}
        </ul>
      )}
    </Card>
  );
}

function CountriesCard({ countries }: { countries: AttackSurfaceResponse['countries'] }) {
  const sorted = [...countries].sort((a, b) => b.ips - a.ips || b.assets - a.assets);
  return (
    <Card title="Countries">
      {sorted.length === 0 ? (
        <EmptyState title="No country data yet" icon={Globe2}>
          Country data appears after the next scan — the worker adds it to DNS results.
        </EmptyState>
      ) : (
        <div className="max-h-80 overflow-y-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b border-line text-left text-xs font-medium uppercase tracking-wide text-fg-subtle">
                <th scope="col" className="py-2 pr-4">
                  Country
                </th>
                <th scope="col" className="py-2 pr-4 text-right">
                  Assets
                </th>
                <th scope="col" className="py-2 text-right">
                  IPs
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line-soft">
              {sorted.map((c) => (
                <tr key={c.country}>
                  <td className="py-2 pr-4 text-fg-2">
                    <span aria-hidden className="mr-2">
                      {flagEmoji(c.country)}
                    </span>
                    {countryName(c.country)}
                  </td>
                  <td className="py-2 pr-4 text-right tabular-nums text-fg">{c.assets}</td>
                  <td className="py-2 text-right tabular-nums text-fg">{c.ips}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
