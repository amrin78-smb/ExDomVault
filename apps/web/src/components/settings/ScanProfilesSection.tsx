import type { ScanCheck, ScanProfile } from '@exdomainvault/shared';
import { SlidersHorizontal } from 'lucide-react';
import type { ReactNode } from 'react';
import { api } from '../../lib/api.ts';
import { useAsync } from '../../lib/use-async.ts';
import { Card } from '../ui/Card.tsx';
import { EmptyState } from '../ui/EmptyState.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';

const CHECK_LABELS: Record<ScanCheck, string> = {
  dns: 'DNS records',
  rdap: 'Registration (RDAP)',
  tls_certificate: 'TLS certificate',
  http_availability: 'HTTP availability',
  http_headers: 'HTTP security headers',
  tcp_ports: 'TCP port probes',
  service_identification: 'Service identification',
  tls_configuration: 'TLS configuration',
  discovery: 'Subdomain discovery',
};

const formatMs = (ms: number) => (ms >= 1000 ? `${ms / 1000} s` : `${ms} ms`);

function Item({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs font-medium uppercase tracking-wide text-fg-subtle">{label}</dt>
      <dd className="mt-0.5 text-fg">{children}</dd>
    </div>
  );
}

/**
 * Read-only view of the server-defined scan profiles (`scans:read`). Profiles are versioned data,
 * changed only by migrations: the UI never sends scanner options.
 */
export function ScanProfilesSection() {
  const state = useAsync((signal) => api.scanProfiles({ signal }), []);

  return (
    <Card title="Scan profiles">
      <div className="space-y-4 text-sm">
        <p className="text-fg-muted">
          Scans run only these server-defined profiles. Nobody can pass scanner options from the
          app. Passive discovery runs as its own job type and is not listed here.
        </p>
        {state.status === 'loading' && (
          <p role="status" className="text-fg-subtle">
            Loading scan profiles…
          </p>
        )}
        {state.status === 'error' && (
          <ErrorAlert error={state.error} title="Could not load scan profiles" />
        )}
        {state.status === 'success' && (
          <>
            <p
              className={`rounded-md border px-3 py-2 ${
                state.data.activeScanningEnabled
                  ? 'border-sky-200 bg-sky-50 text-sky-900'
                  : 'border-amber-200 bg-amber-50 text-amber-900'
              }`}
            >
              {state.data.activeScanningEnabled
                ? 'Active scanning is enabled on the server: active profiles can run against verified domains and approved assets.'
                : 'Active scanning is disabled on the server: only passive profiles run.'}
            </p>
            {state.data.items.length === 0 ? (
              <EmptyState title="No scan profiles" icon={SlidersHorizontal} />
            ) : (
              <ul className="space-y-3">
                {state.data.items.map((p) => (
                  <ProfileItem key={p.key} profile={p} />
                ))}
              </ul>
            )}
          </>
        )}
      </div>
    </Card>
  );
}

function ProfileItem({ profile: p }: { profile: ScanProfile }) {
  const c = p.config;
  const ports = c.tcpPorts.length;
  return (
    <li>
      <article aria-label={p.name} className="rounded-md border border-line p-3">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="font-semibold text-fg">{p.name}</h3>
          <span className="font-mono text-xs text-fg-subtle">
            {p.key} · v{p.version}
          </span>
          <span
            className={`rounded px-1.5 py-0.5 text-xs font-medium ${
              c.active ? 'bg-amber-100 text-amber-900' : 'bg-emerald-100 text-emerald-900'
            }`}
          >
            {c.active ? 'Connects to hosts' : 'Never contacts hosts'}
          </span>
          {!p.enabled && (
            <span className="rounded bg-line px-1.5 py-0.5 text-xs font-medium text-fg-2">
              Disabled
            </span>
          )}
        </div>
        <p className="mt-1 text-fg-muted">{p.description}</p>
        <p className="mt-1 text-xs text-fg-subtle">
          {c.active
            ? 'Connects to target hosts. Needs a verified domain and approved assets.'
            : 'Queries public infrastructure only; never contacts the target hosts.'}
        </p>
        <dl className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div className="sm:col-span-2 lg:col-span-4">
            <dt className="text-xs font-medium uppercase tracking-wide text-fg-subtle">Checks</dt>
            <dd className="mt-1">
              <ul aria-label={`Checks in ${p.name}`} className="flex flex-wrap gap-1.5">
                {c.checks.map((check) => (
                  <li key={check} className="rounded bg-surface-3 px-1.5 py-0.5 text-xs text-fg-2">
                    {CHECK_LABELS[check]}
                  </li>
                ))}
              </ul>
            </dd>
          </div>
          <Item label="TCP ports">
            {ports === 0 ? 'None' : ports === 1 ? '1 port' : `${ports} ports`}
          </Item>
          <Item label="Timeouts">
            connect {formatMs(c.timeouts.connectMs)}, read {formatMs(c.timeouts.readMs)}, per target{' '}
            {c.timeouts.targetSeconds} s
          </Item>
          <Item label="Rate">
            {c.ratePerSecond} requests/s, concurrency {c.concurrency}, up to {c.maxTargets} targets
          </Item>
          <Item label="Default schedule">
            {p.defaultSchedule ? (
              <span className="capitalize">{p.defaultSchedule}</span>
            ) : (
              'On request only'
            )}
          </Item>
        </dl>
      </article>
    </li>
  );
}
