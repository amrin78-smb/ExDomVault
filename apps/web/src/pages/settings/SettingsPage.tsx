import type { Permission, Worker } from '@exdomainvault/shared';
import { Construction, KeyRound, Server } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router';
import { ApprovedNetworksSection } from '../../components/settings/ApprovedNetworksSection.tsx';
import { AuditLogSection } from '../../components/settings/AuditLogSection.tsx';
import { IntelFeedsSection } from '../../components/settings/IntelFeedsSection.tsx';
import { ScanProfilesSection } from '../../components/settings/ScanProfilesSection.tsx';
import { ScheduledScansSection } from '../../components/settings/ScheduledScansSection.tsx';
import { SystemHealthSection } from '../../components/settings/SystemHealthSection.tsx';
import { UsersSection } from '../../components/settings/UsersSection.tsx';
import { Button } from '../../components/ui/Button.tsx';
import { Card } from '../../components/ui/Card.tsx';
import { EmptyState } from '../../components/ui/EmptyState.tsx';
import { ErrorAlert } from '../../components/ui/ErrorAlert.tsx';
import { PageHeader } from '../../components/ui/PageHeader.tsx';
import { api } from '../../lib/api.ts';
import { formatDate, formatDateTime } from '../../lib/format.ts';
import { usePermission, usePermissions, useSession } from '../../lib/session.ts';
import { useAsync } from '../../lib/use-async.ts';

const inputClass = 'w-full rounded-md border border-slate-300 px-2.5 py-1.5 text-sm shadow-sm';

const KEYGEN = `openssl genpkey -algorithm ed25519 -out worker.key
chmod 600 worker.key
openssl pkey -in worker.key -pubout -outform DER | tail -c 32 | base64`;

/** Settings sections, selected with `?tab=` so each one (and its filters) has a shareable URL. */
const TABS = [
  { key: 'general', label: 'Workers and networks', permission: null },
  { key: 'users', label: 'Users', permission: 'users:manage' },
  { key: 'profiles', label: 'Scan profiles', permission: 'scans:read' },
  { key: 'audit', label: 'Audit log', permission: 'audit:read' },
  // Readable by anyone who sees software matches; the API may still restrict it (403 → denied).
  { key: 'intel', label: 'Intelligence feeds', permission: 'findings:read' },
  { key: 'health', label: 'System health', permission: 'settings:manage' },
] as const satisfies readonly { key: string; label: string; permission: Permission | null }[];
type TabKey = (typeof TABS)[number]['key'];

export function SettingsPage() {
  const [params] = useSearchParams();
  const session = useSession();
  const can = usePermissions();
  const requested = params.get('tab') ?? 'general';
  const tab = TABS.find((t) => t.key === requested) ?? TABS[0];
  const visible = TABS.filter((t) => t.permission === null || can(t.permission));
  const allowed = tab.permission === null || can(tab.permission);

  return (
    <>
      <PageHeader
        title="Settings"
        description="Users, scan profiles, the audit log, intelligence feeds, system health, scanning workers and approved networks."
      />
      <nav aria-label="Settings sections" className="mb-6 border-b border-slate-200">
        <ul className="-mb-px flex flex-wrap gap-1">
          {visible.map((t) => {
            const current = t.key === tab.key;
            return (
              <li key={t.key}>
                <Link
                  to={t.key === 'general' ? '?' : `?tab=${t.key}`}
                  aria-current={current ? 'page' : undefined}
                  className={`inline-block border-b-2 px-3 py-2 text-sm font-medium ${
                    current
                      ? 'border-sky-700 text-sky-800'
                      : 'border-transparent text-slate-600 hover:border-slate-300 hover:text-slate-900'
                  }`}
                >
                  {t.label}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>
      {session.status === 'loading' && tab.permission !== null ? (
        <p role="status" className="py-8 text-center text-sm text-slate-500">
          Loading…
        </p>
      ) : allowed ? (
        <TabContent tab={tab.key} />
      ) : (
        <Card>
          <EmptyState title="Administrators only" icon={Construction}>
            You do not have permission to view this section.
          </EmptyState>
        </Card>
      )}
    </>
  );
}

function TabContent({ tab }: { tab: TabKey }) {
  switch (tab) {
    case 'users':
      return <UsersSection />;
    case 'profiles':
      return (
        <div className="space-y-6">
          <ScheduledScansSection />
          <ScanProfilesSection />
        </div>
      );
    case 'audit':
      return <AuditLogSection />;
    case 'intel':
      return <IntelFeedsSection />;
    case 'health':
      return <SystemHealthSection />;
    case 'general':
      return <GeneralSection />;
  }
}

function GeneralSection() {
  const canManage = usePermission('settings:manage');
  const canManagePolicies = usePermission('scan_policies:manage');
  return (
    <div className="space-y-6">
      {canManage ? (
        <WorkersSection />
      ) : (
        <Card>
          <EmptyState title="Administrators only" icon={Construction}>
            Worker and system settings are managed by administrators.
          </EmptyState>
        </Card>
      )}
      {canManagePolicies && <ApprovedNetworksSection />}
    </div>
  );
}

function WorkersSection() {
  const [reload, setReload] = useState(0);
  const state = useAsync((signal) => api.workers.list({ signal }), [reload]);
  const [created, setCreated] = useState<{ name: string; credentialId: string } | null>(null);
  const refresh = () => setReload((r) => r + 1);

  return (
    <Card title="Scanning workers">
      <div className="space-y-5 text-sm">
        <p className="text-slate-600">
          The home worker signs every request with its own Ed25519 private key. Only the public key
          is registered here, so nothing stored in ExDomainVault can be used to impersonate the
          worker. Generate the key on the worker machine:
        </p>
        <pre className="overflow-x-auto rounded bg-slate-100 p-2 font-mono text-xs text-slate-700">
          {KEYGEN}
        </pre>

        {created && (
          <div role="status" className="rounded-md border border-emerald-200 bg-emerald-50 p-3">
            Registered <strong>{created.name}</strong>. Configure the worker with key id{' '}
            <code className="font-mono text-xs">{created.credentialId}</code>.
          </div>
        )}

        <RegisterWorkerForm
          onCreated={(name, credentialId) => {
            setCreated({ name, credentialId });
            refresh();
          }}
        />

        {state.status === 'loading' && <p className="text-slate-500">Loading workers…</p>}
        {state.status === 'error' && <ErrorAlert error={state.error} />}
        {state.status === 'success' &&
          (state.data.items.length === 0 ? (
            <EmptyState title="No workers registered" icon={Server} />
          ) : (
            <ul className="divide-y divide-slate-100 rounded-md border border-slate-200">
              {state.data.items.map((w) => (
                <WorkerRow key={w.id} worker={w} onChanged={refresh} />
              ))}
            </ul>
          ))}
      </div>
    </Card>
  );
}

function RegisterWorkerForm({
  onCreated,
}: {
  onCreated: (name: string, credentialId: string) => void;
}) {
  const [name, setName] = useState('home-1');
  const [publicKey, setPublicKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api.workers.register({ name, publicKey });
      setPublicKey('');
      onCreated(res.worker.name, res.credentialId);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} aria-label="Register a worker" className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-3">
        <label className="block font-medium text-slate-700">
          Worker name
          <input
            className={`${inputClass} mt-1 font-mono`}
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={63}
            required
          />
        </label>
        <label className="block font-medium text-slate-700 sm:col-span-2">
          Public key (base64)
          <input
            className={`${inputClass} mt-1 font-mono`}
            value={publicKey}
            onChange={(e) => setPublicKey(e.target.value)}
            spellCheck={false}
            autoComplete="off"
            required
          />
        </label>
      </div>
      {error && <ErrorAlert error={error} title="The worker was not registered" />}
      <Button type="submit" variant="primary" disabled={busy || publicKey.trim() === ''}>
        <KeyRound className="size-4" aria-hidden />
        Register worker
      </Button>
    </form>
  );
}

function WorkerRow({ worker, onChanged }: { worker: Worker; onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setBusy(false);
    }
  };

  return (
    <li className="space-y-2 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <span className="font-mono font-medium text-slate-900">{worker.name}</span>
          <span
            className={`ml-2 text-xs ${worker.status === 'active' ? 'text-emerald-700' : 'text-red-700'}`}
          >
            {worker.status}
          </span>
          <span className="ml-2 text-xs text-slate-500">
            {worker.lastSeenAt
              ? `last seen ${formatDateTime(worker.lastSeenAt)}`
              : 'never connected'}
            {worker.version ? ` · v${worker.version}` : ''}
          </span>
        </div>
        <Button
          variant={worker.status === 'active' ? 'danger' : 'secondary'}
          disabled={busy}
          onClick={() =>
            act(() =>
              api.workers.setStatus(worker.id, worker.status === 'active' ? 'disabled' : 'active'),
            )
          }
        >
          {worker.status === 'active' ? 'Disable' : 'Enable'}
        </Button>
      </div>
      <table className="min-w-full text-xs">
        <thead>
          <tr className="text-left text-slate-500">
            <th scope="col" className="py-1 pr-3 font-medium">
              Key id
            </th>
            <th scope="col" className="py-1 pr-3 font-medium">
              Fingerprint
            </th>
            <th scope="col" className="py-1 pr-3 font-medium">
              Expires
            </th>
            <th scope="col" className="py-1 pr-3 font-medium">
              Last used
            </th>
            <th scope="col" className="py-1" />
          </tr>
        </thead>
        <tbody>
          {worker.credentials.map((c) => (
            <tr key={c.id} className={c.revokedAt ? 'text-slate-400 line-through' : ''}>
              <td className="py-1 pr-3 font-mono">{c.id}</td>
              <td className="py-1 pr-3 font-mono">{c.fingerprint}</td>
              <td className="py-1 pr-3">{formatDate(c.expiresAt)}</td>
              <td className="py-1 pr-3">{c.lastUsedAt ? formatDateTime(c.lastUsedAt) : '—'}</td>
              <td className="py-1 text-right">
                {!c.revokedAt && (
                  <Button
                    disabled={busy}
                    onClick={() => act(() => api.workers.revokeKey(worker.id, c.id))}
                  >
                    Revoke
                  </Button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {error && <ErrorAlert error={error} />}
    </li>
  );
}
