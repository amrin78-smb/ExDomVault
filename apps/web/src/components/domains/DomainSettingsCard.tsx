import {
  CRITICALITIES,
  CRITICALITY_LABELS,
  type Criticality,
  type Domain,
} from '@exdomainvault/shared';
import { useState, type FormEvent } from 'react';
import { api } from '../../lib/api.ts';
import { usePermission } from '../../lib/session.ts';
import { Button } from '../ui/Button.tsx';
import { Card } from '../ui/Card.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';
import { CriticalityLabel } from './DomainBadges.tsx';

const inputClass = 'w-full rounded-md border border-slate-300 px-2.5 py-1.5 text-sm shadow-sm';

/** Business owner, criticality and monitoring. Monitoring changes need explicit confirmation. */
export function DomainSettingsCard({
  domain,
  onSaved,
}: {
  domain: Domain;
  onSaved: (d: Domain) => void;
}) {
  const canWrite = usePermission('domains:write');
  const [criticality, setCriticality] = useState<Criticality>(domain.criticality);
  const [owner, setOwner] = useState(domain.businessOwner ?? '');
  const [confirmMonitoring, setConfirmMonitoring] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [saved, setSaved] = useState(false);

  const dirty = criticality !== domain.criticality || owner.trim() !== (domain.businessOwner ?? '');

  const save = async (body: Parameters<typeof api.domains.update>[1]) => {
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      const res = await api.domains.update(domain.id, body);
      onSaved(res.domain);
      return true;
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
      return false;
    } finally {
      setBusy(false);
    }
  };

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (await save({ criticality, businessOwner: owner })) setSaved(true);
  };

  const toggleMonitoring = async () => {
    if (await save({ monitoringEnabled: !domain.monitoringEnabled })) setConfirmMonitoring(false);
  };

  return (
    <Card title="Ownership and monitoring">
      {canWrite ? (
        <form onSubmit={onSubmit} className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <label className="block text-sm font-medium text-slate-700">
              Criticality
              <select
                className={`${inputClass} mt-1 bg-white`}
                value={criticality}
                onChange={(e) => setCriticality(e.target.value as Criticality)}
              >
                {CRITICALITIES.map((c) => (
                  <option key={c} value={c}>
                    {CRITICALITY_LABELS[c]}
                  </option>
                ))}
              </select>
            </label>
            <label className="block text-sm font-medium text-slate-700">
              Business owner
              <input
                className={`${inputClass} mt-1`}
                value={owner}
                onChange={(e) => setOwner(e.target.value)}
                maxLength={200}
              />
            </label>
          </div>
          <div className="flex items-center gap-3">
            <Button type="submit" variant="primary" disabled={!dirty || busy}>
              Save changes
            </Button>
            {saved && !dirty && (
              <span className="text-sm text-emerald-700" role="status">
                Saved
              </span>
            )}
          </div>
        </form>
      ) : (
        <dl className="grid gap-4 text-sm sm:grid-cols-2">
          <div>
            <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">
              Criticality
            </dt>
            <dd className="mt-1">
              <CriticalityLabel criticality={domain.criticality} />
            </dd>
          </div>
          <div>
            <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">
              Business owner
            </dt>
            <dd className="mt-1">{domain.businessOwner ?? 'Not set'}</dd>
          </div>
        </dl>
      )}

      <div className="mt-5 border-t border-slate-100 pt-4 text-sm">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="font-medium text-slate-800">
              Monitoring is {domain.monitoringEnabled ? 'on' : 'off'}
            </p>
            <p className="text-xs text-slate-500">
              {domain.verificationStatus === 'verified'
                ? 'When on, this domain is included in scheduled monitoring once scanning is available.'
                : 'Monitoring can be turned on after the domain is verified.'}
            </p>
          </div>
          {canWrite && !confirmMonitoring && (
            <Button
              onClick={() => setConfirmMonitoring(true)}
              disabled={
                busy || (!domain.monitoringEnabled && domain.verificationStatus !== 'verified')
              }
            >
              {domain.monitoringEnabled ? 'Turn off monitoring' : 'Turn on monitoring'}
            </Button>
          )}
        </div>
        {confirmMonitoring && (
          <div
            role="alertdialog"
            aria-label="Confirm monitoring change"
            className="mt-3 rounded-md border border-slate-200 bg-slate-50 p-3"
          >
            <p className="text-slate-700">
              {domain.monitoringEnabled
                ? `Stop monitoring ${domain.fqdn}? Scheduled checks for this domain will stop.`
                : `Start monitoring ${domain.fqdn}? It will be included in scheduled checks within its approved scope.`}
            </p>
            <div className="mt-3 flex gap-2">
              <Button
                variant={domain.monitoringEnabled ? 'danger' : 'primary'}
                onClick={toggleMonitoring}
                disabled={busy}
              >
                {domain.monitoringEnabled ? 'Turn off' : 'Turn on'}
              </Button>
              <Button onClick={() => setConfirmMonitoring(false)} disabled={busy}>
                Cancel
              </Button>
            </div>
          </div>
        )}
      </div>
      {error && (
        <div className="mt-4">
          <ErrorAlert error={error} />
        </div>
      )}
    </Card>
  );
}
