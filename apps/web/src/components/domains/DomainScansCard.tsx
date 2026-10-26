import {
  SCAN_JOB_STATUS_LABELS,
  type Domain,
  type ScanJob,
  type ScanProfile,
} from '@exdomainvault/shared';
import { useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { api } from '../../lib/api.ts';
import { formatDate, formatDateTime } from '../../lib/format.ts';
import { usePermission } from '../../lib/session.ts';
import { useAsync, type AsyncState } from '../../lib/use-async.ts';
import { isScanPickerProfile, JOB_TYPE_LABELS } from '../scans/labels.ts';
import { ScanStatusBadge } from '../scans/ScanStatusBadge.tsx';
import { Button } from '../ui/Button.tsx';
import { Card } from '../ui/Card.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';

/** Why a profile cannot be used for this domain right now, or null if it can. */
function unavailableReason(
  profile: ScanProfile,
  domain: Domain,
  activeScanningEnabled: boolean,
): string | null {
  if (!profile.enabled) return 'disabled';
  if (!profile.config.active) return null;
  if (!activeScanningEnabled) return 'active scanning not enabled yet';
  if (domain.verificationStatus !== 'verified') return 'needs verification';
  if (domain.verificationExpiresAt && new Date(domain.verificationExpiresAt) <= new Date()) {
    return 'authorisation lapsed';
  }
  return null;
}

const jobLabel = (j: ScanJob) =>
  j.jobType === 'discovery'
    ? JOB_TYPE_LABELS.discovery
    : j.profile.charAt(0).toUpperCase() + j.profile.slice(1);

/** The most recent scan, e.g. "Last: Standard · Succeeded · 25 Oct 2026". */
function scansSummary(state: AsyncState<{ items: ScanJob[] }>): string | undefined {
  if (state.status === 'loading') return undefined;
  if (state.status === 'error') return 'Could not load';
  const last = state.data.items[0];
  if (!last) return 'No scans yet';
  return `Last: ${jobLabel(last)} · ${SCAN_JOB_STATUS_LABELS[last.status]} · ${formatDate(last.createdAt)}`;
}

/** Recent scans of a domain and a control to request one. Scans run asynchronously. */
export function DomainScansCard({ domain }: { domain: Domain }) {
  const navigate = useNavigate();
  const canRequest = usePermission('scans:request');
  const profiles = useAsync((signal) => api.scanProfiles({ signal }), []);
  const recent = useAsync(
    (signal) => api.scans.list({ domainId: domain.id, pageSize: 5 }, { signal }),
    [domain.id],
  );
  const [profile, setProfile] = useState('passive');
  const pickable =
    profiles.status === 'success' ? profiles.data.items.filter(isScanPickerProfile) : [];
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const request = async () => {
    setBusy(true);
    setError(null);
    try {
      const { job } = await api.domains.requestScan(domain.id, { profile });
      void navigate(`/scans/${job.id}`);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
      setBusy(false);
    }
  };

  return (
    <Card
      title="Scans"
      collapsible="domain.scans"
      defaultOpen={false}
      summary={scansSummary(recent)}
    >
      <div className="space-y-4 text-sm">
        {canRequest && profiles.status === 'success' && (
          <div className="flex flex-wrap items-end gap-2">
            <label className="text-xs text-slate-600">
              <span className="mb-1 block">Profile</span>
              <select
                className="rounded-md border border-slate-300 bg-white px-2 py-1.5 text-sm shadow-sm"
                value={profile}
                onChange={(e) => setProfile(e.target.value)}
              >
                {pickable.map((p) => {
                  const reason = unavailableReason(p, domain, profiles.data.activeScanningEnabled);
                  return (
                    <option key={p.key} value={p.key} disabled={reason !== null}>
                      {p.name}
                      {reason
                        ? ` (${reason})`
                        : p.config.active
                          ? ''
                          : ' (no contact with your hosts)'}
                    </option>
                  );
                })}
              </select>
            </label>
            <Button variant="primary" onClick={request} disabled={busy}>
              Request scan
            </Button>
          </div>
        )}
        {profiles.status === 'success' && (
          <div className="space-y-1 text-xs text-slate-500">
            <p>{pickable.find((p) => p.key === profile)?.description}</p>
            {pickable.find((p) => p.key === profile)?.config.active && (
              <p data-testid="tier-note">
                TLS and HTTP checks connect like a normal visitor; ports are probed only on approved
                networks.
              </p>
            )}
          </div>
        )}
        {error && <ErrorAlert error={error} title="The scan was not requested" />}

        {recent.status === 'error' && <ErrorAlert error={recent.error} />}
        {recent.status === 'success' &&
          (recent.data.items.length === 0 ? (
            <p className="text-slate-500">No scans yet.</p>
          ) : (
            <ul className="divide-y divide-slate-100">
              {recent.data.items.map((j) => (
                <li key={j.id} className="flex items-center justify-between gap-3 py-2">
                  <Link to={`/scans/${j.id}`} className="text-sky-800 hover:underline">
                    {j.jobType === 'discovery' ? (
                      JOB_TYPE_LABELS.discovery
                    ) : (
                      <span className="capitalize">{j.profile}</span>
                    )}{' '}
                    · {formatDateTime(j.createdAt)}
                  </Link>
                  <ScanStatusBadge status={j.status} />
                </li>
              ))}
            </ul>
          ))}
        {recent.status === 'success' && recent.data.total > 5 && (
          <Link
            to={`/scans?domainId=${domain.id}`}
            className="text-xs text-sky-800 hover:underline"
          >
            All {recent.data.total} scans
          </Link>
        )}
      </div>
    </Card>
  );
}
