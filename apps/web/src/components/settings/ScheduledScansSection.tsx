import type { ScanSchedule, ScanScheduleResponse } from '@exdomainvault/shared';
import { useId, useState, type FormEvent, type ReactNode } from 'react';
import { api } from '../../lib/api.ts';
import { formatDateTime } from '../../lib/format.ts';
import { usePermission } from '../../lib/session.ts';
import { useAsync } from '../../lib/use-async.ts';
import { Button } from '../ui/Button.tsx';
import { Card } from '../ui/Card.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';
import { ConfirmPanel } from './ConfirmPanel.tsx';

type Profile = ScanSchedule['profile'];

const PROFILES: { key: Profile; name: string; description: string }[] = [
  {
    key: 'quick',
    name: 'Quick',
    description:
      'DNS, registration, TLS certificate and HTTP availability of the web servers. No port probes.',
  },
  {
    key: 'standard',
    name: 'Standard',
    description:
      'Quick checks plus HTTP security headers, TCP port probes and limited service identification, only on approved networks.',
  },
];

const profileName = (key: Profile) => PROFILES.find((p) => p.key === key)?.name ?? key;
const every = (days: number) => (days === 1 ? 'every day' : `every ${days} days`);
const domains = (n: number) =>
  n === 1 ? '1 monitored, authorised domain' : `${n} monitored, authorised domains`;

const savedMessage = (s: ScanSchedule) =>
  s.enabled
    ? `Saved. Scheduled scans are on: ${profileName(s.profile)}, about ${every(s.intervalDays)}.`
    : 'Saved. Scheduled scans are off.';

function Item({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-0.5 text-slate-800">{children}</dd>
    </div>
  );
}

/**
 * Scheduled active scans (design §6). Everyone with `scans:read` sees the current state; admins
 * (`scan_policies:manage`) can change it. Turning it on or changing the profile asks for an explicit
 * confirmation that says what the worker will connect to and how often.
 */
export function ScheduledScansSection() {
  const state = useAsync((signal) => api.settings.scanSchedule.get({ signal }), []);
  const canManage = usePermission('scan_policies:manage');
  const [saved, setSaved] = useState<ScanScheduleResponse | null>(null);
  const data = saved ?? (state.status === 'success' ? state.data : null);

  return (
    <Card title="Scheduled scans">
      <div className="space-y-4 text-sm">
        <p className="text-slate-600">
          When on, every monitored domain that is authorised for active scanning is scanned about
          once per interval with the chosen profile. Off by default.
        </p>
        {state.status === 'loading' && (
          <p role="status" className="text-slate-500">
            Loading the scan schedule…
          </p>
        )}
        {state.status === 'error' && (
          <ErrorAlert error={state.error} title="Could not load the scan schedule" />
        )}
        {data && (
          <>
            {!data.activeScanningEnabled && (
              <p className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-amber-900">
                <strong>Active scanning is switched off on the server.</strong> Nothing will be
                scheduled while the server switch is off, even if scheduled scans are on here.
              </p>
            )}
            <ScheduleSummary data={data} />
            {canManage && (
              // Always rendered so the save result is announced by screen readers.
              <div role="status">
                {saved && (
                  <p className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-emerald-900">
                    {savedMessage(saved.schedule)}
                  </p>
                )}
              </div>
            )}
            {canManage ? (
              <ScheduleForm
                key={`${JSON.stringify(data.schedule)}|${data.updatedAt ?? ''}`}
                data={data}
                onSaved={setSaved}
              />
            ) : (
              <p className="text-xs text-slate-500">Only administrators can change the schedule.</p>
            )}
          </>
        )}
      </div>
    </Card>
  );
}

function ScheduleSummary({ data }: { data: ScanScheduleResponse }) {
  const s = data.schedule;
  return (
    <dl aria-label="Current schedule" className="grid gap-3 sm:grid-cols-3">
      <Item label="Status">
        <span
          className={`rounded px-1.5 py-0.5 text-xs font-medium ${
            s.enabled ? 'bg-sky-100 text-sky-900' : 'bg-slate-200 text-slate-700'
          }`}
        >
          {s.enabled ? 'On' : 'Off'}
        </span>
      </Item>
      <Item label="Profile">{profileName(s.profile)}</Item>
      <Item label="Interval">About {every(s.intervalDays)}</Item>
      <Item label="Eligible domains">{data.eligibleDomains}</Item>
      <Item label="Jobs scheduled (last 24 h)">{data.scheduledLast24h}</Item>
      <Item label="Last changed">
        {data.updatedAt ? (
          <>
            {formatDateTime(data.updatedAt)}
            {data.updatedBy && <> by {data.updatedBy.email}</>}
          </>
        ) : (
          'Never (default settings)'
        )}
      </Item>
    </dl>
  );
}

function ScheduleForm({
  data,
  onSaved,
}: {
  data: ScanScheduleResponse;
  onSaved: (r: ScanScheduleResponse) => void;
}) {
  const current = data.schedule;
  const [enabled, setEnabled] = useState(current.enabled);
  const [profile, setProfile] = useState<Profile>(current.profile);
  const [interval, setIntervalText] = useState(String(current.intervalDays));
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const intervalId = useId();
  const intervalHelpId = useId();

  const days = Number(interval);
  const intervalValid = Number.isInteger(days) && days >= 1 && days <= 30;
  const next: ScanSchedule = { enabled, profile, intervalDays: intervalValid ? days : 0 };
  const changed =
    enabled !== current.enabled ||
    profile !== current.profile ||
    (intervalValid && days !== current.intervalDays);
  const needsConfirmation = enabled && (!current.enabled || profile !== current.profile);

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      onSaved(await api.settings.scanSchedule.update(next));
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
      setConfirming(false);
    } finally {
      setBusy(false);
    }
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!intervalValid || !changed || busy) return;
    if (needsConfirmation) setConfirming(true);
    else void save();
  };

  return (
    <form
      onSubmit={submit}
      aria-label="Change the scan schedule"
      className="space-y-4 border-t border-slate-100 pt-4"
    >
      <label className="flex items-center gap-2 font-medium text-slate-700">
        <input
          type="checkbox"
          role="switch"
          checked={enabled}
          onChange={(e) => {
            setEnabled(e.target.checked);
            setConfirming(false);
          }}
          disabled={busy}
          className="size-4"
        />
        Enable scheduled scans
      </label>
      <fieldset disabled={busy}>
        <legend className="font-medium text-slate-700">Profile</legend>
        <div className="mt-1 grid gap-2 sm:grid-cols-2">
          {PROFILES.map((p) => (
            <label
              key={p.key}
              className={`flex gap-2 rounded-md border p-2 ${
                profile === p.key ? 'border-sky-300 bg-sky-50' : 'border-slate-200'
              }`}
            >
              <input
                type="radio"
                name="scan-schedule-profile"
                value={p.key}
                checked={profile === p.key}
                onChange={() => {
                  setProfile(p.key);
                  setConfirming(false);
                }}
                aria-labelledby={`scan-schedule-${p.key}-name`}
                aria-describedby={`scan-schedule-${p.key}-desc`}
                className="mt-0.5"
              />
              <span>
                <span id={`scan-schedule-${p.key}-name`} className="font-medium text-slate-900">
                  {p.name}
                </span>
                <span id={`scan-schedule-${p.key}-desc`} className="block text-xs text-slate-600">
                  {p.description}
                </span>
              </span>
            </label>
          ))}
        </div>
      </fieldset>
      <div>
        <label htmlFor={intervalId} className="block font-medium text-slate-700">
          Interval (days)
        </label>
        <input
          id={intervalId}
          type="number"
          min={1}
          max={30}
          step={1}
          required
          value={interval}
          onChange={(e) => {
            setIntervalText(e.target.value);
            setConfirming(false);
          }}
          disabled={busy}
          aria-invalid={!intervalValid}
          aria-describedby={intervalHelpId}
          className="mt-1 w-24 rounded-md border border-slate-300 px-2.5 py-1.5 text-sm shadow-sm"
        />
        <p
          id={intervalHelpId}
          className={`mt-1 text-xs ${intervalValid ? 'text-slate-500' : 'text-red-700'}`}
        >
          {intervalValid
            ? 'Each eligible domain is scanned about once per interval; jobs are spread across it.'
            : 'Enter a whole number of days from 1 to 30.'}
        </p>
      </div>
      {error && <ErrorAlert error={error} title="Could not save the scan schedule" />}
      {confirming ? (
        <ConfirmPanel
          title="Turn on scheduled active scans?"
          confirmLabel={busy ? 'Saving…' : 'Confirm and save'}
          busy={busy}
          onConfirm={() => void save()}
          onCancel={() => setConfirming(false)}
        >
          <p>
            This machine (the home scanning worker) will connect to the web servers of{' '}
            {domains(data.eligibleDomains)} about {every(days)}, using the {profileName(profile)}{' '}
            profile.
          </p>
          <p className="mt-1">
            {profile === 'standard'
              ? 'Standard also probes ports, but only on approved networks.'
              : 'Quick does not probe ports. Standard also probes ports, but only on approved networks.'}
          </p>
          {!data.activeScanningEnabled && (
            <p className="mt-1">
              Active scanning is switched off on the server, so nothing will run until it is
              switched on.
            </p>
          )}
          <p className="mt-1">You can turn it off at any time.</p>
        </ConfirmPanel>
      ) : (
        <Button type="submit" variant="primary" disabled={!changed || !intervalValid || busy}>
          {busy ? 'Saving…' : 'Save schedule'}
        </Button>
      )}
    </form>
  );
}
