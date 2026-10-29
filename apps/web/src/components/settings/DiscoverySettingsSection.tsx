import { MAX_DISCOVERY_ORG_NAMES, type DiscoverySettingsResponse } from '@exdomainvault/shared';
import { X } from 'lucide-react';
import { useState, type FormEvent, type KeyboardEvent } from 'react';
import { api } from '../../lib/api.ts';
import { formatDateTime } from '../../lib/format.ts';
import { useAsync } from '../../lib/use-async.ts';
import { Button } from '../ui/Button.tsx';
import { Card } from '../ui/Card.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';

const inputClass = 'w-full rounded-md border border-line-strong px-2.5 py-1.5 text-sm shadow-sm';

/**
 * Settings → Discovery (Milestone 15, `settings:manage`): the organisation names that mark an IP
 * network as yours when its public registry (RDAP) record names them. Matched ranges are shown on
 * the Attack Surface page and get a reverse-DNS sweep in the weekly discovery run; names found
 * there become pending assets. Nothing is ever approved or scanned because of a match.
 */
export function DiscoverySettingsSection() {
  const state = useAsync((signal) => api.settings.discovery.get({ signal }), []);
  const [saved, setSaved] = useState<DiscoverySettingsResponse | null>(null);
  const data = saved ?? (state.status === 'success' ? state.data : null);
  return (
    <Card title="Organisation names">
      <div className="space-y-4 text-sm">
        <p className="text-fg-muted">
          Weekly discovery looks up who each of your assets’ IP addresses is registered to (RIR
          RDAP: APNIC, ARIN, RIPE NCC, LACNIC, AFRINIC). A network whose registrant, organisation or
          network name matches one of these names — ignoring case, punctuation and spacing, whole
          words only — is shown as registered to your organisation, and its addresses (IPv4, up to a
          /22) are checked with reverse DNS through public resolvers. Host names found that way
          become <em>pending</em> assets for review. A match never approves a range for scanning.
        </p>
        {state.status === 'loading' && (
          <p role="status" className="text-fg-subtle">
            Loading…
          </p>
        )}
        {state.status === 'error' && (
          <ErrorAlert error={state.error} title="Could not load the discovery settings" />
        )}
        {data && (
          <>
            <div role="status">
              {saved && (
                <p className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-emerald-900">
                  Saved. Matching uses the new names immediately; reverse DNS follows with the next
                  discovery run.
                </p>
              )}
            </div>
            <OrgNamesForm
              key={`${data.orgNames.join('|')}|${data.updatedAt ?? ''}`}
              initial={data.orgNames}
              onSaved={setSaved}
            />
            <p className="text-xs text-fg-subtle">
              Last changed: {data.updatedAt ? formatDateTime(data.updatedAt) : 'never'}
            </p>
          </>
        )}
      </div>
    </Card>
  );
}

function OrgNamesForm({
  initial,
  onSaved,
}: {
  initial: string[];
  onSaved: (r: DiscoverySettingsResponse) => void;
}) {
  const [names, setNames] = useState<string[]>(initial);
  const [draft, setDraft] = useState('');
  const [hint, setHint] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const add = () => {
    const name = draft.trim().replace(/\s+/g, ' ');
    if (name === '') return;
    if (name.length < 2 || name.length > 100) {
      setHint('Names must be 2–100 characters.');
      return;
    }
    if (names.some((n) => n.toLowerCase() === name.toLowerCase())) {
      setHint(`“${name}” is already in the list.`);
      return;
    }
    if (names.length >= MAX_DISCOVERY_ORG_NAMES) {
      setHint(`At most ${MAX_DISCOVERY_ORG_NAMES} names.`);
      return;
    }
    setNames((list) => [...list, name]);
    setDraft('');
    setHint(null);
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      add();
    } else if (e.key === 'Backspace' && draft === '' && names.length > 0) {
      setNames((list) => list.slice(0, -1));
    }
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onSaved(await api.settings.discovery.update({ orgNames: names }));
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setBusy(false);
    }
  };

  const changed = names.join('\n') !== initial.join('\n');

  return (
    <form onSubmit={submit} aria-label="Organisation names" className="space-y-3">
      <ul className="flex flex-wrap gap-2" aria-label="Configured organisation names">
        {names.length === 0 && (
          <li className="text-fg-subtle">No names: no network will be shown as yours.</li>
        )}
        {names.map((n) => (
          <li
            key={n}
            className="inline-flex items-center gap-1 rounded-full border border-line-strong bg-surface-2 py-0.5 pl-3 pr-1"
          >
            {n}
            <button
              type="button"
              onClick={() => setNames((list) => list.filter((x) => x !== n))}
              className="grid size-5 place-items-center rounded-full text-fg-muted hover:bg-line"
              aria-label={`Remove ${n}`}
            >
              <X className="size-3" aria-hidden />
            </button>
          </li>
        ))}
      </ul>
      <div className="flex flex-wrap items-end gap-2">
        <label className="block min-w-60 flex-1 font-medium text-fg-2">
          Add a name
          <input
            className={`${inputClass} mt-1`}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="e.g. Thai Union"
            maxLength={100}
          />
        </label>
        <Button type="button" variant="secondary" onClick={add} disabled={draft.trim() === ''}>
          Add
        </Button>
      </div>
      {hint && <p className="text-xs text-amber-800">{hint}</p>}
      {error && <ErrorAlert error={error} title="Could not save the organisation names" />}
      <Button type="submit" variant="primary" disabled={busy || !changed}>
        {busy ? 'Saving…' : 'Save names'}
      </Button>
    </form>
  );
}
