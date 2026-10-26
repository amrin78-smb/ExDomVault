import type { Domain, ScanProfile } from '@exdomainvault/shared';
import { Loader2, Search, X } from 'lucide-react';
import { useEffect, useId, useRef, useState, type FormEvent, type KeyboardEvent } from 'react';
import { useNavigate } from 'react-router';
import { api } from '../../lib/api.ts';
import { useAsync } from '../../lib/use-async.ts';
import { VerificationBadge } from '../domains/DomainBadges.tsx';
import { isScanPickerProfile, unavailableReason } from '../scans/labels.ts';
import { Button } from '../ui/Button.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';

/** Wait this long after the last keystroke before searching domains. */
export const DOMAIN_SEARCH_DEBOUNCE_MS = 250;

/** Domains a scan can be requested for here: monitored, or verified for active checks. */
const eligible = (d: Domain) => d.monitoringEnabled || d.verificationStatus === 'verified';

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

/** First profile usable for the domain (passive first when available). */
function firstUsable(profiles: ScanProfile[], domain: Domain, active: boolean): string | null {
  const usable = profiles.filter((p) => unavailableReason(p, domain, active) === null);
  return (usable.find((p) => p.key === 'passive') ?? usable[0])?.key ?? null;
}

/**
 * Request a scan of one domain: search monitored/verified domains, pick a profile (profiles the
 * domain is not eligible for are disabled with the reason, as on the domain page), submit, then
 * follow the queued job. The server re-checks scope and eligibility on every request.
 */
export function RunScanDialog({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const q = useDebounced(query.trim(), DOMAIN_SEARCH_DEBOUNCE_MS);
  const domains = useAsync(
    (signal) => api.domains.list({ q: q || undefined, pageSize: 25 }, { signal }),
    [q],
  );
  const profiles = useAsync((signal) => api.scanProfiles({ signal }), []);
  const [domain, setDomain] = useState<Domain | null>(null);
  const [profile, setProfile] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const panelRef = useRef<HTMLFormElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const titleId = useId();

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    inputRef.current?.focus();
    return () => previous?.focus?.();
  }, []);

  const pickable =
    profiles.status === 'success' ? profiles.data.items.filter(isScanPickerProfile) : [];
  const activeEnabled = profiles.status === 'success' && profiles.data.activeScanningEnabled;
  const options = domains.status === 'success' ? domains.data.items.filter(eligible) : [];

  const choose = (d: Domain) => {
    setDomain(d);
    const current = pickable.find((p) => p.key === profile);
    if (!current || unavailableReason(current, d, activeEnabled) !== null) {
      setProfile(firstUsable(pickable, d, activeEnabled));
    }
  };

  const selectedProfile = pickable.find((p) => p.key === profile);
  const canSubmit =
    domain !== null &&
    selectedProfile !== undefined &&
    unavailableReason(selectedProfile, domain, activeEnabled) === null &&
    !busy;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit || !domain || !profile) return;
    setBusy(true);
    setError(null);
    try {
      const { job } = await api.domains.requestScan(domain.id, { profile });
      onClose();
      void navigate(`/scans/${job.id}`);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
      setBusy(false);
    }
  };

  const onKeyDown = (e: KeyboardEvent<HTMLFormElement>) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      onClose();
    } else if (e.key === 'Tab') {
      // Focus trap between the dialog's own controls.
      const focusables = Array.from(
        panelRef.current?.querySelectorAll<HTMLElement>(
          'input:not([disabled]), select:not([disabled]), button:not([disabled])',
        ) ?? [],
      );
      const first = focusables[0];
      const last = focusables.at(-1);
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last?.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first?.focus();
      }
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center px-4 pt-[10vh]">
      <div
        className="absolute inset-0 bg-[#020617]/60 backdrop-blur-sm"
        aria-hidden
        onClick={onClose}
      />
      <form
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onKeyDown={onKeyDown}
        onSubmit={(e) => void submit(e)}
        className="relative w-full max-w-lg overflow-hidden rounded-xl border border-line bg-surface shadow-pop"
      >
        <div className="flex items-center justify-between border-b border-line px-4 py-3">
          <h2 id={titleId} className="text-base font-semibold text-fg">
            Run scan
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="rounded-md p-1 text-fg-subtle hover:bg-surface-3 hover:text-fg"
            aria-label="Close"
          >
            <X className="size-4" aria-hidden />
          </button>
        </div>

        <div className="space-y-4 p-4 text-sm">
          <fieldset className="space-y-2">
            <legend className="mb-1 text-xs font-medium text-fg-muted">Domain</legend>
            <div className="flex items-center gap-2 rounded-lg border border-line-strong bg-surface px-2">
              <Search className="size-4 shrink-0 text-fg-subtle" aria-hidden />
              <input
                ref={inputRef}
                type="search"
                aria-label="Search domains"
                placeholder="Search monitored domains…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                maxLength={253}
                autoComplete="off"
                spellCheck={false}
                className="h-9 min-w-0 flex-1 bg-transparent text-fg placeholder:text-fg-faint focus:outline-none"
              />
              {domains.status === 'loading' && (
                <Loader2 className="size-4 animate-spin text-fg-subtle" aria-hidden />
              )}
            </div>
            <div className="max-h-56 overflow-y-auto rounded-lg border border-line-soft">
              {domains.status === 'error' && (
                <div className="p-2">
                  <ErrorAlert error={domains.error} title="Could not load domains" />
                </div>
              )}
              {domains.status === 'success' && options.length === 0 && (
                <p className="px-3 py-4 text-center text-xs text-fg-subtle">
                  {q
                    ? `No monitored or verified domain matches “${q}”.`
                    : 'No monitored or verified domains yet.'}
                </p>
              )}
              <ul className="divide-y divide-line-soft">
                {options.map((d) => (
                  <li key={d.id}>
                    <label className="flex cursor-pointer items-center gap-3 px-3 py-2 hover:bg-surface-2 has-checked:bg-accent-soft">
                      <input
                        type="radio"
                        name="domain"
                        value={d.id}
                        checked={domain?.id === d.id}
                        onChange={() => choose(d)}
                        className="accent-accent"
                      />
                      <span className="min-w-0 flex-1 truncate font-mono text-fg">{d.fqdn}</span>
                      <VerificationBadge
                        status={d.verificationStatus}
                        method={d.verificationMethod}
                      />
                    </label>
                  </li>
                ))}
              </ul>
            </div>
          </fieldset>

          <label className="block text-xs font-medium text-fg-muted">
            <span className="mb-1 block">Profile</span>
            <select
              className="w-full rounded-md border border-line-strong bg-surface px-2 py-1.5 text-sm text-fg shadow-sm disabled:text-fg-faint"
              value={profile ?? ''}
              onChange={(e) => setProfile(e.target.value || null)}
              disabled={profiles.status !== 'success' || domain === null}
            >
              <option value="">{domain ? 'Choose a profile' : 'Choose a domain first'}</option>
              {pickable.map((p) => {
                const reason = domain ? unavailableReason(p, domain, activeEnabled) : null;
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
          {profiles.status === 'error' && (
            <ErrorAlert error={profiles.error} title="Could not load scan profiles" />
          )}
          {selectedProfile && (
            <div className="space-y-1 text-xs text-fg-subtle">
              <p>{selectedProfile.description}</p>
              {selectedProfile.config.active && (
                <p>
                  TLS and HTTP checks connect like a normal visitor; ports are probed only on
                  approved networks.
                </p>
              )}
            </div>
          )}
          {error && <ErrorAlert error={error} title="The scan was not requested" />}
        </div>

        <div className="flex justify-end gap-2 border-t border-line px-4 py-3">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={!canSubmit} aria-busy={busy}>
            {busy ? 'Requesting…' : 'Run scan'}
          </Button>
        </div>
      </form>
    </div>
  );
}
