import type { Domain } from '@exdomainvault/shared';
import { useState } from 'react';
import { Link } from 'react-router';
import { api } from '../../lib/api.ts';
import { usePermission } from '../../lib/session.ts';
import { Button } from '../ui/Button.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';

/**
 * Brand monitoring (lookalike domains, Milestone 15) for one domain: the admin switch (confirmed,
 * audited server-side) and, while it is on, "Check lookalikes now" for analysts.
 */
export function BrandMonitoringSection({
  domain,
  onSaved,
}: {
  domain: Domain;
  onSaved: (d: Domain) => void;
}) {
  const canWrite = usePermission('domains:write');
  const canRequest = usePermission('scans:request');
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [queued, setQueued] = useState<string | null>(null);
  const on = domain.brandMonitoring;

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setBusy(false);
    }
  };

  const toggle = () =>
    run(async () => {
      const res = await api.domains.update(domain.id, { brandMonitoring: !on });
      setConfirming(false);
      setQueued(null);
      onSaved(res.domain);
    });

  const checkNow = () =>
    run(async () => {
      const res = await api.lookalikes.check(domain.id);
      setQueued(
        res.created
          ? 'Lookalike check queued.'
          : 'A lookalike check is already queued or running for this domain.',
      );
    });

  return (
    <div className="mt-5 border-t border-line-soft pt-4 text-sm">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="font-medium text-fg">
            Brand monitoring (lookalike domains) is {on ? 'on' : 'off'}
          </p>
          <p className="text-xs text-fg-subtle">
            Weekly check whether look-alike names of {domain.fqdn} (typos, look-alike characters,
            other top-level domains) are registered, through public DNS resolvers only. The
            lookalike names are never visited or scanned.{' '}
            <Link to={`/lookalikes?domainId=${domain.id}`} className="text-sky-800 hover:underline">
              View lookalikes
            </Link>
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {on && canRequest && (
            <Button onClick={checkNow} disabled={busy}>
              Check lookalikes now
            </Button>
          )}
          {canWrite && !confirming && (
            <Button onClick={() => setConfirming(true)} disabled={busy}>
              {on ? 'Turn off brand monitoring' : 'Turn on brand monitoring'}
            </Button>
          )}
        </div>
      </div>
      {confirming && (
        <div
          role="alertdialog"
          aria-label="Confirm brand monitoring change"
          className="mt-3 rounded-md border border-line bg-surface-2 p-3"
        >
          <p className="text-fg-2">
            {on
              ? `Stop lookalike monitoring for ${domain.fqdn}? Existing results are kept.`
              : `Start lookalike monitoring for ${domain.fqdn}? About a few hundred look-alike names are checked weekly through public DNS resolvers.`}
          </p>
          <div className="mt-3 flex gap-2">
            <Button variant={on ? 'danger' : 'primary'} onClick={toggle} disabled={busy}>
              {on ? 'Turn off' : 'Turn on'}
            </Button>
            <Button onClick={() => setConfirming(false)} disabled={busy}>
              Cancel
            </Button>
          </div>
        </div>
      )}
      {queued && (
        <p className="mt-2 text-sm text-emerald-700" role="status">
          {queued}
        </p>
      )}
      {error && (
        <div className="mt-3">
          <ErrorAlert error={error} />
        </div>
      )}
    </div>
  );
}
