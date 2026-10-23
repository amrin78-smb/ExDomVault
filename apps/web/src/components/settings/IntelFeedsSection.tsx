import type { IntelFeedStatus } from '@exdomainvault/shared';
import { AlertTriangle, CheckCircle2, CircleDashed, RefreshCw } from 'lucide-react';
import { useState } from 'react';
import { api } from '../../lib/api.ts';
import { formatDateTime } from '../../lib/format.ts';
import { usePermission } from '../../lib/session.ts';
import { useRefreshableAsync } from '../../lib/use-refreshable-async.ts';
import { INTEL_FEED_DESCRIPTIONS, INTEL_FEED_LABELS } from '../software/software-format.ts';
import { Button } from '../ui/Button.tsx';
import { Card } from '../ui/Card.tsx';
import { ErrorAlert } from '../ui/ErrorAlert.tsx';
import { LoadError } from '../ui/LoadError.tsx';
import { StaleDataNotice } from '../ui/StaleDataNotice.tsx';

/**
 * Status of the public intelligence feeds behind the software checks, and a manual sync for
 * administrators (`settings:manage`). The API decides who may read the status; a 403 shows the
 * permission-denied state.
 */
export function IntelFeedsSection() {
  const canSync = usePermission('settings:manage');
  const [reloadKey, setReloadKey] = useState(0);
  const { state, stale, refreshing, retry } = useRefreshableAsync(
    (signal) => api.intel.feeds({ signal }),
    [],
    reloadKey,
  );
  const [busy, setBusy] = useState(false);
  const [syncError, setSyncError] = useState<Error | null>(null);
  const [synced, setSynced] = useState(false);

  const sync = async () => {
    setBusy(true);
    setSyncError(null);
    setSynced(false);
    try {
      await api.intel.sync();
      setSynced(true);
      setReloadKey((k) => k + 1);
    } catch (err) {
      setSyncError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="Intelligence feeds">
      <div className="space-y-4 text-sm">
        <p className="text-slate-600">
          Software checks compare self-reported versions with these public feeds. The server
          synchronises them on a schedule; matches are reported as possibly affected and need
          verification.
        </p>

        {canSync && (
          <div className="flex flex-wrap items-center gap-3">
            <Button variant="primary" onClick={sync} disabled={busy}>
              <RefreshCw className={`size-4 ${busy ? 'animate-spin' : ''}`} aria-hidden />
              {busy ? 'Syncing…' : 'Sync now'}
            </Button>
            <div aria-live="polite">
              {synced && (
                <p role="status" className="text-emerald-800">
                  Sync finished. The status below has been refreshed.
                </p>
              )}
            </div>
          </div>
        )}
        {syncError && <ErrorAlert error={syncError} title="The feeds were not synchronised" />}

        {stale && (
          <StaleDataNotice
            loadedAt={stale.loadedAt}
            error={stale.error}
            onRetry={retry}
            retrying={refreshing}
          />
        )}
        {state.status === 'loading' && (
          <p className="text-slate-500" role="status">
            Loading feed status…
          </p>
        )}
        {state.status === 'error' && (
          <LoadError
            error={state.error}
            title="Could not load the feed status"
            onRetry={retry}
            deniedTitle="Feed status is visible to administrators"
          />
        )}
        {state.status === 'success' &&
          (state.data.feeds.length === 0 ? (
            <p className="text-slate-500">No feeds configured.</p>
          ) : (
            <ul className="divide-y divide-slate-100 rounded-md border border-slate-200">
              {state.data.feeds.map((f) => (
                <FeedRow key={f.feed} feed={f} />
              ))}
            </ul>
          ))}
      </div>
    </Card>
  );
}

function FeedState({ feed }: { feed: IntelFeedStatus }) {
  if (feed.lastError) {
    return (
      <span className="inline-flex items-center gap-1 text-xs font-medium text-red-800">
        <AlertTriangle className="size-3.5" aria-hidden />
        Last attempt failed
      </span>
    );
  }
  if (!feed.lastSuccessAt) {
    return (
      <span className="inline-flex items-center gap-1 text-xs font-medium text-slate-600">
        <CircleDashed className="size-3.5" aria-hidden />
        Never synchronised
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-800">
      <CheckCircle2 className="size-3.5" aria-hidden />
      Up to date
    </span>
  );
}

function FeedRow({ feed }: { feed: IntelFeedStatus }) {
  const label = INTEL_FEED_LABELS[feed.feed];
  return (
    <li className="space-y-2 p-3" aria-label={label}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <div className="font-medium text-slate-900">{label}</div>
          <div className="text-xs text-slate-500">{INTEL_FEED_DESCRIPTIONS[feed.feed]}</div>
        </div>
        <FeedState feed={feed} />
      </div>
      <dl className="grid gap-x-6 gap-y-1 text-xs sm:grid-cols-2 lg:grid-cols-4">
        <div>
          <dt className="text-slate-500">Last success</dt>
          <dd className="text-slate-800">
            {feed.lastSuccessAt ? formatDateTime(feed.lastSuccessAt) : 'Never'}
          </dd>
        </div>
        <div>
          <dt className="text-slate-500">Last attempt</dt>
          <dd className="text-slate-800">
            {feed.lastAttemptAt ? formatDateTime(feed.lastAttemptAt) : 'Never'}
          </dd>
        </div>
        <div>
          <dt className="text-slate-500">Items held</dt>
          <dd className="tabular-nums text-slate-800">{feed.items}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Source version</dt>
          <dd className="font-mono text-slate-800">{feed.sourceVersion ?? '—'}</dd>
        </div>
      </dl>
      {feed.feed === 'nvd' && (
        <p className="text-xs text-slate-600">
          {feed.pending === 0
            ? 'No known-exploited CVEs are waiting for their NVD record.'
            : `${feed.pending} known-exploited CVE${feed.pending === 1 ? ' is' : 's are'} waiting for their NVD record (fetched gradually within NVD rate limits).`}
        </p>
      )}
      {feed.lastError && (
        <p className="rounded border border-red-200 bg-red-50 px-2 py-1 text-xs text-red-800">
          Error: <span className="font-mono">{feed.lastError}</span>
        </p>
      )}
    </li>
  );
}
