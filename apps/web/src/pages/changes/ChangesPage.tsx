import { CHANGE_KINDS, CHANGE_KIND_LABELS } from '@exdomainvault/shared';
import { History, X } from 'lucide-react';
import { ChangeTimeline } from '../../components/changes/ChangeTimeline.tsx';
import { changesSummary } from '../../components/changes/format.ts';
import {
  DomainFilter,
  SelectFilter,
  inputClass,
} from '../../components/inventory/FilterControls.tsx';
import { ListBody } from '../../components/inventory/ListBody.tsx';
import { useListParams } from '../../components/inventory/use-list-params.ts';
import { Card } from '../../components/ui/Card.tsx';
import { PageHeader } from '../../components/ui/PageHeader.tsx';
import { api } from '../../lib/api.ts';
import { useRefreshableAsync } from '../../lib/use-refreshable-async.ts';

const DAY_MS = 86_400_000;
const DEFAULT_DAYS = '30';
const RANGES = [
  { value: '7', label: 'Last 7 days' },
  { value: '30', label: 'Last 30 days' },
  { value: '90', label: 'Last 90 days' },
  { value: '365', label: 'Last 12 months' },
  { value: 'custom', label: 'Custom dates' },
];
const KINDS = [
  { value: '', label: 'All kinds' },
  ...CHANGE_KINDS.map((k) => ({ value: k, label: CHANGE_KIND_LABELS[k] })),
];
const IMPORTANCE = [
  { value: '', label: 'All' },
  { value: 'notable', label: 'Notable and important' },
  { value: 'important', label: 'Important only' },
];
const FILTER_KEYS = ['kind', 'importance', 'domainId', 'assetId', 'from', 'to'] as const;

const DATE = /^\d{4}-\d{2}-\d{2}$/;
/** Start of a YYYY-MM-DD day (UTC) as ISO, or undefined when not a date. */
const dayStart = (v: string | undefined, plusDays = 0) =>
  v && DATE.test(v) && !Number.isNaN(Date.parse(`${v}T00:00:00Z`))
    ? new Date(Date.parse(`${v}T00:00:00Z`) + plusDays * DAY_MS).toISOString()
    : undefined;

/**
 * Change timeline: what changed between successful scans, across the portfolio (asset owners:
 * their assets). Filters, range and page live in the URL. `days` presets compute `since` when the
 * list loads; custom dates are whole UTC days (`to` inclusive).
 */
export function ChangesPage() {
  const { params, get, setParam } = useListParams();
  const requested = get('days');
  const days =
    requested && RANGES.some((r) => r.value === requested)
      ? requested
      : get('from') || get('to')
        ? 'custom'
        : DEFAULT_DAYS;
  const custom = days === 'custom';
  const list = useRefreshableAsync(
    (signal) => {
      // The default period is the server's default window (no `since`).
      const since = custom
        ? dayStart(get('from'))
        : days === DEFAULT_DAYS
          ? undefined
          : new Date(Date.now() - Number(days) * DAY_MS).toISOString();
      return api.changes(
        {
          kind: get('kind'),
          importance: get('importance'),
          domainId: get('domainId'),
          assetId: get('assetId'),
          since,
          until: custom ? dayStart(get('to'), 1) : undefined,
          page: get('page'),
        },
        { signal },
      );
    },
    [params.toString()],
  );
  const data = list.state.status === 'success' ? list.state.data : undefined;
  const filtered = FILTER_KEYS.some((k) => params.get(k));
  const assetId = get('assetId');
  const assetName = assetId ? data?.items.find((e) => e.assetId === assetId)?.hostname : undefined;

  return (
    <>
      <PageHeader
        title="Changes"
        description="What changed between successful scans: DNS records, addresses, certificates, HTTP responses, ports, reported software, registration and assets. Failed or partial scans are never compared. Importance is a hint for reading, not a finding severity."
      />
      <Card>
        <div className="mb-4 flex flex-wrap items-end gap-3">
          <SelectFilter
            label="Kind"
            value={get('kind') ?? ''}
            options={KINDS}
            onChange={(v) => setParam('kind', v)}
          />
          <SelectFilter
            label="Importance"
            value={get('importance') ?? ''}
            options={IMPORTANCE}
            onChange={(v) => setParam('importance', v)}
          />
          <SelectFilter
            label="Period"
            value={days}
            options={RANGES}
            onChange={(v) => setParam('days', v === DEFAULT_DAYS ? '' : v)}
          />
          {custom && (
            <>
              <DateInput
                label="From"
                value={get('from') ?? ''}
                onChange={(v) => setParam('from', v)}
              />
              <DateInput label="To" value={get('to') ?? ''} onChange={(v) => setParam('to', v)} />
            </>
          )}
          <DomainFilter
            value={get('domainId') ?? ''}
            fallbackLabel={data?.items.find((e) => e.domain.id === get('domainId'))?.domain.fqdn}
            onChange={(v) => setParam('domainId', v)}
          />
          {assetId && (
            <button
              type="button"
              onClick={() => setParam('assetId', '')}
              className="inline-flex items-center gap-1 rounded-full border border-line-strong bg-surface-2 px-2.5 py-1 text-xs text-fg-2 hover:bg-surface-3"
            >
              Asset: <span className="font-mono">{assetName ?? 'selected asset'}</span>
              <X className="size-3" aria-hidden />
              <span className="sr-only">Remove asset filter</span>
            </button>
          )}
        </div>
        {data && data.total > 0 && (
          <p className="mb-3 text-xs text-fg-subtle" aria-live="polite">
            {changesSummary(data)}
            {data.counts.notable > 0 && data.counts.important > 0
              ? ` · ${data.counts.notable} notable`
              : ''}
          </p>
        )}
        <ListBody
          list={list}
          noun="changes"
          columns={3}
          onPage={(p) => setParam('page', String(p))}
          empty={
            filtered
              ? {
                  title: 'No changes match these filters',
                  icon: History,
                  body: 'Try another kind, a lower importance or a longer period.',
                }
              : {
                  title: 'No changes in this period',
                  icon: History,
                  body: 'Changes appear once a host has been scanned successfully at least twice and something differs between the two scans.',
                }
          }
        >
          {(page) => <ChangeTimeline items={page.items} />}
        </ListBody>
      </Card>
    </>
  );
}

function DateInput({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <label className="text-xs text-fg-muted">
      <span className="mb-1 block">{label}</span>
      <input
        type="date"
        className={`${inputClass} px-2`}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </label>
  );
}
