import {
  LOOKALIKE_TECHNIQUES,
  LOOKALIKE_TECHNIQUE_LABELS,
  type LookalikeItem,
  type LookalikeListResponse,
} from '@exdomainvault/shared';
import { Mail, ScanSearch } from 'lucide-react';
import { Link } from 'react-router';
import {
  DomainFilter,
  SearchForm,
  SelectFilter,
} from '../../components/inventory/FilterControls.tsx';
import {
  ListBody,
  TableFrame,
  linkClass,
  tdClass,
  thClass,
  theadRowClass,
} from '../../components/inventory/ListBody.tsx';
import { RelativeTime } from '../../components/inventory/RelativeTime.tsx';
import { StatusTabs } from '../../components/inventory/StatusTabs.tsx';
import { useListParams } from '../../components/inventory/use-list-params.ts';
import { Card } from '../../components/ui/Card.tsx';
import { PageHeader } from '../../components/ui/PageHeader.tsx';
import { SeverityBadge } from '../../components/ui/SeverityBadge.tsx';
import { StatCard } from '../../components/ui/StatCard.tsx';
import { api } from '../../lib/api.ts';
import { formatDate } from '../../lib/format.ts';
import { useRefreshableAsync } from '../../lib/use-refreshable-async.ts';

const TABS = [
  { value: 'true', label: 'Registered' },
  { value: 'false', label: 'No longer registered' },
  { value: 'all', label: 'All' },
] as const;
const TECHNIQUE_OPTIONS = [
  { value: '', label: 'All techniques' },
  ...LOOKALIKE_TECHNIQUES.map((t) => ({ value: t, label: LOOKALIKE_TECHNIQUE_LABELS[t] })),
];
const FILTER_KEYS = ['domainId', 'q', 'technique'] as const;
const COLUMNS = 7;

/**
 * Lookalike domains (Milestone 15): registered look-alikes of domains with brand monitoring on,
 * found weekly through public resolvers. The lookalikes themselves are never contacted.
 */
export function LookalikesPage() {
  const { params, get, setParam } = useListParams();
  const registered = get('registered') ?? 'true';
  const query = {
    registered: registered === 'all' ? undefined : registered,
    domainId: get('domainId'),
    technique: get('technique'),
    q: get('q'),
    page: get('page'),
  };
  const list = useRefreshableAsync(
    (signal) => api.lookalikes.list(query, { signal }),
    [params.toString()],
  );
  const data = list.state.status === 'success' ? list.state.data : undefined;
  const summary = data?.summary;
  const filtered = FILTER_KEYS.some((k) => params.get(k)) || registered !== 'true';
  const domainId = get('domainId') ?? '';

  return (
    <>
      <PageHeader
        title="Lookalike domains"
        description="Names that look like your domains (typing mistakes, look-alike characters, other top-level domains) and are registered by someone. Checked weekly through public DNS resolvers for domains with brand monitoring on; the lookalike names are never visited or scanned."
      />
      <div className="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label="Candidates checked"
          value={summary ? summary.candidatesChecked : null}
          hint={
            summary
              ? summary.lastCheckedAt
                ? `Last complete check ${formatDate(summary.lastCheckedAt)}`
                : 'No complete check yet'
              : undefined
          }
        />
        <StatCard
          label="Registered"
          value={summary ? summary.registered : null}
          hint={summary ? `${summary.domainsMonitored} domains monitored` : undefined}
        />
        <StatCard
          label="With mail servers"
          value={summary ? summary.withMail : null}
          hint="Can receive and likely send e-mail"
        />
        <StatCard
          label="New this week"
          value={summary ? summary.newThisWeek : null}
          hint="First seen in the last 7 days"
        />
      </div>
      <Card>
        <StatusTabs
          label="Registration state"
          value={registered}
          onChange={(v) => setParam('registered', v === 'true' ? '' : v)}
          tabs={TABS}
        />
        <div className="my-4 flex flex-wrap items-end gap-3">
          <SearchForm
            id="lookalike-search"
            label="Search lookalike domains"
            placeholder="Lookalike name"
            value={get('q') ?? ''}
            onSearch={(v) => setParam('q', v)}
          />
          <DomainFilter
            value={domainId}
            fallbackLabel={data?.items.find((i) => i.domain.id === domainId)?.domain.fqdn}
            onChange={(v) => setParam('domainId', v)}
          />
          <SelectFilter
            label="Technique"
            value={get('technique') ?? ''}
            options={TECHNIQUE_OPTIONS}
            onChange={(v) => setParam('technique', v)}
          />
        </div>
        <ListBody
          list={list}
          noun="lookalike domains"
          columns={COLUMNS}
          onPage={(p) => setParam('page', String(p))}
          empty={emptyState(filtered, summary)}
        >
          {(page) => <LookalikesTable items={page.items} />}
        </ListBody>
      </Card>
    </>
  );
}

function emptyState(filtered: boolean, summary: LookalikeListResponse['summary'] | undefined) {
  if (summary && summary.domainsMonitored === 0) {
    return {
      title: 'Brand monitoring is not on for any domain',
      icon: ScanSearch,
      body: (
        <>
          An administrator can turn on <strong>Brand monitoring (lookalike domains)</strong> in the
          Ownership and monitoring card of a{' '}
          <Link to="/domains" className={linkClass}>
            domain page
          </Link>
          . Its lookalike names are then checked weekly through public DNS resolvers only.
        </>
      ),
    };
  }
  if (filtered) {
    return {
      title: 'No lookalike domains match these filters',
      icon: ScanSearch,
      body: 'Try another tab or clear the filters.',
    };
  }
  return {
    title: 'No registered lookalike domains found',
    icon: ScanSearch,
    body: summary?.lastCheckedAt
      ? 'None of the generated lookalike names is registered.'
      : 'The first weekly check has not completed yet. You can start one from the domain page.',
  };
}

function Records({ item }: { item: LookalikeItem }) {
  const rows: [string, string[]][] = [
    ['A', [...item.records.A, ...item.records.AAAA]],
    ['MX', item.records.MX],
    ['NS', item.records.NS],
  ];
  const shown = rows.filter(([, v]) => v.length > 0);
  if (shown.length === 0) return <span className="text-fg-faint">—</span>;
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-2 text-xs">
      {shown.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="font-medium text-fg-subtle">{k}</dt>
          <dd className="break-all font-mono text-fg-2" title={v.join(', ')}>
            {v.slice(0, 2).join(', ')}
            {v.length > 2 && <span className="text-fg-faint"> +{v.length - 2}</span>}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function LookalikesTable({ items }: { items: LookalikeItem[] }) {
  return (
    <TableFrame caption="Lookalike domains, latest observation per name">
      <thead>
        <tr className={theadRowClass}>
          <th scope="col" className={thClass}>
            Lookalike
          </th>
          <th scope="col" className={thClass}>
            Looks like
          </th>
          <th scope="col" className={thClass}>
            Technique
          </th>
          <th scope="col" className={thClass}>
            Records
          </th>
          <th scope="col" className={thClass}>
            Registered since
          </th>
          <th scope="col" className={thClass}>
            Finding
          </th>
          <th scope="col" className={`${thClass} pr-0`}>
            Last checked
          </th>
        </tr>
      </thead>
      <tbody>
        {items.map((i) => (
          <tr
            key={`${i.domain.id}:${i.candidate}`}
            className="border-t border-line-soft first:border-t-0"
          >
            <th scope="row" className={`${tdClass} text-left font-normal`}>
              <span className="break-all font-mono text-fg">{i.candidate}</span>
              <div className="mt-1 flex flex-wrap gap-1">
                {i.hasMail && (
                  <span className="inline-flex items-center gap-1 rounded-full bg-amber-50 px-2 py-0.5 text-xs font-medium text-amber-900 ring-1 ring-inset ring-amber-600/30">
                    <Mail className="size-3" aria-hidden />
                    Mail
                  </span>
                )}
                {i.state === 'gone' && (
                  <span className="rounded-full bg-surface-3 px-2 py-0.5 text-xs text-fg-muted">
                    No longer registered
                  </span>
                )}
              </div>
            </th>
            <td className={`${tdClass} whitespace-nowrap`}>
              <Link to={`/domains/${i.domain.id}`} className={`${linkClass} font-mono`}>
                {i.domain.fqdn}
              </Link>
            </td>
            <td className={tdClass}>
              <span className="whitespace-nowrap rounded-md border border-line bg-surface-2 px-1.5 py-0.5 text-xs text-fg-2">
                {LOOKALIKE_TECHNIQUE_LABELS[i.technique]}
              </span>
            </td>
            <td className={`${tdClass} max-w-72`}>
              <Records item={i} />
            </td>
            <td className={`${tdClass} whitespace-nowrap text-xs text-fg-muted`}>
              {formatDate(i.firstSeenAt)}
            </td>
            <td className={tdClass}>
              {i.finding ? (
                <Link
                  to={`/findings/${i.finding.id}`}
                  className="inline-flex items-center gap-1"
                  aria-label={`Finding for ${i.candidate} (${i.finding.status.replace(/_/g, ' ')})`}
                >
                  <SeverityBadge severity={i.finding.severity} />
                  {i.finding.status === 'resolved' && (
                    <span className="text-xs text-fg-subtle">resolved</span>
                  )}
                </Link>
              ) : (
                <span className="text-xs text-fg-faint">—</span>
              )}
            </td>
            <td className={`${tdClass} pr-0 text-xs text-fg-muted`}>
              {i.lastCheckedAt ? <RelativeTime iso={i.lastCheckedAt} /> : '—'}
            </td>
          </tr>
        ))}
      </tbody>
    </TableFrame>
  );
}
