import {
  CERTIFICATE_EXPIRING_DAYS,
  type CertificateItem,
  type CertificateStatus,
} from '@exdomainvault/shared';
import { ChevronRight, FileLock2 } from 'lucide-react';
import { Fragment, useState } from 'react';
import { Link } from 'react-router';
import {
  CertificateStatusChip,
  DaysLeftPill,
} from '../../components/inventory/CertificateBadges.tsx';
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
import { ipPort } from '../../components/inventory/format.ts';
import { useListParams } from '../../components/inventory/use-list-params.ts';
import { ExportCsvButton } from '../../components/reports/ExportCsvButton.tsx';
import { ScheduledScansHint } from '../../components/settings/ScheduledScansHint.tsx';
import { Card } from '../../components/ui/Card.tsx';
import { PageHeader } from '../../components/ui/PageHeader.tsx';
import { api } from '../../lib/api.ts';
import { formatDate } from '../../lib/format.ts';
import { useRefreshableAsync } from '../../lib/use-refreshable-async.ts';

const TABS: readonly { value: CertificateStatus | 'all'; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'expired', label: 'Expired' },
  { value: 'expiring', label: `Expiring ≤${CERTIFICATE_EXPIRING_DAYS} days` },
  { value: 'mismatch', label: 'Mismatch' },
  { value: 'untrusted', label: 'Untrusted' },
  { value: 'valid', label: 'Valid' },
];
const DEFAULT_SORT = 'expiry';
const SORTS = [
  { value: 'expiry', label: 'Expiry (soonest first)' },
  { value: 'hostname', label: 'Hostname (A–Z)' },
];
const FILTER_KEYS = ['domainId', 'q'] as const;
const COLUMNS = 9;

export function CertificatesPage() {
  const { params, get, setParam } = useListParams();
  const status = get('status') ?? 'all';
  const query = {
    status: status === 'all' ? undefined : status,
    domainId: get('domainId'),
    q: get('q'),
    sort: get('sort'),
    page: get('page'),
  };
  const list = useRefreshableAsync(
    (signal) => api.inventory.certificates(query, { signal }),
    [params.toString()],
  );
  const data = list.state.status === 'success' ? list.state.data : undefined;
  const filtered = FILTER_KEYS.some((k) => params.get(k)) || status !== 'all';
  const domainId = get('domainId') ?? '';
  const counts = data?.counts;
  const countOf = (value: CertificateStatus | 'all') =>
    counts === undefined
      ? undefined
      : value === 'all'
        ? Object.values(counts).reduce((sum, n) => sum + n, 0)
        : (counts[value] ?? 0);

  return (
    <>
      <PageHeader
        title="Certificates"
        description={`TLS certificates presented by your hosts in the last 90 days: who issued them, when they expire, and whether they match the hostname and chain to a trusted root. "Expiring" means within ${CERTIFICATE_EXPIRING_DAYS} days.`}
        actions={<ExportCsvButton resource="certificates" filters={query} />}
      />
      <Card>
        <StatusTabs
          label="Certificate status"
          value={status}
          onChange={(v) => setParam('status', v === 'all' ? '' : v)}
          tabs={TABS.map((t) => ({ ...t, count: countOf(t.value) }))}
        />
        <div className="my-4 flex flex-wrap items-end gap-3">
          <SearchForm
            id="certificate-search"
            label="Search certificates"
            placeholder="Hostname, issuer or subject"
            value={get('q') ?? ''}
            onSearch={(v) => setParam('q', v)}
          />
          <DomainFilter
            value={domainId}
            fallbackLabel={data?.items.find((c) => c.domain.id === domainId)?.domain.fqdn}
            onChange={(v) => setParam('domainId', v)}
          />
          <SelectFilter
            label="Sort by"
            value={get('sort') ?? DEFAULT_SORT}
            options={SORTS}
            onChange={(v) => setParam('sort', v === DEFAULT_SORT ? '' : v)}
          />
        </div>
        <ListBody
          list={list}
          noun="certificates"
          columns={COLUMNS}
          onPage={(p) => setParam('page', String(p))}
          empty={
            filtered
              ? {
                  title: 'No certificates match these filters',
                  icon: FileLock2,
                  body: 'Try another status tab or clear the filters.',
                }
              : {
                  title: 'No certificates observed yet',
                  icon: FileLock2,
                  body: (
                    <>
                      Certificates are read by the TLS check of a <strong>Quick</strong> scan or
                      higher on approved hostnames. Run one from a{' '}
                      <Link to="/domains" className={linkClass}>
                        domain page
                      </Link>
                      .
                      <ScheduledScansHint />
                    </>
                  ),
                }
          }
        >
          {(page) => <CertificatesTable items={page.items} />}
        </ListBody>
      </Card>
    </>
  );
}

const certKey = (c: CertificateItem) => `${c.hostname}:${c.port}`;

function CertificatesTable({ items }: { items: CertificateItem[] }) {
  const [open, setOpen] = useState<ReadonlySet<string>>(new Set());
  const toggle = (key: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  return (
    <TableFrame caption="Certificates, latest observation per hostname and port">
      <thead>
        <tr className={theadRowClass}>
          <th scope="col" className={thClass}>
            Hostname
          </th>
          <th scope="col" className={thClass}>
            Domain
          </th>
          <th scope="col" className={thClass}>
            Issuer
          </th>
          <th scope="col" className={thClass}>
            Valid
          </th>
          <th scope="col" className={thClass}>
            Expiry
          </th>
          <th scope="col" className={thClass}>
            Status
          </th>
          <th scope="col" className={thClass}>
            Protocol
          </th>
          <th scope="col" className={thClass}>
            Address
          </th>
          <th scope="col" className={`${thClass} pr-0`}>
            Observed
          </th>
        </tr>
      </thead>
      <tbody>
        {items.map((c) => {
          const key = certKey(c);
          const expanded = open.has(key);
          const detailId = `cert-${key.replace(/[^a-zA-Z0-9-]/g, '-')}`;
          return (
            <Fragment key={key}>
              <tr className="border-t border-line-soft first:border-t-0">
                <th scope="row" className={`${tdClass} text-left font-normal`}>
                  <div className="flex items-start gap-1">
                    <button
                      type="button"
                      onClick={() => toggle(key)}
                      aria-expanded={expanded}
                      aria-controls={detailId}
                      aria-label={`${expanded ? 'Hide' : 'Show'} certificate details for ${c.hostname}:${c.port}`}
                      className="mt-0.5 rounded p-0.5 text-fg-faint hover:bg-surface-3 hover:text-fg"
                    >
                      <ChevronRight
                        className={`size-4 transition-transform ${expanded ? 'rotate-90' : ''}`}
                        aria-hidden
                      />
                    </button>
                    <div className="min-w-0">
                      {c.assetId ? (
                        <Link to={`/assets/${c.assetId}`} className={`${linkClass} font-mono`}>
                          {c.hostname}
                        </Link>
                      ) : (
                        <span className="font-mono text-fg">{c.hostname}</span>
                      )}
                      {c.port !== 443 && (
                        <span className="font-mono text-fg-subtle">:{c.port}</span>
                      )}
                    </div>
                  </div>
                </th>
                <td className={`${tdClass} whitespace-nowrap`}>
                  <Link to={`/domains/${c.domain.id}`} className={`${linkClass} font-mono`}>
                    {c.domain.fqdn}
                  </Link>
                </td>
                <td
                  className={`${tdClass} max-w-56 truncate text-fg-2`}
                  title={c.issuer ?? undefined}
                >
                  {c.issuer ?? <span className="text-fg-faint">Unknown</span>}
                </td>
                <td className={`${tdClass} whitespace-nowrap text-xs text-fg-muted`}>
                  {c.notBefore ? formatDate(c.notBefore) : '?'} –{' '}
                  {c.notAfter ? formatDate(c.notAfter) : '?'}
                </td>
                <td className={tdClass}>
                  <DaysLeftPill daysLeft={c.daysLeft} />
                </td>
                <td className={tdClass}>
                  <CertificateStatusChip status={c.status} />
                </td>
                <td className={`${tdClass} whitespace-nowrap text-xs text-fg-2`}>
                  {c.protocolVersion ?? <span className="text-fg-faint">—</span>}
                </td>
                <td className={`${tdClass} whitespace-nowrap font-mono text-xs text-fg-2`}>
                  {c.ipAddress ? ipPort(c.ipAddress, c.port) : '—'}
                </td>
                <td className={`${tdClass} pr-0 text-xs text-fg-muted`}>
                  <RelativeTime iso={c.observedAt} />
                </td>
              </tr>
              <tr id={detailId} hidden={!expanded}>
                <td colSpan={COLUMNS} className="pb-3 pl-7 pr-0">
                  {expanded && <CertificateDetail c={c} />}
                </td>
              </tr>
            </Fragment>
          );
        })}
      </tbody>
    </TableFrame>
  );
}

const yesNoUnknown = (v: boolean | null, yes: string, no: string) =>
  v === null ? 'Not recorded' : v ? yes : no;

function CertificateDetail({ c }: { c: CertificateItem }) {
  return (
    <dl className="grid gap-x-6 gap-y-2 rounded-lg border border-line bg-surface-2 p-3 text-xs sm:grid-cols-[max-content_1fr]">
      <dt className="text-fg-subtle">Subject</dt>
      <dd className="break-all font-mono text-fg-2">{c.subject ?? 'Not recorded'}</dd>
      <dt className="text-fg-subtle">Issuer</dt>
      <dd className="break-all font-mono text-fg-2">{c.issuer ?? 'Not recorded'}</dd>
      <dt className="text-fg-subtle">Subject alternative names</dt>
      <dd>
        {c.subjectAltNames.length === 0 ? (
          <span className="text-fg-faint">None recorded</span>
        ) : (
          <ul className="flex flex-wrap gap-1">
            {c.subjectAltNames.map((san) => (
              <li
                key={san}
                className="rounded border border-line bg-surface px-1.5 py-0.5 font-mono text-fg-2"
              >
                {san}
              </li>
            ))}
          </ul>
        )}
      </dd>
      <dt className="text-fg-subtle">Hostname match</dt>
      <dd className="text-fg-2">{yesNoUnknown(c.hostnameMatches, 'Matches', 'Does not match')}</dd>
      <dt className="text-fg-subtle">Chain</dt>
      <dd className="text-fg-2">{yesNoUnknown(c.trusted, 'Trusted', 'Not trusted')}</dd>
    </dl>
  );
}
