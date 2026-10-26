import type { VulnerabilityItem } from '@exdomainvault/shared';
import { ExternalLink, ShieldAlert } from 'lucide-react';
import { Link } from 'react-router';
import { CvssChip } from '../../components/inventory/CvssChip.tsx';
import { SearchForm, SelectFilter } from '../../components/inventory/FilterControls.tsx';
import { InfoNote } from '../../components/inventory/InfoNote.tsx';
import {
  ListBody,
  TableFrame,
  linkClass,
  tdClass,
  thClass,
  theadRowClass,
} from '../../components/inventory/ListBody.tsx';
import { useListParams } from '../../components/inventory/use-list-params.ts';
import { ExportCsvButton } from '../../components/reports/ExportCsvButton.tsx';
import { Card } from '../../components/ui/Card.tsx';
import { PageHeader } from '../../components/ui/PageHeader.tsx';
import { api } from '../../lib/api.ts';
import { formatDate } from '../../lib/format.ts';
import { useRefreshableAsync } from '../../lib/use-refreshable-async.ts';

const DEFAULT_SORT = 'hosts';
const SORTS = [
  { value: 'hosts', label: 'Most affected hosts' },
  { value: 'cvss', label: 'Highest CVSS' },
  { value: 'cve', label: 'CVE ID' },
];

const badge =
  'inline-flex items-center whitespace-nowrap rounded px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ring-1 ring-inset';

const nvdUrl = (cve: string) => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`;

export function VulnerabilitiesPage() {
  const { params, get, setParam } = useListParams();
  const query = { q: get('q'), sort: get('sort'), page: get('page') };
  const list = useRefreshableAsync(
    (signal) => api.inventory.vulnerabilities(query, { signal }),
    [params.toString()],
  );
  const filtered = Boolean(params.get('q'));

  return (
    <>
      <PageHeader
        title="Vulnerabilities"
        description="CVEs in CISA's Known Exploited Vulnerabilities catalogue whose affected version ranges include a software version your hosts report."
        actions={<ExportCsvButton resource="vulnerabilities" filters={query} />}
      />
      <div className="space-y-6">
        <InfoNote label="How to read these matches" tone="caution">
          <p className="font-medium">Possibly affected — verify before acting.</p>
          <p className="mt-0.5">
            Versions come from banners; distributions often backport fixes. A match means the
            reported version falls inside the vulnerable range, not that the host is exploitable or
            compromised. Check with the system owner or the package manager first.
          </p>
        </InfoNote>
        <Card>
          <div className="mb-4 flex flex-wrap items-end gap-3">
            <SearchForm
              id="vulnerability-search"
              label="Search vulnerabilities"
              placeholder="CVE, product or title"
              value={get('q') ?? ''}
              onSearch={(v) => setParam('q', v)}
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
            noun="vulnerabilities"
            columns={7}
            onPage={(p) => setParam('page', String(p))}
            empty={
              filtered
                ? {
                    title: 'No vulnerabilities match this search',
                    icon: ShieldAlert,
                    body: 'Clear the search to see every possibly affecting CVE.',
                  }
                : {
                    title: 'No known-exploited CVEs match your software',
                    icon: ShieldAlert,
                    body: (
                      <>
                        Matches need a disclosed software version (see{' '}
                        <Link to="/software" className={linkClass}>
                          Software
                        </Link>
                        ) and the CISA KEV and NVD feeds (
                        <Link to="/settings?tab=intel" className={linkClass}>
                          Settings → Intelligence feeds
                        </Link>
                        ). Hidden versions cannot be matched, so an empty list is not proof of
                        safety.
                      </>
                    ),
                  }
            }
          >
            {(page) => <VulnerabilitiesTable items={page.items} />}
          </ListBody>
        </Card>
      </div>
    </>
  );
}

function VulnerabilitiesTable({ items }: { items: VulnerabilityItem[] }) {
  return (
    <TableFrame caption="Known-exploited CVEs possibly affecting reported software versions">
      <thead>
        <tr className={theadRowClass}>
          <th scope="col" className={thClass}>
            CVE
          </th>
          <th scope="col" className={thClass}>
            Title
          </th>
          <th scope="col" className={thClass}>
            CVSS
          </th>
          <th scope="col" className={thClass}>
            Products
          </th>
          <th scope="col" className={`${thClass} text-right`}>
            Affected
          </th>
          <th scope="col" className={`${thClass} text-right`}>
            Open findings
          </th>
          <th scope="col" className={`${thClass} pr-0`}>
            Added to KEV
          </th>
        </tr>
      </thead>
      <tbody className="divide-y divide-line-soft">
        {items.map((v) => (
          <tr key={v.cve}>
            <th scope="row" className={`${tdClass} text-left font-normal`}>
              <a
                href={nvdUrl(v.cve)}
                target="_blank"
                rel="noopener noreferrer"
                className={`${linkClass} inline-flex items-center gap-1 whitespace-nowrap font-mono`}
              >
                {v.cve}
                <ExternalLink className="size-3" aria-hidden />
                <span className="sr-only"> (NVD, opens in a new tab)</span>
              </a>
              <div className="mt-1 flex flex-wrap gap-1">
                {v.kev && (
                  <span className={`${badge} bg-red-50 text-red-800 ring-red-600/25`}>
                    CISA KEV
                  </span>
                )}
                {v.knownRansomwareUse && (
                  <span className={`${badge} bg-violet-50 text-violet-800 ring-violet-600/25`}>
                    Ransomware use
                  </span>
                )}
              </div>
            </th>
            <td className={`${tdClass} min-w-56 max-w-md text-fg-2`}>
              {v.title ?? <span className="text-fg-faint">No title</span>}
            </td>
            <td className={tdClass}>
              <CvssChip score={v.cvss} />
            </td>
            <td className={tdClass}>
              <ul className="flex flex-wrap gap-1">
                {v.products.map((p) => (
                  <li key={p.product}>
                    <Link
                      to={`/software?product=${encodeURIComponent(p.product)}&status=kev`}
                      className="inline-block whitespace-nowrap rounded-md border border-line bg-surface-2 px-1.5 py-0.5 text-xs text-fg-2 hover:border-accent hover:text-fg"
                    >
                      {p.productLabel}
                    </Link>
                  </li>
                ))}
              </ul>
            </td>
            <td className={`${tdClass} whitespace-nowrap text-right text-xs text-fg-2`}>
              <div className="font-semibold tabular-nums text-fg">
                {`${v.affectedHosts} ${v.affectedHosts === 1 ? 'host' : 'hosts'}`}
              </div>
              <div className="tabular-nums text-fg-subtle">
                {`${v.affectedDomains} ${v.affectedDomains === 1 ? 'domain' : 'domains'}`}
              </div>
            </td>
            <td className={`${tdClass} text-right`}>
              {v.openFindings > 0 ? (
                <Link
                  to={`/findings?${new URLSearchParams({ ruleId: 'SOFT-002', q: v.cve }).toString()}`}
                  className={`${linkClass} tabular-nums`}
                  aria-label={`${v.openFindings} open ${v.openFindings === 1 ? 'finding' : 'findings'} for ${v.cve}`}
                >
                  {v.openFindings}
                </Link>
              ) : (
                <span className="tabular-nums text-fg-subtle">0</span>
              )}
            </td>
            <td className={`${tdClass} whitespace-nowrap pr-0 text-xs text-fg-muted`}>
              {v.kevDateAdded ? formatDate(v.kevDateAdded) : '—'}
            </td>
          </tr>
        ))}
      </tbody>
    </TableFrame>
  );
}
