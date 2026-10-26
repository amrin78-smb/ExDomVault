import {
  ASSET_ROLE_LABELS,
  SCAN_JOB_STATUSES,
  type DashboardResponse,
  type ScanJobStatus,
} from '@exdomainvault/shared';
import { ArrowRight } from 'lucide-react';
import { Link } from 'react-router';
import { formatDate, formatDateTime } from '../../lib/format.ts';
import type { AsyncState } from '../../lib/use-async.ts';
import { ScanStatusBadge } from '../scans/ScanStatusBadge.tsx';
import { Card } from '../ui/Card.tsx';
import { ProportionBar } from '../ui/ProportionBar.tsx';
import { SeverityBadge } from '../ui/SeverityBadge.tsx';
import { assetPill, expiryText, expiryTone, type AssetPill, type ExpiryTone } from './format.ts';
import { CardBody, CardEmpty, cardLinkClass } from './states.tsx';

type Dash = AsyncState<DashboardResponse>;

function ViewAll({ to, label = 'View all' }: { to: string; label?: string }) {
  return (
    <Link to={to} className={cardLinkClass}>
      {label} <ArrowRight className="size-3" aria-hidden />
    </Link>
  );
}

const rowLink = 'block rounded-md px-2 py-2 -mx-2 hover:bg-surface-2';

// --- Top remediation priorities -------------------------------------------------------------------

export function TopRemediationCard({ state, onRetry }: { state: Dash; onRetry: () => void }) {
  return (
    <Card title="Top remediation priorities" actions={<ViewAll to="/findings?sort=-riskScore" />}>
      <CardBody state={state} onRetry={onRetry}>
        {(d) =>
          d.topRemediation.length === 0 ? (
            <CardEmpty title="Nothing to prioritise">
              No open findings. Findings appear here, highest risk first, after scans complete.
            </CardEmpty>
          ) : (
            <ul className="divide-y divide-line-soft">
              {d.topRemediation.map((f) => {
                const subtitle = [
                  f.cves[0],
                  f.hostname ?? f.domain.fqdn,
                  f.assetRole ? ASSET_ROLE_LABELS[f.assetRole] : null,
                ]
                  .filter(Boolean)
                  .join(' · ');
                return (
                  <li key={f.findingId}>
                    <Link
                      to={`/findings/${f.findingId}`}
                      className={`${rowLink} flex items-center gap-3`}
                      aria-label={`${f.title}, risk ${f.riskScore}`}
                    >
                      <SeverityBadge severity={f.severity} />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-sm font-medium text-fg">
                          {f.title}
                        </span>
                        <span className="block truncate font-mono text-xs text-fg-subtle">
                          {subtitle}
                        </span>
                      </span>
                      <span className="flex shrink-0 items-center gap-2" title="Risk score (0–100)">
                        <ProportionBar
                          percent={f.riskScore}
                          className="h-1.5 w-16 rounded-full bg-line"
                          fillClassName="fill-highlight"
                        />
                        <span className="w-7 text-right text-sm font-semibold tabular-nums text-fg">
                          {f.riskScore}
                        </span>
                      </span>
                    </Link>
                  </li>
                );
              })}
            </ul>
          )
        }
      </CardBody>
    </Card>
  );
}

// --- Latest scans ---------------------------------------------------------------------------------

const isJobStatus = (s: string): s is ScanJobStatus =>
  (SCAN_JOB_STATUSES as readonly string[]).includes(s);

export function LatestScansCard({
  state,
  onRetry,
  canRead,
}: {
  state: Dash;
  onRetry: () => void;
  canRead: boolean;
}) {
  return (
    <Card title="Latest scans" actions={canRead ? <ViewAll to="/scans" /> : undefined}>
      {!canRead ? (
        <CardEmpty title="Scan history is not visible to your role">
          Analysts and administrators can see scan runs.
        </CardEmpty>
      ) : (
        <CardBody state={state} onRetry={onRetry}>
          {(d) =>
            d.latestScans.length === 0 ? (
              <CardEmpty title="No scans have run">
                Scans run daily for monitored domains, or on request with Run scan.
              </CardEmpty>
            ) : (
              <ul className="divide-y divide-line-soft">
                {d.latestScans.map((j) => (
                  <li key={j.id} className="flex items-center justify-between gap-3 py-2">
                    <span className="min-w-0">
                      <Link
                        to={`/domains/${j.domain.id}`}
                        className="block truncate font-mono text-sm text-fg hover:underline"
                      >
                        {j.domain.fqdn}
                      </Link>
                      <Link
                        to={`/scans/${j.id}`}
                        className="block truncate text-xs text-fg-subtle hover:text-highlight hover:underline"
                      >
                        <span className="capitalize">
                          {j.jobType === 'discovery' ? 'Discovery' : j.profile}
                        </span>{' '}
                        · {formatDateTime(j.completedAt ?? j.createdAt)}
                      </Link>
                    </span>
                    {isJobStatus(j.status) ? (
                      <ScanStatusBadge status={j.status} />
                    ) : (
                      <span className="text-xs text-fg-muted">{j.status}</span>
                    )}
                  </li>
                ))}
              </ul>
            )
          }
        </CardBody>
      )}
    </Card>
  );
}

// --- Certificate expiry ---------------------------------------------------------------------------

const TONE_CLASS: Record<ExpiryTone, string> = {
  red: 'bg-red-50 text-red-800 ring-red-600/25 dark:ring-red-400/50',
  amber: 'bg-amber-50 text-amber-900 ring-amber-600/30 dark:ring-amber-400/50',
  blue: 'bg-blue-50 text-blue-800 ring-blue-600/25 dark:ring-blue-400/50',
  slate: 'bg-surface-3 text-fg-2 ring-slate-500/25',
};

export function CertificateExpiryCard({ state, onRetry }: { state: Dash; onRetry: () => void }) {
  return (
    <Card title="Certificate expiry" actions={<ViewAll to="/certificates" />}>
      <CardBody state={state} onRetry={onRetry}>
        {(d) =>
          d.certificateExpiry.length === 0 ? (
            <CardEmpty title="No certificates collected yet">
              Run a Standard scan of a verified domain to record its TLS certificates.
            </CardEmpty>
          ) : (
            <ul className="divide-y divide-line-soft">
              {d.certificateExpiry.map((c) => {
                const tone = expiryTone(c.daysLeft);
                return (
                  <li key={`${c.hostname}-${c.notAfter}`}>
                    <Link
                      to={`/certificates?q=${encodeURIComponent(c.hostname)}`}
                      className={`${rowLink} flex items-center justify-between gap-3`}
                    >
                      <span className="min-w-0">
                        <span className="block truncate font-mono text-sm text-fg">
                          {c.hostname}
                        </span>
                        <span className="block text-xs text-fg-subtle">
                          {expiryText(c.daysLeft)} · {formatDate(c.notAfter)}
                        </span>
                      </span>
                      <span
                        className={`shrink-0 rounded-full px-2 py-0.5 text-xs font-semibold tabular-nums ring-1 ring-inset ${TONE_CLASS[tone]}`}
                        data-testid="expiry-pill"
                        data-tone={tone}
                      >
                        {c.daysLeft < 0 ? 'Expired' : `${c.daysLeft} d`}
                      </span>
                    </Link>
                  </li>
                );
              })}
            </ul>
          )
        }
      </CardBody>
    </Card>
  );
}

// --- Recently discovered assets ---------------------------------------------------------------------

const PILL_CLASS: Record<AssetPill, string> = {
  New: 'bg-cyan-50 text-cyan-800 ring-cyan-600/25 dark:ring-cyan-400/50',
  Pending: 'bg-amber-50 text-amber-900 ring-amber-600/30 dark:ring-amber-400/50',
  Approved: 'bg-emerald-50 text-emerald-800 ring-emerald-600/25 dark:ring-emerald-400/50',
  Rejected: 'bg-surface-3 text-fg-muted ring-slate-500/25',
  Suspended: 'bg-surface-3 text-fg-muted ring-slate-500/25',
};

const th = 'px-2 py-2 text-left text-xs font-medium text-fg-subtle';
const td = 'px-2 py-2 align-middle';

export function RecentAssetsCard({ state, onRetry }: { state: Dash; onRetry: () => void }) {
  return (
    <Card
      title="Recently discovered assets"
      actions={<ViewAll to="/assets?status=pending&sort=-firstSeenAt" />}
    >
      <CardBody state={state} onRetry={onRetry}>
        {(d) =>
          d.recentAssets.length === 0 ? (
            <CardEmpty title="No assets discovered yet">
              Hostnames found by discovery or added from a domain appear here.
            </CardEmpty>
          ) : (
            <div className="-mx-2 overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-b border-line">
                  <tr>
                    <th scope="col" className={th}>
                      Asset
                    </th>
                    <th scope="col" className={th}>
                      Type
                    </th>
                    <th scope="col" className={th}>
                      First seen
                    </th>
                    <th scope="col" className={th}>
                      Status
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line-soft">
                  {d.recentAssets.map((a) => {
                    const pill = assetPill(a.status, a.firstSeenAt, d.generatedAt);
                    return (
                      <tr key={a.id} className="hover:bg-surface-2">
                        <td className={`${td} max-w-36`}>
                          <Link
                            to={`/assets/${a.id}`}
                            className="block truncate font-mono text-fg hover:text-highlight hover:underline"
                          >
                            {a.hostname}
                          </Link>
                        </td>
                        <td className={`${td} whitespace-nowrap text-xs text-fg-muted`}>
                          {ASSET_ROLE_LABELS[a.role]}
                        </td>
                        <td className={`${td} whitespace-nowrap text-xs text-fg-muted`}>
                          {formatDate(a.firstSeenAt)}
                        </td>
                        <td className={td}>
                          <span
                            className={`inline-flex whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${PILL_CLASS[pill]}`}
                          >
                            {pill}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )
        }
      </CardBody>
    </Card>
  );
}

// --- Exposed software -------------------------------------------------------------------------------

export function ExposedSoftwareCard({ state, onRetry }: { state: Dash; onRetry: () => void }) {
  return (
    <Card title="Exposed software (top 5)" actions={<ViewAll to="/software" />}>
      <CardBody state={state} onRetry={onRetry}>
        {(d) =>
          d.topSoftware.length === 0 ? (
            <CardEmpty title="No software recorded yet">
              Quick scans record HTTP server headers; Standard and Deep scans also identify service
              versions.
            </CardEmpty>
          ) : (
            <div className="space-y-2">
              <div className="-mx-2 overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="border-b border-line">
                    <tr>
                      <th scope="col" className={th}>
                        Product
                      </th>
                      <th scope="col" className={th}>
                        Versions
                      </th>
                      <th scope="col" className={`${th} text-right`}>
                        Hosts
                      </th>
                      <th scope="col" className={th}>
                        Risk
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line-soft">
                    {d.topSoftware.map((p) => (
                      <tr key={p.product} className="hover:bg-surface-2">
                        <td className={td}>
                          <Link
                            to={`/software?q=${encodeURIComponent(p.product)}`}
                            className="font-medium text-fg hover:text-highlight hover:underline"
                          >
                            {p.productLabel}
                          </Link>
                        </td>
                        <td className={`${td} max-w-32 truncate font-mono text-xs text-fg-muted`}>
                          {p.versions.length > 0 ? p.versions.join(', ') : 'hidden'}
                        </td>
                        <td className={`${td} text-right tabular-nums text-fg`}>{p.hosts}</td>
                        <td className={td}>
                          <span className="flex flex-wrap gap-1">
                            <span
                              className={`rounded px-1.5 py-0.5 text-xs font-medium ring-1 ring-inset ${
                                p.kevCves > 0
                                  ? 'bg-red-50 text-red-800 ring-red-600/25 dark:ring-red-400/50'
                                  : 'bg-surface-3 text-fg-subtle ring-slate-500/20'
                              }`}
                              data-testid="kev-badge"
                              data-tone={p.kevCves > 0 ? 'red' : 'neutral'}
                            >
                              {p.kevCves} KEV
                            </span>
                            {p.eolHosts > 0 && (
                              <span className="rounded bg-amber-50 px-1.5 py-0.5 text-xs font-medium text-amber-900 ring-1 ring-inset ring-amber-600/30 dark:ring-amber-400/50">
                                {p.eolHosts} EOL
                              </span>
                            )}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="text-xs text-fg-subtle">
                Versions are self-reported; KEV matches mean possibly affected — verify.
              </p>
            </div>
          )
        }
      </CardBody>
    </Card>
  );
}
