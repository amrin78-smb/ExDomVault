import type { SoftwareItem } from '@exdomainvault/shared';
import { Link } from 'react-router';
import { formatDateTime } from '../../lib/format.ts';
import { BackportHint, EolBadge, EolDetail, KevChips, VersionText } from './SoftwareBadges.tsx';
import { SOFTWARE_SOURCE_LABELS, softwareLocation } from './software-format.ts';

const th = 'py-2 pr-4';
const td = 'py-2.5 pr-4 align-top';

/**
 * Software inventory rows. `compact` (the domain card) drops the domain, source and banner columns
 * but keeps the version, end-of-life and known-exploited columns.
 */
export function SoftwareTable({
  items,
  compact = false,
}: {
  items: SoftwareItem[];
  compact?: boolean;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-sm">
        <thead>
          <tr className="border-b border-slate-200 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
            {!compact && (
              <th scope="col" className={th}>
                Domain
              </th>
            )}
            <th scope="col" className={th}>
              Location
            </th>
            <th scope="col" className={th}>
              Product
            </th>
            <th scope="col" className={th}>
              Version
            </th>
            {!compact && (
              <th scope="col" className={th}>
                Source
              </th>
            )}
            <th scope="col" className={th}>
              End of life
            </th>
            <th scope="col" className={th}>
              Known exploited (KEV)
            </th>
            {!compact && (
              <th scope="col" className="py-2">
                Last seen
              </th>
            )}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {items.map((s) => (
            <tr key={s.id}>
              {!compact && (
                <td className={td}>
                  <Link
                    to={`/domains/${s.domain.id}`}
                    className="font-mono text-sky-800 hover:underline"
                  >
                    {s.domain.fqdn}
                  </Link>
                </td>
              )}
              <td className={`${td} break-all font-mono text-xs text-slate-800`}>
                {softwareLocation(s)}
              </td>
              <td className={`${td} whitespace-nowrap text-slate-800`}>{s.productLabel}</td>
              <td className={td}>
                <VersionText version={s.version} />
                <BackportHint hint={s.backportHint} />
              </td>
              {!compact && (
                <td className={td}>
                  <div className="whitespace-nowrap text-xs text-slate-700">
                    {SOFTWARE_SOURCE_LABELS[s.source]}
                  </div>
                  <div
                    className="max-w-56 truncate font-mono text-[11px] text-slate-500"
                    title={s.banner}
                  >
                    {s.banner}
                  </div>
                </td>
              )}
              <td className={td}>
                <EolBadge eol={s.eol} />
                {!compact && <EolDetail eol={s.eol} />}
              </td>
              <td className={td}>
                <KevChips items={s.knownExploited} />
              </td>
              {!compact && (
                <td className="whitespace-nowrap py-2.5 align-top text-xs text-slate-600">
                  {formatDateTime(s.lastSeenAt)}
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
