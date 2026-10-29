import { ArrowRight } from 'lucide-react';
import { Link } from 'react-router';
import { api } from '../../lib/api.ts';
import { useRefreshableAsync } from '../../lib/use-refreshable-async.ts';
import { CardBody, CardEmpty, cardLinkClass } from '../dashboard/states.tsx';
import { Card } from '../ui/Card.tsx';
import { ImportanceChip } from './ChangeTimeline.tsx';
import { KIND_ICONS } from './kind-icons.ts';
import { changesSummary, timeLabel } from './format.ts';

const SHOWN = 6;
/** The request (the server's default window: the last 30 days). */
const RECENT_CHANGES_QUERY = { importance: 'notable', pageSize: SHOWN } as const;

/**
 * Overview card: the newest notable-or-important changes of the last 30 days across the portfolio
 * (asset owners: their assets), linking to the full timeline.
 */
export function RecentChangesCard() {
  const list = useRefreshableAsync((signal) => api.changes(RECENT_CHANGES_QUERY, { signal }), []);
  return (
    <Card
      title="Recent changes"
      actions={
        <Link to="/changes?importance=notable" className={cardLinkClass}>
          View all <ArrowRight className="size-3" aria-hidden />
        </Link>
      }
    >
      <CardBody state={list.state} onRetry={list.retry}>
        {(d) =>
          d.total === 0 ? (
            <CardEmpty title="No notable changes in 30 days">
              DNS, address, certificate, port, software and registration changes between successful
              scans appear here.
            </CardEmpty>
          ) : (
            <>
              <p className="mb-2 text-xs text-fg-subtle">{changesSummary(d)} (notable or more)</p>
              <ul className="divide-y divide-line-soft">
                {d.items.map((e) => {
                  const Icon = KIND_ICONS[e.kind];
                  return (
                    <li key={e.id} className="flex items-start gap-2 py-2">
                      <Icon className="mt-0.5 size-4 shrink-0 text-fg-subtle" aria-hidden />
                      <div className="min-w-0 flex-1">
                        <p className="line-clamp-2 break-words text-sm text-fg">{e.summary}</p>
                        <p className="mt-0.5 text-xs text-fg-subtle">
                          <time dateTime={e.at}>
                            {new Date(e.at).toISOString().slice(0, 10)} {timeLabel(e.at)}
                          </time>{' '}
                          ·{' '}
                          <Link
                            to={`/domains/${e.domain.id}`}
                            className="font-mono hover:text-fg hover:underline"
                          >
                            {e.domain.fqdn}
                          </Link>
                        </p>
                      </div>
                      <ImportanceChip importance={e.severityHint} />
                    </li>
                  );
                })}
              </ul>
            </>
          )
        }
      </CardBody>
    </Card>
  );
}
