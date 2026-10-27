import { CONTINENTS, type AttackSurfaceResponse } from '@exdomainvault/shared';
import { continentRows } from './format.ts';
import { ArrowRight } from 'lucide-react';
import { Link, useNavigate } from 'react-router';
import type { AsyncState } from '../../lib/use-async.ts';
import { percentOf } from '../charts/palette.ts';
import { Card } from '../ui/Card.tsx';
import { CardBody, CardEmpty, Skeleton, cardLinkClass } from './states.tsx';

import { LazyWorldMap } from '../map/LazyWorldMap.tsx';

export function RegionCard({
  state,
  onRetry,
}: {
  state: AsyncState<AttackSurfaceResponse>;
  onRetry: () => void;
}) {
  const navigate = useNavigate();
  return (
    <Card
      title="Attack surface by region"
      actions={
        <Link to="/attack-surface" className={cardLinkClass}>
          Open attack surface map <ArrowRight className="size-3" aria-hidden />
        </Link>
      }
    >
      <CardBody state={state} onRetry={onRetry} skeleton={<Skeleton className="h-40 w-full" />}>
        {(d) => {
          const { rows, total } = continentRows(d);
          if (total === 0) {
            return (
              <CardEmpty title="No locations yet">
                Addresses are geolocated after scans resolve approved assets
                {d.unknownCountryIps > 0
                  ? ` (${d.unknownCountryIps.toLocaleString()} not yet located)`
                  : ''}
                .
              </CardEmpty>
            );
          }
          return (
            <div className="space-y-3">
              <div className="grid items-center gap-4 sm:grid-cols-[minmax(0,3fr)_minmax(9rem,2fr)]">
                <div className="min-w-0">
                  {/* The map renders the DB-IP attribution (CC BY 4.0) whenever it shows data. */}
                  <LazyWorldMap
                    countries={d.countries}
                    compact
                    height={150}
                    attribution={d.geoAttribution ?? undefined}
                    label="Current IP addresses of approved assets by country"
                    onSelectCountry={(code) =>
                      void navigate(`/assets?status=approved&country=${code}`)
                    }
                  />
                </div>
                <ul className="space-y-1.5 text-sm" aria-label="IP addresses by continent">
                  {rows.map((r) => (
                    <li key={r.label} className="flex items-center justify-between gap-2">
                      {(CONTINENTS as readonly string[]).includes(r.label) ? (
                        <Link
                          to={`/assets?status=approved&continent=${encodeURIComponent(r.label)}`}
                          className="text-fg-2 hover:text-highlight hover:underline"
                        >
                          {r.label}
                        </Link>
                      ) : (
                        <span className="text-fg-2">{r.label}</span>
                      )}
                      <span className="tabular-nums">
                        <span className="font-medium text-fg" data-testid={`region-${r.label}`}>
                          {r.ips.toLocaleString()}
                        </span>{' '}
                        <span className="text-fg-subtle">{percentOf(r.ips, total)}%</span>
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
              <p className="text-xs text-fg-subtle">
                Current IP addresses of approved assets
                {d.unknownCountryIps > 0
                  ? `; ${d.unknownCountryIps.toLocaleString()} not yet located`
                  : ''}
                .
              </p>
            </div>
          );
        }}
      </CardBody>
    </Card>
  );
}
