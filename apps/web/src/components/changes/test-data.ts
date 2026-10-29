// Test-only: change timeline fixtures (synthetic data, reserved names).
import type { ChangeEvent, ChangesResponse } from '@exdomainvault/shared';

export const CHANGE_DOMAIN_ID = '0b4f7c2e-5d1a-4c3b-9e8f-1a2b3c4d5e6f';
export const CHANGE_ASSET_ID = '7c9e6679-7425-40de-944b-e07fc1f90ae7';
export const UNTIL = '2026-10-23T10:00:00.000Z';
export const SINCE = '2026-09-23T10:00:00.000Z';

/** The Overview card's request (default 30-day window). */
export const RECENT_CHANGES_PATH = 'GET /api/v1/changes?importance=notable&pageSize=6';
export const changesPath = (query = '') => `GET /api/v1/changes${query}`;

let n = 0;
export function changeEvent(over: Partial<ChangeEvent> = {}): ChangeEvent {
  n += 1;
  return {
    id: `dns:job-${n}:www.example.com:A`,
    at: '2026-10-22T08:15:00.000Z',
    kind: 'dns',
    domain: { id: CHANGE_DOMAIN_ID, fqdn: 'example.com' },
    assetId: CHANGE_ASSET_ID,
    hostname: 'www.example.com',
    subject: 'A record',
    summary: 'A record of www.example.com changed: added 192.0.2.3; removed 192.0.2.1',
    before: ['192.0.2.1', '192.0.2.2'],
    after: ['192.0.2.2', '192.0.2.3'],
    severityHint: 'notable',
    ...over,
  };
}

export function changesPage(
  items: ChangeEvent[],
  over: Partial<ChangesResponse> = {},
): ChangesResponse {
  const count = (h: ChangeEvent['severityHint']) =>
    items.filter((e) => e.severityHint === h).length;
  return {
    items,
    page: 1,
    pageSize: 50,
    total: items.length,
    since: SINCE,
    until: UNTIL,
    counts: { info: count('info'), notable: count('notable'), important: count('important') },
    ...over,
  };
}
