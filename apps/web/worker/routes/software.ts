import {
  softwareListQuerySchema,
  type IntelFeedsResponse,
  type SoftwareListResponse,
  type SoftwareSummaryResponse,
} from '@exdomainvault/shared';
import { Hono } from 'hono';
import type { FetchLike } from '../lib/feed-fetch.ts';
import { parseQuery } from '../lib/validation.ts';
import { requirePermission } from '../middleware/auth.ts';
import { writeAudit } from '../services/audit.ts';
import { feedStatus, syncEndOfLife, syncKev, userAgentFor } from '../services/intel-feeds.ts';
import { listSoftware, softwareSummary } from '../services/software.ts';
import type { AppBindings } from '../types.ts';

export interface SoftwareRouteDeps {
  now?: () => Date;
}

/**
 * Exposed-software inventory (Milestone 11), mounted at /api/v1/software. `findings:read`: the
 * inventory is evidence in the same sense as findings, and asset owners see only rows on assets
 * they own (enforced in the service).
 */
export function softwareRoutes(deps: SoftwareRouteDeps = {}) {
  const now = deps.now ?? (() => new Date());
  return new Hono<AppBindings>()
    .get('/', requirePermission('findings:read'), async (c) => {
      const query = parseQuery(c, softwareListQuerySchema);
      const db = await c.get('db')();
      const res: SoftwareListResponse = await listSoftware(db, c.get('user'), query, now());
      return c.json(res);
    })
    .get('/summary', requirePermission('findings:read'), async (c) => {
      const db = await c.get('db')();
      const res: SoftwareSummaryResponse = await softwareSummary(db, c.get('user'), now());
      return c.json(res);
    });
}

export interface IntelRouteDeps {
  now?: () => Date;
  /** Network access for the manual sync (tests inject a mock; defaults to the Workers fetch). */
  fetch?: FetchLike;
}

/**
 * Intelligence feed status and manual sync, mounted at /api/v1/intel. Status is `findings:read`
 * (feed freshness qualifies every software verdict the reader sees); the sync is `settings:manage`
 * and audited `intel.sync_requested`. A manual sync runs endoflife.date and CISA KEV now (bounded
 * by their timeouts, at most once a minute); NVD keeps its own rate-limited cron schedule.
 */
export function intelRoutes(deps: IntelRouteDeps = {}) {
  const now = deps.now ?? (() => new Date());
  const doFetch: FetchLike = deps.fetch ?? ((input, init) => fetch(input, init));
  return new Hono<AppBindings>()
    .get('/feeds', requirePermission('findings:read'), async (c) => {
      const db = await c.get('db')();
      const res: IntelFeedsResponse = await feedStatus(db);
      return c.json(res);
    })
    .post('/feeds/sync', requirePermission('settings:manage'), async (c) => {
      const db = await c.get('db')();
      const at = now();
      await writeAudit(db, {
        actorType: 'user',
        actorUserId: c.get('user').id,
        action: 'intel.sync_requested',
        resourceType: 'intel_feed',
        requestId: c.get('requestId'),
        metadata: { feeds: ['endoflife', 'cisa_kev'] },
      });
      const intel = {
        fetch: doFetch,
        userAgent: userAgentFor(c.get('config').version),
        logger: c.get('logger'),
      };
      const endoflife = await syncEndOfLife(db, at, intel, { force: true });
      const kev = await syncKev(db, at, intel, { force: true });
      c.get('logger').info('intel_sync_requested', { endoflife, kev });
      const res: IntelFeedsResponse = await feedStatus(db);
      return c.json(res);
    });
}
