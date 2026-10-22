import { RULES, type Rule } from '@exdomainvault/rules';
import {
  findingBulkUpdateRequestSchema,
  findingCommentRequestSchema,
  findingListQuerySchema,
  findingUpdateRequestSchema,
  type FindingBulkUpdateResponse,
  type FindingReassessResponse,
} from '@exdomainvault/shared';
import { Hono, type Context } from 'hono';
import { z } from 'zod';
import { parseJsonBody, parseQuery, uuidParam } from '../lib/validation.ts';
import { requirePermission } from '../middleware/auth.ts';
import type { Actor } from '../services/domains.ts';
import {
  addComment,
  bulkUpdateFindings,
  reassessFinding,
  updateFinding,
} from '../services/finding-lifecycle.ts';
import { findingSummary, getFindingDetail, listFindings } from '../services/findings.ts';
import type { AppBindings } from '../types.ts';

export interface FindingRouteDeps {
  /** Rule registry used for rule documentation (defaults to the production registry). */
  rules?: readonly Rule[];
  now?: () => Date;
}

const summaryQuerySchema = z.object({ domainId: z.uuid().optional() });

const actorOf = (c: Context<AppBindings>): Actor => ({
  userId: c.get('user').id,
  requestId: c.get('requestId'),
});

/**
 * Findings. Reads need `findings:read`; asset owners are scoped to their own assets' findings.
 * Lifecycle changes (Milestone 8) check per-transition permissions in the service, server-side.
 */
export function findingRoutes(deps: FindingRouteDeps = {}) {
  const rules = deps.rules ?? RULES;
  const now = deps.now ?? (() => new Date());
  return (
    new Hono<AppBindings>()
      .get('/', requirePermission('findings:read'), async (c) => {
        const query = parseQuery(c, findingListQuerySchema);
        const db = await c.get('db')();
        return c.json(await listFindings(db, c.get('user'), query, rules));
      })
      .get('/summary', requirePermission('findings:read'), async (c) => {
        const { domainId } = parseQuery(c, summaryQuerySchema);
        const db = await c.get('db')();
        return c.json(await findingSummary(db, c.get('user'), domainId));
      })
      // Registered before the `/:id` routes.
      .post('/bulk', requirePermission('findings:read'), async (c) => {
        const body = await parseJsonBody(c, findingBulkUpdateRequestSchema);
        const db = await c.get('db')();
        const res: FindingBulkUpdateResponse = await bulkUpdateFindings(
          db,
          c.get('user'),
          body,
          rules,
          actorOf(c),
          now(),
        );
        c.get('logger').info('findings_bulk_updated', {
          requested: body.ids.length,
          updated: res.updated,
          skipped: res.skipped.length,
        });
        return c.json(res);
      })
      .get('/:id', requirePermission('findings:read'), async (c) => {
        const id = uuidParam(c, 'id');
        const db = await c.get('db')();
        return c.json(await getFindingDetail(db, c.get('user'), id, rules));
      })
      .patch('/:id', requirePermission('findings:read'), async (c) => {
        const id = uuidParam(c, 'id');
        const body = await parseJsonBody(c, findingUpdateRequestSchema);
        const db = await c.get('db')();
        const finding = await updateFinding(db, c.get('user'), id, body, rules, actorOf(c), now());
        c.get('logger').info('finding_updated', { findingId: id, status: finding.status });
        return c.json({ finding });
      })
      .post('/:id/comments', requirePermission('findings:read'), async (c) => {
        const id = uuidParam(c, 'id');
        const { body } = await parseJsonBody(c, findingCommentRequestSchema);
        const db = await c.get('db')();
        const comment = await addComment(db, c.get('user'), id, body, actorOf(c), now());
        return c.json({ comment }, 201);
      })
      .post('/:id/reassess', requirePermission('scans:request'), async (c) => {
        const id = uuidParam(c, 'id');
        const db = await c.get('db')();
        const res: FindingReassessResponse = await reassessFinding(
          db,
          c.get('user'),
          id,
          rules,
          actorOf(c),
          now(),
          { activeScanningEnabled: c.get('config').activeScanningEnabled },
        );
        c.get('logger').info('finding_reassess', { findingId: id, ...res });
        return c.json(res, res.created ? 201 : 200);
      })
  );
}
