import {
  authorisationSchema,
  bulkAuthoriseRequestSchema,
  createDomainRequestSchema,
  hasPermission,
  revokeRequestSchema,
  domainListQuerySchema,
  importConfirmRequestSchema,
  importPreviewRequestSchema,
  updateDomainRequestSchema,
  type CreateChallengeResponse,
  type DomainDetailResponse,
  type VerifyDomainResponse,
} from '@exdomainvault/shared';
import type { Database } from '@exdomainvault/database';
import { Hono, type Context } from 'hono';
import { createDohResolver, type TxtResolver } from '../lib/doh.ts';
import { parseJsonBody, parseQuery, uuidParam } from '../lib/validation.ts';
import { requirePermission } from '../middleware/auth.ts';
import { authoriseDomains, revokeDomain } from '../services/domain-authorisation.ts';
import { confirmImport, previewImport } from '../services/domain-import.ts';
import { ApiError } from '../lib/errors.ts';
import {
  checkChallenge,
  createChallenge,
  expireStaleChallenges,
  latestChallenge,
  toChallengeDto,
} from '../services/domain-verification.ts';
import {
  createDomain,
  getDomainRow,
  listDomains,
  toDomainDto,
  updateDomain,
  type Actor,
} from '../services/domains.ts';
import type { AppBindings } from '../types.ts';

export interface DomainRouteDeps {
  /** TXT resolver used for verification (defaults to DNS-over-HTTPS via Cloudflare). */
  resolveTxt?: TxtResolver;
  /** Clock, injectable so expiry can be tested. */
  now?: () => Date;
}

const actorOf = (c: Context<AppBindings>): Actor => ({
  userId: c.get('user').id,
  requestId: c.get('requestId'),
});

async function detailOf(db: Database, id: string): Promise<DomainDetailResponse> {
  const row = await getDomainRow(db, id);
  const challenge = await latestChallenge(db, id);
  return {
    domain: toDomainDto(row),
    verification: challenge ? toChallengeDto(challenge, row.fqdn) : null,
  };
}

export function domainRoutes(deps: DomainRouteDeps = {}) {
  const resolveTxt = deps.resolveTxt ?? createDohResolver();
  const now = deps.now ?? (() => new Date());

  return new Hono<AppBindings>()
    .get('/', requirePermission('domains:read'), async (c) => {
      const query = parseQuery(c, domainListQuerySchema);
      const db = await c.get('db')();
      await expireStaleChallenges(db, now());
      return c.json(await listDomains(db, query));
    })
    .post('/', requirePermission('domains:write'), async (c) => {
      const body = await parseJsonBody(c, createDomainRequestSchema);
      const db = await c.get('db')();
      const row = await createDomain(db, body, actorOf(c));
      c.get('logger').info('domain_created', { domainId: row.id });
      const res: DomainDetailResponse = { domain: toDomainDto(row), verification: null };
      return c.json(res, 201);
    })
    .post('/import/preview', requirePermission('domains:write'), async (c) => {
      const { csv } = await parseJsonBody(c, importPreviewRequestSchema);
      const db = await c.get('db')();
      return c.json(await previewImport(db, csv));
    })
    .post('/import', requirePermission('domains:write'), async (c) => {
      const { csv, digest, authorisation } = await parseJsonBody(c, importConfirmRequestSchema);
      if (authorisation && !hasPermission(c.get('user').role, 'domains:verify')) {
        throw new ApiError(403, 'forbidden', 'You do not have permission to authorise domains.');
      }
      const db = await c.get('db')();
      const result = await confirmImport(db, csv, digest, actorOf(c), {
        authorisation,
        now: now(),
      });
      c.get('logger').info('domains_imported', { created: result.created.length, skipped: result.skipped });
      return c.json(result, 201);
    })
    .post('/authorise', requirePermission('domains:verify'), async (c) => {
      const { domainIds, ...auth } = await parseJsonBody(c, bulkAuthoriseRequestSchema);
      const db = await c.get('db')();
      const ids = domainIds.map((id) => id.toLowerCase());
      await Promise.all(ids.map((id) => expireStaleChallenges(db, now(), id)));
      const result = await authoriseDomains(db, ids, auth, actorOf(c), now(), 'bulk');
      c.get('logger').info('domains_authorised', {
        authorised: result.authorised.length,
        skipped: result.skipped.length,
      });
      return c.json(result);
    })
    .get('/:id', requirePermission('domains:read'), async (c) => {
      const id = uuidParam(c, 'id');
      const db = await c.get('db')();
      await expireStaleChallenges(db, now(), id);
      const row = await getDomainRow(db, id);
      const challenge = await latestChallenge(db, id);
      const res: DomainDetailResponse = {
        domain: toDomainDto(row),
        verification: challenge ? toChallengeDto(challenge, row.fqdn) : null,
      };
      return c.json(res);
    })
    .patch('/:id', requirePermission('domains:write'), async (c) => {
      const id = uuidParam(c, 'id');
      const patch = await parseJsonBody(c, updateDomainRequestSchema);
      const db = await c.get('db')();
      const row = await updateDomain(db, id, patch, actorOf(c));
      const challenge = await latestChallenge(db, id);
      const res: DomainDetailResponse = {
        domain: toDomainDto(row),
        verification: challenge ? toChallengeDto(challenge, row.fqdn) : null,
      };
      return c.json(res);
    })
    .post('/:id/verification', requirePermission('domains:verify'), async (c) => {
      const id = uuidParam(c, 'id');
      const db = await c.get('db')();
      const res: CreateChallengeResponse = await createChallenge(db, id, actorOf(c), now());
      c.get('logger').info('domain_verification_started', { domainId: id, challengeId: res.challenge.id });
      return c.json(res, 201);
    })
    .post('/:id/authorise', requirePermission('domains:verify'), async (c) => {
      const id = uuidParam(c, 'id');
      const auth = await parseJsonBody(c, authorisationSchema);
      const db = await c.get('db')();
      await expireStaleChallenges(db, now(), id);
      const result = await authoriseDomains(db, [id], auth, actorOf(c), now(), 'manual');
      const skipped = result.skipped[0];
      if (skipped?.reason === 'not_found') {
        throw new ApiError(404, 'not_found', 'The requested resource was not found.');
      }
      if (skipped?.reason === 'already_verified') {
        throw new ApiError(409, 'conflict', 'This domain is already verified.');
      }
      return c.json(await detailOf(db, id));
    })
    .post('/:id/revoke', requirePermission('domains:verify'), async (c) => {
      const id = uuidParam(c, 'id');
      const { reason } = await parseJsonBody(c, revokeRequestSchema);
      const db = await c.get('db')();
      await expireStaleChallenges(db, now(), id);
      await revokeDomain(db, id, reason, actorOf(c));
      return c.json(await detailOf(db, id));
    })
    .post('/:id/verify', requirePermission('domains:verify'), async (c) => {
      const id = uuidParam(c, 'id');
      const db = await c.get('db')();
      const logger = c.get('logger');
      const result = await checkChallenge(db, id, resolveTxt, actorOf(c), now(), (e, f) =>
        logger.warn(e, f),
      );
      logger.info('domain_verification_checked', { domainId: id, outcome: result.outcome });
      const res: VerifyDomainResponse = {
        outcome: result.outcome,
        message: result.message,
        domain: toDomainDto(result.domain),
        verification: result.challenge ? toChallengeDto(result.challenge, result.domain.fqdn) : null,
      };
      return c.json(res);
    });
}
