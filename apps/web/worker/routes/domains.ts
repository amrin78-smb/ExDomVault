import {
  createDomainRequestSchema,
  domainListQuerySchema,
  importConfirmRequestSchema,
  importPreviewRequestSchema,
  updateDomainRequestSchema,
  type CreateChallengeResponse,
  type DomainDetailResponse,
  type VerifyDomainResponse,
} from '@exdomainvault/shared';
import { Hono, type Context } from 'hono';
import { createDohResolver, type TxtResolver } from '../lib/doh.ts';
import { parseJsonBody, parseQuery, uuidParam } from '../lib/validation.ts';
import { requirePermission } from '../middleware/auth.ts';
import { confirmImport, previewImport } from '../services/domain-import.ts';
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
      const { csv, digest } = await parseJsonBody(c, importConfirmRequestSchema);
      const db = await c.get('db')();
      const result = await confirmImport(db, csv, digest, actorOf(c));
      c.get('logger').info('domains_imported', { created: result.created.length, skipped: result.skipped });
      return c.json(result, 201);
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
