import { schema, type Database } from '@exdomainvault/database';
import {
  ATTESTATION_MAX_MONTHS,
  type AuthorisationInput,
  type BulkAuthoriseResponse,
} from '@exdomainvault/shared';
import { and, eq, inArray } from 'drizzle-orm';
import { ApiError } from '../lib/errors.ts';
import { writeAudit, writeAuditMany } from './audit.ts';
import type { Actor, DomainRow } from './domains.ts';

const { domains, domainVerifications } = schema;

/**
 * Administrator attestation: for domains the organisation owns but whose DNS it cannot edit (e.g.
 * registrar-managed zones), an administrator records why the domain is authorised for active
 * scanning, with a reference and a review-by date. It is weaker evidence than a DNS TXT proof, is
 * labelled as such everywhere, is audited, and lapses on the review date unless renewed.
 */

/** Review dates are calendar dates; the authorisation lapses at the end of that day (UTC). */
export function reviewDeadline(reviewBy: string, now: Date): Date {
  const deadline = new Date(`${reviewBy}T23:59:59.999Z`);
  const max = new Date(now);
  max.setUTCMonth(max.getUTCMonth() + ATTESTATION_MAX_MONTHS);
  if (Number.isNaN(deadline.getTime()) || deadline <= now) {
    throw new ApiError(400, 'validation_failed', 'The authorisation is invalid.', [
      { path: 'reviewBy', message: 'The review date must be in the future.' },
    ]);
  }
  if (deadline > max) {
    throw new ApiError(400, 'validation_failed', 'The authorisation is invalid.', [
      {
        path: 'reviewBy',
        message: `The review date must be within ${ATTESTATION_MAX_MONTHS} months.`,
      },
    ]);
  }
  return deadline;
}

interface NormalisedAuthorisation {
  reason: string;
  reference: string | null;
  deadline: Date;
}

export function prepareAuthorisation(input: AuthorisationInput, now: Date): NormalisedAuthorisation {
  return {
    reason: input.reason.trim(),
    reference: input.reference?.trim() || null,
    deadline: reviewDeadline(input.reviewBy, now),
  };
}

/**
 * Authorises each listed domain inside the caller's transaction. Already-verified domains and
 * unknown ids are skipped (reported back), never modified.
 */
export async function authoriseWithin(
  tx: Database,
  domainIds: string[],
  auth: NormalisedAuthorisation,
  actor: Actor,
  now: Date,
  source: 'manual' | 'bulk' | 'import',
): Promise<BulkAuthoriseResponse> {
  const rows = await tx
    .select()
    .from(domains)
    .where(inArray(domains.id, domainIds))
    .orderBy(domains.fqdn)
    .for('update');
  const byId = new Map(rows.map((r) => [r.id, r]));

  const result: BulkAuthoriseResponse = { authorised: [], skipped: [] };
  const eligible: DomainRow[] = [];
  for (const id of domainIds) {
    const domain = byId.get(id);
    if (!domain) result.skipped.push({ id, fqdn: null, reason: 'not_found' });
    else if (domain.verificationStatus === 'verified') {
      result.skipped.push({ id, fqdn: domain.fqdn, reason: 'already_verified' });
    } else eligible.push(domain);
  }
  if (eligible.length === 0) return result;

  // Set-based: a fixed number of statements however many domains are authorised.
  const ids = eligible.map((d) => d.id);
  const superseded = await tx
    .update(domainVerifications)
    .set({ status: 'superseded' })
    .where(and(inArray(domainVerifications.domainId, ids), eq(domainVerifications.status, 'pending')))
    .returning({ id: domainVerifications.id, domainId: domainVerifications.domainId });
  const records = await tx
    .insert(domainVerifications)
    .values(
      ids.map((domainId) => ({
        domainId,
        method: 'admin_attestation' as const,
        status: 'verified' as const,
        reason: auth.reason,
        reference: auth.reference,
        createdBy: actor.userId,
        createdAt: now,
        verifiedAt: now,
        expiresAt: auth.deadline,
      })),
    )
    .returning({ id: domainVerifications.id, domainId: domainVerifications.domainId });
  await tx
    .update(domains)
    .set({
      verificationStatus: 'verified',
      verifiedAt: now,
      verificationMethod: 'admin_attestation',
      verificationExpiresAt: auth.deadline,
    })
    .where(inArray(domains.id, ids));

  const recordOf = new Map(records.map((r) => [r.domainId, r.id]));
  await writeAuditMany(
    tx,
    eligible.map((domain) => ({
      actorType: 'user' as const,
      actorUserId: actor.userId,
      action: 'domain.authorised',
      resourceType: 'domain',
      resourceId: domain.id,
      requestId: actor.requestId,
      metadata: {
        fqdn: domain.fqdn,
        method: 'admin_attestation',
        reason: auth.reason,
        reference: auth.reference,
        reviewBy: auth.deadline.toISOString(),
        verificationId: recordOf.get(domain.id),
        superseded: superseded.filter((s) => s.domainId === domain.id).map((s) => s.id),
        source,
      },
    })),
  );
  result.authorised = eligible.map((d) => ({ id: d.id, fqdn: d.fqdn }));
  return result;
}

export async function authoriseDomains(
  db: Database,
  domainIds: string[],
  input: AuthorisationInput,
  actor: Actor,
  now: Date,
  source: 'manual' | 'bulk',
): Promise<BulkAuthoriseResponse> {
  const auth = prepareAuthorisation(input, now);
  return db.transaction((tx) =>
    authoriseWithin(tx as unknown as Database, domainIds, auth, actor, now, source),
  );
}

/** Withdraws a domain's authorisation (either method). Active scanning stops being allowed. */
export async function revokeDomain(
  db: Database,
  id: string,
  reason: string,
  actor: Actor,
): Promise<DomainRow> {
  return db.transaction(async (tx) => {
    const [domain] = await tx.select().from(domains).where(eq(domains.id, id)).for('update');
    if (!domain) throw new ApiError(404, 'not_found', 'The requested resource was not found.');
    if (domain.verificationStatus !== 'verified') {
      throw new ApiError(409, 'conflict', 'Only a verified domain can have its verification revoked.');
    }
    const [updated] = await tx
      .update(domains)
      .set({
        verificationStatus: 'revoked',
        verifiedAt: null,
        verificationMethod: null,
        verificationExpiresAt: null,
      })
      .where(eq(domains.id, id))
      .returning();
    await tx
      .update(domainVerifications)
      .set({ status: 'revoked', failureReason: 'revoked' })
      .where(and(eq(domainVerifications.domainId, id), eq(domainVerifications.status, 'verified')));
    await writeAudit(tx as unknown as Database, {
      actorType: 'user',
      actorUserId: actor.userId,
      action: 'domain.verification_revoked',
      resourceType: 'domain',
      resourceId: id,
      requestId: actor.requestId,
      metadata: { fqdn: domain.fqdn, reason, previousMethod: domain.verificationMethod },
    });
    if (!updated) throw new Error('Expected the revoked domain row');
    return updated;
  });
}
