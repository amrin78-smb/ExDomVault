import { schema, type Database } from '@exdomainvault/database';
import type {
  CreateChallengeResponse,
  VerificationChallenge,
  VerificationOutcome,
} from '@exdomainvault/shared';
import { and, desc, eq, gt, inArray, isNull, lt, lte, or } from 'drizzle-orm';
import type { TxtResolver } from '../lib/doh.ts';
import { firstRow } from '../lib/db.ts';
import { ApiError } from '../lib/errors.ts';
import { writeAudit } from './audit.ts';
import type { Actor, DomainRow } from './domains.ts';

const { domains, domainVerifications } = schema;

/**
 * DNS TXT domain-control verification (design §5.3).
 *
 * - The challenge token is 256 random bits, shown to the user once. Only its SHA-256 is stored.
 * - The user publishes `TXT _exdomainvault-challenge.<domain> "exdomainvault-verification=<token>"`.
 * - Checks resolve that one name through a public DoH resolver from the Worker.
 * - Challenges expire; a new challenge supersedes any pending one.
 * - Verification proves control of the DNS zone only. It never approves hosts, IPs or third-party
 *   infrastructure for scanning.
 */
export const CHALLENGE_RECORD_LABEL = '_exdomainvault-challenge';
export const CHALLENGE_VALUE_PREFIX = 'exdomainvault-verification=';
export const CHALLENGE_TTL_MS = 72 * 60 * 60 * 1000;
export const MIN_CHECK_INTERVAL_MS = 10 * 1000;

export type ChallengeRow = typeof domainVerifications.$inferSelect;

export const challengeRecordName = (fqdn: string) => `${CHALLENGE_RECORD_LABEL}.${fqdn}`;

const iso = (d: Date | null) => (d ? d.toISOString() : null);

export function toChallengeDto(row: ChallengeRow, fqdn: string): VerificationChallenge {
  return {
    id: row.id,
    method: row.method,
    status: row.status,
    recordName: challengeRecordName(fqdn),
    createdAt: row.createdAt.toISOString(),
    expiresAt: row.expiresAt.toISOString(),
    lastCheckedAt: iso(row.lastCheckedAt),
    verifiedAt: iso(row.verifiedAt),
    failureReason: row.failureReason,
  };
}

function toHex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function sha256Hex(value: string): Promise<string> {
  return toHex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
}

/** Constant-time comparison of two equal-length hex digests. */
export function digestsEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function generateToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Checks published TXT values against the stored hash. */
export async function matchesChallenge(records: string[], challengeHash: string): Promise<boolean> {
  let matched = false;
  for (const record of records) {
    const value = record.trim();
    if (!value.startsWith(CHALLENGE_VALUE_PREFIX)) continue;
    const token = value.slice(CHALLENGE_VALUE_PREFIX.length);
    // Evaluate every candidate so timing does not reveal which record matched.
    if (digestsEqual(await sha256Hex(token), challengeHash)) matched = true;
  }
  return matched;
}

/**
 * Marks pending challenges past their expiry as expired and returns their domains to `unverified`
 * (audited as a system action). Called before any read or change that depends on challenge state.
 */
export async function expireStaleChallenges(
  db: Database,
  now: Date,
  domainId?: string,
): Promise<number> {
  return db.transaction(async (tx) => {
    const expired = await tx
      .update(domainVerifications)
      .set({ status: 'expired', failureReason: 'expired' })
      .where(
        and(
          eq(domainVerifications.status, 'pending'),
          lte(domainVerifications.expiresAt, now),
          domainId ? eq(domainVerifications.domainId, domainId) : undefined,
        ),
      )
      .returning({ id: domainVerifications.id, domainId: domainVerifications.domainId });
    if (expired.length === 0) return 0;

    await tx
      .update(domains)
      .set({ verificationStatus: 'unverified' })
      .where(
        and(
          inArray(
            domains.id,
            expired.map((e) => e.domainId),
          ),
          eq(domains.verificationStatus, 'pending'),
        ),
      );
    for (const e of expired) {
      await writeAudit(tx as unknown as Database, {
        actorType: 'system',
        action: 'domain.verification_expired',
        resourceType: 'domain',
        resourceId: e.domainId,
        metadata: { challengeId: e.id },
      });
    }
    return expired.length;
  });
}

/** The pending challenge if there is one, otherwise the most recent. */
export async function latestChallenge(db: Database, domainId: string): Promise<ChallengeRow | null> {
  const [pending] = await db
    .select()
    .from(domainVerifications)
    .where(and(eq(domainVerifications.domainId, domainId), eq(domainVerifications.status, 'pending')))
    .limit(1);
  if (pending) return pending;
  const [latest] = await db
    .select()
    .from(domainVerifications)
    .where(eq(domainVerifications.domainId, domainId))
    .orderBy(desc(domainVerifications.createdAt))
    .limit(1);
  return latest ?? null;
}

export async function createChallenge(
  db: Database,
  domainId: string,
  actor: Actor,
  now: Date,
): Promise<CreateChallengeResponse> {
  await expireStaleChallenges(db, now, domainId);
  const token = generateToken();
  const challengeHash = await sha256Hex(token);
  const expiresAt = new Date(now.getTime() + CHALLENGE_TTL_MS);

  const { row, fqdn } = await db.transaction(async (tx) => {
    const [domain] = await tx.select().from(domains).where(eq(domains.id, domainId)).for('update');
    if (!domain) throw new ApiError(404, 'not_found', 'The requested resource was not found.');
    if (domain.verificationStatus === 'verified') {
      throw new ApiError(409, 'conflict', 'This domain is already verified.');
    }

    const superseded = await tx
      .update(domainVerifications)
      .set({ status: 'superseded' })
      .where(
        and(eq(domainVerifications.domainId, domainId), eq(domainVerifications.status, 'pending')),
      )
      .returning({ id: domainVerifications.id });
    const inserted = firstRow(
      await tx
      .insert(domainVerifications)
      .values({
        domainId,
        method: 'dns_txt',
        challengeHash,
        createdBy: actor.userId,
        createdAt: now,
        expiresAt,
      })
      .returning(),
    );
    await tx.update(domains).set({ verificationStatus: 'pending' }).where(eq(domains.id, domainId));
    await writeAudit(tx as unknown as Database, {
      actorType: 'user',
      actorUserId: actor.userId,
      action: 'domain.verification_started',
      resourceType: 'domain',
      resourceId: domainId,
      requestId: actor.requestId,
      metadata: {
        fqdn: domain.fqdn,
        method: 'dns_txt',
        challengeId: inserted.id,
        expiresAt: expiresAt.toISOString(),
        superseded: superseded.map((s) => s.id),
      },
    });
    return { row: inserted, fqdn: domain.fqdn };
  });

  return {
    challenge: toChallengeDto(row, fqdn),
    record: { type: 'TXT', name: challengeRecordName(fqdn), value: `${CHALLENGE_VALUE_PREFIX}${token}` },
  };
}

const OUTCOME_MESSAGES: Record<VerificationOutcome, string> = {
  verified: 'Domain ownership verified.',
  record_not_found:
    'No verification TXT record was found yet. DNS changes can take a while to appear; try again shortly.',
  value_mismatch:
    'A TXT record exists but does not contain the current verification value. Check it was copied exactly, or generate a new value.',
  expired: 'The verification value has expired. Generate a new one.',
  dns_error: 'The DNS lookup failed. Try again shortly.',
  too_soon: 'Please wait a few seconds before checking again.',
};

export interface CheckResult {
  outcome: VerificationOutcome;
  message: string;
  domain: DomainRow;
  challenge: ChallengeRow | null;
}

/** Resolves the challenge record and verifies the domain if the published value matches. */
export async function checkChallenge(
  db: Database,
  domainId: string,
  resolver: TxtResolver,
  actor: Actor,
  now: Date,
  log: (event: string, fields: Record<string, unknown>) => void,
): Promise<CheckResult> {
  await expireStaleChallenges(db, now, domainId);

  const [domain] = await db.select().from(domains).where(eq(domains.id, domainId)).limit(1);
  if (!domain) throw new ApiError(404, 'not_found', 'The requested resource was not found.');
  if (domain.verificationStatus === 'verified') {
    throw new ApiError(409, 'conflict', 'This domain is already verified.');
  }

  const challenge = await latestChallenge(db, domainId);
  if (!challenge || challenge.status !== 'pending') {
    if (challenge?.status === 'expired') {
      return { outcome: 'expired', message: OUTCOME_MESSAGES.expired, domain, challenge };
    }
    throw new ApiError(409, 'conflict', 'Start verification to get a TXT record value first.');
  }

  // Atomic throttle: only one check per challenge per interval, across concurrent requests.
  const [claimed] = await db
    .update(domainVerifications)
    .set({ lastCheckedAt: now })
    .where(
      and(
        eq(domainVerifications.id, challenge.id),
        eq(domainVerifications.status, 'pending'),
        or(
          isNull(domainVerifications.lastCheckedAt),
          lt(domainVerifications.lastCheckedAt, new Date(now.getTime() - MIN_CHECK_INTERVAL_MS)),
        ),
      ),
    )
    .returning();
  if (!claimed) {
    return { outcome: 'too_soon', message: OUTCOME_MESSAGES.too_soon, domain, challenge };
  }

  const recordName = challengeRecordName(domain.fqdn);
  const lookup = await resolver(recordName);
  let outcome: VerificationOutcome;
  if (lookup.status === 'error') {
    log('domain_verification_dns_error', { domainId, detail: lookup.detail });
    outcome = 'dns_error';
  } else if (lookup.status === 'nxdomain' || lookup.records.length === 0) {
    outcome = 'record_not_found';
  } else if (await matchesChallenge(lookup.records, challenge.challengeHash)) {
    outcome = 'verified';
  } else {
    outcome = 'value_mismatch';
  }
  const dnssec = lookup.status === 'ok' ? lookup.authenticated : false;

  return db.transaction(async (tx) => {
    const audit = (action: string, metadata: Record<string, unknown>) =>
      writeAudit(tx as unknown as Database, {
        actorType: 'user',
        actorUserId: actor.userId,
        action,
        resourceType: 'domain',
        resourceId: domainId,
        requestId: actor.requestId,
        metadata: { fqdn: domain.fqdn, challengeId: challenge.id, ...metadata },
      });

    if (outcome !== 'verified') {
      const [updated] = await tx
        .update(domainVerifications)
        .set({ failureReason: outcome })
        .where(and(eq(domainVerifications.id, challenge.id), eq(domainVerifications.status, 'pending')))
        .returning();
      await audit('domain.verification_failed', { outcome });
      return { outcome, message: OUTCOME_MESSAGES[outcome], domain, challenge: updated ?? challenge };
    }

    // The challenge must still be the live one: not superseded or expired since the lookup began.
    const [verified] = await tx
      .update(domainVerifications)
      .set({ status: 'verified', verifiedAt: now, failureReason: null })
      .where(
        and(
          eq(domainVerifications.id, challenge.id),
          eq(domainVerifications.status, 'pending'),
          gt(domainVerifications.expiresAt, now),
        ),
      )
      .returning();
    if (!verified) {
      throw new ApiError(409, 'conflict', 'The verification value changed during the check. Try again.');
    }
    const updatedDomain = firstRow(
      await tx
        .update(domains)
        .set({ verificationStatus: 'verified', verifiedAt: now })
        .where(eq(domains.id, domainId))
        .returning(),
    );
    await audit('domain.verified', { method: 'dns_txt', dnssecAuthenticated: dnssec });
    return {
      outcome,
      message: OUTCOME_MESSAGES.verified,
      domain: updatedDomain,
      challenge: verified,
    };
  });
}
