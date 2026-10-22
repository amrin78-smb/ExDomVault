import { schema, type Database } from '@exdomainvault/database';
import type { Worker } from '@exdomainvault/shared';
import { asc, eq, inArray } from 'drizzle-orm';
import { firstRow } from '../lib/db.ts';
import { canonicalPublicKey, keyFingerprint } from '../lib/ed25519.ts';
import { ApiError } from '../lib/errors.ts';
import { writeAudit } from './audit.ts';
import { isUniqueViolation, type Actor } from './domains.ts';

const { workerCredentials, workerRegistry } = schema;

const iso = (d: Date | null) => (d ? d.toISOString() : null);

async function canonicalOrThrow(publicKey: string): Promise<string> {
  const key = await canonicalPublicKey(publicKey);
  if (!key) {
    throw new ApiError(400, 'validation_failed', 'The public key is invalid.', [
      { path: 'publicKey', message: 'Not a valid Ed25519 public key.' },
    ]);
  }
  return key;
}

export async function listWorkers(db: Database, ids?: string[]): Promise<Worker[]> {
  const workers = await db
    .select()
    .from(workerRegistry)
    .where(ids ? inArray(workerRegistry.id, ids) : undefined)
    .orderBy(asc(workerRegistry.name));
  if (workers.length === 0) return [];
  const creds = await db
    .select()
    .from(workerCredentials)
    .where(
      inArray(
        workerCredentials.workerId,
        workers.map((w) => w.id),
      ),
    )
    .orderBy(asc(workerCredentials.createdAt));
  return Promise.all(
    workers.map(async (w) => ({
      id: w.id,
      name: w.name,
      status: w.status,
      version: w.version,
      lastSeenAt: iso(w.lastSeenAt),
      createdAt: w.createdAt.toISOString(),
      credentials: await Promise.all(
        creds
          .filter((c) => c.workerId === w.id)
          .map(async (c) => ({
            id: c.id,
            fingerprint: await keyFingerprint(c.publicKey),
            createdAt: c.createdAt.toISOString(),
            expiresAt: c.expiresAt.toISOString(),
            revokedAt: iso(c.revokedAt),
            lastUsedAt: iso(c.lastUsedAt),
          })),
      ),
    })),
  );
}

async function workerOrThrow(db: Database, id: string) {
  const [w] = await listWorkers(db, [id]);
  if (!w) throw new ApiError(404, 'not_found', 'The requested resource was not found.');
  return w;
}

const expiry = (now: Date, days: number) => new Date(now.getTime() + days * 86_400_000);

/** Registers a worker with its first public key. The private key never reaches the server. */
export async function registerWorker(
  db: Database,
  input: { name: string; publicKey: string; expiresInDays: number },
  actor: Actor,
  now: Date,
): Promise<{ worker: Worker; credentialId: string }> {
  const publicKey = await canonicalOrThrow(input.publicKey);
  try {
    const { workerId, credentialId } = await db.transaction(async (tx) => {
      const worker = firstRow(
        await tx
          .insert(workerRegistry)
          .values({ name: input.name })
          .returning({ id: workerRegistry.id }),
      );
      const cred = firstRow(
        await tx
          .insert(workerCredentials)
          .values({
            workerId: worker.id,
            publicKey,
            createdBy: actor.userId,
            createdAt: now,
            expiresAt: expiry(now, input.expiresInDays),
          })
          .returning({ id: workerCredentials.id }),
      );
      await writeAudit(tx as unknown as Database, {
        actorType: 'user',
        actorUserId: actor.userId,
        action: 'worker.registered',
        resourceType: 'worker',
        resourceId: worker.id,
        requestId: actor.requestId,
        metadata: {
          name: input.name,
          credentialId: cred.id,
          fingerprint: await keyFingerprint(publicKey),
        },
      });
      return { workerId: worker.id, credentialId: cred.id };
    });
    return { worker: await workerOrThrow(db, workerId), credentialId };
  } catch (err) {
    if (isUniqueViolation(err)) {
      throw new ApiError(
        409,
        'conflict',
        'A worker with this name or public key is already registered.',
      );
    }
    throw err;
  }
}

/** Adds a key (rotation). The old key keeps working until revoked or expired. */
export async function addCredential(
  db: Database,
  workerId: string,
  input: { publicKey: string; expiresInDays: number },
  actor: Actor,
  now: Date,
): Promise<{ worker: Worker; credentialId: string }> {
  const publicKey = await canonicalOrThrow(input.publicKey);
  await workerOrThrow(db, workerId);
  try {
    const credentialId = await db.transaction(async (tx) => {
      const cred = firstRow(
        await tx
          .insert(workerCredentials)
          .values({
            workerId,
            publicKey,
            createdBy: actor.userId,
            createdAt: now,
            expiresAt: expiry(now, input.expiresInDays),
          })
          .returning({ id: workerCredentials.id }),
      );
      await writeAudit(tx as unknown as Database, {
        actorType: 'user',
        actorUserId: actor.userId,
        action: 'worker.credential_added',
        resourceType: 'worker',
        resourceId: workerId,
        requestId: actor.requestId,
        metadata: { credentialId: cred.id, fingerprint: await keyFingerprint(publicKey) },
      });
      return cred.id;
    });
    return { worker: await workerOrThrow(db, workerId), credentialId };
  } catch (err) {
    if (isUniqueViolation(err)) {
      throw new ApiError(409, 'conflict', 'This public key is already registered.');
    }
    throw err;
  }
}

export async function revokeCredential(
  db: Database,
  workerId: string,
  credentialId: string,
  actor: Actor,
  now: Date,
): Promise<Worker> {
  await db.transaction(async (tx) => {
    const [cred] = await tx
      .select()
      .from(workerCredentials)
      .where(eq(workerCredentials.id, credentialId))
      .for('update');
    if (!cred || cred.workerId !== workerId) {
      throw new ApiError(404, 'not_found', 'The requested resource was not found.');
    }
    if (cred.revokedAt) return;
    await tx
      .update(workerCredentials)
      .set({ revokedAt: now })
      .where(eq(workerCredentials.id, credentialId));
    await writeAudit(tx as unknown as Database, {
      actorType: 'user',
      actorUserId: actor.userId,
      action: 'worker.credential_revoked',
      resourceType: 'worker',
      resourceId: workerId,
      requestId: actor.requestId,
      metadata: { credentialId },
    });
  });
  return workerOrThrow(db, workerId);
}

export async function setWorkerStatus(
  db: Database,
  workerId: string,
  status: 'active' | 'disabled',
  actor: Actor,
): Promise<Worker> {
  await db.transaction(async (tx) => {
    const [w] = await tx
      .select()
      .from(workerRegistry)
      .where(eq(workerRegistry.id, workerId))
      .for('update');
    if (!w) throw new ApiError(404, 'not_found', 'The requested resource was not found.');
    if (w.status === status) return;
    await tx.update(workerRegistry).set({ status }).where(eq(workerRegistry.id, workerId));
    await writeAudit(tx as unknown as Database, {
      actorType: 'user',
      actorUserId: actor.userId,
      action: status === 'active' ? 'worker.enabled' : 'worker.disabled',
      resourceType: 'worker',
      resourceId: workerId,
      requestId: actor.requestId,
      metadata: { name: w.name },
    });
  });
  return workerOrThrow(db, workerId);
}
