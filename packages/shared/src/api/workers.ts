import { z } from 'zod';
import { scanTargetStatusSchema, scopeSnapshotSchema } from './scans.ts';

const isoDateTime = z.iso.datetime();

// --- Worker administration (UI → API) ------------------------------------------------------------

/** Base64 (standard or URL-safe) of a raw 32-byte Ed25519 public key. */
export const ed25519PublicKeySchema = z
  .string()
  .trim()
  .regex(/^[A-Za-z0-9+/_-]{43}=?$/, 'Paste the base64 Ed25519 public key (44 characters).');

export const workerCredentialSchema = z.object({
  id: z.uuid(),
  /** Short SHA-256 fingerprint of the public key, for recognising keys. */
  fingerprint: z.string(),
  createdAt: isoDateTime,
  expiresAt: isoDateTime,
  revokedAt: isoDateTime.nullable(),
  lastUsedAt: isoDateTime.nullable(),
});
export type WorkerCredential = z.infer<typeof workerCredentialSchema>;

export const workerSchema = z.object({
  id: z.uuid(),
  name: z.string(),
  status: z.enum(['active', 'disabled']),
  version: z.string().nullable(),
  lastSeenAt: isoDateTime.nullable(),
  createdAt: isoDateTime,
  credentials: z.array(workerCredentialSchema),
});
export type Worker = z.infer<typeof workerSchema>;

export const workerListResponseSchema = z.object({ items: z.array(workerSchema) });

const expiresInDays = z.int().min(1).max(730).default(365);

export const registerWorkerRequestSchema = z.strictObject({
  name: z
    .string()
    .trim()
    .regex(/^[a-z0-9][a-z0-9-]{0,62}$/, 'Use 1–63 lowercase letters, digits and hyphens.'),
  publicKey: ed25519PublicKeySchema,
  expiresInDays,
});
export type RegisterWorkerRequest = z.input<typeof registerWorkerRequestSchema>;

export const addWorkerCredentialRequestSchema = z.strictObject({
  publicKey: ed25519PublicKeySchema,
  expiresInDays,
});

export const updateWorkerRequestSchema = z.strictObject({
  status: z.enum(['active', 'disabled']),
});

/** Returned when a credential is created: the id the worker uses as its key id. */
export const workerCredentialCreatedResponseSchema = z.object({
  worker: workerSchema,
  credentialId: z.uuid(),
});
export type WorkerCredentialCreatedResponse = z.infer<typeof workerCredentialCreatedResponseSchema>;

// --- Internal worker protocol (worker → API) ---------------------------------------------------

/**
 * Request signing: the worker signs
 *   `EDV1\n<METHOD>\n<path>\n<timestamp>\n<nonce>\n<sha256 hex of body>`
 * with its Ed25519 private key and sends the headers below. The server keeps only public keys.
 */
export const WORKER_SIGNATURE_VERSION = 'EDV1';
export const WORKER_HEADERS = {
  keyId: 'X-EDV-Key-Id',
  timestamp: 'X-EDV-Timestamp',
  nonce: 'X-EDV-Nonce',
  signature: 'X-EDV-Signature',
  version: 'X-EDV-Worker-Version',
} as const;
export const WORKER_SIGNATURE_MAX_SKEW_SECONDS = 300;

export function workerSigningString(
  method: string,
  path: string,
  timestamp: string,
  nonce: string,
  bodySha256Hex: string,
): string {
  return [
    WORKER_SIGNATURE_VERSION,
    method.toUpperCase(),
    path,
    timestamp,
    nonce,
    bodySha256Hex,
  ].join('\n');
}

const jobRef = {
  jobId: z.uuid(),
  /** Fencing token: the attempt number returned by claim. Stale attempts are rejected. */
  attempt: z.int().min(1),
};

export const claimRequestSchema = z.strictObject({
  /** Profiles this worker can run; omitted = all. */
  profiles: z.array(z.string().min(1).max(40)).max(10).optional(),
});

export const claimedJobSchema = z.object({
  id: z.uuid(),
  attempt: z.int(),
  profile: z.string(),
  leaseExpiresAt: isoDateTime,
  leaseSeconds: z.int(),
  heartbeatSeconds: z.int(),
  snapshot: scopeSnapshotSchema,
  targets: z.array(z.object({ id: z.uuid(), hostname: z.string(), ip: z.string().nullable() })),
});
export type ClaimedJob = z.infer<typeof claimedJobSchema>;

export const claimResponseSchema = z.object({ job: claimedJobSchema.nullable() });
export type ClaimResponse = z.infer<typeof claimResponseSchema>;

export const heartbeatRequestSchema = z.strictObject({
  ...jobRef,
  progress: z
    .strictObject({
      completedTargets: z.int().min(0).max(100_000),
      totalTargets: z.int().min(0).max(100_000),
      message: z.string().max(200).optional(),
    })
    .optional(),
});

export const heartbeatResponseSchema = z.object({
  leaseExpiresAt: isoDateTime,
  /** The job was cancelled by a user: stop work and report a failure with `cancelled`. */
  cancelRequested: z.boolean(),
});

export const resultsRequestSchema = z.strictObject({
  ...jobRef,
  /** Idempotency key chosen by the worker; resubmitting the same id is a no-op. */
  resultId: z.string().regex(/^[A-Za-z0-9_-]{8,128}$/),
  targets: z
    .array(
      z.strictObject({
        targetId: z.uuid(),
        status: scanTargetStatusSchema.exclude(['pending']),
        errorCode: z
          .string()
          .regex(/^[a-z0-9_]{1,64}$/)
          .optional(),
      }),
    )
    .max(1000),
  /** The worker has submitted everything for this attempt. */
  complete: z.boolean(),
});
export type ResultsRequest = z.input<typeof resultsRequestSchema>;

export const resultsResponseSchema = z.object({
  /** False when this resultId was already processed (duplicate delivery). */
  accepted: z.boolean(),
  status: z.string(),
});

export const failureRequestSchema = z.strictObject({
  ...jobRef,
  errorCode: z.string().regex(/^[a-z0-9_]{1,64}$/),
  errorSummary: z.string().max(500),
  retryable: z.boolean(),
});

export const failureResponseSchema = z.object({
  status: z.string(),
  retryAt: isoDateTime.nullable(),
});
