// Test-only helpers (imported by *.test.ts files, never by application code).
import { schema } from '@exdomainvault/database';
import type { TestDatabase } from '@exdomainvault/database/testing';
import { WORKER_HEADERS, workerSigningString, type Role } from '@exdomainvault/shared';
import { createApp, type AppDeps } from '../app.ts';
import { encodeBase64, sha256HexBytes } from '../lib/ed25519.ts';

export const ORIGIN = 'http://localhost';
const HYPERDRIVE = { connectionString: 'postgres://u:p@db.example.invalid/app' };

export interface Harness {
  deps: AppDeps;
  env: (role: Role, extra?: Record<string, string>) => Record<string, unknown>;
}

export function harness(
  t: () => TestDatabase,
  clock: () => Date,
  extra: Partial<AppDeps> = {},
): Harness {
  return {
    deps: {
      connect: async () => ({ db: t().db, close: async () => {} }),
      now: clock,
      domains: { now: clock, resolveTxt: async () => ({ status: 'nxdomain' }) },
      ...extra,
    },
    env: (role, more = {}) => ({
      APP_ENV: 'development',
      APP_VERSION: 'test',
      AUTH_PROVIDER: 'dev',
      DEV_AUTH_EMAIL: `${role}@example.com`,
      HYPERDRIVE,
      ...more,
    }),
  };
}

export async function ensureUser(t: TestDatabase, role: Role): Promise<string> {
  const email = `${role}@example.com`;
  const [row] = await t.db
    .insert(schema.users)
    .values({ email, role, authProvider: 'dev', authProviderSubject: `dev:${email}` })
    .onConflictDoUpdate({ target: schema.users.email, set: { role } })
    .returning({ id: schema.users.id });
  if (!row) throw new Error('user not created');
  return row.id;
}

/** Calls the API as a signed-in user of the given role. */
export async function userCall(
  h: Harness,
  t: TestDatabase,
  role: Role,
  method: string,
  path: string,
  body?: unknown,
  envExtra: Record<string, string> = {},
): Promise<Response> {
  await ensureUser(t, role);
  return createApp(h.deps).request(
    `/api/v1${path}`,
    {
      method,
      headers: {
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(method !== 'GET' ? { Origin: ORIGIN } : {}),
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    },
    h.env(role, envExtra) as unknown as Env,
  );
}

export interface TestWorkerKey {
  publicKey: string;
  privateKey: CryptoKey;
}

export async function generateWorkerKey(): Promise<TestWorkerKey> {
  const pair = (await crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const raw = new Uint8Array((await crypto.subtle.exportKey('raw', pair.publicKey)) as ArrayBuffer);
  return { publicKey: encodeBase64(raw), privateKey: pair.privateKey };
}

let nonceCounter = 0;

/** Builds the signed headers a worker sends; options allow tampering for negative tests. */
export async function signedHeaders(
  key: TestWorkerKey,
  keyId: string,
  method: string,
  path: string,
  body: string,
  opts: { timestamp?: number; nonce?: string; signedBody?: string; now?: Date } = {},
): Promise<Record<string, string>> {
  const timestamp = String(opts.timestamp ?? Math.floor((opts.now ?? new Date()).getTime() / 1000));
  const nonce = opts.nonce ?? `nonce-${Date.now()}-${nonceCounter++}-abcdef`;
  const message = workerSigningString(
    method,
    path,
    timestamp,
    nonce,
    await sha256HexBytes(opts.signedBody ?? body),
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign('Ed25519', key.privateKey, new TextEncoder().encode(message)),
  );
  return {
    'Content-Type': 'application/json',
    [WORKER_HEADERS.keyId]: keyId,
    [WORKER_HEADERS.timestamp]: timestamp,
    [WORKER_HEADERS.nonce]: nonce,
    [WORKER_HEADERS.signature]: encodeBase64(signature),
    [WORKER_HEADERS.version]: '0.1.0-test',
  };
}

/** Calls the internal worker API with a signed request. */
export async function workerCall(
  h: Harness,
  key: TestWorkerKey,
  keyId: string,
  endpoint: 'claim' | 'heartbeat' | 'results' | 'failures',
  body: unknown,
  opts: Parameters<typeof signedHeaders>[5] & { envExtra?: Record<string, string> } = {},
): Promise<Response> {
  const path = `/api/v1/internal/worker/${endpoint}`;
  const text = JSON.stringify(body);
  const headers = await signedHeaders(key, keyId, 'POST', path, text, opts);
  return createApp(h.deps).request(
    path,
    { method: 'POST', headers, body: text },
    h.env('viewer', opts.envExtra) as unknown as Env,
  );
}
