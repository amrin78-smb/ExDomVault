import {
  claimRequestSchema,
  failureRequestSchema,
  heartbeatRequestSchema,
  resultsRequestSchema,
  type ClaimResponse,
} from '@exdomainvault/shared';
import { Hono } from 'hono';
import { parseJsonBody } from '../lib/validation.ts';
import { WORKER_MAX_BODY_BYTES, requireWorker } from '../middleware/worker-auth.ts';
import {
  claimJob,
  heartbeat,
  reportFailure,
  submitResultsDetailed,
} from '../services/job-lifecycle.ts';
import type { AppBindings } from '../types.ts';

/**
 * Internal API for the home scanning worker (design §10). Authenticated by request signature, not
 * by user sessions; never exposed to the browser. The worker can only act on jobs it holds and
 * targets inside the job's immutable snapshot.
 */
export function internalWorkerRoutes(deps: { now?: () => Date } = {}) {
  const now = deps.now ?? (() => new Date());
  return new Hono<AppBindings>()
    .use('*', requireWorker({ now }))
    .post('/claim', async (c) => {
      const { profiles } = await parseJsonBody(c, claimRequestSchema, WORKER_MAX_BODY_BYTES);
      const db = await c.get('db')();
      const worker = c.get('worker');
      const job = await claimJob(db, worker, profiles, now(), {
        activeScanningEnabled: c.get('config').activeScanningEnabled,
      });
      if (job)
        c.get('logger').info('job_claimed', {
          jobId: job.id,
          attempt: job.attempt,
          worker: worker.name,
        });
      const res: ClaimResponse = { job };
      return c.json(res);
    })
    .post('/heartbeat', async (c) => {
      const body = await parseJsonBody(c, heartbeatRequestSchema, WORKER_MAX_BODY_BYTES);
      const db = await c.get('db')();
      return c.json(await heartbeat(db, c.get('worker'), body, now()));
    })
    .post('/results', async (c) => {
      const body = await parseJsonBody(c, resultsRequestSchema, WORKER_MAX_BODY_BYTES);
      const db = await c.get('db')();
      const res = await submitResultsDetailed(db, c.get('worker'), body, now());
      c.get('logger').info('job_results', {
        jobId: body.jobId,
        accepted: res.accepted,
        complete: body.complete,
        observations: res.observations,
      });
      return c.json({ accepted: res.accepted, status: res.status });
    })
    .post('/failures', async (c) => {
      const body = await parseJsonBody(c, failureRequestSchema, WORKER_MAX_BODY_BYTES);
      const db = await c.get('db')();
      const res = await reportFailure(db, c.get('worker'), body, now());
      c.get('logger').warn('job_failure_reported', {
        jobId: body.jobId,
        errorCode: body.errorCode,
        status: res.status,
      });
      return c.json(res);
    });
}
