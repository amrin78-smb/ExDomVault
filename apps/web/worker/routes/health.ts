import { pingDatabase } from '@exdomainvault/database';
import type { ComponentStatus, HealthResponse } from '@exdomainvault/shared';
import { Hono } from 'hono';
import type { AppBindings } from '../types.ts';

export interface HealthDeps {
  pingDatabase: typeof pingDatabase;
}

const DB_PING_TIMEOUT_MS = 3_000;

export function healthRoutes(deps: HealthDeps = { pingDatabase }) {
  return new Hono<AppBindings>().get('/', async (c) => {
    const config = c.get('config');
    const logger = c.get('logger');

    let database: ComponentStatus = 'not_configured';
    const connectionString = c.env.HYPERDRIVE?.connectionString;
    if (connectionString) {
      const result = await deps.pingDatabase(connectionString, { timeoutMs: DB_PING_TIMEOUT_MS });
      database = result.status;
      if (result.status === 'down') {
        // Details stay in server logs; clients only see `down`.
        logger.error('database_ping_failed', { error: result.error, latencyMs: result.latencyMs });
      } else {
        logger.debug('database_ping_ok', { latencyMs: result.latencyMs });
      }
    }

    const auth: ComponentStatus = config.auth.kind === 'unconfigured' ? 'not_configured' : 'ok';
    const components: HealthResponse['components'] = { database, auth };
    const allOk = Object.values(components).every((status) => status === 'ok');

    const body: HealthResponse = {
      status: allOk ? 'ok' : 'degraded',
      service: 'exdomainvault-api',
      version: config.version,
      environment: config.environment,
      time: new Date().toISOString(),
      components,
    };
    return c.json(body);
  });
}
