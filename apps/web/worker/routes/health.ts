import type { HealthResponse } from '@exdomainvault/shared';
import { Hono } from 'hono';
import type { AppBindings } from '../types.ts';

export const healthRoutes = new Hono<AppBindings>().get('/', (c) => {
  const config = c.get('config');

  // Database and authentication arrive in Milestone 2. Report them honestly until then.
  const components: HealthResponse['components'] = {
    database: 'not_configured',
    auth: 'not_configured',
  };
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
