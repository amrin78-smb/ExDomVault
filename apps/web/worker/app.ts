import { Hono } from 'hono';
import { configMiddleware } from './middleware/config.ts';
import { requestContext } from './middleware/request-context.ts';
import { securityHeaders } from './middleware/security-headers.ts';
import { handleError, handleNotFound } from './lib/errors.ts';
import { healthRoutes, type HealthDeps } from './routes/health.ts';
import type { AppBindings } from './types.ts';

export interface AppDeps {
  health?: HealthDeps;
}

/**
 * Builds the API application. Exported separately from the Worker entry point so tests can
 * call it directly and substitute external dependencies.
 */
export function createApp(deps: AppDeps = {}) {
  const app = new Hono<AppBindings>();

  app.use('*', requestContext());
  app.use('*', securityHeaders());
  app.use('*', configMiddleware());

  const v1 = new Hono<AppBindings>();
  v1.route('/health', healthRoutes(deps.health));

  app.route('/api/v1', v1);

  app.notFound(handleNotFound);
  app.onError(handleError);

  return app;
}

export type App = ReturnType<typeof createApp>;
