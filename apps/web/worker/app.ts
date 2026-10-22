import { Hono } from 'hono';
import type { AuthProviderDeps } from './auth/provider.ts';
import { handleError, handleNotFound } from './lib/errors.ts';
import { requireAuth } from './middleware/auth.ts';
import { configMiddleware } from './middleware/config.ts';
import { sameOriginWrites } from './middleware/csrf.ts';
import { database, type Connector } from './middleware/database.ts';
import { requestContext } from './middleware/request-context.ts';
import { securityHeaders } from './middleware/security-headers.ts';
import { domainRoutes, type DomainRouteDeps } from './routes/domains.ts';
import { healthRoutes, type HealthDeps } from './routes/health.ts';
import { internalWorkerRoutes } from './routes/internal-worker.ts';
import { meRoutes } from './routes/me.ts';
import { scanProfileRoutes, scanRoutes } from './routes/scans.ts';
import { workerAdminRoutes } from './routes/workers.ts';
import type { AppBindings } from './types.ts';

export interface AppDeps {
  health?: HealthDeps;
  /** Opens a database connection (defaults to node-postgres via Hyperdrive). */
  connect?: Connector;
  auth?: AuthProviderDeps;
  domains?: DomainRouteDeps;
  /** Clock for scans, workers and the internal worker API (tests). */
  now?: () => Date;
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
  app.use('*', database(deps.connect));

  // Public: liveness and configuration status only, no data.
  const v1 = new Hono<AppBindings>();
  v1.route('/health', healthRoutes(deps.health));
  // Scanning worker: request-signature authentication, no user session, no CSRF (no cookies).
  v1.route('/internal/worker', internalWorkerRoutes({ now: deps.now }));

  // Everything else requires an authenticated, provisioned user. Unknown paths also require
  // authentication, so route existence is not revealed to anonymous clients.
  const authed = new Hono<AppBindings>();
  authed.use('*', sameOriginWrites());
  authed.use('*', requireAuth(deps.auth));
  authed.route('/me', meRoutes);
  authed.route('/domains', domainRoutes({ now: deps.now, ...deps.domains }));
  authed.route('/scan-profiles', scanProfileRoutes());
  authed.route('/scans', scanRoutes({ now: deps.now }));
  authed.route('/workers', workerAdminRoutes({ now: deps.now }));
  v1.route('/', authed);

  app.route('/api/v1', v1);

  app.notFound(handleNotFound);
  app.onError(handleError);

  return app;
}

export type App = ReturnType<typeof createApp>;
