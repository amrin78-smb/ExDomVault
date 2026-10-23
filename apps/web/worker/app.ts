import { Hono } from 'hono';
import type { AuthProviderDeps } from './auth/provider.ts';
import { handleError, handleNotFound } from './lib/errors.ts';
import { requireAuth } from './middleware/auth.ts';
import { configMiddleware } from './middleware/config.ts';
import { sameOriginWrites } from './middleware/csrf.ts';
import { database, type Connector } from './middleware/database.ts';
import { requestContext } from './middleware/request-context.ts';
import { securityHeaders } from './middleware/security-headers.ts';
import type { Rule } from '@exdomainvault/rules';
import { advisoryRoutes } from './routes/advisories.ts';
import { assetRoutes } from './routes/assets.ts';
import { auditLogRoutes } from './routes/audit-logs.ts';
import { domainRoutes, type DomainRouteDeps } from './routes/domains.ts';
import { findingRoutes } from './routes/findings.ts';
import { healthRoutes, type HealthDeps } from './routes/health.ts';
import { internalWorkerRoutes } from './routes/internal-worker.ts';
import { meRoutes } from './routes/me.ts';
import { approvedNetworkRoutes } from './routes/networks.ts';
import { reportRoutes } from './routes/reports.ts';
import { ruleRoutes } from './routes/rules.ts';
import { scanProfileRoutes, scanRoutes } from './routes/scans.ts';
import { settingsRoutes } from './routes/settings.ts';
import { intelRoutes, softwareRoutes } from './routes/software.ts';
import type { FetchLike } from './lib/feed-fetch.ts';
import { userRoutes } from './routes/users.ts';
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
  /** Rule registry for the rule catalogue and finding detail (tests; defaults to RULES). */
  rules?: readonly Rule[];
  /** Public intelligence feeds (tests inject a mock fetch; defaults to the Workers fetch). */
  intel?: { fetch?: FetchLike };
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
  v1.route('/internal/worker', internalWorkerRoutes({ now: deps.now, connect: deps.connect }));

  // Everything else requires an authenticated, provisioned user. Unknown paths also require
  // authentication, so route existence is not revealed to anonymous clients.
  const authed = new Hono<AppBindings>();
  authed.use('*', sameOriginWrites());
  authed.use('*', requireAuth(deps.auth));
  authed.route('/me', meRoutes);
  authed.route('/domains', domainRoutes({ now: deps.now, ...deps.domains }));
  authed.route('/assets', assetRoutes({ now: deps.now }));
  authed.route('/scan-profiles', scanProfileRoutes());
  authed.route('/scans', scanRoutes({ now: deps.now }));
  authed.route('/workers', workerAdminRoutes({ now: deps.now }));
  authed.route('/approved-networks', approvedNetworkRoutes({ now: deps.now }));
  authed.route('/findings', findingRoutes({ rules: deps.rules, now: deps.now }));
  authed.route('/advisories', advisoryRoutes());
  authed.route('/rules', ruleRoutes({ rules: deps.rules }));
  authed.route('/users', userRoutes({ now: deps.now }));
  authed.route('/settings', settingsRoutes({ now: deps.now }));
  authed.route('/audit-logs', auditLogRoutes());
  authed.route('/reports', reportRoutes({ now: deps.now }));
  authed.route('/software', softwareRoutes({ now: deps.now }));
  authed.route('/intel', intelRoutes({ now: deps.now, fetch: deps.intel?.fetch }));
  v1.route('/', authed);

  app.route('/api/v1', v1);

  app.notFound(handleNotFound);
  app.onError(handleError);

  return app;
}

export type App = ReturnType<typeof createApp>;
