import { connect } from '@exdomainvault/database';
import { createApp } from './app.ts';
import { loadConfig } from './config.ts';
import { createLogger, errorFields } from './lib/logger.ts';
import { userAgentFor } from './services/intel-feeds.ts';
import { runMaintenance } from './services/maintenance.ts';

const app = createApp();

export default {
  fetch: app.fetch,

  /**
   * Cron Trigger (see `triggers.crons` in wrangler.jsonc): lease reaping, verification expiry,
   * nonce pruning, scheduling of passive monitoring, discovery and (when enabled) active scan jobs, rules evaluation and the public
   * intelligence feeds (endoflife.date, CISA KEV, NVD). Safe to run repeatedly.
   */
  async scheduled(controller, env, ctx) {
    const logger = createLogger({ cron: controller.cron, run: crypto.randomUUID() });
    const connectionString = env.HYPERDRIVE?.connectionString;
    if (!connectionString) {
      logger.error('maintenance_skipped', { reason: 'database not configured' });
      return;
    }
    const conn = await connect(connectionString);
    try {
      const vars = env as unknown as Record<string, unknown>;
      let activeScanningEnabled = false;
      try {
        activeScanningEnabled = loadConfig(vars).activeScanningEnabled;
      } catch (err) {
        // Invalid configuration: fail closed (no scheduled active scans), keep the other steps.
        logger.error('maintenance_config_invalid', {
          ...errorFields(err),
        });
      }
      const apiKey = typeof vars.NVD_API_KEY === 'string' ? vars.NVD_API_KEY.trim() : '';
      await runMaintenance(conn.db, new Date(controller.scheduledTime), logger, {
        intel: {
          fetch: (input, init) => fetch(input, init),
          userAgent: userAgentFor(typeof vars.APP_VERSION === 'string' ? vars.APP_VERSION : '0'),
          nvdApiKey: apiKey || null,
        },
        activeScanningEnabled,
      });
    } finally {
      ctx.waitUntil(conn.close());
    }
  },
} satisfies ExportedHandler<Env>;
