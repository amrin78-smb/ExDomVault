import { connect } from '@exdomainvault/database';
import { createApp } from './app.ts';
import { createLogger } from './lib/logger.ts';
import { userAgentFor } from './services/intel-feeds.ts';
import { runMaintenance } from './services/maintenance.ts';

const app = createApp();

export default {
  fetch: app.fetch,

  /**
   * Cron Trigger (see `triggers.crons` in wrangler.jsonc): lease reaping, verification expiry,
   * nonce pruning, scheduling of passive monitoring jobs, rules evaluation and the public
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
      const apiKey = typeof vars.NVD_API_KEY === 'string' ? vars.NVD_API_KEY.trim() : '';
      await runMaintenance(conn.db, new Date(controller.scheduledTime), logger, {
        intel: {
          fetch: (input, init) => fetch(input, init),
          userAgent: userAgentFor(typeof vars.APP_VERSION === 'string' ? vars.APP_VERSION : '0'),
          nvdApiKey: apiKey || null,
        },
      });
    } finally {
      ctx.waitUntil(conn.close());
    }
  },
} satisfies ExportedHandler<Env>;
