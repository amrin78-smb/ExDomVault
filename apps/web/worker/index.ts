import { connect } from '@exdomainvault/database';
import { createApp } from './app.ts';
import { createLogger } from './lib/logger.ts';
import { runMaintenance } from './services/maintenance.ts';

const app = createApp();

export default {
  fetch: app.fetch,

  /**
   * Cron Trigger (see `triggers.crons` in wrangler.jsonc): lease reaping, verification expiry,
   * nonce pruning and scheduling of passive monitoring jobs. Safe to run repeatedly.
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
      await runMaintenance(conn.db, new Date(controller.scheduledTime), logger);
    } finally {
      ctx.waitUntil(conn.close());
    }
  },
} satisfies ExportedHandler<Env>;
