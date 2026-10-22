import type { AppConfig } from './config.ts';
import type { Logger } from './lib/logger.ts';

/** Hono context typing shared by all routes and middleware. */
export interface AppBindings {
  Bindings: Env;
  Variables: {
    requestId: string;
    config: AppConfig;
    logger: Logger;
  };
}
