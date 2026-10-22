import type { Database } from '@exdomainvault/database';
import type { CurrentUser } from '@exdomainvault/shared';
import type { Identity } from './auth/types.ts';
import type { AppConfig } from './config.ts';
import type { Logger } from './lib/logger.ts';

/** Hono context typing shared by all routes and middleware. */
export interface AppBindings {
  Bindings: Env;
  Variables: {
    requestId: string;
    config: AppConfig;
    logger: Logger;
    /** Lazily opens one database connection for this request (closed after the response). */
    db: () => Promise<Database>;
    /** Set by requireAuth. */
    identity: Identity;
    user: CurrentUser;
  };
}
