import { appEnvironmentSchema, type AppEnvironment } from '@exdomainvault/shared';
import { z } from 'zod';

const rawConfigSchema = z.object({
  APP_ENV: appEnvironmentSchema,
  APP_VERSION: z.string().min(1),
});

export interface AppConfig {
  environment: AppEnvironment;
  version: string;
}

export class ConfigError extends Error {
  override name = 'ConfigError';
}

/**
 * Parses Worker bindings into typed configuration. Invalid or missing configuration throws,
 * so a misconfigured deployment fails closed instead of running with guessed defaults.
 */
export function loadConfig(env: Record<string, unknown>): AppConfig {
  const parsed = rawConfigSchema.safeParse(env);
  if (!parsed.success) {
    const fields = parsed.error.issues.map((issue) => issue.path.join('.')).join(', ');
    throw new ConfigError(`Invalid application configuration: ${fields}`);
  }
  return { environment: parsed.data.APP_ENV, version: parsed.data.APP_VERSION };
}
