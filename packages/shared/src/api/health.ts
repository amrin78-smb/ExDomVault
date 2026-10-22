import { z } from 'zod';

export const APP_ENVIRONMENTS = ['development', 'test', 'production'] as const;
export const appEnvironmentSchema = z.enum(APP_ENVIRONMENTS);
export type AppEnvironment = z.infer<typeof appEnvironmentSchema>;

/** Status of a dependency the API relies on. `not_configured` is reported honestly, never as `ok`. */
export const componentStatusSchema = z.enum(['ok', 'degraded', 'down', 'not_configured']);
export type ComponentStatus = z.infer<typeof componentStatusSchema>;

export const healthResponseSchema = z.object({
  status: z.enum(['ok', 'degraded']),
  service: z.literal('exdomainvault-api'),
  version: z.string(),
  environment: appEnvironmentSchema,
  time: z.iso.datetime(),
  components: z.object({
    database: componentStatusSchema,
    auth: componentStatusSchema,
  }),
});
export type HealthResponse = z.infer<typeof healthResponseSchema>;
