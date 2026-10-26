import { appEnvironmentSchema, type AppEnvironment } from '@exdomainvault/shared';
import { z } from 'zod';

/** Treats empty strings (unset wrangler vars) as missing. */
const optionalString = z
  .string()
  .trim()
  .transform((v) => (v === '' ? undefined : v))
  .optional();

const rawConfigSchema = z.object({
  APP_ENV: appEnvironmentSchema,
  APP_VERSION: z.string().min(1),
  AUTH_PROVIDER: optionalString,
  ACCESS_TEAM_DOMAIN: optionalString,
  ACCESS_AUD: optionalString,
  DEV_AUTH_EMAIL: optionalString,
  DEV_AUTH_NAME: optionalString,
  BOOTSTRAP_ADMIN_EMAILS: optionalString,
  ACTIVE_SCANNING_ENABLED: optionalString,
  /** Organisation label shown in the UI (optional Worker secret/var; never required). */
  ORG_NAME: optionalString,
});

export type AuthConfig =
  | { kind: 'cloudflare_access'; issuer: string; audience: string }
  | { kind: 'dev'; email: string; name: string | null }
  | { kind: 'unconfigured'; reason: string };

export interface AppConfig {
  environment: AppEnvironment;
  version: string;
  auth: AuthConfig;
  /** Lowercased emails that become administrators on first sign-in. */
  bootstrapAdminEmails: ReadonlySet<string>;
  /**
   * Whether jobs with active (target-contacting) profiles may be created. Off unless explicitly
   * "true": active scanning stays disabled until the Milestone 6 scope validator is complete.
   */
  activeScanningEnabled: boolean;
  /** Organisation label from `ORG_NAME` (trimmed, max ORG_NAME_MAX_LENGTH chars); null when unset. */
  organisation: string | null;
}

export const ORG_NAME_MAX_LENGTH = 100;

export class ConfigError extends Error {
  override name = 'ConfigError';
}

const emailSchema = z.email();

/** Accepts `team.cloudflareaccess.com` or `https://team.cloudflareaccess.com`; returns the issuer URL. */
function accessIssuer(teamDomain: string): string {
  const host = teamDomain.replace(/^https:\/\//, '').replace(/\/+$/, '');
  if (!/^[a-z0-9-]+\.cloudflareaccess\.com$/i.test(host)) {
    throw new ConfigError('ACCESS_TEAM_DOMAIN must look like <team>.cloudflareaccess.com');
  }
  return `https://${host.toLowerCase()}`;
}

function parseAuth(raw: z.infer<typeof rawConfigSchema>, environment: AppEnvironment): AuthConfig {
  switch (raw.AUTH_PROVIDER) {
    case undefined:
      return { kind: 'unconfigured', reason: 'AUTH_PROVIDER is not set' };
    case 'cloudflare_access':
      if (!raw.ACCESS_TEAM_DOMAIN || !raw.ACCESS_AUD) {
        return {
          kind: 'unconfigured',
          reason: 'ACCESS_TEAM_DOMAIN and ACCESS_AUD are required for cloudflare_access',
        };
      }
      return {
        kind: 'cloudflare_access',
        issuer: accessIssuer(raw.ACCESS_TEAM_DOMAIN),
        audience: raw.ACCESS_AUD,
      };
    case 'dev': {
      // The development identity must never be reachable in production.
      if (environment === 'production') {
        throw new ConfigError('AUTH_PROVIDER=dev is not allowed when APP_ENV=production');
      }
      const email = raw.DEV_AUTH_EMAIL?.toLowerCase();
      if (!email || !emailSchema.safeParse(email).success) {
        throw new ConfigError('DEV_AUTH_EMAIL must be a valid email when AUTH_PROVIDER=dev');
      }
      return { kind: 'dev', email, name: raw.DEV_AUTH_NAME ?? null };
    }
    default:
      throw new ConfigError('AUTH_PROVIDER must be "cloudflare_access" or "dev"');
  }
}

/**
 * A cosmetic display label: never a reason to fail requests. Control characters are removed, the
 * value is trimmed and cut to ORG_NAME_MAX_LENGTH characters; empty means unset (null).
 */
function parseOrganisation(value: string | undefined): string | null {
  if (value === undefined) return null;
  const chars = [...value.replace(/\p{Cc}/gu, ' ').trim()];
  return chars.slice(0, ORG_NAME_MAX_LENGTH).join('').trim() || null;
}

function parseFlag(name: string, value: string | undefined): boolean {
  if (value === undefined || value === 'false') return false;
  if (value === 'true') return true;
  throw new ConfigError(`${name} must be "true" or "false"`);
}

function parseEmails(value: string | undefined): Set<string> {
  const emails = (value ?? '')
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);
  for (const e of emails) {
    if (!emailSchema.safeParse(e).success) {
      throw new ConfigError('BOOTSTRAP_ADMIN_EMAILS must be a comma-separated list of emails');
    }
  }
  return new Set(emails);
}

/**
 * Parses Worker bindings into typed configuration. Invalid configuration throws, so a
 * misconfigured deployment fails closed instead of running with guessed defaults. Missing
 * authentication settings yield `unconfigured`, which makes every protected route return 503.
 */
export function loadConfig(env: Record<string, unknown>): AppConfig {
  const parsed = rawConfigSchema.safeParse(env);
  if (!parsed.success) {
    const fields = parsed.error.issues.map((issue) => issue.path.join('.')).join(', ');
    throw new ConfigError(`Invalid application configuration: ${fields}`);
  }
  const raw = parsed.data;
  return {
    environment: raw.APP_ENV,
    version: raw.APP_VERSION,
    auth: parseAuth(raw, raw.APP_ENV),
    bootstrapAdminEmails: parseEmails(raw.BOOTSTRAP_ADMIN_EMAILS),
    activeScanningEnabled: parseFlag('ACTIVE_SCANNING_ENABLED', raw.ACTIVE_SCANNING_ENABLED),
    organisation: parseOrganisation(raw.ORG_NAME),
  };
}
