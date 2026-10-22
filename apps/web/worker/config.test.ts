// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig } from './config.ts';

const base = { APP_ENV: 'production', APP_VERSION: '1.2.3' };

describe('loadConfig', () => {
  it('parses valid configuration', () => {
    expect(loadConfig(base)).toMatchObject({ environment: 'production', version: '1.2.3' });
  });

  it.each([
    [{}],
    [{ APP_ENV: 'staging', APP_VERSION: '1' }],
    [{ APP_ENV: 'production', APP_VERSION: '' }],
  ])('rejects invalid configuration %j', (env) => {
    expect(() => loadConfig(env)).toThrow(ConfigError);
  });

  describe('authentication', () => {
    it('is unconfigured when no provider is set', () => {
      expect(loadConfig(base).auth.kind).toBe('unconfigured');
    });

    it('is unconfigured when Cloudflare Access values are empty', () => {
      const config = loadConfig({
        ...base,
        AUTH_PROVIDER: 'cloudflare_access',
        ACCESS_TEAM_DOMAIN: '',
        ACCESS_AUD: '',
      });
      expect(config.auth.kind).toBe('unconfigured');
    });

    it('builds the Access issuer from the team domain', () => {
      const config = loadConfig({
        ...base,
        AUTH_PROVIDER: 'cloudflare_access',
        ACCESS_TEAM_DOMAIN: 'https://MyTeam.cloudflareaccess.com/',
        ACCESS_AUD: 'aud',
      });
      expect(config.auth).toEqual({
        kind: 'cloudflare_access',
        issuer: 'https://myteam.cloudflareaccess.com',
        audience: 'aud',
      });
    });

    it('rejects a team domain that is not a Cloudflare Access domain', () => {
      expect(() =>
        loadConfig({
          ...base,
          AUTH_PROVIDER: 'cloudflare_access',
          ACCESS_TEAM_DOMAIN: 'evil.example.com',
          ACCESS_AUD: 'aud',
        }),
      ).toThrow(ConfigError);
    });

    it('refuses the development provider in production', () => {
      expect(() =>
        loadConfig({ ...base, AUTH_PROVIDER: 'dev', DEV_AUTH_EMAIL: 'dev@example.com' }),
      ).toThrow(/not allowed/);
    });

    it('allows the development provider in development', () => {
      const config = loadConfig({
        ...base,
        APP_ENV: 'development',
        AUTH_PROVIDER: 'dev',
        DEV_AUTH_EMAIL: 'Dev@Example.com',
      });
      expect(config.auth).toEqual({ kind: 'dev', email: 'dev@example.com', name: null });
    });

    it('rejects unknown providers', () => {
      expect(() => loadConfig({ ...base, AUTH_PROVIDER: 'header' })).toThrow(ConfigError);
    });

    it('parses and validates bootstrap admin emails', () => {
      expect([
        ...loadConfig({ ...base, BOOTSTRAP_ADMIN_EMAILS: ' A@example.com, b@example.com ' })
          .bootstrapAdminEmails,
      ]).toEqual(['a@example.com', 'b@example.com']);
      expect(() => loadConfig({ ...base, BOOTSTRAP_ADMIN_EMAILS: 'not-an-email' })).toThrow(
        ConfigError,
      );
    });
  });
});
