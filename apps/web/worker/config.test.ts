// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig } from './config.ts';

describe('loadConfig', () => {
  it('parses valid configuration', () => {
    expect(loadConfig({ APP_ENV: 'production', APP_VERSION: '1.2.3' })).toEqual({
      environment: 'production',
      version: '1.2.3',
    });
  });

  it.each([
    [{}],
    [{ APP_ENV: 'staging', APP_VERSION: '1' }],
    [{ APP_ENV: 'production', APP_VERSION: '' }],
  ])('rejects invalid configuration %j', (env) => {
    expect(() => loadConfig(env)).toThrow(ConfigError);
  });
});
