/// <reference types="node" />
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  TAKEOVER_FINGERPRINTS,
  takeoverFingerprintByKey,
  takeoverFingerprintForName,
  workerSignatureTable,
} from './takeover-fingerprints.ts';

describe('takeover fingerprint table', () => {
  it('has unique, well-formed keys and suffixes', () => {
    const keys = TAKEOVER_FINGERPRINTS.map((f) => f.key);
    expect(new Set(keys).size).toBe(keys.length);
    const suffixes = TAKEOVER_FINGERPRINTS.flatMap((f) => f.cnameSuffixes);
    expect(new Set(suffixes).size).toBe(suffixes.length);
    for (const f of TAKEOVER_FINGERPRINTS) {
      expect(f.key).toMatch(/^[a-z0-9_]{1,40}$/);
      expect(['vulnerable', 'edge_case']).toContain(f.status);
      expect(f.cnameSuffixes.length).toBeGreaterThan(0);
      for (const s of f.cnameSuffixes) {
        expect(s).toMatch(/^[a-z0-9-]+(\.[a-z0-9-]+)+$/);
      }
      // Every entry has a deterministic signal: NXDOMAIN or at least one HTTP signature.
      expect(f.nxdomain || f.http.length > 0).toBe(true);
      for (const sig of f.http) {
        expect(sig.bodyContains.length).toBeGreaterThan(0);
        for (const needle of sig.bodyContains) expect(needle.trim().length).toBeGreaterThan(0);
        for (const status of sig.statuses) {
          expect(status).toBeGreaterThanOrEqual(100);
          expect(status).toBeLessThanOrEqual(599);
        }
      }
    }
  });

  it('excludes services can-i-take-over-xyz lists as not vulnerable', () => {
    const all = TAKEOVER_FINGERPRINTS.flatMap((f) => [f.key, ...f.cnameSuffixes]).join(' ');
    for (const name of ['zendesk', 'fastly', 'unbounce', 'kinsta', 'fly.dev']) {
      expect(all).not.toContain(name);
    }
  });

  it('matches CNAME targets on label boundaries only', () => {
    expect(takeoverFingerprintForName('old-site.azurewebsites.net.')?.key).toBe('azure');
    expect(takeoverFingerprintForName('ORG.GitHub.io')?.key).toBe('github_pages');
    expect(takeoverFingerprintForName('bucket.s3-website-eu-west-1.amazonaws.com')?.key).toBe(
      'aws_s3',
    );
    expect(takeoverFingerprintForName('bucket.s3.amazonaws.com')?.key).toBe('aws_s3');
    expect(takeoverFingerprintForName('notgithub.io')).toBeUndefined();
    expect(takeoverFingerprintForName('github.io.example.com')).toBeUndefined();
    expect(takeoverFingerprintForName('ec2.amazonaws.com')).toBeUndefined();
    expect(takeoverFingerprintByKey('heroku')?.provider).toBe('Heroku');
  });

  it('is mirrored exactly by the worker JSON (regenerate it when this fails)', () => {
    const path = new URL('../../../worker/app/takeover_fingerprints.json', import.meta.url);
    const mirror: unknown = JSON.parse(readFileSync(path, 'utf8'));
    expect(mirror).toEqual(workerSignatureTable());
  });
});
