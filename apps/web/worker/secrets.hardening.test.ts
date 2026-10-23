// @vitest-environment node
/**
 * Milestone 11/12 hardening: secret handling.
 *
 *  1. No tracked (or untracked, not ignored) file in the repository contains a credential: database
 *     URLs with real passwords, Neon passwords, Cloudflare API / Access service tokens, private keys,
 *     NVD API keys, worker signing keys, tunnel credentials or common cloud tokens. Files that may
 *     only exist locally (.env, .dev.vars, keys) must not be tracked at all.
 *  2. The built client bundle (apps/web/dist/client, if a build exists) contains no server-side
 *     configuration or secret names.
 *
 * Complements the gitleaks CI job; this one runs with every `npm test`.
 * The patterns below are assembled from parts so this file never matches itself.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const SELF = relative(ROOT, fileURLToPath(import.meta.url));

function repoFiles(): string[] {
  const out = execFileSync(
    'git',
    ['ls-files', '-z', '--cached', '--others', '--exclude-standard'],
    { cwd: ROOT, maxBuffer: 64 * 1024 * 1024 },
  ).toString('utf8');
  return [...new Set(out.split('\0').filter(Boolean))].filter((f) => existsSync(join(ROOT, f)));
}

const B = 'BEGIN';
const PK = 'PRIVATE KEY';
/** A value that is clearly a placeholder, not a credential. */
const PLACEHOLDER =
  /^(<[^>]*>|\$\{?[A-Z_]+\}?|x+|X+|\*+|\.\.\.|changeme|change-me|password|passwd|secret|s3cret|p4ssw0rd|p|pass|pw|user|example|placeholder|your[-_a-z]*|REDACTED|redacted|test[-_a-z0-9]*|dummy|fake[-_a-z0-9]*)$/;

interface Rule {
  name: string;
  re: RegExp;
  /** Return true when the match is a real secret (default: always). */
  real?: (m: RegExpExecArray) => boolean;
}

const RULES: Rule[] = [
  {
    name: 'PostgreSQL URL with a password',
    re: /postgres(?:ql)?:\/\/([^:\s/'"`@]+):([^@\s'"`]+)@([^\s/'"`?:]+)/g,
    real: (m) => {
      const [, , password, host] = m as unknown as string[];
      if (PLACEHOLDER.test(password!)) return false;
      if (/(^|\.)(example(\.\w+)?|invalid|test|localhost|local|internal)$/i.test(host!))
        return false;
      if (/^(127\.0\.0\.1|localhost|db|postgres|host)$/i.test(host!)) return false;
      return true;
    },
  },
  { name: 'Neon password', re: new RegExp('\\b' + 'npg' + '_[A-Za-z0-9]{12,}', 'g') },
  {
    name: 'Neon host with credentials',
    re: /[A-Za-z0-9_]+:([A-Za-z0-9_]{8,})@ep-[a-z0-9-]+(?:-pooler)?\.[a-z0-9.-]*neon\.tech/g,
    real: (m) => !PLACEHOLDER.test(m[1]!),
  },
  {
    // A real key block: the header followed by base64 key material (test fakes have none).
    name: 'private key block',
    re: new RegExp(`-----${B} ([A-Z0-9 ]+ )?${PK}-----\\s*(?:\\\\n)?[A-Za-z0-9+/=]{64,}`, 'g'),
  },
  {
    name: 'Cloudflare API token / client secret (cfat_ / cfast_ / cfut_)',
    re: new RegExp('\\b' + 'cf(?:at|ast|ut)' + '_[A-Za-z0-9_-]{20,}', 'g'),
  },
  {
    name: 'Cloudflare token assignment',
    re: /\b(?:CLOUDFLARE_API_TOKEN|CF_API_TOKEN|CLOUDFLARE_API_KEY|CF_ACCESS_CLIENT_SECRET)\s*[:=]\s*["']?([A-Za-z0-9_-]{30,})/g,
  },
  {
    name: 'Cloudflare Access service-token secret header',
    re: /CF-Access-Client-Secret\s*[:=]\s*["']?([a-f0-9]{64})/gi,
  },
  {
    name: 'NVD API key assignment',
    re: /\bNVD_API_KEY\s*[:=]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/gi,
  },
  {
    name: 'worker private key assignment',
    re: /\b(?:EXDV_WORKER_PRIVATE_KEY|WORKER_PRIVATE_KEY|PRIVATE_KEY)\s*[:=]\s*["']?([A-Za-z0-9+/_-]{43}=?)(?![A-Za-z0-9+/=_-])/g,
  },
  { name: 'Cloudflare Tunnel credentials', re: /"TunnelSecret"\s*:\s*"[A-Za-z0-9+/=]{30,}"/g },
  { name: 'AWS access key', re: new RegExp('\\b' + 'AKIA' + '[0-9A-Z]{16}\\b', 'g') },
  { name: 'GitHub token', re: new RegExp('\\b' + 'gh[pousr]' + '_[A-Za-z0-9]{36,}', 'g') },
  { name: 'Slack token', re: new RegExp('\\b' + 'xox[abprs]' + '-[A-Za-z0-9-]{10,}', 'g') },
  {
    name: 'Anthropic / OpenAI key',
    re: new RegExp('\\b' + 'sk-(?:ant-)?' + '[A-Za-z0-9_-]{32,}', 'g'),
  },
];

/** Files that must never be tracked, whatever their content. */
const FORBIDDEN_FILES: RegExp[] = [
  /(^|\/)\.env$/,
  /(^|\/)\.env\.(?!example$)[^/]+$/,
  /(^|\/)\.dev\.vars$/,
  /(^|\/)\.dev\.vars\.(?!example$)[^/]+$/,
  /\.(pem|key|p12|pfx|jks)$/i,
  /(^|\/)id_(rsa|ed25519|ecdsa)$/,
  /(^|\/)[0-9a-f-]{36}\.json$/, // cloudflared tunnel credentials file name
  /(^|\/)cert\.pem$/,
  /(^|\/)\.wrangler\//,
  /(^|\/)worker-key(\.|$)/,
];

/** Paths exempt from content scanning (rule definitions, lockfiles). */
const SKIP_CONTENT = [SELF, '.gitleaks.toml', 'package-lock.json'];

function isText(buf: Buffer) {
  return !buf.subarray(0, 8000).includes(0);
}

describe('repository secret scan', () => {
  const files = repoFiles();

  it('scans a plausible number of files (sanity)', () => {
    expect(files.length).toBeGreaterThan(100);
    expect(files).toContain('package.json');
  });

  it('tracks no local-only credential files', () => {
    const bad = files.filter((f) => FORBIDDEN_FILES.some((re) => re.test(f)));
    expect(bad).toEqual([]);
  });

  it('the example environment files contain placeholders only', () => {
    const examples = files.filter((f) => /\.(env|dev\.vars)\.example$|\.env\.example$/.test(f));
    expect(examples.length).toBeGreaterThan(0);
    for (const f of examples) {
      for (const line of readFileSync(join(ROOT, f), 'utf8').split('\n')) {
        const m =
          /^\s*([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PRIVATE_KEY|API_KEY|DATABASE_URL)[A-Z0-9_]*)\s*=\s*(.*)$/.exec(
            line,
          );
        if (!m) continue;
        const value = m[2]!.trim().replace(/^["']|["']$/g, '');
        const ok =
          value === '' ||
          PLACEHOLDER.test(value) ||
          /<[^>]+>|\.\.\.|example|invalid|replace|your|changeme/i.test(value) ||
          /^postgres(ql)?:\/\/[^:]+:(<[^>]+>|password|\*+|x+)@/i.test(value);
        expect(ok, `${f}: ${m[1]} looks like a real value`).toBe(true);
      }
    }
  });

  it('no file contains a credential', () => {
    const findings: string[] = [];
    for (const f of files) {
      if (SKIP_CONTENT.includes(f)) continue;
      const path = join(ROOT, f);
      const st = statSync(path);
      if (!st.isFile() || st.size > 5 * 1024 * 1024) continue;
      const buf = readFileSync(path);
      if (!isText(buf)) continue;
      const text = buf.toString('utf8');
      for (const rule of RULES) {
        rule.re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = rule.re.exec(text))) {
          if (!rule.real || rule.real(m)) {
            const line = text.slice(0, m.index).split('\n').length;
            findings.push(`${f}:${line} ${rule.name}: ${m[0].slice(0, 24)}…`);
          }
        }
      }
    }
    expect(findings).toEqual([]);
  });

  it('the scanner detects planted secrets (self-test)', () => {
    const planted = [
      `postgres://app:${'Zq9'}rT5sLkW2@ep-cool-snow-123.eu-central-1.aws.neon.tech/neondb`,
      `${'npg'}_AbCdEf123456XyZ`,
      `-----${B} OPENSSH ${PK}-----\n${'b3BlbnNzaC1rZXktdjEAAAAA'.repeat(4)}`,
      `${'cfat'}_0123456789abcdefABCDEF0123`,
      `NVD_API_KEY=0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b`,
      `EXDV_WORKER_PRIVATE_KEY=${'A'.repeat(43)}=`,
    ];
    for (const sample of planted) {
      const hit = RULES.some((r) => {
        r.re.lastIndex = 0;
        const m = r.re.exec(sample);
        return m !== null && (!r.real || r.real(m));
      });
      expect(hit, sample.slice(0, 20)).toBe(true);
    }
    // And ignores the placeholders used throughout tests and docs.
    for (const benign of [
      'postgres://u:p@db.example.invalid/app',
      'postgres://user:password@ep-xxx.neon.tech/neondb',
      'postgres://app:<password>@ep-example.neon.tech/db',
    ]) {
      const hit = RULES.some((r) => {
        r.re.lastIndex = 0;
        const m = r.re.exec(benign);
        return m !== null && (!r.real || r.real(m));
      });
      expect(hit, benign).toBe(false);
    }
  });
});

describe('client bundle', () => {
  const CLIENT = join(ROOT, 'apps/web/dist/client');
  const built = existsSync(CLIENT);

  const walk = (dir: string): string[] =>
    readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
      e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)],
    );

  const FORBIDDEN_IN_CLIENT: RegExp[] = [
    /DATABASE_URL/,
    /HYPERDRIVE/,
    /connectionString/,
    /postgres(ql)?:\/\//,
    /neon\.tech/,
    new RegExp('npg' + '_'),
    /NVD_API_KEY/,
    /DEV_AUTH_EMAIL/,
    /BOOTSTRAP_ADMIN_EMAILS/,
    /ALLOW_PRODUCTION_MIGRATION/,
    /ACCESS_AUD/,
    /CF_Authorization/, // the client never reads the Access cookie (HttpOnly; server-side only)
    /WORKER_PRIVATE_KEY/,
    new RegExp(`${B} [A-Z ]*${PK}`),
    /\bsecret_[a-z]/i,
    /exdomainvault_app/,
    /flat-sound-26073660/, // Neon project id
  ];

  it.skipIf(!built)('contains no server configuration or secret names', () => {
    const offenders: string[] = [];
    for (const file of walk(CLIENT)) {
      const text = readFileSync(file, 'utf8');
      for (const re of FORBIDDEN_IN_CLIENT) {
        if (re.test(text)) offenders.push(`${relative(CLIENT, file)}: ${re}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it.skipIf(!built)('ships no source maps and no dev fixtures', () => {
    const files = walk(CLIENT).map((f) => relative(CLIENT, f));
    expect(files.filter((f) => f.endsWith('.map'))).toEqual([]);
    const js = files.filter((f) => f.endsWith('.js'));
    expect(js.length).toBeGreaterThan(0);
    for (const f of js) {
      const text = readFileSync(join(CLIENT, f), 'utf8');
      expect(text, f).not.toMatch(/sourceMappingURL=/);
      // Dev fixtures are labelled and stripped from production builds (CLAUDE.md).
      expect(text, f).not.toMatch(/DEV FIXTURE|dev-fixture|lib\/fixtures\//i);
    }
  });
});
