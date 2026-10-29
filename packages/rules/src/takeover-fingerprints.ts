/**
 * Subdomain-takeover fingerprints (DNS-008), curated from the public "can-i-take-over-xyz" project
 * (https://github.com/EdOverflow/can-i-take-over-xyz, retrieved 2026-10-29). Only services that
 * project lists as **Vulnerable** or **Edge case** AND that have a deterministic signature are
 * included. Services it lists as "Not vulnerable" (Zendesk "Help Center Closed", Fastly "unknown
 * domain", Unbounce, Kinsta, Fly.io) and services whose only signature is generic (Cargo Collective
 * "404 Not Found", LaunchRock "HTTP 500") are deliberately excluded.
 *
 * Per entry:
 * - `cnameSuffixes`: a CNAME chain member equal to or ending in `.<suffix>` (label boundary) points at
 *   the provider.
 * - `nxdomain`: the provider releases names on deletion and anyone can re-register them, so a chain
 *   that ends at NXDOMAIN under one of the suffixes is takeover evidence on its own (Azure, Elastic
 *   Beanstalk). Providers with wildcard DNS (github.io, herokuapp.com, s3.amazonaws.com…) never
 *   return NXDOMAIN for an unclaimed name, so only the HTTP signature can confirm them.
 * - `http`: "unclaimed resource" responses. A signature matches when the status is one of `statuses`
 *   (empty = any) and the response body contains EVERY string in `bodyContains` (case-sensitive).
 *   The worker evaluates them on the body it already reads for `http_availability` (≤ 64 KB, no
 *   extra request) and reports only `{ provider: key, signature }`, never the body.
 * - `matchWithoutCname`: the provider is also used through A records on the customer's own name
 *   (GitHub Pages apex), so an HTTP signature on a host WITHOUT a CNAME is accepted (medium
 *   confidence).
 *
 * The HTTP half of the table is mirrored for the Python worker in
 * `worker/app/takeover_fingerprints.json` (generated projection; a test fails on drift).
 */

export type TakeoverStatus = 'vulnerable' | 'edge_case';

export interface TakeoverHttpSignature {
  /** Accepted status codes; empty = any status. */
  statuses: readonly number[];
  /** Every string must occur in the body (case-sensitive substring match). */
  bodyContains: readonly string[];
}

export interface TakeoverFingerprint {
  /** Stable key (lowercase, underscores) used in evidence and by the worker. */
  key: string;
  provider: string;
  /** Status in can-i-take-over-xyz. */
  status: TakeoverStatus;
  cnameSuffixes: readonly string[];
  nxdomain: boolean;
  http: readonly TakeoverHttpSignature[];
  matchWithoutCname?: boolean;
  /** Additional label-anchored pattern for names a suffix list cannot express (regional S3). */
  cnamePattern?: RegExp;
  /** Provider documentation on removing dangling records / claiming custom domains. */
  reference?: string;
}

export const TAKEOVER_FINGERPRINTS_SOURCE = 'https://github.com/EdOverflow/can-i-take-over-xyz';

export const TAKEOVER_FINGERPRINTS: readonly TakeoverFingerprint[] = [
  {
    key: 'azure',
    provider: 'Microsoft Azure',
    status: 'vulnerable',
    cnameSuffixes: [
      'azurewebsites.net',
      'cloudapp.net',
      'cloudapp.azure.com',
      'trafficmanager.net',
      'blob.core.windows.net',
      'azure-api.net',
      'azurehdinsight.net',
      'azureedge.net',
      'azurecontainer.io',
      'database.windows.net',
      'azuredatalakestore.net',
      'search.windows.net',
      'azurecr.io',
      'redis.cache.windows.net',
      'servicebus.windows.net',
      'visualstudio.com',
    ],
    nxdomain: true,
    http: [],
    reference: 'https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover',
  },
  {
    key: 'aws_elastic_beanstalk',
    provider: 'AWS Elastic Beanstalk',
    status: 'vulnerable',
    cnameSuffixes: ['elasticbeanstalk.com'],
    nxdomain: true,
    http: [],
    reference: 'https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/customdomains.html',
  },
  {
    key: 'aws_s3',
    provider: 'AWS S3',
    status: 'vulnerable',
    cnameSuffixes: ['s3.amazonaws.com'],
    // Regional and website endpoints: bucket.s3.eu-west-1.amazonaws.com,
    // bucket.s3-website-eu-west-1.amazonaws.com, bucket.s3-website.eu-west-1.amazonaws.com.
    cnamePattern: /(^|\.)s3[.-][a-z0-9.-]*\.amazonaws\.com$/,
    nxdomain: false,
    http: [
      { statuses: [404], bodyContains: ['NoSuchBucket', 'The specified bucket does not exist'] },
    ],
    reference:
      'https://docs.aws.amazon.com/AmazonS3/latest/userguide/website-hosting-custom-domain-walkthrough.html',
  },
  {
    key: 'github_pages',
    provider: 'GitHub Pages',
    status: 'edge_case',
    cnameSuffixes: ['github.io'],
    nxdomain: false,
    http: [{ statuses: [404], bodyContains: ["There isn't a GitHub Pages site here."] }],
    matchWithoutCname: true,
    reference:
      'https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages',
  },
  {
    key: 'heroku',
    provider: 'Heroku',
    status: 'edge_case',
    cnameSuffixes: ['herokuapp.com', 'herokudns.com', 'herokussl.com'],
    nxdomain: false,
    http: [{ statuses: [404], bodyContains: ['No such app'] }],
    reference: 'https://devcenter.heroku.com/articles/custom-domains',
  },
  {
    key: 'bitbucket',
    provider: 'Bitbucket',
    status: 'vulnerable',
    cnameSuffixes: ['bitbucket.io'],
    nxdomain: false,
    http: [{ statuses: [404], bodyContains: ['Repository not found'] }],
  },
  {
    key: 'ghost',
    provider: 'Ghost',
    status: 'vulnerable',
    cnameSuffixes: ['ghost.io'],
    nxdomain: false,
    http: [
      { statuses: [], bodyContains: ['Failed to resolve DNS path for this host'] },
      { statuses: [], bodyContains: ['Site unavailable.'] },
    ],
  },
  {
    key: 'help_scout',
    provider: 'Help Scout',
    status: 'vulnerable',
    cnameSuffixes: ['helpscoutdocs.com'],
    nxdomain: false,
    http: [{ statuses: [], bodyContains: ['No settings were found for this company:'] }],
  },
  {
    key: 'help_juice',
    provider: 'Helpjuice',
    status: 'vulnerable',
    cnameSuffixes: ['helpjuice.com'],
    nxdomain: false,
    http: [{ statuses: [], bodyContains: ["We could not find what you're looking for."] }],
  },
  {
    key: 'pantheon',
    provider: 'Pantheon',
    status: 'vulnerable',
    cnameSuffixes: ['pantheonsite.io'],
    nxdomain: false,
    http: [{ statuses: [404], bodyContains: ['404 error unknown site!'] }],
  },
  {
    key: 'readme',
    provider: 'ReadMe',
    status: 'vulnerable',
    cnameSuffixes: ['readme.io', 'readmessl.com'],
    nxdomain: false,
    http: [
      {
        statuses: [],
        bodyContains: [
          'The creators of this project are still working on making everything perfect!',
        ],
      },
    ],
  },
  {
    key: 'readthedocs',
    provider: 'Read the Docs',
    status: 'vulnerable',
    cnameSuffixes: ['readthedocs.io'],
    nxdomain: false,
    http: [
      {
        statuses: [404],
        bodyContains: ['The link you have followed or the URL that you entered does not exist.'],
      },
    ],
  },
  {
    key: 'shopify',
    provider: 'Shopify',
    status: 'edge_case',
    cnameSuffixes: ['myshopify.com'],
    nxdomain: false,
    http: [{ statuses: [], bodyContains: ['Sorry, this shop is currently unavailable.'] }],
  },
  {
    key: 'netlify',
    provider: 'Netlify',
    status: 'edge_case',
    cnameSuffixes: ['netlify.app', 'netlify.com'],
    nxdomain: false,
    http: [{ statuses: [404], bodyContains: ['Not Found - Request ID:'] }],
  },
  {
    key: 'webflow',
    provider: 'Webflow',
    status: 'edge_case',
    cnameSuffixes: ['proxy.webflow.com', 'proxy-ssl.webflow.com', 'webflow.io'],
    nxdomain: false,
    http: [
      {
        statuses: [404],
        bodyContains: ["The page you are looking for doesn't exist or has been moved."],
      },
    ],
  },
  {
    key: 'wordpress',
    provider: 'WordPress.com',
    status: 'vulnerable',
    cnameSuffixes: ['wordpress.com'],
    nxdomain: false,
    http: [{ statuses: [], bodyContains: ['Do you want to register', '.wordpress.com'] }],
  },
  {
    key: 'surge',
    provider: 'Surge.sh',
    status: 'vulnerable',
    cnameSuffixes: ['surge.sh'],
    nxdomain: false,
    http: [{ statuses: [404], bodyContains: ['project not found'] }],
  },
  {
    key: 'tumblr',
    provider: 'Tumblr',
    status: 'edge_case',
    cnameSuffixes: ['domains.tumblr.com'],
    nxdomain: false,
    http: [
      {
        statuses: [],
        bodyContains: ["Whatever you were looking for doesn't currently exist at this address"],
      },
    ],
  },
  {
    key: 'strikingly',
    provider: 'Strikingly',
    status: 'vulnerable',
    cnameSuffixes: ['strikinglydns.com'],
    nxdomain: false,
    http: [{ statuses: [], bodyContains: ['PAGE NOT FOUND.'] }],
  },
  {
    key: 'ngrok',
    provider: 'ngrok',
    status: 'vulnerable',
    cnameSuffixes: ['ngrok.io'],
    nxdomain: false,
    http: [{ statuses: [], bodyContains: ['Tunnel ', '.ngrok.io not found'] }],
  },
  {
    key: 'jetbrains_youtrack',
    provider: 'JetBrains YouTrack',
    status: 'vulnerable',
    cnameSuffixes: ['youtrack.cloud', 'myjetbrains.com'],
    nxdomain: false,
    http: [{ statuses: [], bodyContains: ['is not a registered InCloud YouTrack'] }],
  },
  {
    key: 'canny',
    provider: 'Canny',
    status: 'vulnerable',
    cnameSuffixes: ['canny.io'],
    nxdomain: false,
    http: [
      {
        statuses: [],
        bodyContains: ['There is no such company. Did you enter the right URL?'],
      },
    ],
  },
];

const normalise = (name: string) => {
  const lower = name.trim().toLowerCase();
  return lower.endsWith('.') ? lower.slice(0, -1) : lower;
};

/** The fingerprint whose CNAME suffix matches `name` on a label boundary, or undefined. */
export function takeoverFingerprintForName(name: string): TakeoverFingerprint | undefined {
  const n = normalise(name);
  return TAKEOVER_FINGERPRINTS.find(
    (f) =>
      f.cnameSuffixes.some((s) => n === s || n.endsWith(`.${s}`)) ||
      (f.cnamePattern?.test(n) ?? false),
  );
}

export function takeoverFingerprintByKey(key: string): TakeoverFingerprint | undefined {
  return TAKEOVER_FINGERPRINTS.find((f) => f.key === key);
}

/** The worker-side projection (HTTP signatures only), as stored in the worker's JSON mirror. */
export function workerSignatureTable(): {
  source: string;
  providers: { key: string; signatures: { statuses: number[]; bodyContains: string[] }[] }[];
} {
  return {
    source: TAKEOVER_FINGERPRINTS_SOURCE,
    providers: TAKEOVER_FINGERPRINTS.filter((f) => f.http.length > 0).map((f) => ({
      key: f.key,
      signatures: f.http.map((s) => ({
        statuses: [...s.statuses],
        bodyContains: [...s.bodyContains],
      })),
    })),
  };
}
