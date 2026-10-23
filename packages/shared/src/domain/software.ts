/**
 * Exposed-software catalogue (Milestone 11). The single list of products ExDomainVault recognises
 * in HTTP headers (`Server`, `X-Powered-By`) and Nmap service identification, and how each maps to
 * the public intelligence sources:
 *
 * - `eolSlug`: product id on endoflife.date (release cycles and end-of-life dates); null = none.
 * - `cpe`: NVD CPE 2.3 vendor/product, used to read affected version ranges of CVEs from NVD.
 * - `kevAliases`: lowercase substrings matched against CISA KEV `vendorProject` + `product` to
 *   pre-select candidate KEV entries before their NVD records are fetched.
 * - `patterns`: case-insensitive tokens recognised in banners (`token/1.2.3` or Nmap product names).
 *
 * Detection is self-reported by the server (banners) and is never proof: distributions backport
 * fixes without changing the version string, and a hidden version means "unknown", never "not
 * affected". Extend the list as needed; keys are stable identifiers stored in the database.
 */
export interface SoftwareProduct {
  key: string;
  label: string;
  eolSlug: string | null;
  cpe: { vendor: string; product: string } | null;
  kevAliases: readonly string[];
  /** Header tokens (`Apache/2.4.41`) and Nmap product names (`Apache httpd`), lowercase. */
  patterns: readonly string[];
}

export const SOFTWARE_PRODUCTS: readonly SoftwareProduct[] = [
  {
    key: 'php',
    label: 'PHP',
    eolSlug: 'php',
    cpe: { vendor: 'php', product: 'php' },
    kevAliases: ['php'],
    patterns: ['php'],
  },
  {
    key: 'nginx',
    label: 'nginx',
    eolSlug: 'nginx',
    cpe: { vendor: 'f5', product: 'nginx' },
    kevAliases: ['nginx'],
    patterns: ['nginx'],
  },
  {
    key: 'apache_httpd',
    label: 'Apache HTTP Server',
    eolSlug: 'apache-http-server',
    cpe: { vendor: 'apache', product: 'http_server' },
    kevAliases: ['apache http server', 'apache httpd'],
    patterns: ['apache', 'apache httpd'],
  },
  {
    key: 'apache_tomcat',
    label: 'Apache Tomcat',
    eolSlug: 'tomcat',
    cpe: { vendor: 'apache', product: 'tomcat' },
    kevAliases: ['tomcat'],
    patterns: ['apache-coyote', 'apache tomcat', 'tomcat'],
  },
  {
    key: 'openssl',
    label: 'OpenSSL',
    eolSlug: 'openssl',
    cpe: { vendor: 'openssl', product: 'openssl' },
    kevAliases: ['openssl'],
    patterns: ['openssl'],
  },
  {
    key: 'openssh',
    label: 'OpenSSH',
    eolSlug: null,
    cpe: { vendor: 'openbsd', product: 'openssh' },
    kevAliases: ['openssh'],
    patterns: ['openssh'],
  },
  {
    key: 'microsoft_iis',
    label: 'Microsoft IIS',
    eolSlug: null,
    cpe: { vendor: 'microsoft', product: 'internet_information_services' },
    kevAliases: ['internet information services', 'iis'],
    patterns: ['microsoft-iis', 'microsoft iis httpd'],
  },
  {
    key: 'lighttpd',
    label: 'lighttpd',
    eolSlug: null,
    cpe: { vendor: 'lighttpd', product: 'lighttpd' },
    kevAliases: ['lighttpd'],
    patterns: ['lighttpd'],
  },
  {
    key: 'nodejs',
    label: 'Node.js',
    eolSlug: 'nodejs',
    cpe: { vendor: 'nodejs', product: 'node.js' },
    kevAliases: ['node.js', 'nodejs'],
    patterns: ['node.js', 'nodejs'],
  },
  {
    key: 'mysql',
    label: 'MySQL',
    eolSlug: 'mysql',
    cpe: { vendor: 'oracle', product: 'mysql' },
    kevAliases: ['mysql'],
    patterns: ['mysql'],
  },
  {
    key: 'mariadb',
    label: 'MariaDB',
    eolSlug: 'mariadb',
    cpe: { vendor: 'mariadb', product: 'mariadb' },
    kevAliases: ['mariadb'],
    patterns: ['mariadb'],
  },
  {
    key: 'postgresql',
    label: 'PostgreSQL',
    eolSlug: 'postgresql',
    cpe: { vendor: 'postgresql', product: 'postgresql' },
    kevAliases: ['postgresql'],
    patterns: ['postgresql'],
  },
  {
    key: 'redis',
    label: 'Redis',
    eolSlug: 'redis',
    cpe: { vendor: 'redis', product: 'redis' },
    kevAliases: ['redis'],
    patterns: ['redis'],
  },
  {
    key: 'mongodb',
    label: 'MongoDB',
    eolSlug: 'mongodb',
    cpe: { vendor: 'mongodb', product: 'mongodb' },
    kevAliases: ['mongodb'],
    patterns: ['mongodb'],
  },
  {
    key: 'exim',
    label: 'Exim',
    eolSlug: null,
    cpe: { vendor: 'exim', product: 'exim' },
    kevAliases: ['exim'],
    patterns: ['exim', 'exim smtpd'],
  },
  {
    key: 'postfix',
    label: 'Postfix',
    eolSlug: null,
    cpe: { vendor: 'postfix', product: 'postfix' },
    kevAliases: ['postfix'],
    patterns: ['postfix', 'postfix smtpd'],
  },
];

export const SOFTWARE_PRODUCT_KEYS = SOFTWARE_PRODUCTS.map((p) => p.key);

export function softwareProduct(key: string): SoftwareProduct | undefined {
  return SOFTWARE_PRODUCTS.find((p) => p.key === key);
}
