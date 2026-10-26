import { z } from 'zod';

/**
 * Asset roles (Milestone 13): a deterministic classification of what a host appears to BE, derived
 * only from collected evidence — never from its name. One primary role per asset; `unclassified`
 * when evidence is missing (e.g. the host has not been scanned yet). Used for the "Asset types"
 * charts and the role column on asset lists.
 */
export const ASSET_ROLES = [
  'mail',
  'dns',
  'remote_access',
  'file_transfer',
  'database',
  'web',
  'cloud_service',
  'unclassified',
] as const;
export const assetRoleSchema = z.enum(ASSET_ROLES);
export type AssetRole = z.infer<typeof assetRoleSchema>;

export const ASSET_ROLE_LABELS: Record<AssetRole, string> = {
  mail: 'Mail server',
  dns: 'DNS server',
  remote_access: 'Remote access',
  file_transfer: 'File server',
  database: 'Database',
  web: 'Web server',
  cloud_service: 'Cloud / SaaS service',
  unclassified: 'Unclassified',
};

/** Open TCP ports that identify a role (from approved-network port probes). */
export const ROLE_PORTS: Record<
  'mail' | 'dns' | 'remote_access' | 'file_transfer' | 'database',
  readonly number[]
> = {
  mail: [25, 110, 143, 465, 587, 993, 995],
  dns: [53],
  remote_access: [22, 23, 3389, 5900, 1194, 1723],
  file_transfer: [21, 69, 445, 990, 2049],
  database: [1433, 1521, 3306, 5432, 6379, 9200, 27017],
};

export interface AssetRoleEvidence {
  /** The hostname is an MX target of a domain we monitor (latest successful DNS). */
  isMxTarget: boolean;
  /** The hostname is an NS value of a domain we monitor (latest successful DNS). */
  isNsTarget: boolean;
  /** Open TCP ports on the asset's current addresses (latest port observations). */
  openPorts: readonly number[];
  /** At least one successful HTTP(S) response from the asset (latest HTTP observations). */
  respondsToHttp: boolean;
  /** `hosting_hint.kind` when the asset is hosted by a known third party. */
  hostingKind: 'cdn' | 'cloud' | 'paas' | 'saas' | 'hosting' | null;
}

/**
 * Primary role, first match wins: mail → dns → remote access → file transfer → database (named
 * record or a role port open) → web (HTTP answered) → cloud/SaaS (third-party hosting, nothing else
 * observed) → unclassified. Exposed infrastructure services rank above web because they matter more
 * for exposure review.
 */
export function classifyAssetRole(e: AssetRoleEvidence): AssetRole {
  const open = new Set(e.openPorts);
  const has = (ports: readonly number[]) => ports.some((p) => open.has(p));
  if (e.isMxTarget || has(ROLE_PORTS.mail)) return 'mail';
  if (e.isNsTarget || has(ROLE_PORTS.dns)) return 'dns';
  if (has(ROLE_PORTS.remote_access)) return 'remote_access';
  if (has(ROLE_PORTS.file_transfer)) return 'file_transfer';
  if (has(ROLE_PORTS.database)) return 'database';
  if (e.respondsToHttp) return 'web';
  if (e.hostingKind !== null) return 'cloud_service';
  return 'unclassified';
}
