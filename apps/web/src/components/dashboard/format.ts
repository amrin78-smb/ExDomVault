import type { AssetStatus, AttackSurfaceResponse, Worker } from '@exdomainvault/shared';

export type ExpiryTone = 'red' | 'amber' | 'blue' | 'slate';

/** ≤ 7 days (or expired) red, ≤ 14 amber, ≤ 30 blue, otherwise neutral. */
export function expiryTone(daysLeft: number): ExpiryTone {
  if (daysLeft <= 7) return 'red';
  if (daysLeft <= 14) return 'amber';
  if (daysLeft <= 30) return 'blue';
  return 'slate';
}

export function expiryText(daysLeft: number): string {
  if (daysLeft === 0) return 'Expires today';
  if (daysLeft < 0) {
    const n = -daysLeft;
    return `Expired ${n} day${n === 1 ? '' : 's'} ago`;
  }
  return `Expires in ${daysLeft} day${daysLeft === 1 ? '' : 's'}`;
}

export const NEW_DAYS = 7;
export type AssetPill = 'New' | 'Pending' | 'Approved' | 'Rejected' | 'Suspended';
/** "New" = still pending and first seen within the last week; otherwise the review status. */
export function assetPill(status: AssetStatus, firstSeenAt: string, now: string): AssetPill {
  if (status === 'pending') {
    const age = Date.parse(now) - Date.parse(firstSeenAt);
    return age <= NEW_DAYS * 86_400_000 ? 'New' : 'Pending';
  }
  return status === 'approved' ? 'Approved' : status === 'rejected' ? 'Rejected' : 'Suspended';
}

const NAMED = ['Asia', 'Europe', 'North America'] as const;

/** Current IPs of approved assets by continent: Asia, Europe, North America and the rest. */
export function continentRows(d: AttackSurfaceResponse) {
  const ipsOf = (c: string) => d.continents.find((x) => x.continent === c)?.ips ?? 0;
  const named = NAMED.map((c) => ({ label: c as string, ips: ipsOf(c) }));
  const others = d.continents
    .filter((c) => !(NAMED as readonly string[]).includes(c.continent))
    .reduce((n, c) => n + c.ips, 0);
  const rows = [...named, { label: 'Others', ips: others }];
  const total = rows.reduce((n, r) => n + r.ips, 0);
  return { rows, total };
}

/** A worker is considered stale when it has not polled for 10 minutes. */
const STALE_MS = 10 * 60 * 1000;
export const isStale = (w: Worker, now = Date.now()) =>
  w.lastSeenAt === null || now - new Date(w.lastSeenAt).getTime() > STALE_MS;
