import type { CertificateStatus } from '@exdomainvault/shared';

const DAY_MS = 86_400_000;

const relativeFmt = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });

/** "3 days ago", "in 2 hours", "just now"; coarse on purpose (the exact time is in the tooltip). */
export function formatRelative(iso: string, now: number = Date.now()): string {
  const diff = new Date(iso).getTime() - now;
  const abs = Math.abs(diff);
  if (abs < 60_000) return 'just now';
  if (abs < 3_600_000) return relativeFmt.format(Math.round(diff / 60_000), 'minute');
  if (abs < DAY_MS) return relativeFmt.format(Math.round(diff / 3_600_000), 'hour');
  if (abs < 30 * DAY_MS) return relativeFmt.format(Math.round(diff / DAY_MS), 'day');
  if (abs < 365 * DAY_MS) return relativeFmt.format(Math.round(diff / (30 * DAY_MS)), 'month');
  return relativeFmt.format(Math.round(diff / (365 * DAY_MS)), 'year');
}

/** Square-bracket IPv6 literals so `addr:port` stays unambiguous. */
export const ipPort = (ip: string, port: number) =>
  ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`;

/** "CVSS v3" qualitative severity rating bands (FIRST CVSS v3.x specification, section 5). */
export type CvssBand = 'None' | 'Low' | 'Medium' | 'High' | 'Critical';
export function cvssBand(score: number): CvssBand {
  if (score >= 9) return 'Critical';
  if (score >= 7) return 'High';
  if (score >= 4) return 'Medium';
  if (score > 0) return 'Low';
  return 'None';
}

export const CERTIFICATE_STATUS_LABELS: Record<CertificateStatus, string> = {
  expired: 'Expired',
  expiring: 'Expiring soon',
  mismatch: 'Hostname mismatch',
  untrusted: 'Untrusted chain',
  valid: 'Valid',
};

/** Tone of the days-left pill: ≤ 7 days (and expired) red, ≤ 14 amber, ≤ 30 blue, else neutral. */
export function daysLeftTone(daysLeft: number): 'red' | 'amber' | 'blue' | 'neutral' {
  if (daysLeft <= 7) return 'red';
  if (daysLeft <= 14) return 'amber';
  if (daysLeft <= 30) return 'blue';
  return 'neutral';
}

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;

export function daysLeftText(daysLeft: number): string {
  if (daysLeft < 0) return `Expired ${plural(-daysLeft, 'day')} ago`;
  if (daysLeft === 0) return 'Expires today';
  return `${plural(daysLeft, 'day')} left`;
}
