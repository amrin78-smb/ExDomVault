import type { ChangeImportance, ChangesResponse } from '@exdomainvault/shared';

/** "12 changes in 30 days · 2 important" (for collapsed card title bars). */
export function changesSummary(res: ChangesResponse): string {
  const days = Math.round((Date.parse(res.until) - Date.parse(res.since)) / 86_400_000);
  if (res.total === 0) return `No changes in ${days} days`;
  const parts = [`${res.total} change${res.total === 1 ? '' : 's'} in ${days} days`];
  if (res.counts.important > 0) parts.push(`${res.counts.important} important`);
  else if (res.counts.notable > 0) parts.push(`${res.counts.notable} notable`);
  return parts.join(' · ');
}

export const IMPORTANCE_LABELS: Record<ChangeImportance, string> = {
  important: 'Important',
  notable: 'Notable',
  info: 'Info',
};

const scalar = (v: unknown): string =>
  v === null || v === undefined
    ? '—'
    : typeof v === 'string'
      ? v
      : typeof v === 'number' || typeof v === 'boolean'
        ? String(v)
        : JSON.stringify(v);

/**
 * A before/after value as display lines: arrays give one line per element; objects one line per
 * key (`key: value`, arrays expanded to one line per element). Null gives no lines.
 */
export function linesOf(value: unknown): string[] {
  if (value === null || value === undefined) return [];
  if (Array.isArray(value)) return value.map(scalar);
  if (typeof value === 'object') {
    const out: string[] = [];
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (Array.isArray(v)) {
        if (v.length === 0) out.push(`${k}: —`);
        else for (const item of v) out.push(`${k}: ${scalar(item)}`);
      } else {
        out.push(`${k}: ${scalar(v)}`);
      }
    }
    return out;
  }
  return [scalar(value)];
}

export interface DiffLine {
  op: 'added' | 'removed' | 'same';
  text: string;
}

/** Set-style diff of two values: unchanged lines first, then removed, then added. */
export function diffLines(before: unknown, after: unknown): DiffLine[] {
  const b = linesOf(before);
  const a = linesOf(after);
  const inA = new Set(a);
  const inB = new Set(b);
  return [
    ...b.filter((l) => inA.has(l)).map((text) => ({ op: 'same' as const, text })),
    ...b.filter((l) => !inA.has(l)).map((text) => ({ op: 'removed' as const, text })),
    ...a.filter((l) => !inB.has(l)).map((text) => ({ op: 'added' as const, text })),
  ];
}

const dayFmt = new Intl.DateTimeFormat(undefined, {
  weekday: 'short',
  day: 'numeric',
  month: 'short',
  year: 'numeric',
  timeZone: 'UTC',
});
const timeFmt = new Intl.DateTimeFormat(undefined, { timeStyle: 'short', timeZone: 'UTC' });

/** UTC day key (YYYY-MM-DD) and labels, matching the UTC dates shown elsewhere. */
export const dayKey = (iso: string) => new Date(iso).toISOString().slice(0, 10);
export const dayLabel = (iso: string) => dayFmt.format(new Date(iso));
export const timeLabel = (iso: string) => `${timeFmt.format(new Date(iso))} UTC`;
