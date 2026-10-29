import { z } from 'zod';
import { paginatedSchema } from './pagination.ts';

/**
 * Change timeline (Milestone 14): "what changed" per host and domain, derived at read time from
 * observations already stored. Each event compares one successful observation (of a succeeded
 * job) with the previous successful one for the same key; failed, partial and timed-out results
 * are skipped, never compared. The first observation of a key produces no event ("first seen" is
 * covered by the asset-discovered event). Nothing here is a finding: `importance` is a display
 * hint, not a severity.
 */

export const CHANGE_KINDS = [
  'dns',
  'ip',
  'tls',
  'http',
  'port',
  'software',
  'registration',
  'asset',
] as const;
export const changeKindSchema = z.enum(CHANGE_KINDS);
export type ChangeKind = z.infer<typeof changeKindSchema>;

export const CHANGE_KIND_LABELS: Record<ChangeKind, string> = {
  dns: 'DNS',
  ip: 'IP address',
  tls: 'Certificate',
  http: 'HTTP',
  port: 'Port',
  software: 'Software',
  registration: 'Registration',
  asset: 'Asset',
};

/** Ordered from least to most important; filters treat a value as a minimum. */
export const CHANGE_IMPORTANCE = ['info', 'notable', 'important'] as const;
export const changeImportanceSchema = z.enum(CHANGE_IMPORTANCE);
export type ChangeImportance = z.infer<typeof changeImportanceSchema>;

/** Default and maximum look-back of the timeline. */
export const CHANGES_DEFAULT_DAYS = 30;
export const CHANGES_MAX_DAYS = 366;

const isoDateTime = z.iso.datetime({ offset: true });

export const changeEventSchema = z.object({
  /** Deterministic: the same stored data always yields the same id. */
  id: z.string(),
  at: isoDateTime,
  kind: changeKindSchema,
  domain: z.object({ id: z.uuid(), fqdn: z.string() }),
  assetId: z.uuid().nullable(),
  hostname: z.string().nullable(),
  /** What changed, e.g. "A record", "443/tcp", "certificate", "nameservers". */
  subject: z.string(),
  /** One human sentence. */
  summary: z.string(),
  /** Kind-specific state before and after (null when not applicable, e.g. a new asset). */
  before: z.unknown().nullable(),
  after: z.unknown().nullable(),
  severityHint: changeImportanceSchema,
});
export type ChangeEvent = z.infer<typeof changeEventSchema>;

export const changesQuerySchema = z
  .object({
    page: z.coerce.number().int().min(1).max(10_000).default(1),
    pageSize: z.coerce.number().int().min(1).max(100).default(50),
    domainId: z.uuid().optional(),
    assetId: z.uuid().optional(),
    /** One kind, or several comma-separated. */
    kind: z
      .string()
      .max(200)
      .transform((s) => s.split(',').filter(Boolean))
      .pipe(z.array(changeKindSchema).max(CHANGE_KINDS.length))
      .optional(),
    /** Minimum importance. */
    importance: changeImportanceSchema.optional(),
    since: isoDateTime.optional(),
    until: isoDateTime.optional(),
  })
  .refine((q) => !q.since || !q.until || Date.parse(q.since) < Date.parse(q.until), {
    message: '`since` must be before `until`',
    path: ['since'],
  });
export type ChangesQuery = z.infer<typeof changesQuerySchema>;
export type ChangesQueryInput = z.input<typeof changesQuerySchema>;

export const changesResponseSchema = paginatedSchema(changeEventSchema).extend({
  /** The window actually used (defaults applied, clamped to `CHANGES_MAX_DAYS`). */
  since: isoDateTime,
  until: isoDateTime,
  /** Counts over every event matching the filters (all pages), by importance. */
  counts: z.object({ info: z.int(), notable: z.int(), important: z.int() }),
});
export type ChangesResponse = z.infer<typeof changesResponseSchema>;
