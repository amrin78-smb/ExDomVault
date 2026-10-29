import { z } from 'zod';
import { findingStatusSchema } from './findings.ts';
import { lookalikeTechniqueSchema } from './observations.ts';
import { paginatedSchema } from './pagination.ts';
import { severitySchema } from '../domain/severity.ts';

/**
 * Milestone 15 — lookalike domains (brand monitoring). Read model of `lookalike_observations`:
 * one item per (domain, candidate) that has ever been seen registered.
 */

const isoDateTime = z.iso.datetime();

/**
 * `registered`: registered in the domain's latest complete brand run (or seen since).
 * `gone`: seen registered before, but a later complete run no longer found it.
 */
export const LOOKALIKE_STATES = ['registered', 'gone'] as const;
export const lookalikeStateSchema = z.enum(LOOKALIKE_STATES);
export type LookalikeState = z.infer<typeof lookalikeStateSchema>;

export const LOOKALIKE_TECHNIQUE_LABELS: Record<
  z.infer<typeof lookalikeTechniqueSchema>,
  string
> = {
  omission: 'Omission',
  repetition: 'Repetition',
  transposition: 'Transposition',
  replacement: 'Replacement',
  insertion: 'Insertion',
  homoglyph: 'Homoglyph',
  hyphenation: 'Hyphenation',
  bitsquatting: 'Bitsquatting',
  vowel_swap: 'Vowel swap',
  tld_swap: 'Other TLD',
  subdomain_dot: 'Subdomain split',
};

const recordsSchema = z.object({
  A: z.array(z.string()).default([]),
  AAAA: z.array(z.string()).default([]),
  MX: z.array(z.string()).default([]),
  NS: z.array(z.string()).default([]),
});

export const lookalikeItemSchema = z.object({
  domain: z.object({ id: z.uuid(), fqdn: z.string() }),
  candidate: z.string(),
  technique: lookalikeTechniqueSchema,
  state: lookalikeStateSchema,
  /** Records from the latest observation that found it registered. */
  records: recordsSchema,
  /** Has MX records (can receive, and is likely set up to send, mail). */
  hasMail: z.boolean(),
  /** First and latest observation that found it registered. */
  firstSeenAt: isoDateTime,
  lastSeenAt: isoDateTime,
  /** When the domain's lookalikes were last checked completely (null: no complete run yet). */
  lastCheckedAt: isoDateTime.nullable(),
  /** The LOOK-001 finding for this candidate, if any. */
  finding: z
    .object({ id: z.uuid(), status: findingStatusSchema, severity: severitySchema })
    .nullable(),
});
export type LookalikeItem = z.infer<typeof lookalikeItemSchema>;

export const lookalikeListQuerySchema = z.object({
  page: z.coerce.number().int().min(1).max(10_000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(50),
  domainId: z.uuid().optional(),
  /** `true` = currently registered (default view in the UI), `false` = no longer registered. */
  registered: z.enum(['true', 'false']).optional(),
  technique: lookalikeTechniqueSchema.optional(),
  /** Substring of the candidate name. */
  q: z.string().trim().max(253).optional(),
});
export type LookalikeListQuery = z.infer<typeof lookalikeListQuerySchema>;

export const lookalikeSummarySchema = z.object({
  /** Domains with brand monitoring on. */
  domainsMonitored: z.int().min(0),
  /** Candidates checked in each domain's latest complete run, summed. */
  candidatesChecked: z.int().min(0),
  /** Currently registered lookalikes (within the filters' domain, if any). */
  registered: z.int().min(0),
  /** …of which have MX records. */
  withMail: z.int().min(0),
  /** Currently registered and first seen within the last 7 days. */
  newThisWeek: z.int().min(0),
  /** Latest complete run (null if none). */
  lastCheckedAt: isoDateTime.nullable(),
});
export type LookalikeSummary = z.infer<typeof lookalikeSummarySchema>;

export const lookalikeListResponseSchema = paginatedSchema(lookalikeItemSchema).extend({
  summary: lookalikeSummarySchema,
});
export type LookalikeListResponse = z.infer<typeof lookalikeListResponseSchema>;

/** POST /domains/:id/lookalikes/check */
export const lookalikeCheckResponseSchema = z.object({
  scanJobId: z.uuid(),
  /** False when a brand job was already queued or running for the domain (that job is returned). */
  created: z.boolean(),
});
export type LookalikeCheckResponse = z.infer<typeof lookalikeCheckResponseSchema>;
