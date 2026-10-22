import { z } from 'zod';

/**
 * Admin-approved networks: the only destinations network-tier checks (port probes, service
 * identification, TLS configuration enumeration) may contact. Typically the organisation's own server
 * ranges. Each approval has a reason and a review date, is audited, and can be revoked.
 */

const isoDateTime = z.iso.datetime();

export const APPROVED_NETWORK_MAX_MONTHS = 24;

export const approvedNetworkSchema = z.object({
  id: z.uuid(),
  /** Canonical CIDR (network address, e.g. `203.0.113.0/24`, `2001:db8:1::/48`). */
  cidr: z.string(),
  label: z.string(),
  reason: z.string(),
  reference: z.string().nullable(),
  createdBy: z.object({ id: z.uuid(), email: z.string() }).nullable(),
  createdAt: isoDateTime,
  expiresAt: isoDateTime,
  revokedAt: isoDateTime.nullable(),
  revokeReason: z.string().nullable(),
});
export type ApprovedNetwork = z.infer<typeof approvedNetworkSchema>;

export const approvedNetworkListResponseSchema = z.object({
  items: z.array(approvedNetworkSchema),
});

export const createApprovedNetworkRequestSchema = z.strictObject({
  /**
   * IPv4 or IPv6 CIDR (or a single address). Must be public unicast space; at most a /16 (IPv4) or
   * /32 (IPv6) so a single approval cannot cover a whole provider.
   */
  cidr: z.string().trim().min(2).max(64),
  label: z.string().trim().min(1).max(100),
  reason: z
    .string()
    .trim()
    .min(10, 'Give a reason of at least 10 characters.')
    .max(500, 'The reason must be at most 500 characters.'),
  reference: z
    .string()
    .trim()
    .max(200)
    .transform((v) => (v === '' ? null : v))
    .nullish(),
  reviewBy: z.iso.date('Enter the review date as YYYY-MM-DD.'),
});
export type CreateApprovedNetworkRequest = z.input<typeof createApprovedNetworkRequestSchema>;

export const revokeApprovedNetworkRequestSchema = z.strictObject({
  reason: z.string().trim().min(10).max(500),
});
