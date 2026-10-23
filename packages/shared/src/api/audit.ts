import { z } from 'zod';
import { paginatedSchema } from './pagination.ts';

/** Read-only audit log (`audit:read`, administrators). Entries are append-only. */

export const auditEntrySchema = z.object({
  id: z.uuid(),
  actorType: z.enum(['user', 'worker', 'system']),
  actor: z.object({ id: z.uuid(), email: z.string() }).nullable(),
  action: z.string(),
  resourceType: z.string(),
  resourceId: z.string().nullable(),
  requestId: z.string().nullable(),
  metadata: z.record(z.string(), z.unknown()),
  createdAt: z.iso.datetime(),
});
export type AuditEntry = z.infer<typeof auditEntrySchema>;

export const auditListQuerySchema = z.object({
  page: z.coerce.number().int().min(1).max(10_000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(50),
  /** Exact action (`finding.status_changed`) or a prefix ending in `.` (`finding.`). */
  action: z
    .string()
    .trim()
    .max(64)
    .regex(/^[a-z_.]+$/)
    .optional(),
  resourceType: z
    .string()
    .trim()
    .max(32)
    .regex(/^[a-z_]+$/)
    .optional(),
  resourceId: z.string().trim().max(200).optional(),
  actorUserId: z.uuid().optional(),
  actorType: z.enum(['user', 'worker', 'system']).optional(),
  /** ISO dates (inclusive range on created_at). */
  from: z.iso.datetime().optional(),
  to: z.iso.datetime().optional(),
});
export type AuditListQuery = z.infer<typeof auditListQuerySchema>;

export const auditListResponseSchema = paginatedSchema(auditEntrySchema);
export type AuditListResponse = z.infer<typeof auditListResponseSchema>;
