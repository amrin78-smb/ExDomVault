import { z } from 'zod';

/**
 * Scheduled active scans (design §6 default schedules). Off by default. When an administrator
 * enables it (`scan_policies:manage`, audited `settings.scan_schedule_updated`), the cron queues the
 * chosen profile for every domain that is monitored AND currently authorised for active scanning
 * (DNS-verified or admin-authorised, review date not passed), while the server's
 * ACTIVE_SCANNING_ENABLED switch is on. Jobs are staggered across the interval (by domain-id hash),
 * capped per cron run, and queued behind user-requested scans. Targets follow the normal rules: the
 * apex plus approved assets; network checks only reach approved networks.
 *
 * Stored in `application_settings` under key SCAN_SCHEDULE_SETTING_KEY.
 */

export const SCAN_SCHEDULE_SETTING_KEY = 'scan_schedule';
export const SCHEDULED_SCAN_PROFILES = ['quick', 'standard'] as const;

export const scanScheduleSchema = z
  .object({
    enabled: z.boolean(),
    profile: z.enum(SCHEDULED_SCAN_PROFILES),
    /** Each eligible domain is scanned about once per interval. */
    intervalDays: z.int().min(1).max(30),
  })
  .strict();
export type ScanSchedule = z.infer<typeof scanScheduleSchema>;

export const DEFAULT_SCAN_SCHEDULE: ScanSchedule = {
  enabled: false,
  profile: 'quick',
  intervalDays: 1,
};

export const scanScheduleResponseSchema = z.object({
  schedule: scanScheduleSchema,
  updatedAt: z.iso.datetime().nullable(),
  updatedBy: z.object({ id: z.uuid(), email: z.string() }).nullable(),
  /** Monitored domains currently authorised for active scanning. */
  eligibleDomains: z.int(),
  /** Server kill switch; when false nothing active is scheduled regardless of `enabled`. */
  activeScanningEnabled: z.boolean(),
  /** Scheduled jobs of the profile created in the last 24 hours. */
  scheduledLast24h: z.int(),
});
export type ScanScheduleResponse = z.infer<typeof scanScheduleResponseSchema>;
