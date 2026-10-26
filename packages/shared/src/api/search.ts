import { z } from 'zod';
import { severitySchema } from '../domain/severity.ts';

/**
 * Global search (Milestone 13, top bar / Ctrl+K). `GET /api/v1/search?q=` (`domains:read`).
 * Case-insensitive substring match per group, at most SEARCH_GROUP_LIMIT hits per group, results
 * scoped like the lists they link to (a group the caller may not read is returned empty). A query
 * that is a port number (`443`, `port:443`) also searches open ports; one that looks like a CVE id
 * (`CVE-2024-38475`, partial `2024-384`) searches vulnerabilities; IP-looking text matches by
 * prefix. Wildcards are not supported (`%` and `_` are escaped).
 */

export const SEARCH_GROUP_LIMIT = 5;

export const searchQuerySchema = z.object({
  q: z.string().trim().min(2).max(100),
});

const ref = z.object({ id: z.uuid(), fqdn: z.string() });

export const searchResponseSchema = z.object({
  q: z.string(),
  domains: z.array(ref),
  assets: z.array(z.object({ id: z.uuid(), hostname: z.string(), domain: ref })),
  ips: z.array(
    z.object({
      ipAddress: z.string(),
      assets: z.array(z.object({ id: z.uuid(), hostname: z.string() })),
    }),
  ),
  ports: z.array(
    z.object({
      ipAddress: z.string(),
      port: z.int(),
      service: z.string().nullable(),
      hostname: z.string().nullable(),
    }),
  ),
  software: z.array(
    z.object({
      product: z.string(),
      productLabel: z.string(),
      version: z.string().nullable(),
      hostname: z.string().nullable(),
      domain: ref,
    }),
  ),
  vulnerabilities: z.array(z.object({ cve: z.string(), kev: z.boolean(), affectedHosts: z.int() })),
  findings: z.array(
    z.object({ id: z.uuid(), title: z.string(), severity: severitySchema, domain: ref }),
  ),
});
export type SearchResponse = z.infer<typeof searchResponseSchema>;
