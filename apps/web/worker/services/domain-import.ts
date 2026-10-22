import { schema, type Database } from '@exdomainvault/database';
import {
  CRITICALITIES,
  IMPORT_MAX_ROWS,
  type AuthorisationInput,
  type Criticality,
  type ImportConfirmResponse,
  type ImportPreviewResponse,
  type ImportPreviewRow,
} from '@exdomainvault/shared';
import { normaliseDomain } from '@exdomainvault/shared/hostname';
import { inArray } from 'drizzle-orm';
import { CsvError, parseCsv } from '../lib/csv.ts';
import { ApiError } from '../lib/errors.ts';
import { writeAudit, writeAuditMany } from './audit.ts';
import { authoriseWithin, prepareAuthorisation } from './domain-authorisation.ts';
import type { Actor } from './domains.ts';
import { sha256Hex } from './domain-verification.ts';

const { domains } = schema;

/**
 * CSV import: the client uploads a file for a server-side preview, then confirms by sending the same
 * file with the preview's digest. Rows are re-validated on confirm; only valid rows are imported.
 *
 * Columns (header row required, case-insensitive): `domain` (required), `criticality`
 * (low|medium|high|critical, default medium), `business_owner`.
 */
const COLUMN_ALIASES: Record<string, 'domain' | 'criticality' | 'business_owner'> = {
  domain: 'domain',
  fqdn: 'domain',
  criticality: 'criticality',
  business_owner: 'business_owner',
  'business owner': 'business_owner',
  owner: 'business_owner',
};

export async function previewImport(db: Database, csv: string): Promise<ImportPreviewResponse> {
  const digest = await sha256Hex(csv);
  const empty = (fileErrors: string[]): ImportPreviewResponse => ({
    digest,
    rows: [],
    fileErrors,
    summary: { total: 0, valid: 0, invalid: 0, duplicateInFile: 0, alreadyRegistered: 0 },
  });

  let records;
  try {
    records = parseCsv(csv, IMPORT_MAX_ROWS + 1);
  } catch (err) {
    if (err instanceof CsvError) {
      return empty([
        err.message.startsWith('more than')
          ? `The file has more than ${IMPORT_MAX_ROWS} rows. Split it into smaller files.`
          : `The file is not valid CSV: ${err.message}.`,
      ]);
    }
    throw err;
  }
  const [header, ...dataRows] = records;
  if (!header) return empty(['The file is empty.']);

  const columns = header.fields.map((f) => COLUMN_ALIASES[f.trim().toLowerCase()]);
  const unknown = header.fields.filter((_, i) => !columns[i]);
  const fileErrors: string[] = [];
  if (unknown.length > 0) {
    fileErrors.push(
      `Unknown column${unknown.length > 1 ? 's' : ''}: ${unknown.map((u) => `"${u.slice(0, 40)}"`).join(', ')}. Allowed: domain, criticality, business_owner.`,
    );
  }
  if (!columns.includes('domain')) fileErrors.push('The header row must include a "domain" column.');
  if (new Set(columns.filter(Boolean)).size !== columns.filter(Boolean).length) {
    fileErrors.push('A column appears more than once in the header row.');
  }
  if (dataRows.length === 0) fileErrors.push('The file has a header row but no domains.');
  if (fileErrors.length > 0) return empty(fileErrors);

  const seen = new Set<string>();
  const rows: ImportPreviewRow[] = dataRows.map(({ line, fields }) => {
    const get = (name: string) => {
      const i = columns.indexOf(name as (typeof columns)[number]);
      return i >= 0 ? (fields[i] ?? '').trim() : '';
    };
    const input = get('domain');
    const errors: string[] = [];
    if (fields.length !== columns.length) {
      errors.push(`Expected ${columns.length} columns, found ${fields.length}.`);
    }

    const n = normaliseDomain(input);
    if (!n.ok) errors.push(n.message);

    const rawCriticality = get('criticality').toLowerCase();
    let criticality: Criticality | null = 'medium';
    if (rawCriticality !== '') {
      if ((CRITICALITIES as readonly string[]).includes(rawCriticality)) {
        criticality = rawCriticality as Criticality;
      } else {
        criticality = null;
        errors.push('Criticality must be low, medium, high or critical.');
      }
    }

    const owner = get('business_owner');
    if (owner.length > 200) errors.push('Business owner must be at most 200 characters.');

    let status: ImportPreviewRow['status'] = errors.length > 0 ? 'invalid' : 'valid';
    if (status === 'valid' && n.ok) {
      if (seen.has(n.fqdn)) status = 'duplicate_in_file';
      seen.add(n.fqdn);
    }
    return {
      line,
      input: input.slice(0, 300),
      fqdn: n.ok ? n.fqdn : null,
      unicodeFqdn: n.ok ? n.unicode : null,
      criticality,
      businessOwner: owner === '' ? null : owner.slice(0, 200),
      status,
      errors,
      warnings: n.ok ? n.warnings : [],
    };
  });

  const candidates = rows.flatMap((r) => (r.status === 'valid' && r.fqdn ? [r.fqdn] : []));
  if (candidates.length > 0) {
    const existing = await db
      .select({ fqdn: domains.fqdn })
      .from(domains)
      .where(inArray(domains.fqdn, candidates));
    const existingSet = new Set(existing.map((e) => e.fqdn));
    for (const r of rows) {
      if (r.status === 'valid' && r.fqdn && existingSet.has(r.fqdn)) r.status = 'already_registered';
    }
  }

  const countOf = (s: ImportPreviewRow['status']) => rows.filter((r) => r.status === s).length;
  return {
    digest,
    rows,
    fileErrors: [],
    summary: {
      total: rows.length,
      valid: countOf('valid'),
      invalid: countOf('invalid'),
      duplicateInFile: countOf('duplicate_in_file'),
      alreadyRegistered: countOf('already_registered'),
    },
  };
}

export async function confirmImport(
  db: Database,
  csv: string,
  digest: string,
  actor: Actor,
  opts: { authorisation?: AuthorisationInput; now: Date },
): Promise<ImportConfirmResponse> {
  // Validate the authorisation (review date) before touching anything.
  const auth = opts.authorisation ? prepareAuthorisation(opts.authorisation, opts.now) : null;
  const preview = await previewImport(db, csv);
  if (preview.digest !== digest) {
    throw new ApiError(400, 'bad_request', 'The file changed after it was previewed. Preview it again.');
  }
  if (preview.fileErrors.length > 0) {
    throw new ApiError(400, 'validation_failed', 'The file cannot be imported.', [
      ...preview.fileErrors.map((message) => ({ path: 'csv', message })),
    ]);
  }
  // Valid rows always carry a normalised name and criticality.
  const valid = preview.rows.flatMap((r) =>
    r.status === 'valid' && r.fqdn && r.criticality
      ? [{ fqdn: r.fqdn, criticality: r.criticality, businessOwner: r.businessOwner }]
      : [],
  );
  if (valid.length === 0) return { created: [], skipped: preview.rows.length, authorised: 0 };

  return db.transaction(async (tx) => {
    // ON CONFLICT DO NOTHING: a domain registered between preview and confirm is skipped, not an error.
    const created = await tx
      .insert(domains)
      .values(
        valid.map((r) => ({
          fqdn: r.fqdn,
          criticality: r.criticality,
          businessOwner: r.businessOwner,
          createdBy: actor.userId,
        })),
      )
      .onConflictDoNothing({ target: domains.fqdn })
      .returning({ id: domains.id, fqdn: domains.fqdn, criticality: domains.criticality });

    await writeAuditMany(
      tx as unknown as Database,
      created.map((d) => ({
        actorType: 'user' as const,
        actorUserId: actor.userId,
        action: 'domain.created',
        resourceType: 'domain',
        resourceId: d.id,
        requestId: actor.requestId,
        metadata: { fqdn: d.fqdn, criticality: d.criticality, source: 'import', importDigest: digest },
      })),
    );
    await writeAudit(tx as unknown as Database, {
      actorType: 'user',
      actorUserId: actor.userId,
      action: 'domain.import_completed',
      resourceType: 'domain_import',
      resourceId: digest,
      requestId: actor.requestId,
      metadata: { rows: preview.rows.length, created: created.length, authorised: auth !== null },
    });

    const authorised = auth
      ? await authoriseWithin(
          tx as unknown as Database,
          created.map((d) => d.id),
          auth,
          actor,
          opts.now,
          'import',
        )
      : null;

    return {
      created: created.map(({ id, fqdn }) => ({ id, fqdn })),
      skipped: preview.rows.length - created.length,
      authorised: authorised?.authorised.length ?? 0,
    };
  });
}
