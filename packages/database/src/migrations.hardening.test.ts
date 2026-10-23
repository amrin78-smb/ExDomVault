/**
 * Milestone 11/12 hardening: migration verification.
 *
 *  - The committed migrations, applied to a fresh PostgreSQL (PGlite), produce exactly the schema
 *    recorded in the latest drizzle-kit snapshot (tables, columns, nullability, enums, indexes,
 *    foreign keys, unique and check constraints).
 *  - The Drizzle schema in src/schema has no drift against that snapshot (the `db:check` /
 *    `db:generate` invariant: generating now would produce no statements).
 *  - Re-running the migrator is a no-op (already-applied migrations are skipped).
 *  - The journal, SQL files and snapshots are consistent; there are no down migrations, and the
 *    rollback strategy (restore through Neon, not reverse migrations) is documented.
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { drizzle } from 'drizzle-orm/pglite';
import { migrate } from 'drizzle-orm/pglite/migrator';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as schema from './schema/index.ts';
import { MIGRATIONS_FOLDER, createTestDatabase, type TestDatabase } from './testing.ts';

interface SnapshotColumn {
  name: string;
  type: string;
  notNull: boolean;
  primaryKey: boolean;
}
interface SnapshotTable {
  name: string;
  schema: string;
  columns: Record<string, SnapshotColumn>;
  indexes: Record<string, { name: string; isUnique: boolean; where?: string }>;
  foreignKeys: Record<string, { name: string; tableTo: string; onDelete?: string }>;
  uniqueConstraints: Record<string, { name: string }>;
  checkConstraints: Record<string, { name: string }>;
  compositePrimaryKeys: Record<string, unknown>;
}
interface Snapshot {
  id: string;
  prevId: string;
  tables: Record<string, SnapshotTable>;
  enums: Record<string, { name: string; values: string[] }>;
}
interface Journal {
  entries: { idx: number; tag: string; when: number }[];
}

const REPO_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const journal: Journal = JSON.parse(
  readFileSync(join(MIGRATIONS_FOLDER, 'meta', '_journal.json'), 'utf8'),
);
const readSnapshot = (idx: number): Snapshot =>
  JSON.parse(
    readFileSync(
      join(MIGRATIONS_FOLDER, 'meta', `${String(idx).padStart(4, '0')}_snapshot.json`),
      'utf8',
    ),
  );
const latest = readSnapshot(journal.entries.at(-1)!.idx);

let t: TestDatabase;
beforeAll(async () => {
  t = await createTestDatabase();
}, 60_000);
afterAll(async () => {
  await t?.close();
});

/** PostgreSQL truncates identifiers to NAMEDATALEN - 1 = 63 bytes (drizzle-kit keeps the long name). */
const pg = (name: string) => name.slice(0, 63);

const q = async <T>(sql: string, params: unknown[] = []) =>
  (await t.pglite.query<T>(sql, params)).rows;

describe('migration files', () => {
  it('journal entries are sequential, time-ordered and each has its SQL and snapshot', () => {
    journal.entries.forEach((e, i) => {
      expect(e.idx).toBe(i);
      expect(e.tag).toMatch(new RegExp(`^${String(i).padStart(4, '0')}_[a-z0-9_]+$`));
      if (i > 0) expect(e.when).toBeGreaterThan(journal.entries[i - 1]!.when);
      expect(existsSync(join(MIGRATIONS_FOLDER, `${e.tag}.sql`)), e.tag).toBe(true);
      expect(
        existsSync(join(MIGRATIONS_FOLDER, 'meta', `${String(i).padStart(4, '0')}_snapshot.json`)),
        e.tag,
      ).toBe(true);
    });
  });

  it('there are no SQL files outside the journal and no down/rollback migrations', () => {
    const tags = new Set(journal.entries.map((e) => `${e.tag}.sql`));
    const files = readdirSync(MIGRATIONS_FOLDER).filter((f) => f.endsWith('.sql'));
    expect(files.filter((f) => !tags.has(f))).toEqual([]);
    expect(
      readdirSync(MIGRATIONS_FOLDER, { recursive: true })
        .map(String)
        .filter((f) => /down|rollback|revert/i.test(f)),
    ).toEqual([]);
  });

  it('snapshots form an unbroken chain', () => {
    for (let i = 1; i < journal.entries.length; i++) {
      expect(readSnapshot(i).prevId, `snapshot ${i}`).toBe(readSnapshot(i - 1).id);
    }
  });

  it('migrations contain no destructive statements without review markers', () => {
    // A DROP TABLE / DROP COLUMN / TRUNCATE in a forward-only migration loses data that only a
    // Neon restore can bring back; none exist today. If one is ever needed, update this list
    // deliberately alongside a documented data-migration plan.
    const ALLOWED: string[] = [];
    for (const e of journal.entries) {
      const sql = readFileSync(join(MIGRATIONS_FOLDER, `${e.tag}.sql`), 'utf8');
      if (/\b(DROP\s+TABLE|DROP\s+COLUMN|TRUNCATE)\b/i.test(sql) && !ALLOWED.includes(e.tag)) {
        throw new Error(`${e.tag} contains a destructive statement`);
      }
    }
  });
});

describe('applied schema matches the latest snapshot', () => {
  it('has exactly the snapshot tables', async () => {
    const rows = await q<{ table_name: string }>(
      "select table_name from information_schema.tables where table_schema = 'public' and table_type = 'BASE TABLE' order by 1",
    );
    expect(rows.map((r) => r.table_name)).toEqual(
      Object.values(latest.tables)
        .map((x) => x.name)
        .sort(),
    );
  });

  it('has the snapshot columns with matching nullability and types', async () => {
    const rows = await q<{
      table_name: string;
      column_name: string;
      is_nullable: string;
      data_type: string;
      udt_name: string;
    }>(
      "select table_name, column_name, is_nullable, data_type, udt_name from information_schema.columns where table_schema = 'public'",
    );
    const actual = new Map(rows.map((r) => [`${r.table_name}.${r.column_name}`, r]));
    const expected = new Set<string>();
    for (const table of Object.values(latest.tables)) {
      for (const col of Object.values(table.columns)) {
        const key = `${table.name}.${col.name}`;
        expected.add(key);
        const row = actual.get(key);
        expect(row, `missing column ${key}`).toBeDefined();
        expect(row!.is_nullable === 'NO', `${key} NOT NULL`).toBe(col.notNull || col.primaryKey);
        const base = col.type.replace(/\(.*\)$/, '').replace(/\[\]$/, '');
        const isArray = col.type.endsWith('[]');
        expect(row!.data_type === 'ARRAY', `${key} array`).toBe(isArray);
        const udt = row!.udt_name.replace(/^_/, '');
        const ALIASES: Record<string, string[]> = {
          text: ['text'],
          uuid: ['uuid'],
          boolean: ['bool'],
          integer: ['int4'],
          bigint: ['int8'],
          smallint: ['int2'],
          jsonb: ['jsonb'],
          json: ['json'],
          date: ['date'],
          inet: ['inet'],
          cidr: ['cidr'],
          'timestamp with time zone': ['timestamptz'],
          timestamp: ['timestamp'],
          'double precision': ['float8'],
          real: ['float4'],
          numeric: ['numeric'],
          varchar: ['varchar'],
        };
        const allowed = ALIASES[base] ?? [base]; // enums: udt_name is the enum type name
        expect(allowed, `${key} type ${col.type} vs ${row!.udt_name}`).toContain(udt);
      }
    }
    expect([...actual.keys()].filter((k) => !expected.has(k))).toEqual([]);
  });

  it('has the snapshot enums with values in order', async () => {
    const rows = await q<{ typname: string; labels: string[] }>(
      `select t.typname, array_agg(e.enumlabel order by e.enumsortorder) as labels
         from pg_type t join pg_enum e on e.enumtypid = t.oid
         join pg_namespace n on n.oid = t.typnamespace
        where n.nspname = 'public' group by t.typname`,
    );
    const actual = Object.fromEntries(rows.map((r) => [r.typname, r.labels]));
    const expected = Object.fromEntries(Object.values(latest.enums).map((e) => [e.name, e.values]));
    expect(actual).toEqual(expected);
  });

  it('has every snapshot index (including partial unique indexes) and constraint', async () => {
    const indexes = await q<{ tablename: string; indexname: string; indexdef: string }>(
      "select tablename, indexname, indexdef from pg_indexes where schemaname = 'public'",
    );
    const byName = new Map(indexes.map((i) => [i.indexname, i]));
    const constraints = await q<{ conname: string; contype: string; relname: string }>(
      `select c.conname, c.contype, r.relname from pg_constraint c
         join pg_class r on r.oid = c.conrelid join pg_namespace n on n.oid = r.relnamespace
        where n.nspname = 'public'`,
    );
    const conByName = new Map(constraints.map((c) => [c.conname, c]));

    for (const table of Object.values(latest.tables)) {
      for (const idx of Object.values(table.indexes)) {
        const actual = byName.get(pg(idx.name));
        expect(actual, `index ${idx.name}`).toBeDefined();
        expect(actual!.tablename).toBe(table.name);
        expect(/CREATE UNIQUE INDEX/.test(actual!.indexdef), `${idx.name} unique`).toBe(
          idx.isUnique,
        );
        expect(/ WHERE /.test(actual!.indexdef), `${idx.name} partial`).toBe(Boolean(idx.where));
      }
      for (const fk of Object.values(table.foreignKeys)) {
        expect(conByName.get(pg(fk.name))?.contype, `fk ${fk.name}`).toBe('f');
      }
      for (const u of Object.values(table.uniqueConstraints)) {
        expect(conByName.get(pg(u.name))?.contype, `unique ${u.name}`).toBe('u');
      }
      for (const c of Object.values(table.checkConstraints)) {
        expect(conByName.get(pg(c.name))?.contype, `check ${c.name}`).toBe('c');
      }
    }
    // Nothing in the database that the snapshot does not know about (except primary keys).
    const knownIdx = new Set(
      Object.values(latest.tables).flatMap((t) => Object.values(t.indexes).map((i) => pg(i.name))),
    );
    const extraIdx = indexes
      .filter((i) => !knownIdx.has(i.indexname))
      .filter((i) => !conByName.has(i.indexname)); // pkey / unique-constraint backing indexes
    expect(extraIdx.map((i) => i.indexname)).toEqual([]);
    const knownCon = new Set(
      Object.values(latest.tables).flatMap((t) => [
        ...Object.values(t.foreignKeys).map((x) => pg(x.name)),
        ...Object.values(t.uniqueConstraints).map((x) => pg(x.name)),
        ...Object.values(t.checkConstraints).map((x) => pg(x.name)),
      ]),
    );
    expect(
      constraints
        .filter((c) => ['f', 'u', 'c'].includes(c.contype) && !knownCon.has(c.conname))
        .map((c) => c.conname),
    ).toEqual([]);
  });

  it('reports identifiers PostgreSQL truncates (informational; names must stay unique)', () => {
    const names = Object.values(latest.tables).flatMap((t) => [
      ...Object.values(t.indexes).map((x) => x.name),
      ...Object.values(t.foreignKeys).map((x) => x.name),
      ...Object.values(t.uniqueConstraints).map((x) => x.name),
      ...Object.values(t.checkConstraints).map((x) => x.name),
    ]);
    const truncated = names.map(pg);
    expect(new Set(truncated).size, 'two constraint names collide after truncation').toBe(
      truncated.length,
    );
  });

  it('the active-finding fingerprint is enforced by a partial unique index', () => {
    const findings = latest.tables['public.findings']!;
    const partialUnique = Object.values(findings.indexes).filter((i) => i.isUnique && i.where);
    expect(partialUnique.length).toBeGreaterThan(0);
  });
});

describe('Drizzle schema has no drift against the committed migrations', () => {
  it('generating a migration now would produce no statements', async () => {
    const { generateDrizzleJson, generateMigration } = await import('drizzle-kit/api');
    const current = generateDrizzleJson(schema as unknown as Record<string, unknown>, latest.id);
    const statements = await generateMigration(latest as never, current);
    expect(statements, 'run `npm run db:generate` and commit the migration').toEqual([]);
  }, 60_000);
});

describe('re-running the migrator', () => {
  it('skips every applied migration and changes nothing', async () => {
    const before = await q<{ hash: string; created_at: string }>(
      'select hash, created_at::text from drizzle.__drizzle_migrations order by id',
    );
    expect(before).toHaveLength(journal.entries.length);
    const tablesBefore = await q<{ n: number }>(
      "select count(*)::int as n from information_schema.columns where table_schema = 'public'",
    );
    const db = drizzle(t.pglite, { schema });
    await migrate(db, { migrationsFolder: MIGRATIONS_FOLDER });
    await migrate(db, { migrationsFolder: MIGRATIONS_FOLDER });
    const after = await q<{ hash: string; created_at: string }>(
      'select hash, created_at::text from drizzle.__drizzle_migrations order by id',
    );
    expect(after).toEqual(before);
    expect(
      await q<{ n: number }>(
        "select count(*)::int as n from information_schema.columns where table_schema = 'public'",
      ),
    ).toEqual(tablesBefore);
  });

  it('records each migration by its folder timestamp, matching the journal', async () => {
    const rows = await q<{ created_at: string }>(
      'select created_at::text from drizzle.__drizzle_migrations order by id',
    );
    expect(rows.map((r) => Number(r.created_at))).toEqual(journal.entries.map((e) => e.when));
  });
});

describe('rollback strategy', () => {
  const docs = ['docs/backup-restore.md', 'docs/deployment.md', 'docs/database-schema.md']
    .map((p) => join(REPO_ROOT, p))
    .filter((p) => existsSync(p))
    .map((p) => readFileSync(p, 'utf8'))
    .join('\n');

  it('documents restore through Neon (point-in-time / branch restore)', () => {
    expect(docs).toMatch(/point[- ]in[- ]time/i);
    expect(docs).toMatch(/neon branches restore|branch restore|restore .*branch/i);
  });

  it('documents that migrations are forward-only (no down migrations)', () => {
    expect(docs).toMatch(
      /forward[- ]only|no down[- ]migrations|down migrations|not reversible|irreversible/i,
    );
  });

  it('the migrate script refuses production unless explicitly allowed, and pooled URLs', () => {
    const script = readFileSync(join(REPO_ROOT, 'packages/database/scripts/migrate.ts'), 'utf8');
    expect(script).toMatch(/ALLOW_PRODUCTION_MIGRATION/);
    expect(script).toMatch(/-pooler/);
  });
});
