#!/usr/bin/env bash
# Copies all application data from the Neon `production` branch into the local database
# (schema must already be migrated to the same version). Replaces local data. Read-only on Neon.
#
#   bash scripts/local-db/copy-from-neon.sh
#
# Tables are copied parents-first (foreign-key order) with explicit column lists, then row counts are
# compared table by table. Credentials: Neon via the `neon` CLI, local owner from
# ~/.config/exdomainvault/local-db.env. Nothing is printed.
set -euo pipefail

PROJECT=flat-sound-26073660
# shellcheck disable=SC1091
source "$HOME/.config/exdomainvault/local-db.env"
NEON_URL=$(neon cs production --project-id "$PROJECT")
export PGPASSWORD="$EXDV_LOCAL_OWNER_PASSWORD"
LOCAL=(psql -h 127.0.0.1 -U exdomainvault_owner -d exdomainvault -v ON_ERROR_STOP=1 -Atq)
REMOTE=(psql "$NEON_URL" -v ON_ERROR_STOP=1 -Atq)

remote_version=$("${REMOTE[@]}" -c 'select max(created_at) from drizzle.__drizzle_migrations')
local_version=$("${LOCAL[@]}" -c 'select max(created_at) from drizzle.__drizzle_migrations')
if [[ "$remote_version" != "$local_version" ]]; then
  echo "Schema versions differ (neon $remote_version, local $local_version). Migrate first." >&2
  exit 1
fi

# Parents before children (self-references ignored).
mapfile -t TABLES < <("${LOCAL[@]}" <<'SQL'
with recursive fk as (
  select c.conrelid::regclass::text as child, c.confrelid::regclass::text as parent
  from pg_constraint c
  where c.contype = 'f' and c.connamespace = 'public'::regnamespace and c.conrelid <> c.confrelid
), t as (select tablename::text as name from pg_tables where schemaname = 'public'),
lvl(name, depth) as (
  select name, 0 from t
  union all
  select fk.child, lvl.depth + 1 from fk join lvl on fk.parent = lvl.name where lvl.depth < 50
)
select name from lvl group by name order by max(depth), name;
SQL
)

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
chmod 700 "$WORK"

echo "==> Exporting ${#TABLES[@]} tables from one consistent Neon snapshot"
{
  echo 'begin isolation level repeatable read read only;'
  for t in "${TABLES[@]}"; do
    cols=$("${LOCAL[@]}" -c "select string_agg(quote_ident(column_name), ',' order by ordinal_position) from information_schema.columns where table_schema='public' and table_name='$t'")
    echo "$cols" >"$WORK/$t.cols"
    echo "\\copy (select $cols from public.$t) to '$WORK/$t.dat'"
    echo "select '$t', count(*) from public.$t \\g '$WORK/$t.count'"
  done
  echo 'commit;'
} >"$WORK/export.sql"
"${REMOTE[@]}" -f "$WORK/export.sql" >/dev/null

echo "==> Loading into the local database"
{
  echo 'begin;'
  echo "truncate $(IFS=,; echo "${TABLES[*]}") cascade;"
  for t in "${TABLES[@]}"; do
    echo "\\copy public.$t ($(cat "$WORK/$t.cols")) from '$WORK/$t.dat'"
  done
  echo 'commit;'
} >"$WORK/load.sql"
"${LOCAL[@]}" -f "$WORK/load.sql" >/dev/null

echo "==> Verifying row counts"
fail=0
for t in "${TABLES[@]}"; do
  r=$(cut -d'|' -f2 "$WORK/$t.count")
  l=$("${LOCAL[@]}" -c "select count(*) from public.$t")
  if [[ "$r" != "$l" ]]; then
    echo "    MISMATCH $t: snapshot $r, local $l"
    fail=1
  fi
  printf '    %-32s %s\n' "$t" "$l"
done
"${LOCAL[@]}" -c "analyze $(IFS=,; echo "${TABLES[*]}")"
[[ $fail -eq 0 ]] && echo "All tables match." || { echo "Row counts differ." >&2; exit 1; }
