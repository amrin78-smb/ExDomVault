#!/usr/bin/env bash
# Restore drill: restores the newest backup into exdomainvault_restore_test, compares row counts
# with the live database (live may be slightly ahead), then empties the scratch database again.
#
#   bash scripts/local-db/restore-drill.sh [backup-file]
set -euo pipefail
# shellcheck disable=SC1091
source "$HOME/.config/exdomainvault/local-db.env"
export PGPASSWORD="$EXDV_LOCAL_OWNER_PASSWORD"
export PGOPTIONS="-c client_min_messages=warning"
FILE="${1:-$(ls -1t "$HOME"/backups/exdomainvault/exdomainvault-*.dump | head -1)}"
PSQL=(psql -h 127.0.0.1 -U exdomainvault_owner -v ON_ERROR_STOP=1 -Atq)
echo "==> Restoring $(basename "$FILE")"
"${PSQL[@]}" -d exdomainvault_restore_test -c 'drop schema if exists drizzle cascade; drop schema public cascade; create schema public;'
start=$(date +%s)
pg_restore -h 127.0.0.1 -U exdomainvault_owner -d exdomainvault_restore_test --no-owner --no-acl --exit-on-error "$FILE"
echo "    restored in $(( $(date +%s) - start ))s"
echo "==> Comparing row counts (backup vs live)"
fail=0
for t in $("${PSQL[@]}" -d exdomainvault_restore_test -c "select tablename from pg_tables where schemaname='public' order by 1"); do
  b=$("${PSQL[@]}" -d exdomainvault_restore_test -c "select count(*) from public.$t")
  l=$("${PSQL[@]}" -d exdomainvault -c "select count(*) from public.$t")
  flag=""; (( b > l )) && { flag="  <- backup has MORE rows than live"; fail=1; }
  printf '    %-28s backup %-7s live %s%s\n' "$t" "$b" "$l" "$flag"
done
m=$("${PSQL[@]}" -d exdomainvault_restore_test -c 'select count(*) from drizzle.__drizzle_migrations')
echo "    migrations recorded: $m"
"${PSQL[@]}" -d exdomainvault_restore_test -c 'drop schema if exists drizzle cascade; drop schema public cascade; create schema public;'
[[ $fail -eq 0 ]] && echo "Restore drill passed." || { echo "Restore drill found problems." >&2; exit 1; }
