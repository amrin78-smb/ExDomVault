#!/usr/bin/env bash
# Daily backup of the local ExDomainVault database (custom-format pg_dump, compressed), keeping
# the last 14 days. Runs as the desktop user from cron; no sudo needed.
#
#   bash scripts/local-db/backup.sh            # one backup now
#   crontab: 30 2 * * * bash /home/amrin/development/Nocvault/ExDomVault/scripts/local-db/backup.sh
#
# Restore (into an empty database created by the setup script):
#   pg_restore -h 127.0.0.1 -U exdomainvault_owner -d exdomainvault --clean --if-exists <file>.dump
set -euo pipefail
umask 077
DIR="${EXDV_BACKUP_DIR:-$HOME/backups/exdomainvault}"
KEEP_DAYS="${EXDV_BACKUP_KEEP_DAYS:-14}"
mkdir -p "$DIR"
# shellcheck disable=SC1091
source "$HOME/.config/exdomainvault/local-db.env"
export PGPASSWORD="$EXDV_LOCAL_OWNER_PASSWORD"
FILE="$DIR/exdomainvault-$(date -u +%Y%m%dT%H%M%SZ).dump"
pg_dump -h 127.0.0.1 -U exdomainvault_owner -d exdomainvault -Fc -Z 6 -f "$FILE.partial"
pg_restore --list "$FILE.partial" >/dev/null # the archive is readable end to end
mv "$FILE.partial" "$FILE"
find "$DIR" -name 'exdomainvault-*.dump' -mtime +"$KEEP_DAYS" -delete
find "$DIR" -name '*.partial' -mmin +120 -delete
echo "$(date -u +%FT%TZ) backup ok $(du -h "$FILE" | cut -f1) $FILE"
