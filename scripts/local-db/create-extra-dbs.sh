#!/usr/bin/env bash
# Creates the two extra local databases (run with sudo, idempotent):
#   exdomainvault_dev           local development (replaces the Neon `dev` branch)
#   exdomainvault_restore_test  scratch target for backup restore drills (emptied after each drill)
# Both are owned by exdomainvault_owner, so drills and dev migrations need no further sudo.
#
#   sudo bash scripts/local-db/create-extra-dbs.sh
set -euo pipefail
if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo: sudo bash $0" >&2
  exit 1
fi
runuser -u postgres -- psql -v ON_ERROR_STOP=1 -q <<'SQL'
SELECT 'CREATE DATABASE exdomainvault_dev OWNER exdomainvault_owner'
  WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'exdomainvault_dev') \gexec
SELECT 'CREATE DATABASE exdomainvault_restore_test OWNER exdomainvault_owner'
  WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'exdomainvault_restore_test') \gexec
REVOKE ALL ON DATABASE exdomainvault_dev FROM PUBLIC;
REVOKE ALL ON DATABASE exdomainvault_restore_test FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE exdomainvault_dev TO exdomainvault_owner;
GRANT CONNECT, TEMPORARY ON DATABASE exdomainvault_restore_test TO exdomainvault_owner;
\connect exdomainvault_dev
ALTER SCHEMA public OWNER TO exdomainvault_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
\connect exdomainvault_restore_test
ALTER SCHEMA public OWNER TO exdomainvault_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SQL
echo "Created exdomainvault_dev and exdomainvault_restore_test (owner exdomainvault_owner)."
