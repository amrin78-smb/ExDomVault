#!/usr/bin/env bash
# One-time host setup for running the ExDomainVault database on this machine (run with sudo).
#
#   sudo bash scripts/local-db/setup-host.sh
#
# 1. Installs cloudflared from Cloudflare's apt repository (if missing).
# 2. Checks that PostgreSQL accepts TLS (Hyperdrive requires it; Ubuntu enables it by default).
# 3. Creates the roles and the database (idempotent):
#      exdomainvault_owner  owns the database and schema; used for migrations and backups
#      exdomainvault_app    least-privilege application role (Hyperdrive), DML only
# 4. Installs the Cloudflare Tunnel as a systemd service (outbound only; nothing is exposed).
#
# Secrets are read from files written by the setup assistant, never passed on the command line:
#   ~/.config/exdomainvault/local-db.env   EXDV_LOCAL_OWNER_PASSWORD, EXDV_LOCAL_APP_PASSWORD
#   ~/.config/exdomainvault/tunnel-token   Cloudflare Tunnel token
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo: sudo bash $0" >&2
  exit 1
fi
OWNER_HOME=$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)
CONF="$OWNER_HOME/.config/exdomainvault"
[[ -r "$CONF/local-db.env" && -r "$CONF/tunnel-token" ]] || {
  echo "Missing $CONF/local-db.env or $CONF/tunnel-token" >&2
  exit 1
}
# shellcheck disable=SC1091
source "$CONF/local-db.env"

echo "==> cloudflared"
if ! command -v cloudflared >/dev/null; then
  install -d -m 0755 /usr/share/keyrings
  curl -fsSL https://pkg.cloudflare.com/cloudflare-public-v2.gpg -o /usr/share/keyrings/cloudflare-public-v2.gpg
  echo 'deb [signed-by=/usr/share/keyrings/cloudflare-public-v2.gpg] https://pkg.cloudflare.com/cloudflared any main' \
    >/etc/apt/sources.list.d/cloudflared.list
  apt-get update -qq
  apt-get install -y -qq cloudflared
fi
cloudflared --version

echo "==> PostgreSQL TLS"
SSL=$(runuser -u postgres -- psql -Atqc 'show ssl')
if [[ "$SSL" != "on" ]]; then
  echo "PostgreSQL ssl is '$SSL'. Enable it (ssl = on with a certificate) and re-run." >&2
  exit 1
fi
echo "    ssl = on"

echo "==> Roles and database"
runuser -u postgres -- env OWNER_PW="$EXDV_LOCAL_OWNER_PASSWORD" APP_PW="$EXDV_LOCAL_APP_PASSWORD" \
  psql -v ON_ERROR_STOP=1 -q <<'SQL'
\getenv owner_pw OWNER_PW
\getenv app_pw APP_PW
SELECT format('CREATE ROLE exdomainvault_owner LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS', :'owner_pw')
  WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'exdomainvault_owner') \gexec
SELECT format('ALTER ROLE exdomainvault_owner PASSWORD %L', :'owner_pw') \gexec
SELECT format('CREATE ROLE exdomainvault_app LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS', :'app_pw')
  WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'exdomainvault_app') \gexec
SELECT format('ALTER ROLE exdomainvault_app PASSWORD %L', :'app_pw') \gexec
SELECT 'CREATE DATABASE exdomainvault OWNER exdomainvault_owner'
  WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'exdomainvault') \gexec
REVOKE ALL ON DATABASE exdomainvault FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE exdomainvault TO exdomainvault_owner;
GRANT CONNECT ON DATABASE exdomainvault TO exdomainvault_app;
\connect exdomainvault
ALTER SCHEMA public OWNER TO exdomainvault_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO exdomainvault_app;
ALTER DEFAULT PRIVILEGES FOR ROLE exdomainvault_owner IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO exdomainvault_app;
ALTER DEFAULT PRIVILEGES FOR ROLE exdomainvault_owner IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO exdomainvault_app;
SQL
echo "    exdomainvault (owner exdomainvault_owner), app role exdomainvault_app"

echo "==> Cloudflare Tunnel service"
if systemctl list-unit-files cloudflared.service >/dev/null 2>&1 && systemctl is-enabled cloudflared >/dev/null 2>&1; then
  echo "    cloudflared service already installed"
else
  cloudflared service install "$(cat "$CONF/tunnel-token")"
fi
systemctl enable --now cloudflared >/dev/null 2>&1 || true
sleep 3
systemctl is-active cloudflared

echo
echo "Done. Tell the assistant: setup finished."
