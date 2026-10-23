#!/usr/bin/env bash
# Installs or upgrades the ExDomainVault worker on this host (docs/home-worker-setup.md steps 2-4, 9).
# Run from anywhere in the repository checkout:  sudo bash worker/deploy/install.sh
#
# Safe to re-run (upgrades code and dependencies). It never overwrites an existing private key or
# worker.env, never prints secrets, and does not start the service: that is a separate, explicit step
# once worker.env is complete.
set -euo pipefail

SERVICE_USER=exdomainvault-worker
APP_DIR=/opt/exdomainvault-worker
ETC_DIR=/etc/exdomainvault
KEY_FILE="$ETC_DIR/worker.key"
ENV_FILE="$ETC_DIR/worker.env"
REPO_WORKER="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo: sudo bash $0" >&2
  exit 1
fi
for cmd in python3.12 openssl rsync systemctl; do
  command -v "$cmd" >/dev/null || { echo "Missing required command: $cmd" >&2; exit 1; }
done

echo "==> Service user and directories"
id "$SERVICE_USER" &>/dev/null ||
  useradd --system --home /var/lib/exdomainvault-worker --shell /usr/sbin/nologin "$SERVICE_USER"
install -d -o root -g root -m 0755 "$APP_DIR"
install -d -o root -g "$SERVICE_USER" -m 0750 "$ETC_DIR"

echo "==> Code (root-owned, read-only to the service)"
rsync -a --delete --chown=root:root \
  --exclude '.venv/' --exclude '__pycache__/' --exclude '.pytest_cache/' --exclude '.ruff_cache/' \
  --exclude '*.key' --exclude '.env' --exclude 'tests/' \
  "$REPO_WORKER/" "$APP_DIR/"

echo "==> Python environment and pinned dependencies"
[[ -x "$APP_DIR/.venv/bin/python" ]] || python3.12 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --quiet --no-cache-dir -r "$APP_DIR/requirements.txt"
"$APP_DIR/.venv/bin/pip" install --quiet --no-cache-dir --no-deps --force-reinstall "$APP_DIR"
"$APP_DIR/.venv/bin/exdomainvault-worker" --version >/dev/null

echo "==> Worker key"
if [[ -f "$KEY_FILE" ]]; then
  echo "    keeping existing $KEY_FILE"
else
  (umask 077 && openssl genpkey -algorithm ed25519 -out "$KEY_FILE")
fi
chown root:root "$KEY_FILE"
chmod 600 "$KEY_FILE"

echo "==> Configuration"
if [[ -f "$ENV_FILE" ]]; then
  echo "    keeping existing $ENV_FILE"
else
  (umask 027 && cat >"$ENV_FILE" <<'EOF'
EXDV_API_BASE_URL=https://exdomainvault.amrin78.workers.dev
EXDV_WORKER_ID=home-worker-01
EXDV_KEY_ID=REPLACE_WITH_KEY_ID_FROM_SETTINGS
EXDV_ACCESS_CLIENT_ID=REPLACE_WITH_SERVICE_TOKEN_CLIENT_ID
EXDV_ACCESS_CLIENT_SECRET=REPLACE_WITH_SERVICE_TOKEN_CLIENT_SECRET
EXDV_ENVIRONMENT=production
EXDV_POLL_INTERVAL_SECONDS=30
EXDV_PROFILES=passive,discovery
EXDV_LOG_LEVEL=INFO
# Active scanning (TLS/HTTP/port checks) stays off until explicitly set to true.
EXDV_ACTIVE_SCANNING_ENABLED=false
# Networks never to contact (comma-separated CIDRs), e.g. this home's static public IP/32 and IPv6 /64.
#EXDV_DENY_NETWORKS=
EOF
  )
fi
chown root:"$SERVICE_USER" "$ENV_FILE"
chmod 640 "$ENV_FILE"

echo "==> systemd units (installed, not started)"
install -o root -g root -m 0644 "$APP_DIR/deploy/exdomainvault-worker.service" \
  "$APP_DIR/deploy/exdomainvault-worker-health.service" \
  "$APP_DIR/deploy/exdomainvault-worker-health.timer" /etc/systemd/system/
systemctl daemon-reload

echo
echo "Public key to register in ExDomainVault (Settings -> Scanning workers):"
openssl pkey -in "$KEY_FILE" -pubout -outform DER | tail -c 32 | base64
echo
if grep -q REPLACE_WITH "$ENV_FILE"; then
  echo "Next: register the key, then 'sudoedit $ENV_FILE' to fill in EXDV_KEY_ID and the service token."
  echo "Then: sudo systemctl enable --now exdomainvault-worker"
else
  echo "Upgrade complete. Restart with: sudo systemctl restart exdomainvault-worker"
fi
