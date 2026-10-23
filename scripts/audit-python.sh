#!/usr/bin/env bash
# Audits the worker's pinned Python dependencies with pip-audit (OSV/PyPI advisories).
#
# Usage: scripts/audit-python.sh [pip-audit binary]
# Installs nothing itself unless no binary is given, in which case it creates worker/.venv-audit
# (git-ignored) with the pinned tooling from worker/requirements-audit.txt.
# Unexpired entries in .github/audit/pip-audit-exceptions.txt are passed as --ignore-vuln.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

pip_audit="${1:-}"
if [[ -z "$pip_audit" ]]; then
  if [[ ! -x worker/.venv-audit/bin/pip-audit ]]; then
    python3 -m venv worker/.venv-audit
    worker/.venv-audit/bin/pip install --quiet --upgrade pip
    worker/.venv-audit/bin/pip install --quiet -r worker/requirements-audit.txt
  fi
  pip_audit="worker/.venv-audit/bin/pip-audit"
fi

today="$(date -u +%F)"
ignore_args=()
while read -r id expires _reason; do
  [[ -z "${id:-}" || "$id" == \#* ]] && continue
  if [[ ! "$expires" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    echo "invalid expiry for $id in pip-audit-exceptions.txt: $expires" >&2
    exit 2
  fi
  if [[ "$today" < "$expires" ]]; then
    echo "pip-audit: ignoring $id until $expires"
    ignore_args+=(--ignore-vuln "$id")
  else
    echo "pip-audit: exception for $id expired on $expires; it is enforced again"
  fi
done < .github/audit/pip-audit-exceptions.txt

status=0
for req in worker/requirements.txt worker/requirements-dev.txt; do
  echo "== pip-audit $req"
  "$pip_audit" --progress-spinner off --strict --desc on -r "$req" "${ignore_args[@]}" || status=1
done
exit "$status"
