# ExDomainVault worker

Python 3.12+ home scanning worker. It pulls jobs from the ExDomainVault API over authenticated
outbound HTTPS and never exposes an inbound listener.

**Status (Milestone 1):** configuration loading and validation only. Job claiming arrives in
Milestone 4–5; network checks are disabled until the Milestone 6 scope-validation gate passes.

```bash
# Requires python3-venv (Ubuntu: sudo apt install python3.12-venv)
npm run worker:install   # from the repo root: creates worker/.venv and installs pinned deps
npm run worker:test      # pytest
npm run worker:lint      # ruff

# Validate a configuration
cd worker && EXDV_API_BASE_URL=https://exdomainvault.example.com EXDV_WORKER_ID=home-worker-01 \
  .venv/bin/python -m app.main --check-config
```

Installation under systemd is documented in `docs/home-worker-setup.md` (Milestone 5).
