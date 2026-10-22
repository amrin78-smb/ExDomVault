# ExDomainVault worker

Python 3.12+ home scanning worker. It pulls jobs from the ExDomainVault API over signed, outbound
HTTPS and never listens on a port. The protocol and every configuration variable are specified in
[`docs/worker-protocol.md`](../docs/worker-protocol.md); production installation is in
[`docs/home-worker-setup.md`](../docs/home-worker-setup.md).

Active network scanning is hard-coded off until the Milestone 6 scope validator is complete. Only the
passive checks (`dns`, `rdap`) run.

## Set up and test

```bash
# Requires python3.12-venv (Ubuntu: sudo apt install python3.12-venv)
npm run worker:install   # from the repo root: worker/.venv with pinned runtime + dev deps
npm run worker:test      # pytest (no live network: mocks and synthetic data only)
npm run worker:lint      # ruff check + ruff format --check
```

## Run locally against `npm run dev`

1. Start the app from the repo root with `npm run dev` and note the URL it prints (Vite's default is
   `http://localhost:5173`; it picks the next free port, e.g. `http://localhost:5199`, if that is taken).
2. Generate a development key pair (git-ignored by the `*.key` rule):

   ```bash
   cd worker
   (umask 077 && openssl genpkey -algorithm ed25519 -out dev-worker.key)
   openssl pkey -in dev-worker.key -pubout -outform DER | tail -c 32 | base64
   ```

3. In the local app, **Settings → Scanning workers**: register a worker (e.g. `dev-worker`) with that
   public key and copy the **key id**.
4. Create `worker/.env` from `.env.example` (git-ignored) and set at least:

   ```bash
   EXDV_API_BASE_URL=http://localhost:5199   # the URL npm run dev printed
   EXDV_ENVIRONMENT=development              # plain http is accepted only for localhost in development
   EXDV_WORKER_ID=dev-worker
   EXDV_KEY_ID=<key id from step 3>
   EXDV_PRIVATE_KEY_FILE=./dev-worker.key
   EXDV_HEALTH_FILE=./health.json
   ```

   Remove the `EXDV_ACCESS_CLIENT_*` lines: the local app is not behind Cloudflare Access.

5. Install the worker package into the venv once (`npm run worker:install` installs only the
   dependencies), then export `.env` — the worker reads the process environment only — and run it:

   ```bash
   .venv/bin/pip install --no-deps -e .
   set -a && . ./.env && set +a
   .venv/bin/exdomainvault-worker --check-config   # validate configuration and exit
   .venv/bin/exdomainvault-worker --once           # one claim/process cycle, then exit
   .venv/bin/exdomainvault-worker --health         # report the health file written by the loop
   .venv/bin/exdomainvault-worker                  # run the polling loop (Ctrl-C to stop)
   ```

   `.venv/bin/python -m app.main` (from `worker/`) is equivalent if you skip the package install.

Logs are JSON lines on stdout. Request a passive scan from the app (domain page → **Scans** →
**Request scan**) to see the worker claim it.

## Container image

`Dockerfile` builds a non-root (uid 10001), multi-stage image with a read-only-friendly layout; the
run command is in the file header. The systemd installation remains the documented deployment for the
home host.
