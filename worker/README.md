# ExDomainVault worker

Python 3.12+ home scanning worker. It pulls jobs from the ExDomainVault API over signed, outbound
HTTPS and never listens on a port. The protocol and every configuration variable are specified in
[`docs/worker-protocol.md`](../docs/worker-protocol.md); production installation is in
[`docs/home-worker-setup.md`](../docs/home-worker-setup.md).

By default only the passive checks (`dns`, `rdap`) run. Active checks (TLS certificate, HTTP
availability/headers, TCP ports via Nmap) run only with `EXDV_ACTIVE_SCANNING_ENABLED=true`, and every
connection goes through the scope validator (`app/policy.py`, `app/net.py`):

- Destinations are resolved, validated against the prohibited ranges and the deny list, pinned, and
  revalidated immediately before connecting; CNAME hops must stay inside the job's domain.
- HTTP redirects are followed only to the job's approved target hostnames, on the scheme's default
  port or the first URL's port, within one overall deadline (the target's remaining budget).
- Job domains that are a single label, under `.arpa`, or a common public suffix are refused (backstop;
  the server enforces the full Public Suffix List).
- Home-network self-protection (`app/self_protection.py`): while active scanning is enabled, the host's
  own interface addresses (IPv6 as /64) and its public egress address (a `whoami.cloudflare` CHAOS TXT
  query to 1.1.1.1) are added to every job's deny list at start-up and hourly. If the egress address is
  unknown and `EXDV_DENY_NETWORKS` is empty, web/network checks fail with `egress_ip_unknown`.
- A heartbeat response carrying `approvedNetworks` shrinks the running job's approved networks
  (intersection; never widened).
- Nmap runs from a fixed argv template with rlimits and its own process group; `-sV` runs only Nmap's
  `version`-category NSE scripts (see `app/port_checks.py`).

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
