# Home worker setup

Operator guide for running the ExDomainVault scanning worker as a systemd service on the home host
(Ubuntu 24.04, this machine). The worker makes outbound HTTPS requests to the application, signs each
one with an Ed25519 key, and never listens on a port. The protocol and configuration variables are
specified in [`worker-protocol.md`](worker-protocol.md); this guide only covers installation and
operation.

Commands marked `sudo` are run by the owner. Nothing here is automated.

| Item          | Value                                                                     |
| ------------- | ------------------------------------------------------------------------- |
| Service user  | `exdomainvault-worker` (system account, no shell, no login)               |
| Code and venv | `/opt/exdomainvault-worker` (root-owned, read-only to the service)        |
| Configuration | `/etc/exdomainvault/worker.env` (`0640 root:exdomainvault-worker`)        |
| Private key   | `/etc/exdomainvault/worker.key` (`0600 root:root`, see step 4)            |
| State         | `/var/lib/exdomainvault-worker` (created by systemd, `0700`; health file) |
| Units         | `worker/deploy/exdomainvault-worker.service` (+ optional health timer)    |
| Application   | `https://exdomainvault.amrin78.workers.dev` (behind Cloudflare Access)    |

## 1. Prerequisites

- Ubuntu 24.04 with systemd 255, Python 3.12 and `python3.12-venv`
  (`sudo apt install python3.12-venv` if `python3.12 -m venv` fails).
- `openssl`, `rsync` and `jq` (all present on this host).
- Accurate time: requests are rejected if the clock is more than 300 s off. Check that
  `timedatectl show -p NTPSynchronized` prints `NTPSynchronized=yes`.
- An ExDomainVault administrator account (to register the worker) and access to the Cloudflare
  dashboard (to create the Access service token).
- Nmap is **not** needed yet. It arrives with active scanning in Milestone 6.

## 2. Create the service user and directories

```bash
sudo useradd --system --home /var/lib/exdomainvault-worker --shell /usr/sbin/nologin exdomainvault-worker
sudo install -d -o root -g root -m 0755 /opt/exdomainvault-worker
sudo install -d -o root -g exdomainvault-worker -m 0750 /etc/exdomainvault
```

Do not create `/var/lib/exdomainvault-worker` yourself: `StateDirectory=` in the unit creates it with
the right owner and mode.

## 3. Install the code

From the repository checkout (as your normal user, `git pull` first):

```bash
cd ~/development/Nocvault/ExDomVault
sudo rsync -a --delete --chown=root:root \
  --exclude '.venv/' --exclude '__pycache__/' --exclude '.pytest_cache/' --exclude '.ruff_cache/' \
  --exclude '*.key' --exclude '.env' --exclude 'tests/' \
  worker/ /opt/exdomainvault-worker/
sudo python3.12 -m venv /opt/exdomainvault-worker/.venv
sudo /opt/exdomainvault-worker/.venv/bin/pip install --no-cache-dir -r /opt/exdomainvault-worker/requirements.txt
sudo /opt/exdomainvault-worker/.venv/bin/pip install --no-cache-dir --no-deps /opt/exdomainvault-worker
```

The code and venv stay owned by root, so the service account cannot modify what it runs. If
`requirements.txt` later carries `--hash=` entries, add `--require-hashes` to the first `pip install`.
`rsync --delete` would remove a venv on a later upgrade, which is why `.venv/` is excluded.

## 4. Generate the worker key

The key is created by root and stays `0600 root:root` at rest. The unit passes it to the worker with
`LoadCredential=`: systemd copies it into a private, non-swappable credentials directory readable only
by the running service, and points `EXDV_PRIVATE_KEY_FILE` at that copy. The worker process itself
cannot read `/etc/exdomainvault` at all (`InaccessiblePaths=`). This is stronger than giving the
service user ownership of the key file, which the unit would otherwise need.

```bash
sudo sh -c 'umask 077 && openssl genpkey -algorithm ed25519 -out /etc/exdomainvault/worker.key'
sudo chmod 600 /etc/exdomainvault/worker.key
sudo openssl pkey -in /etc/exdomainvault/worker.key -pubout -outform DER | tail -c 32 | base64
```

The last command prints the 44-character base64 public key. The private key never leaves the machine;
do not copy it into the repository (`*.key` is git-ignored as a safety net).

## 5. Register the worker in ExDomainVault

1. Sign in as an administrator and open **Settings → Scanning workers**.
2. **Worker name**: e.g. `home-worker-01` (2–63 lowercase letters, digits or hyphens; the same value
   goes in `EXDV_WORKER_ID`).
3. **Public key (base64)**: paste the output of step 4, then **Register worker**.
4. Copy the **key id** (a UUID) shown after registration; it is also in the worker's credential table.
   It goes in `EXDV_KEY_ID`. Credentials expire after 365 days by default.

## 6. Create the Cloudflare Access service token

Access protects the whole Worker (_All traffic_), so without a service token every worker request is
redirected to the Access login page. The token only gets requests past Access; the application still
authenticates the worker by its Ed25519 signature and rejects service tokens on user routes.
Dashboard labels change over time; the paths below describe the current layout.

1. **Create the token.** Cloudflare dashboard → **Zero Trust** → **Access** → **Service credentials**
   → **Service Tokens** → **Create Service Token**. Name it `exdomainvault-home-worker`, choose a
   duration (e.g. 1 year; note the expiry date), and copy the **Client ID** and **Client Secret**. The
   secret is shown only once.
2. **Allow it through Access.** Add a policy with action **Service Auth** whose _Include_ rule is
   _Service Token_ → `exdomainvault-home-worker`. Either:
   - **Workers & Pages → exdomainvault → Access** (the per-Worker Access settings), and add the policy
     next to the existing _Allow_ policy for people; or
   - **Zero Trust → Access → Applications**, open the application Cloudflare created for the Worker
     (`exdomainvault.amrin78.workers.dev`), **Policies → Add a policy**.

   Keep the existing _Allow_ policy for people unchanged. Do not use _Bypass_.

3. **Check it** (after step 7 has created `worker.env`). This passes the headers via `curl -K -` so the
   secret is not visible in the process list:

   ```bash
   sudo bash -c 'set -a; . /etc/exdomainvault/worker.env; printf "header = \"CF-Access-Client-Id: %s\"\nheader = \"CF-Access-Client-Secret: %s\"\n" "$EXDV_ACCESS_CLIENT_ID" "$EXDV_ACCESS_CLIENT_SECRET" | curl -sS -o /dev/null -w "%{http_code} %{redirect_url}\n" -K - "$EXDV_API_BASE_URL/api/v1/health"'
   ```

   `200` means Access let the token through. A `302` to `*.cloudflareaccess.com` means the token or
   the Service Auth policy is missing or wrong.

## 7. Write `worker.env`

Start from [`worker/.env.example`](../worker/.env.example) and fill in real values:

```bash
sudo install -o root -g exdomainvault-worker -m 0640 /opt/exdomainvault-worker/.env.example /etc/exdomainvault/worker.env
sudoedit /etc/exdomainvault/worker.env
```

```bash
EXDV_API_BASE_URL=https://exdomainvault.amrin78.workers.dev
EXDV_WORKER_ID=home-worker-01
EXDV_KEY_ID=<key id from step 5>
EXDV_PRIVATE_KEY_FILE=/etc/exdomainvault/worker.key
EXDV_ACCESS_CLIENT_ID=<Client ID from step 6>
EXDV_ACCESS_CLIENT_SECRET=<Client Secret from step 6>
EXDV_ENVIRONMENT=production
EXDV_POLL_INTERVAL_SECONDS=30
EXDV_PROFILES=passive
EXDV_LOG_LEVEL=INFO
```

Leave `EXDV_DNS_RESOLVERS` unset to query the public resolvers 1.1.1.1 and 9.9.9.9 (and their IPv6
addresses), so records are seen as the internet sees them. `system` uses the host's resolver
(`127.0.0.53`, systemd-resolved), which answers DS/DNSKEY queries with SERVFAIL. Write
the values without quotes or trailing comments: systemd's `EnvironmentFile=` parser is not a shell.
The unit overrides `EXDV_PRIVATE_KEY_FILE` with its `LoadCredential=` copy of the key.

## 8. Validate and dry-run

Because the key is delivered through `LoadCredential=`, run manual checks in a transient unit with the
same user, environment file and credential as the service. Define a helper in your shell:

```bash
exdv_run() {
  sudo systemd-run --unit=exdomainvault-worker-manual --pipe --wait --collect --quiet \
    -p User=exdomainvault-worker -p Group=exdomainvault-worker \
    -p EnvironmentFile=/etc/exdomainvault/worker.env \
    -p LoadCredential=worker.key:/etc/exdomainvault/worker.key \
    -p Environment=EXDV_PRIVATE_KEY_FILE=/run/credentials/exdomainvault-worker-manual.service/worker.key \
    -p StateDirectory=exdomainvault-worker \
    /opt/exdomainvault-worker/.venv/bin/exdomainvault-worker "$@"
}
```

Then:

```bash
exdv_run --check-config   # validates configuration and the key, exits 0 when valid
exdv_run --once           # one claim/process cycle against the live application, then exits
```

`--once` is a real cycle, not a simulation: if a passive job is queued it is claimed, processed and
reported. With nothing queued it makes one claim request and exits. Either way the worker should now
show as **last seen** in **Settings → Scanning workers**. A `401`/`302` here is diagnosed in step 13.

## 9. Install and enable the service

```bash
sudo install -o root -g root -m 0644 /opt/exdomainvault-worker/deploy/exdomainvault-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now exdomainvault-worker
```

Optional periodic health check (runs `--health` every 5 minutes; failures appear in
`systemctl --failed` and the journal):

```bash
sudo install -o root -g root -m 0644 \
  /opt/exdomainvault-worker/deploy/exdomainvault-worker-health.service \
  /opt/exdomainvault-worker/deploy/exdomainvault-worker-health.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now exdomainvault-worker-health.timer
```

What the unit does (see the comments in the file):

- Runs as `exdomainvault-worker` with no capabilities, `NoNewPrivileges`, a read-only file system
  (`ProtectSystem=strict`) except its state directory, private `/tmp` and devices, a native-only
  `@system-service` system-call filter and `MemoryDenyWriteExecute`.
- `ExecStartPre=… --check-config` stops a bad configuration before the loop starts.
- `Restart=on-failure` after 30 s; after 5 failed starts in 10 minutes systemd stops trying
  (`sudo systemctl reset-failed exdomainvault-worker` once fixed).
- Limits: `MemoryMax=512M`, `TasksMax=64`, `CPUQuota=50%`.
- **Egress filter:** `IPAddressDeny=` blocks loopback, RFC 1918 private, CGNAT, link-local, multicast
  and IPv6 ULA destinations, except the resolver stub `127.0.0.53`. The worker can reach the public
  internet but not the home LAN. If you set `EXDV_DNS_RESOLVERS` to a LAN resolver, add it to
  `IPAddressAllow=`. This is defence in depth; the Milestone 6 scope validator remains the primary
  control.

Check the hardening score with `systemd-analyze security exdomainvault-worker` (about 1.2, "OK").

## 10. Health checks

```bash
systemctl status exdomainvault-worker
journalctl -u exdomainvault-worker -f -o cat | jq .     # logs are JSON lines
exdv_run --health                                        # reads the health file (exit 0 = healthy)
sudo cat /var/lib/exdomainvault-worker/health.json | jq .
systemctl list-timers exdomainvault-worker-health.timer  # if the timer is enabled
```

In the application, **Settings → Scanning workers** shows **last seen** and the worker version; the key
row shows **Last used**. A worker that is running but never "seen" is not reaching the API (step 13).

## 11. Upgrade and restart

```bash
cd ~/development/Nocvault/ExDomVault && git pull
sudo rsync -a --delete --chown=root:root \
  --exclude '.venv/' --exclude '__pycache__/' --exclude '.pytest_cache/' --exclude '.ruff_cache/' \
  --exclude '*.key' --exclude '.env' --exclude 'tests/' \
  worker/ /opt/exdomainvault-worker/
sudo /opt/exdomainvault-worker/.venv/bin/pip install --no-cache-dir -r /opt/exdomainvault-worker/requirements.txt
sudo /opt/exdomainvault-worker/.venv/bin/pip install --no-cache-dir --no-deps --force-reinstall /opt/exdomainvault-worker
exdv_run --check-config
# If the unit files changed:
sudo install -o root -g root -m 0644 /opt/exdomainvault-worker/deploy/exdomainvault-worker*.service \
  /opt/exdomainvault-worker/deploy/exdomainvault-worker-health.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl restart exdomainvault-worker
```

A restart mid-job is safe: the job's lease expires and the application retries it (bounded attempts).
After a Python minor-version upgrade of the OS, recreate the venv (`sudo rm -rf
/opt/exdomainvault-worker/.venv` and repeat step 3). To roll back, check out the previous commit and
repeat the same commands.

## 12. Credential rotation

**Worker key** (before it expires, or at once if it may be exposed):

1. Generate the new key next to the old one:
   `sudo sh -c 'umask 077 && openssl genpkey -algorithm ed25519 -out /etc/exdomainvault/worker.key.new'`
   and print its public key as in step 4.
2. Register it for the existing worker with `POST /api/v1/workers/:id/credentials` (administrator;
   there is no Settings button for adding a second key yet). The API sits behind Access and accepts
   same-origin writes only, so the simplest way is the browser console on the signed-in app:

   ```js
   const { items } = await (await fetch('/api/v1/workers')).json();
   const id = items.find((w) => w.name === 'home-worker-01').id;
   await (
     await fetch(`/api/v1/workers/${id}/credentials`, {
       method: 'POST',
       headers: { 'content-type': 'application/json' },
       body: JSON.stringify({ publicKey: '<base64 public key>' }),
     })
   ).json();
   ```

   Note the new key id (also shown in Settings).

3. `sudo mv /etc/exdomainvault/worker.key.new /etc/exdomainvault/worker.key`, set the new
   `EXDV_KEY_ID` in `worker.env`, then `sudo systemctl restart exdomainvault-worker`.
4. Confirm the new key's **Last used** updates in **Settings → Scanning workers**, then **Revoke** the
   old key there. If a key is compromised, revoke it first (or **Disable** the worker, which stops all of
   its requests) and then rotate.

**Access service token:** create a second token (step 6.1), add it to the same Service Auth policy,
put the new Client ID/Secret in `worker.env`, restart, confirm the worker is still seen, then remove
the old token from the policy and delete it under **Service Tokens**. Rotate before the token's
expiry date; an expired token makes every request fail at Access (`302`/`403`).

## 13. Troubleshooting

The application answers every worker authentication failure with a generic `401`; the specific reason
is in the application's Workers logs as `worker_auth_failed` with a `reason` field.

| Symptom                                                         | Likely cause and fix                                                                                                                                                                                                            |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `401`, reason `timestamp_out_of_window`                         | Clock more than 300 s off. `timedatectl` must show _System clock synchronized: yes_; enable NTP with `sudo timedatectl set-ntp true`.                                                                                           |
| `401`, reason `unknown_key` / `bad_signature`                   | `EXDV_KEY_ID` does not match the key in `/etc/exdomainvault/worker.key`, or the wrong public key was registered. Re-derive the public key (step 4); if in doubt, register it again and use the new key id.                      |
| `401`, reason `key_revoked` / `key_expired` / `worker_disabled` | Register a new key (step 12) or re-enable the worker in **Settings → Scanning workers**.                                                                                                                                        |
| `401`, reason `replayed_nonce`                                  | A request was re-sent with the same nonce. Should not happen (each retry is re-signed); report it as a bug.                                                                                                                     |
| `302` to `*.cloudflareaccess.com`, or `403` from Access         | Service token missing, wrong or expired, or no **Service Auth** policy includes it. Check `EXDV_ACCESS_CLIENT_*` and step 6; test with the `curl` check in step 6.3. The worker does not follow redirects and reports an error. |
| `409` on heartbeat/results                                      | The job lease was lost (expired or reassigned). The worker stops that job without reporting further; the application retries it. Frequent `409`s mean the host is stalling or was suspended.                                    |
| `429`                                                           | More than 120 requests per minute for the key. Raise `EXDV_POLL_INTERVAL_SECONDS`; check that only one worker process uses the key.                                                                                             |
| Service in `failed` state, `start request repeated too quickly` | Start limit reached (usually invalid configuration). `journalctl -u exdomainvault-worker -o cat -n 50`, fix, `sudo systemctl reset-failed exdomainvault-worker`, start again.                                                   |
| `invalid_config` at start                                       | Read the `detail` field; run `exdv_run --check-config` after each fix.                                                                                                                                                          |
| `Failed to set up credentials` / status `243/CREDENTIALS`       | `/etc/exdomainvault/worker.key` is missing or unreadable by root.                                                                                                                                                               |
| DNS checks all time out                                         | `EXDV_DNS_RESOLVERS` points at a LAN address blocked by `IPAddressDeny=`; unset it or add it to `IPAddressAllow=`.                                                                                                              |

## 14. Security notes

- **Outbound only.** The worker opens no listening socket and needs no inbound firewall rule, port
  forward or Cloudflare Tunnel.
- **Two independent gates:** Cloudflare Access (service token) and the application's Ed25519 request
  signature. Either alone is insufficient.
- **Secrets stay on this host** in `/etc/exdomainvault` (root-owned; `worker.env` group-readable by
  the service account only for systemd's use). Never commit them, paste them into tickets, or log them.
- **No GitHub self-hosted runner** on this machine: it would run untrusted workflow code next to the
  worker's credentials and network position.
- **Active scanning is disabled.** The worker hard-codes `active_scanning_enabled = False` and the
  application refuses active profiles while `ACTIVE_SCANNING_ENABLED=false`. Only passive DNS and RDAP
  checks run until the Milestone 6 scope validator is complete and tested. When it is, Nmap is
  installed as an OS package and run unprivileged (TCP connect scans; no `CAP_NET_RAW`).
- Keep the OS and Python packages patched (`sudo apt upgrade`, then step 11 for Python dependencies).

## Alternative: container

`worker/Dockerfile` builds a non-root (uid 10001), multi-stage image with a read-only root file system
and a `HEALTHCHECK` using `--health`; the `docker run` command is in the file header. It is not the
documented deployment for this host (Docker is not installed and the systemd unit's egress filter and
credential handling have no direct equivalent there).
