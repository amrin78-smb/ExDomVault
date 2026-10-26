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
- Outbound HTTPS (TCP 443) to `crt.sh` for passive subdomain discovery (profile `discovery`,
  Milestone 9). This is the only new destination; nothing else about the host, firewall or systemd
  unit changes (crt.sh is a public address, so the unit's `IPAddressDeny=` list does not affect it).
- Nmap, only for the network-tier checks of the `standard`/`deep` profiles (`sudo apt install nmap`;
  this host has 7.94). It runs unprivileged as a TCP connect scan (no `CAP_NET_RAW`). Without it those
  checks fail with `nmap_unavailable`; passive and web checks are unaffected.

## Quick path: install script

`worker/deploy/install.sh` performs steps 2–4 and installs the units from step 9 (it does not start
the service). It is safe to re-run for upgrades and never overwrites an existing key or `worker.env` (so variables
added in later versions must be added to `worker.env` by hand, see step 11):

```bash
cd ~/development/Nocvault/ExDomVault && git pull
sudo bash worker/deploy/install.sh        # prints the public key to register
```

Then register the public key (step 5), fill in `EXDV_KEY_ID` and the service token with
`sudoedit /etc/exdomainvault/worker.env` (step 7), optionally dry-run (step 8), and
`sudo systemctl enable --now exdomainvault-worker` (step 9). The manual steps follow.

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
EXDV_ACCESS_CLIENT_ID=<Client ID from step 6>
EXDV_ACCESS_CLIENT_SECRET=<Client Secret from step 6>
EXDV_ENVIRONMENT=production
EXDV_POLL_INTERVAL_SECONDS=30
EXDV_PROFILES=passive,discovery
EXDV_LOG_LEVEL=INFO
EXDV_ACTIVE_SCANNING_ENABLED=false
#EXDV_DENY_NETWORKS=
```

`discovery` is passive (Certificate Transparency via crt.sh plus public DNS resolvers); drop it from
`EXDV_PROFILES` to stop this worker from running discovery jobs. `EXDV_ACTIVE_SCANNING_ENABLED` stays `false` (the default) until you deliberately enable active scanning
(step 15). Leave `EXDV_DNS_RESOLVERS` unset to query the public resolvers 1.1.1.1 and 9.9.9.9 (and their IPv6
addresses), so records are seen as the internet sees them. `system` uses the host's resolver
(`127.0.0.53`, systemd-resolved), which answers DS/DNSKEY queries with SERVFAIL. Write
the values without quotes or trailing comments: systemd's `EnvironmentFile=` parser is not a shell.
Do **not** set `EXDV_PRIVATE_KEY_FILE` here: the unit sets it to its `LoadCredential=` copy of the key,
and a value in `worker.env` would take precedence (systemd's `EnvironmentFile=` overrides
`Environment=`) and point at `/etc/exdomainvault`, which the service cannot read.

### IP geolocation (DB-IP Lite)

The worker adds the country of each A/AAAA answer to DNS observations (shown on the map and region
views; never used for scope decisions). It downloads DB-IP's free "IP to Country Lite" file
(`https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.csv.gz`, a few MB compressed) once a
month into `/var/lib/exdomainvault-worker/geoip/` (inside the unit's `StateDirectory=`, so no extra
permissions are needed) and keeps it in memory (about 15 MB). Outbound HTTPS to `download.db-ip.com`
must be allowed. If a download fails the previous file stays in use; with no file at all DNS
observations simply carry no country.

- **Attribution:** the data is licensed CC BY 4.0. Anything that displays it must credit
  **"IP geolocation by DB-IP"** with a link to https://db-ip.com (the application shows this next to
  the map).
- **Disable:** `EXDV_GEOIP_ENABLED=false` in `worker.env` (no download, no `geo` field). You can delete
  `/var/lib/exdomainvault-worker/geoip/` afterwards.
- **Custom location:** `EXDV_GEOIP_DIR=/absolute/path`. Under systemd anything outside
  `/var/lib/exdomainvault-worker` is read-only (`ProtectSystem=strict`); add it to `ReadWritePaths=` in
  a drop-in (`systemctl edit exdomainvault-worker`), owned by `exdomainvault-worker`, mode 0700.
- **Check:** `journalctl -u exdomainvault-worker -o cat | grep geoip` shows `geoip_downloaded` /
  `geoip_loaded` (or `geoip_download_failed` with the error class).

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
- **Egress filter:** `IPAddressDeny=` mirrors the application's prohibited-address table (loopback,
  RFC 1918 private, CGNAT, link-local, multicast, reserved, documentation, benchmarking, broadcast,
  IPv4-embedding IPv6 prefixes, ULA, site-local) plus all IPv6 outside `2000::/3`, except the resolver
  stub `127.0.0.53`. It applies to Nmap as well (same cgroup). The worker can reach the public internet
  but not the home LAN. If you set `EXDV_DNS_RESOLVERS` to a LAN resolver, add it to
  `IPAddressAllow=`. This is defence in depth; the scope validator remains the primary control. It
  does not cover the home's public IP — the worker's self-protection and `EXDV_DENY_NETWORKS` do
  (step 15).

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

The simplest path is the install script, which syncs the code, reinstalls the pinned dependencies and
the package, and reinstalls the unit files (it never touches the key or `worker.env`):

```bash
cd ~/development/Nocvault/ExDomVault && git pull
sudo bash worker/deploy/install.sh
exdv_run --check-config
sudo systemctl restart exdomainvault-worker
journalctl -u exdomainvault-worker -o cat -n 20 | jq .   # expect worker_started, no invalid_config
```

**Because `worker.env` is never overwritten, add variables introduced by a new version by hand**
(`sudoedit /etc/exdomainvault/worker.env`, compare with `worker/.env.example`). For the Milestone 6
upgrade these are:

```bash
EXDV_ACTIVE_SCANNING_ENABLED=false
#EXDV_DENY_NETWORKS=
```

Both are optional (the defaults are `false` and empty), so an upgrade without them keeps the worker
passive-only. Set them when enabling active scanning (step 15).

For the Milestone 9 upgrade (passive discovery), add `discovery` to the existing profile list, e.g.
`EXDV_PROFILES=passive,discovery` (or `passive,discovery,quick,standard` with active scanning). An
explicit `EXDV_PROFILES` without `discovery` means discovery jobs stay queued until another worker
claims them. The upgrade also needs outbound HTTPS to `crt.sh`.

**Application first.** When the new worker version goes with application changes that need a database
migration (Milestone 6: `0003_approved_networks`), the migration and application deploy come first
([`deployment.md`](deployment.md#milestone-6-scope-validator-and-active-checks)); the worker is
upgraded afterwards.

Manual equivalent of the script:

```bash
sudo rsync -a --delete --chown=root:root \
  --exclude '.venv/' --exclude '__pycache__/' --exclude '.pytest_cache/' --exclude '.ruff_cache/' \
  --exclude '*.key' --exclude '.env' --exclude 'tests/' \
  worker/ /opt/exdomainvault-worker/
sudo /opt/exdomainvault-worker/.venv/bin/pip install --no-cache-dir -r /opt/exdomainvault-worker/requirements.txt
sudo /opt/exdomainvault-worker/.venv/bin/pip install --no-cache-dir --no-deps --force-reinstall /opt/exdomainvault-worker
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

| Symptom                                                             | Likely cause and fix                                                                                                                                                                                                                                                                                                             |
| ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `401`, reason `timestamp_out_of_window`                             | Clock more than 300 s off. `timedatectl` must show _System clock synchronized: yes_; enable NTP with `sudo timedatectl set-ntp true`.                                                                                                                                                                                            |
| `401`, reason `unknown_key` / `bad_signature`                       | `EXDV_KEY_ID` does not match the key in `/etc/exdomainvault/worker.key`, or the wrong public key was registered. Re-derive the public key (step 4); if in doubt, register it again and use the new key id.                                                                                                                       |
| `401`, reason `key_revoked` / `key_expired` / `worker_disabled`     | Register a new key (step 12) or re-enable the worker in **Settings → Scanning workers**.                                                                                                                                                                                                                                         |
| `401`, reason `replayed_nonce`                                      | A request was re-sent with the same nonce. Should not happen (each retry is re-signed); report it as a bug.                                                                                                                                                                                                                      |
| `302` to `*.cloudflareaccess.com`, or `403` from Access             | Service token missing, wrong or expired, or no **Service Auth** policy includes it. Check `EXDV_ACCESS_CLIENT_*` and step 6; test with the `curl` check in step 6.3. The worker does not follow redirects and reports an error.                                                                                                  |
| `409` on heartbeat/results                                          | The job lease was lost (expired or reassigned), or (results only) the job is no longer authorised for active checks — kill switch off, domain revoked or lapsed. The worker stops that job without reporting further. Frequent lease `409`s mean the host is stalling or was suspended.                                          |
| Targets fail with `egress_ip_unknown`                               | Self-protection could not detect the public IPv4 (`self_protection_refreshed` with `egressDetected: false` in the journal) and `EXDV_DENY_NETWORKS` is empty. Check outbound DNS to 1.1.1.1, or set `EXDV_DENY_NETWORKS` (step 15).                                                                                              |
| Port checks fail with `nmap_unavailable`                            | Nmap is not installed at `EXDV_NMAP_PATH` (default `/usr/bin/nmap`): `sudo apt install nmap`.                                                                                                                                                                                                                                    |
| Port checks refused (`network_not_approved` / `no_allowed_address`) | The target's addresses are not inside an approved network. Approve the range in **Settings → Approved networks**, then request a new scan.                                                                                                                                                                                       |
| `invalid_config` mentioning `EXDV_DENY_NETWORKS`                    | Each entry must be a canonical CIDR with host bits zero (`203.0.113.7/32`, `2001:db8:1:2::/64`) or a single address; at most 100.                                                                                                                                                                                                |
| `429`                                                               | More than 120 requests per minute for the key. Raise `EXDV_POLL_INTERVAL_SECONDS`; check that only one worker process uses the key.                                                                                                                                                                                              |
| Service in `failed` state, `start request repeated too quickly`     | Start limit reached (usually invalid configuration). `journalctl -u exdomainvault-worker -o cat -n 50`, fix, `sudo systemctl reset-failed exdomainvault-worker`, start again.                                                                                                                                                    |
| `invalid_config` at start                                           | Read the `detail` field; run `exdv_run --check-config` after each fix.                                                                                                                                                                                                                                                           |
| `Failed to set up credentials` / status `243/CREDENTIALS`           | `/etc/exdomainvault/worker.key` is missing or unreadable by root.                                                                                                                                                                                                                                                                |
| Discovery jobs fail with `discovery_provider_unavailable`           | crt.sh timed out, rate-limited (429) or returned 5xx; the application retries with backoff. Persistent failures: check outbound HTTPS to `crt.sh` (`curl -sI https://crt.sh/`); crt.sh is often slow for very large domains.                                                                                                     |
| Discovery target `failed` with `discovery_provider_error`           | crt.sh returned something other than JSON (HTML error page, redirect, 4xx). The `discovery` observation's `evidence.errorClass` says which; the next scheduled run retries.                                                                                                                                                      |
| `geoip_download_failed` / no countries on the map                   | Outbound HTTPS to `download.db-ip.com` blocked, or the month's file not yet published (the worker falls back to the previous month on `404`, retries after 6 h otherwise). `error: unexpected_redirect` means db-ip.com answered with a redirect, which the worker never follows. Set `EXDV_GEOIP_ENABLED=false` to turn it off. |
| DNS checks all time out                                             | `EXDV_DNS_RESOLVERS` points at a LAN address blocked by `IPAddressDeny=`; unset it or add it to `IPAddressAllow=`.                                                                                                                                                                                                               |

## 14. Security notes

- **Outbound only.** The worker opens no listening socket and needs no inbound firewall rule, port
  forward or Cloudflare Tunnel.
- **Two independent gates:** Cloudflare Access (service token) and the application's Ed25519 request
  signature. Either alone is insufficient.
- **Secrets stay on this host** in `/etc/exdomainvault` (root-owned; `worker.env` group-readable by
  the service account only for systemd's use). Never commit them, paste them into tickets, or log them.
- **No GitHub self-hosted runner** on this machine: it would run untrusted workflow code next to the
  worker's credentials and network position.
- **Active scanning is off by default.** The worker runs active checks only with
  `EXDV_ACTIVE_SCANNING_ENABLED=true`, and the application refuses active profiles while its own
  `ACTIVE_SCANNING_ENABLED` is `false` (both ship `false`). Until both are switched on only passive DNS,
  RDAP and Certificate Transparency discovery checks run. Nmap runs unprivileged (TCP connect scans; no `CAP_NET_RAW`).
- Keep the OS and Python packages patched (`sudo apt upgrade`, then step 11 for Python dependencies).

## 15. Enabling active scanning

Only after the owner has decided to enable it and the application side is ready (migration
`0003_approved_networks` applied, Milestone 6 deployed, server `ACTIVE_SCANNING_ENABLED` set to
`"true"` — see [`deployment.md`](deployment.md#enabling-active-scanning)). Both switches must be on;
either one off stops active checks.

1. **Install Nmap** (for `standard`/`deep` port checks): `sudo apt install nmap`.
2. **Find the home's public addresses.** The worker detects them itself (below), but list them
   explicitly so there is no gap:

   ```bash
   dig +short TXT CH whoami.cloudflare @1.1.1.1              # public IPv4, e.g. "203.0.113.7"
   dig +short TXT CH whoami.cloudflare @2606:4700:4700::1111 # public IPv6 (if the host has IPv6)
   ip -6 addr show scope global                              # global IPv6 addresses and their prefix
   ```

   Use the IPv4 as `/32` and the IPv6 prefix as `/64` with the host bits zero (for
   `2001:db8:1234:5678:a:b:c:d` that is `2001:db8:1234:5678::/64`).

3. **Edit `worker.env`** (`sudoedit /etc/exdomainvault/worker.env`):

   ```bash
   EXDV_ACTIVE_SCANNING_ENABLED=true
   EXDV_PROFILES=passive,discovery,quick,standard
   EXDV_DENY_NETWORKS=203.0.113.7/32,2001:db8:1234:5678::/64
   ```

   Add `deep` to `EXDV_PROFILES` only if wanted. Optional: `EXDV_NMAP_PATH` (default `/usr/bin/nmap`).

4. `exdv_run --check-config`, then `sudo systemctl restart exdomainvault-worker` (the switch is read at
   start-up).
5. **Check self-protection** in the journal:

   ```bash
   journalctl -u exdomainvault-worker -o cat | jq 'select(.message == "self_protection_refreshed")'
   ```

   Expect `egressDetected: true`, the interface networks and the egress address, and
   `failClosed: false`.

6. In the application (administrator): approve the organisation's own server ranges in **Settings →
   Approved networks** before requesting `standard`/`deep` scans — port probes only reach approved
   networks, and a job snapshots the approvals active when it is created.

**How self-protection works.** While `EXDV_ACTIVE_SCANNING_ENABLED=true`, at start-up and then hourly
the worker adds every local interface address (global IPv6 as its /64) and the public egress address
(the `whoami.cloudflare` query above, sent to Cloudflare's resolver) to every active job's deny list,
on top of `EXDV_DENY_NETWORKS`. If the IPv4 egress address cannot be detected **and**
`EXDV_DENY_NETWORKS` is empty, web and network checks fail closed with `egress_ip_unknown` (passive
checks still run). Detection counts IPv4 only, so **an IPv6-only host must set `EXDV_DENY_NETWORKS`**.
Update the list when the ISP changes the address; a dynamic address is still detected within an hour.

**Turning it off:** set `EXDV_ACTIVE_SCANNING_ENABLED=false` and restart (the running job's lease
expires and it is retried; the worker then refuses active jobs), or have the application's switch
turned off, which stops running active jobs at their next heartbeat.

## Alternative: container

`worker/Dockerfile` builds a non-root (uid 10001), multi-stage image with a read-only root file system
and a `HEALTHCHECK` using `--health`; the `docker run` command is in the file header. It is not the
documented deployment for this host (Docker is not installed and the systemd unit's egress filter and
credential handling have no direct equivalent there).
