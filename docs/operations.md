# Operations

Running ExDomainVault day to day: what to check, how alerts reach the owner, retention, rate limits,
worker outages, key rotation and patching the scan host. Deployment and rollback are in
[deployment.md](deployment.md), restores in [backup-restore.md](backup-restore.md), symptom-driven
fixes in [troubleshooting.md](troubleshooting.md).

## Daily and weekly checks

**Daily (2 minutes, in the app)**

- The **alert banner** at the top of every page (`GET /api/v1/ops/alerts`). It appears only when
  something needs attention: `worker_outage` (critical), `feeds_stale` (warning: an intelligence feed
  has not updated for over 3 days), `active_scanning_disabled` (warning: scheduled active scans are on
  but the server switch is off). Administrators see the details; other users see only that scans or
  intelligence are delayed.
- **Settings → System health** (administrators, `settings:manage`; `GET /api/v1/ops/health`):
  - **Workers**: each registered worker `online` (seen ≤ 5 min), `stale` (≤ 30 min), `offline` or
    `never_seen`, with version.
  - **Queue**: queued and running jobs per profile, age of the oldest queued job. A growing oldest
    age with an `online` worker means the worker is busy (large discovery runs) or not claiming that
    profile (`EXDV_PROFILES`).
  - **Scans**: last 24 h / 7 days succeeded, failed, cancelled, success rate, p50/p95 duration.
  - **Failures by code** (last 24 h): the most frequent job/target error codes — look these up in
    [troubleshooting.md](troubleshooting.md) and [home-worker-setup.md §13](home-worker-setup.md#13-troubleshooting).
  - **Database** reachability and latency, **feeds** status, **retention** last run and rows deleted.
- **Overview**: new critical/high findings.

**Weekly (15 minutes)**

- GitHub: the **Security** workflow's Monday run is green; review open Dependabot PRs (grouped,
  weekly) and merge only after CI passes ([Security checks](#security-checks)).
- Scan host: `systemctl --failed`, `journalctl -u exdomainvault-worker --since -7d -p warning -o cat | jq -c . | tail`,
  disk space (`df -h /`), pending updates ([OS patching](#os-patching-of-the-scan-host)).
- Workers Logs (dashboard → **Workers & Pages → exdomainvault → Observability**, retained 7 days on
  Workers Paid): filter for `maintenance_step_failed`, `retention_step_failed`, `rate_limited`,
  `rate_limiter_unavailable`, `worker_auth_failed`.
- **Settings → Scanning workers**: key and service-token expiry dates (rotate ≥ 30 days before).
- **Settings → Audit log**: unexpected privileged actions (user changes, scope approvals, policy
  changes).

**Monthly**: the [tested-restore drill](backup-restore.md#tested-restore-drill); review accepted
risks due (Reports page) and approved networks' review dates.

## Alerting on worker outage

The Cron Trigger (every 5 minutes) detects a **persistent worker outage**: no active worker seen for
30 minutes (`WORKER_OFFLINE_AFTER_SECONDS`) **while jobs are queued**. It logs each transition exactly
once (the state row is locked, so concurrent cron runs cannot double-log):

```json
{"level":"error","message":"worker_outage_started","alert":"worker_outage","since":"…","queuedJobs":12,"lastSeenAt":"…"}
{"level":"info","message":"worker_outage_ended","alert":"worker_outage","since":"…","durationSeconds":5400,"lastSeenAt":"…"}
```

The in-app banner shows the outage while it lasts. To be told when you are not looking at the app, set
up a Cloudflare alert on that log line. Checked against Cloudflare's documentation on 2026-10-23:

### Option 1 (recommended): Cloudflare Monitors on Workers Logs

Cloudflare **Alerts → Monitors** (beta, announced 2026-10-02) run a query on a schedule and notify
email, webhook or PagerDuty. Workers Logs are available as a dataset for Workers with
observability enabled (`"observability": { "enabled": true }` is set in `wrangler.jsonc`).

1. Cloudflare dashboard → **Alerts** (under Observability) → **Monitors** → **Create a Monitor**.
2. Detection method: **Threshold**.
3. Query (visual builder): dataset **Workers Logs**; filter Worker (script) = `exdomainvault` and the
   log's `message` field = `worker_outage_started` (Workers Logs indexes the fields of JSON log
   lines; pick the field names the builder offers). Aggregate: **count**.
4. Condition: count **> 0**; evaluation interval 5–10 minutes (the cron runs every 5).
5. Name `ExDomainVault worker outage`; destination: **Email** to the owner (all plans).
6. **Create**. Optional second monitor on `worker_outage_ended` (info) to be told of recovery.

Because Monitors are in beta and their dataset field names are not fully documented yet, **test the
monitor once**: stop the worker during a time when jobs are queued
(`sudo systemctl stop exdomainvault-worker`), wait ~35 minutes for the `worker_outage_started` line,
confirm the email, then start the worker again and watch for `worker_outage_ended`.

Useful additional monitors from the same dataset: count of `maintenance_step_failed` > 0 over 1 hour
(warning), and Cloudflare's built-in Workers platform notifications (errors / CPU exceeded) under
**Alerts → Platform notifications**.

### Option 2: Tail Worker or Logpush

If Monitors are unavailable on the account: a **Tail Worker** receives every log event of
`exdomainvault` and can POST matching lines to a webhook (ntfy, Slack, email relay), or **Workers
Logpush** ships logs to storage/a SIEM that alerts. Both are more moving parts and are not set up.

### On the scan host

The worker's own view, independent of Cloudflare:

```bash
systemctl status exdomainvault-worker                        # active (running)?
journalctl -u exdomainvault-worker -f -o cat | jq .          # live JSON logs
journalctl -u exdomainvault-worker --since -1h -p warning -o cat | jq -c .
systemctl list-timers exdomainvault-worker-health.timer      # health timer (every 5 min)
systemctl status exdomainvault-worker-health.service         # last --health result
systemctl --failed                                            # a failing health check shows here
```

The optional health timer ([home-worker-setup.md §9](home-worker-setup.md#9-install-and-enable-the-service))
runs `exdomainvault-worker --health` every 5 minutes: it exits 1 when the health file shows no recent
successful poll, which marks `exdomainvault-worker-health.service` failed. Nothing sends that
anywhere yet; it is for `systemctl --failed` and the journal.

## Worker outage and recovery

What happens while the worker is down:

- Jobs stay `queued` in PostgreSQL; schedulers keep adding passive/discovery jobs (one queued/active
  job per domain and profile, so they do not pile up per domain).
- Jobs the worker held keep their lease until it expires; the Cron's **lease reaper** then requeues
  them with backoff (60 s × 2^(attempt−1), capped at 30 min) up to **3 attempts**. A job that hits the
  ceiling ends `failed` — and **a failed or incomplete scan never resolves findings**.
- After 30 minutes without a worker and with queued jobs, the outage alert fires.

Recovery:

```bash
journalctl -u exdomainvault-worker -o cat -n 50 | jq .       # why did it stop?
sudo systemctl reset-failed exdomainvault-worker             # if the start limit was hit
sudo systemctl start exdomainvault-worker
journalctl -u exdomainvault-worker -o cat -n 20 | jq .       # expect worker_started, then claims
```

Within one poll interval the worker claims queued jobs again; **Settings → System health** shows it
`online`, the queue draining and, at the next cron run, `worker_outage_ended` is logged and the
banner disappears. Jobs that failed after three attempts are not retried automatically; re-request
them from the domain page (or wait for the next scheduled run).

Planned maintenance (OS updates, reboots): `sudo systemctl stop exdomainvault-worker` is safe at any
time — SIGTERM stops claiming and the current job's lease expires and is retried. A stop shorter than
30 minutes raises no alert.

**Stopping all scanning quickly:** stop the worker (everything) or set `ACTIVE_SCANNING_ENABLED`
to `"false"` and deploy (active scans only; running ones stop at the next heartbeat).

## Retention policy

`RETENTION_POLICY` in `packages/shared/src/api/ops.ts`, applied by the Cron Trigger at most hourly in
bounded batches (5000 rows per table per run; a run that hits the limit continues on the next tick).
Each table is failure-isolated (`retention_step_failed` in the logs); the outcome is shown in
**Settings → System health**.

| Data                                                          | Kept                                                                                                                                                                                                                                                                                        |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Observations (DNS, registration, TLS, HTTP, port, discovery)  | **180 days**, except the latest successful and the latest observation of any status per key (DNS name+type, registration per domain, TLS host+IP+port, HTTP URL, port IP+port, discovery hostname+source per domain) — kept indefinitely so change detection and current views keep working |
| Finished scan jobs (with their targets and results)           | **365 days**                                                                                                                                                                                                                                                                                |
| Audit log, findings, finding status history, finding comments | **forever** (never deleted; append-only for the app role)                                                                                                                                                                                                                                   |
| Worker request nonces                                         | pruned after the 300 s signature window                                                                                                                                                                                                                                                     |
| Workers Logs (Cloudflare)                                     | 7 days (Workers Paid)                                                                                                                                                                                                                                                                       |
| Neon history                                                  | 6 hours (Free plan; [backup-restore.md](backup-restore.md))                                                                                                                                                                                                                                 |

Changing the policy is a code change (shared constant + tests), reviewed and deployed like any other.

## Rate limits and scan quotas

`RATE_LIMITS` in `packages/shared/src/api/ops.ts`. Exceeding one returns `429` with error code
`rate_limited` and a `Retry-After` header; the UI shows the message.

| Limit                               | Value     | Mechanism                                                                                                 |
| ----------------------------------- | --------- | --------------------------------------------------------------------------------------------------------- |
| API requests per user               | 300 / min | Workers Rate Limiting binding `API_RATE_LIMITER`, keyed by user id; approximate (per Cloudflare location) |
| Mutating requests per user          | 60 / min  | binding `MUTATION_RATE_LIMITER`                                                                           |
| Scans a user requests               | 60 / hour | exact count in PostgreSQL at job creation (manual, re-check and discovery requests)                       |
| Requested active scans per domain   | 24 / day  | exact count, all users                                                                                    |
| Requested discovery runs per domain | 6 / day   | exact count, all users                                                                                    |

Scheduled (system) jobs do not count toward the quotas. The request limiters **degrade open**: if a
binding is missing or errors, the request passes and `rate_limiter_unavailable` is logged (Access still
fronts every request) — a recurring warning means the binding needs fixing. Worker requests have their
own limit: 120 signed requests per minute per key.

## Security checks

Automated in GitHub Actions (`.github/workflows/security.yml`), on every push to `main`, every pull
request, weekly (Monday 03:17 UTC) and on demand (**Actions → Security → Run workflow**):

| Check       | Fails when                                                                                                                                                                                                             |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `npm audit` | a **high or critical** advisory affects a production dependency (`--omit=dev`), or a **critical** one affects any dependency incl. build/test tooling. The full report (all severities) is printed for review.         |
| `pip-audit` | any known vulnerability in `worker/requirements.txt` or `requirements-dev.txt`, except unexpired, documented entries in `.github/audit/pip-audit-exceptions.txt` (each has an expiry date, after which it fails again) |
| gitleaks    | a secret pattern anywhere in the git history (allowlist: `.gitleaks.toml`, only the public Access AUD tag)                                                                                                             |

Dev dependencies are treated differently because they never run in the deployed Worker (npm `--omit=dev`
is what ships), but they do run in CI and on the dev machine and the build tooling produces the
bundle — hence the critical threshold rather than none. `ci.yml` also fails if `package-lock.json`
changes after `npm install --package-lock-only` (lockfile drift).

Locally: `npm run audit:npm` and `npm run worker:audit` (creates `worker/.venv-audit` with the pinned
`pip-audit`; needs network access to PyPI/OSV).

Dependabot (`.github/dependabot.yml`) opens grouped weekly PRs for npm, pip (`worker/`) and GitHub
Actions, with a 14-day **cooldown** matching the project rule that releases must be at least 14 days
old. TypeScript majors are ignored (pinned to `~6.0`). Actions are pinned to full commit SHAs with the
version in a comment; Dependabot updates both.

Fixing an advisory: upgrade the pinned version if the fix release is ≥ 14 days old; otherwise add a
time-boxed exception (pip) or document it in `docs/progress.md` (npm) and upgrade when eligible.

## Rotating keys

| What                         | When                                      | How                                                                                                            |
| ---------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Worker Ed25519 key           | before expiry (365 days), or on suspicion | [home-worker-setup.md §12](home-worker-setup.md#12-credential-rotation): new key, register, switch, revoke old |
| Access service token         | before its expiry date                    | same section: second token on the Service Auth policy, switch, delete old                                      |
| `exdomainvault_app` password | yearly / on suspicion                     | [deployment.md → Secrets](deployment.md#secrets-inventory-and-rotation)                                        |
| `NVD_API_KEY`                | on suspicion                              | `npx wrangler secret put NVD_API_KEY`                                                                          |
| Neon owner password          | on suspicion                              | Neon console → Roles, then `neon env pull`                                                                     |

On suspected compromise of the scan host: **Disable** the worker in **Settings → Scanning workers**
(stops all its requests at once), remove the service token from the Access policy, then rebuild and
re-register.

## OS patching of the scan host

The scan host runs Ubuntu 24.04-based Zorin OS with `unattended-upgrades` installed and enabled.

```bash
systemctl is-enabled unattended-upgrades          # enabled
sudo unattended-upgrade --dry-run --debug | tail  # what would be installed
cat /var/log/unattended-upgrades/unattended-upgrades.log | tail
sudo apt update && apt list --upgradable          # weekly manual review
```

- Security updates from the `noble-security` pocket install automatically. Check
  `/etc/apt/apt.conf.d/50unattended-upgrades` for `Unattended-Upgrade::Automatic-Reboot`; if reboots
  are not automatic, reboot after kernel/libc/OpenSSL updates (`/var/run/reboot-required` exists).
  The worker unit is enabled, so it starts after a reboot; jobs held during the reboot are retried.
- **Nmap** comes from Ubuntu **universe** (`7.94+git20230807…`). Universe security fixes for 24.04
  are published through Ubuntu Pro's `esm-apps`, which is not attached on this host — so Nmap
  security updates are not guaranteed. Options: attach Ubuntu Pro (free for personal use) with
  `sudo pro attach`, or follow Nmap advisories and update manually. Nmap runs unprivileged inside the
  sandboxed unit (TCP connect only), which limits the impact of a parser bug.
- **Python**: the worker's venv uses the system `python3.12` (patched by apt) and the pinned packages
  in `worker/requirements.txt` (patched by Dependabot PRs → `git pull && sudo bash worker/deploy/install.sh`
  → restart, [home-worker-setup.md §11](home-worker-setup.md#11-upgrade-and-restart)). After a Python
  minor-version upgrade, recreate the venv.
- Keep the clock synchronised (`timedatectl`): signatures are rejected beyond ±300 s.
