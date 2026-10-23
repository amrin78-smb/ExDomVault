# Troubleshooting

Symptom → cause → fix, collected from real issues in this project. Worker authentication and scan
errors have their own detailed table in [home-worker-setup.md §13](home-worker-setup.md#13-troubleshooting);
this page covers the rest and the cross-cutting cases.

Where to look first:

- **App/API:** Workers Logs (dashboard → **Workers & Pages → exdomainvault → Observability**) or live
  `cd apps/web && npx wrangler tail --format pretty`. Every API error response carries a `requestId`;
  search the logs for it.
- **Scan host:** `journalctl -u exdomainvault-worker -o cat -n 50 | jq .`
- **In the app:** **Settings → System health** (administrators).

## Scan host and worker

### Worker exits with `invalid_config` after editing `worker.env`

**Symptom:** the service fails to start; the journal shows
`{"level":"ERROR","message":"invalid_config","detail":"EXDV_KEY_ID is required"}` (or another
variable) although the variable "is in the file".

**Cause (seen 2026-10):** a stray character typed into the variable name while editing —
`SEXDV_KEY_ID=…` or `.EXDV_KEY_ID=…` instead of `EXDV_KEY_ID=…`. systemd's `EnvironmentFile=` sets
`SEXDV_KEY_ID` (or ignores the invalid `.EXDV_…` name), so the real variable is missing. Quotes,
trailing comments and spaces around `=` cause similar surprises: the file is not parsed by a shell.

**Fix:**

```bash
sudo grep -nvE '^(#|$|EXDV_[A-Z0-9_]+=)' /etc/exdomainvault/worker.env   # lines that are not comments or EXDV_* assignments
sudoedit /etc/exdomainvault/worker.env
exdv_run --check-config                                                  # helper from home-worker-setup.md §8
sudo systemctl reset-failed exdomainvault-worker && sudo systemctl start exdomainvault-worker
```

The `detail` field always names the variable; `--check-config` exits 0 when the configuration is
valid.

### Service `failed` with `start request repeated too quickly`

**Cause:** systemd's start limit — after 5 failed starts in 10 minutes it stops retrying
(`Restart=on-failure`, 30 s delay). Usually an invalid configuration (above) or a missing key.

**Fix:** find the real error first (`journalctl -u exdomainvault-worker -o cat -n 50 | jq .`), fix it,
then `sudo systemctl reset-failed exdomainvault-worker` and `sudo systemctl start exdomainvault-worker`.
`systemctl restart` alone is refused until the failed state is reset.

### `EXDV_PRIVATE_KEY_FILE` errors / `LoadCredential` permissions

| Symptom                                                                                                                          | Cause                                                                                                                                                                                                         | Fix                                                                                                                                                                                                                       |
| -------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `invalid_config` "must not be readable or writable by group or others (chmod 600)" on the first start under systemd (2026-10-22) | systemd's `LoadCredential=` copy is `0440` inside the per-service credentials directory; the first worker version required `0600` everywhere                                                                  | Fixed in the worker (`f2c57c5`): inside `$CREDENTIALS_DIRECTORY` the directory and file must be closed to others ("credential must not be accessible by others"); elsewhere `0600` is still required. Upgrade the worker. |
| `invalid_config` "EXDV_PRIVATE_KEY_FILE does not exist or cannot be accessed"                                                    | `EXDV_PRIVATE_KEY_FILE` is set in `worker.env` (e.g. copied from `.env.example`). `EnvironmentFile=` overrides the unit's `Environment=`, so it points at `/etc/exdomainvault`, which the service cannot read | Delete the line from `/etc/exdomainvault/worker.env`; the unit sets it to the credential copy                                                                                                                             |
| Status `243/CREDENTIALS`, `Failed to set up credentials`                                                                         | `/etc/exdomainvault/worker.key` missing or unreadable by root                                                                                                                                                 | Recreate/restore the key file (`0600 root:root`); a new key must be registered (home-worker-setup.md §4–5)                                                                                                                |
| `invalid_config` "… must not be readable or writable by group or others (chmod 600)" on a manual run                             | key file mode too open outside the credentials directory                                                                                                                                                      | `sudo chmod 600 /etc/exdomainvault/worker.key`; run manual checks through `exdv_run` (home-worker-setup.md §8), which uses `LoadCredential=`                                                                              |

### Worker gets `302` to `*.cloudflareaccess.com` / `403`

Service token missing, wrong, expired, or not in a **Service Auth** policy. Test with the `curl -K -`
check in [home-worker-setup.md §6.3](home-worker-setup.md#6-create-the-cloudflare-access-service-token).
Then the Ed25519 layer: `401` reasons are in the app's logs as `worker_auth_failed` (§13 there).

### Discovery is slow or fails: crt.sh

**Symptom:** discovery jobs take minutes, end `failed` with `discovery_provider_unavailable`, or
targets `failed` with `discovery_provider_error`; **System health** lists these codes.

**Cause:** crt.sh (the only Certificate Transparency provider) is a free public service that is often
slow, times out or returns 429/5xx or an HTML error page, especially for domains with many
certificates. The worker waits ≥ 3 s between requests and caps responses at 32 MB (larger ones are
parsed incrementally and marked `partial`).

**Fix:** usually nothing — transient failures are retried with backoff (3 attempts) and the weekly
schedule tries again. If it persists: `curl -sI https://crt.sh/` from the scan host; check that
`discovery` is in `EXDV_PROFILES`. Do not raise request rates: crt.sh rate-limits aggressive clients.
A failed discovery never removes or changes existing assets.

### Feeds: NVD rate limit

**Symptom:** **Settings → Intelligence feeds** shows NVD with `rate_limited`, or KEV CVEs stay
"pending" for a long time; possibly the `feeds_stale` banner.

**Cause:** NVD allows 5 requests / 30 s without a key (50 with one). The Cron syncs 5 CVEs per run
without a key, 20 with `NVD_API_KEY`; a `rate_limited` answer stops that run's batch without
penalising the CVE.

**Fix:** set the key (`cd apps/web && npx wrangler secret put NVD_API_KEY`; set in production
2026-10-23). If it is set and still rate-limited, check that the key is valid (NVD revokes unused keys)
and that nothing else uses it. NVD catches up over the following cron runs.

## Application (Cloudflare Worker)

### `503` / error 1102 "Worker exceeded resource limits"

**Cause (seen 2026-10-22):** on the Workers **Free** plan each request has 10 ms of CPU; with 339
monitored domains, result uploads and some page loads exceeded it (`exceededCpu` in the logs) and were
retried. **Fix:** the account moved to **Workers Paid** on 2026-10-23 (30 s CPU default). If it
recurs, check the plan, then the request in Workers Logs (`cpuTime`); bulk endpoints are set-based to
keep CPU low.

### Data looks stale for about a minute after a change

**Cause (seen 2026-10-22):** Hyperdrive **query caching** served cached `SELECT` results for up to 60 s
— including the authorisation and kill-switch re-checks the worker API relies on.

**Fix:** caching is disabled on `exdomainvault-db`; if a new Hyperdrive config is created, disable it
again: `npx wrangler hyperdrive update <id> --caching-disabled`. Check with
`npx wrangler hyperdrive get <id>`.

### API calls fail with "The API could not be reached" / Access `302`

**Cause:** the Cloudflare Access session (24 h) expired. Access answers API requests with a `302` to
the login page on `*.cloudflareaccess.com`; the browser's `fetch` follows it cross-origin and fails,
so the UI reports a network error rather than a sign-in prompt. The same happens for `curl` or scripts
without an Access token.

**Fix:** reload the page (Access signs you in again). For scripts, use the browser console on the
signed-in app, or a service token (which works only on `/api/v1/internal/worker/*` and `/api/v1/health`;
user routes reject service tokens with `401`).

### CSV export says "The export did not return a CSV file"

**Cause:** same as above — the session expired, so the export request received the Access login page
(HTML) instead of a CSV. The UI checks the content type and refuses to save the HTML as a CSV.

**Fix:** reload the page to sign in again, then export. If the message is "truncated", the export hit
its 5000-row limit (`X-Truncated`): narrow the filters.

### `429 rate_limited`

A per-user request limit or a scan quota was hit ([operations.md](operations.md#rate-limits-and-scan-quotas)).
The response's `Retry-After` says when to retry. Scheduled jobs are not affected.

### Protected routes return `503`, health shows `auth: not_configured`

`ACCESS_TEAM_DOMAIN` or `ACCESS_AUD` is empty in `wrangler.jsonc` (fail closed). Restore the values
([deployment.md](deployment.md#authentication-cloudflare-access)) and deploy.

### Signed in but `403` everywhere

Access let the person through but they are not an active user in ExDomainVault. Add them in
**Settings → Users** (or reactivate). Deactivated users are refused on every request.

## Database and local development

### Local dev: `database: down` / connection errors after a week

**Cause:** the Neon `dev` branch expires 7 days after creation (`neon.ts` policy) and is deleted.

**Fix:**

```bash
neon checkout dev --create      # recreate from production's current state and write .env.local
npm run db:migrate              # apply any migrations newer than production
```

Check the expiry with `neon branches list` (`Expires At` column).

### `npm run db:migrate` refuses to run

| Message                                                                                   | Cause                                                                         | Fix                                                                                                                                                  |
| ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Refusing to migrate through a pooled (-pooler) endpoint; use the direct URL.`            | `MIGRATION_DATABASE_URL` / `DATABASE_URL_UNPOOLED` contains a `-pooler.` host | Use the direct URL: `neon env pull` writes `DATABASE_URL_UNPOOLED`; don't point it at `DATABASE_URL`                                                 |
| `Refusing to migrate the production branch. Re-run with ALLOW_PRODUCTION_MIGRATION=yes …` | `.neon` has `production` checked out (`NEON_BRANCH=production`)               | Intended guard. For dev: `neon checkout dev`. For production: only with the owner's approval ([deployment.md](deployment.md#2-migrating-production)) |
| `No MIGRATION_DATABASE_URL or DATABASE_URL_UNPOOLED. Run neon env pull first.`            | `.env.local` missing                                                          | `neon checkout dev` or `neon env pull`                                                                                                               |

### Tests crash the machine / get killed

Full Vitest runs use PGlite per file and are capped at 2 workers; running two full suites at once (e.g.
several agents or terminals) exhausts memory on the scan host. Run one suite at a time, or a single
project (`npx vitest run --project shared`).

## CI

| Failure                                   | Fix                                                                                                                                                                                    |
| ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| "package-lock.json changed after install" | `package.json` and the lockfile disagree. Run `npm install`, commit `package-lock.json`.                                                                                               |
| `npm audit` (Security)                    | Upgrade the affected package if a fix ≥ 14 days old exists (`npm audit` shows the path); otherwise document it in `docs/progress.md`.                                                  |
| `pip-audit` (Security)                    | Bump the pin in `worker/requirements*.txt` if the fix is ≥ 14 days old; otherwise add a dated entry to `.github/audit/pip-audit-exceptions.txt`. An expired exception fails by design. |
| gitleaks                                  | A secret was committed: **rotate it first** (it is public once pushed), then remove it. Only genuinely public values go in `.gitleaks.toml`.                                           |
| "Schema and migrations are in sync"       | Run `npm run db:generate` and commit the new migration.                                                                                                                                |
