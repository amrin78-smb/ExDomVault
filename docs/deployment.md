# Deployment

Covers only what is implemented. Nothing in this repository deploys automatically: CI
(`.github/workflows/`) runs checks only and holds no Cloudflare or Neon credentials. Deploying,
migrating `production` and changing Cloudflare/Neon account settings are owner actions; Claude does
them only with the owner's explicit approval.

Related: [operations.md](operations.md) (daily running, alerts, retention),
[backup-restore.md](backup-restore.md) (Neon restore and the tested-restore drill),
[troubleshooting.md](troubleshooting.md), [home-worker-setup.md](home-worker-setup.md) (scan host).

## Current production state (2026-10-23)

| Item               | Value                                                                                                                                            |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| URL                | https://exdomainvault.amrin78.workers.dev (Worker `exdomainvault`, `workers_dev` on, preview URLs off)                                           |
| Cloudflare account | `a2c0616cdf9b25972e26618151f392f7`, **Workers Paid (Standard)** since 2026-10-23                                                                 |
| Access             | Worker → **Access** tab, scope _All traffic_; policy `demo-allowlist` (Allow: owner email) + Service Auth policy (`exdomainvault-home-worker`)   |
| Access team domain | `fragrant-grass-4d8f.cloudflareaccess.com`                                                                                                       |
| Hyperdrive         | `exdomainvault-db` (`c43bce859dcd405c9aaca22897818529`) → Neon `production` direct endpoint, **query caching disabled**                          |
| Database role      | `exdomainvault_app` (least privilege, see below)                                                                                                 |
| Neon `production`  | migrated through `0007_software_intel` (8 migrations)                                                                                            |
| Neon plan          | **Free**: history (point-in-time restore) window 6 hours, 1 manual snapshot, no scheduled snapshots — see [backup-restore.md](backup-restore.md) |
| Worker secrets     | `BOOTSTRAP_ADMIN_EMAILS`, `NVD_API_KEY`                                                                                                          |
| Deployed version   | `36d3d0c3-4604-45e1-90e9-b7903b20916c` (scheduled active scans, 2026-10-23); Cron `*/5 * * * *`                                                  |
| Active scanning    | `ACTIVE_SCANNING_ENABLED = "true"` in `wrangler.jsonc` (owner, 2026-10-22)                                                                       |
| Home worker        | `home-worker-01` under systemd on the home host ([home-worker-setup.md](home-worker-setup.md))                                                   |

Milestone 12 (production hardening) is **not deployed yet**; see [Milestone 12 deploy notes](#milestone-12-deploy-notes).

`demo-allowlist` is a reusable Access policy shared with another app; anyone added to it can also reach
ExDomainVault (but gets 403 from the API unless provisioned in `users`). Consider a dedicated policy.

## Deployment checklist

Copy this list into the change record for every production deploy. Every step is an owner action
or needs the owner's approval.

**Before**

- [ ] `git status` clean, on `main`, pulled; CI (**CI** and **Security** workflows) green for the commit.
- [ ] Local checks pass: `npm ci && npm run lint && npm run typecheck && npm test && npm run build`
      (and `npm run worker:lint && npm run worker:test` if `worker/` changed).
- [ ] Read the commits since the deployed version (`git log <deployed-commit>..HEAD`) and
      `docs/progress.md` for required migrations, new bindings, new secrets and worker upgrades.
- [ ] Note the currently deployed version id (`npx wrangler deployments status`) — this is the
      rollback target.
- [ ] If a migration is pending: applied and verified on Neon `dev` first; a pre-migration Neon
      snapshot or restore timestamp recorded ([backup-restore.md](backup-restore.md#before-a-production-migration)).
- [ ] New secrets set (`wrangler secret put` — note this deploys immediately, see [Secrets](#secrets-inventory-and-rotation)).

**Deploy**

- [ ] Migrate `production` if needed ([Migrating production](#2-migrating-production)).
- [ ] `cd apps/web && npx wrangler deploy` and record the printed version id.
- [ ] Upgrade the home worker if `worker/` changed ([home-worker-setup.md §11](home-worker-setup.md#11-upgrade-and-restart)).

**After** ([Smoke checks](#4-smoke-checks))

- [ ] Unauthenticated `/` and `/api/v1/health` → `302` to the Access login.
- [ ] Service-token `GET /api/v1/health` → `200`, `database: ok`, `auth: ok`, `environment: production`.
- [ ] Owner sign-in works; **Settings → System health** shows the worker `online` and no outage.
- [ ] Next Cron run logs `maintenance_step` without `maintenance_step_failed` (Workers Logs).
- [ ] Record the deploy (version id, migrations, date) in `docs/progress.md` and the table above.

## Deploy procedure

### 1. Pre-checks

```bash
git switch main && git pull --ff-only && git status            # clean tree
npm ci
npm run lint && npm run typecheck && npm test && npm run build
cd apps/web
npx wrangler whoami                                             # account a2c0616c…
npx wrangler deployments status                                 # current version = rollback target
npx wrangler secret list                                        # names only, never values
```

`npm test` runs Vitest with at most two workers (memory); do not run two full suites at once on the
scan host.

### 2. Migrating production

Migrations are forward-only SQL files in `packages/database/migrations/` (drizzle-kit `generate`;
there are **no down migrations**). The runner (`npm run db:migrate`, `packages/database/scripts/migrate.ts`)
refuses `NEON_BRANCH=production` unless `ALLOW_PRODUCTION_MIGRATION=yes`, refuses pooled
(`-pooler`) URLs and forces `sslmode=verify-full`.

Only after the same migration is applied and verified on a development branch, and with the owner's
approval:

```bash
# 1. Verify on dev first
neon checkout dev                       # or: neon checkout dev --create   (expires after 7 days)
npm run db:migrate
# … run the app against dev (npm run dev), exercise the changed features …

# 2. Recovery point for production (see backup-restore.md)
date -u +%Y-%m-%dT%H:%M:%SZ            # note the timestamp: PITR target if the migration goes wrong
neon snapshots create --branch production --name pre-migration-$(date -u +%Y%m%d)   # optional, Free plan keeps 1

# 3. Migrate production
neon checkout production
ALLOW_PRODUCTION_MIGRATION=yes npm run db:migrate
neon checkout dev                       # do not leave production checked out
```

Then check the application role's privileges. Tables created by the owner role inherit the default
privileges (`SELECT, INSERT, UPDATE, DELETE` for `exdomainvault_app`); re-check that the append-only
tables stay append-only:

```sql
\dp audit_logs
\dp finding_status_history
\dp finding_comments
-- exdomainvault_app must have only "ar" (INSERT, SELECT) on these three tables.
```

**Order.** Migrate first, then deploy the code that needs the new schema. Most migrations here are
additive (new tables, nullable columns), so the previous code version keeps working against the
migrated schema and a code-only rollback is safe. Read each migration before applying it: one that
drops or renames a column, or adds a `NOT NULL` column without a default (as `0004` did on
`findings`), can break the previous version — then a rollback also needs a database restore, so take
a snapshot first.

### 3. Deploy the Worker

```bash
cd apps/web
npx wrangler deploy
```

`wrangler deploy` does not build. `npm run build` (step 1) wrote the Worker and SPA to
`apps/web/dist/` and a redirect (`apps/web/.wrangler/deploy/config.json` →
`dist/exdomainvault/wrangler.json`), and `wrangler deploy` uploads that build as a new version at 100%
of traffic and registers the Cron Trigger. **Always build from the commit being deployed** immediately
before deploying; a stale `dist/` would deploy old code. Record the version id it prints.

### 4. Smoke checks

```bash
BASE=https://exdomainvault.amrin78.workers.dev

# Access in front of everything (no token): expect 302 to fragrant-grass-4d8f.cloudflareaccess.com
curl -sI "$BASE/" | grep -iE '^(HTTP|location)'
curl -sI "$BASE/api/v1/health" | grep -iE '^(HTTP|location)'

# Through Access with the home worker's service token (on the scan host; secret never in argv)
sudo bash -c 'set -a; . /etc/exdomainvault/worker.env; printf "header = \"CF-Access-Client-Id: %s\"\nheader = \"CF-Access-Client-Secret: %s\"\n" "$EXDV_ACCESS_CLIENT_ID" "$EXDV_ACCESS_CLIENT_SECRET" | curl -sS -K - "$EXDV_API_BASE_URL/api/v1/health"' | jq .
# expect: "status":"ok", "environment":"production", components.database "ok", components.auth "ok"

# Live logs during the next Cron run (every 5 minutes)
cd apps/web && npx wrangler tail --format pretty
```

Then sign in as the owner: the UI loads, the top bar shows _Administrator_, **Settings → System
health** shows the worker `online`, the queue moving and no outage alert. A service token on a user
route (e.g. `/api/v1/me`) must be rejected (`401`): service tokens carry no email.

## Rollback

### Code: `wrangler rollback`

Workers keeps every uploaded version; a rollback redeploys an earlier version at 100% of traffic
without rebuilding. Checked against the Wrangler documentation (2026-10-23):

```bash
cd apps/web
npx wrangler deployments list           # the 10 most recent deployments, with version ids
npx wrangler versions list              # the 10 most recent versions
npx wrangler versions view <VERSION_ID> # inspect one (bindings, vars, created on)
npx wrangler rollback <VERSION_ID> --message "rollback: <reason>"
npx wrangler deployments status         # confirm the active version
```

- `wrangler rollback` without a version id rolls back to the version uploaded before the latest.
  Passing `--message` skips the interactive confirmation.
- Only the 100 most recent versions can be rolled back to. Dashboard alternative: **Workers & Pages →
  exdomainvault → Deployments →** ⋯ next to the version → **Rollback**.
- A rollback restores the version's code, vars (including `ACTIVE_SCANNING_ENABLED`) and binding
  _references_. It does **not** change connected resources or data: the Neon database, the Hyperdrive
  configuration, Access policies and Cron runs continue as they are. Cloudflare's docs do not state
  how secrets behave on rollback; after a rollback, check `npx wrangler secret list` and
  re-`put` anything that is missing.
- Rollback is blocked if the target version binds to a resource that no longer exists.
- Then run the [smoke checks](#4-smoke-checks) and record the rollback in `docs/progress.md`.

**Emergency stop for active scanning** (faster than a rollback when the problem is scanning
behaviour): set `"ACTIVE_SCANNING_ENABLED": "false"` in `apps/web/wrangler.jsonc` and deploy; new
active jobs are refused and running ones stop at their next heartbeat. Or stop the worker on the scan
host (`sudo systemctl stop exdomainvault-worker`), which stops all scanning; queued jobs wait.

### Database: no down migrations

There are no down migrations. Because migrations are additive, the normal response to a bad deploy
is a **code rollback only**: the previous version ignores the new tables/columns. Restore the database
only when data itself is wrong (a destructive migration, a bug that corrupted rows, accidental
deletion). Options, all in [backup-restore.md](backup-restore.md):

1. **Inspect first:** create a branch from a timestamp before the incident
   (`neon branches create --name restore-check --parent <RFC3339 timestamp>`), compare, copy back only
   the affected rows if that is enough.
2. **Restore `production` in place** to a point in time inside the history window
   (`neon branches restore production ^self@<timestamp> --preserve-under-name production_before_restore`).
   Connection details stay the same, so Hyperdrive keeps working; everything written after the
   timestamp is lost (it remains in the preserved branch).
3. **Restore from a snapshot** (`neon snapshots restore <id> --target-branch production`, then
   `neon snapshots finalize`).

**Plan limit:** on the Neon Free plan the history window is **6 hours**
(`history_retention_seconds: 21600`, read from the project 2026-10-23). A problem noticed later than
that can only be restored from a snapshot or a logical dump. Restoring `production` to before a
migration also means rolling the code back to the version that matches that schema.

## Secrets inventory and rotation

Nothing secret is committed. `wrangler.jsonc` holds only public values (Access team domain and AUD
tag are public identifiers; the gitleaks allowlist in `.gitleaks.toml` covers exactly the AUD).

| Secret                          | Lives in                                                        | Used by                    | Rotate                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ------------------------------- | --------------------------------------------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `exdomainvault_app` DB password | Hyperdrive config `exdomainvault-db` only                       | Worker → Neon              | Yearly or on suspicion. As the owner on `production`: `ALTER ROLE exdomainvault_app PASSWORD '<new>';` then immediately `npx wrangler hyperdrive update c43bce859dcd405c9aaca22897818529 --origin-password '<new>'` (Wrangler 4 flag). Expect a short window of failed DB requests between the two commands; run it outside scan hours. The password appears in shell history: prefix the command with a space (`HISTCONTROL=ignorespace`) or clear it afterwards. |
| Neon owner credentials          | `.env.local` on the dev machine (git-ignored), Neon console     | migrations, `neon` CLI     | Neon console → Roles → reset password, then `neon env pull`. Never given to the Worker.                                                                                                                                                                                                                                                                                                                                                                            |
| `BOOTSTRAP_ADMIN_EMAILS`        | Worker secret                                                   | first sign-in → admin      | Not a credential, but grants admin on first sign-in. The first admin exists, so **delete it**: `npx wrangler secret delete BOOTSTRAP_ADMIN_EMAILS`. Re-add only to recover from losing every admin.                                                                                                                                                                                                                                                                |
| `NVD_API_KEY`                   | Worker secret                                                   | NVD feed sync              | Request a new key at nvd.nist.gov, `npx wrangler secret put NVD_API_KEY`. Without it the sync falls back to the public rate.                                                                                                                                                                                                                                                                                                                                       |
| Access service token            | Zero Trust → Service Tokens; `worker.env` on the scan host      | home worker → Access       | Before its expiry (note the date at creation): [home-worker-setup.md §12](home-worker-setup.md#12-credential-rotation) — second token, add to the Service Auth policy, switch, delete the old one.                                                                                                                                                                                                                                                                 |
| Worker Ed25519 private key      | `/etc/exdomainvault/worker.key` (root, `0600`) on the scan host | signs every worker request | Before expiry (365 days by default; shown in **Settings → Scanning workers**): [home-worker-setup.md §12](home-worker-setup.md#12-credential-rotation). Compromise: **Revoke** the key or **Disable** the worker first.                                                                                                                                                                                                                                            |
| Access IdP / session            | Cloudflare Zero Trust                                           | user sign-in               | Managed in Zero Trust; session duration 24 h.                                                                                                                                                                                                                                                                                                                                                                                                                      |

`wrangler secret put` (and `secret delete`) creates and deploys a **new Worker version
immediately**. Change secrets as part of a planned deploy, not in the middle of one, and note the new
version id (it becomes the newest rollback point).

## Database: Neon + Cloudflare Hyperdrive

| Item           | Value                                                                                                                                                  |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Neon project   | `ExDomVault` (`flat-sound-26073660`), org `org-holy-dream-05269506`, region `aws-ap-southeast-1`, PostgreSQL 18                                        |
| Branches       | `production` (default, live), `dev` (development; created from `neon.ts`, expires 7 days after creation)                                               |
| Project link   | `.neon` (git-ignored, records the checked-out branch), policy in `neon.ts`                                                                             |
| Local env      | repo-root `.env.local` (git-ignored), from `neon env pull` / `neon checkout`: `DATABASE_URL` (pooled), `DATABASE_URL_UNPOOLED` (direct), `NEON_BRANCH` |
| Driver         | `pg` (node-postgres) + Drizzle ORM, one client per request (`packages/database`)                                                                       |
| Worker binding | `HYPERDRIVE` in `apps/web/wrangler.jsonc`                                                                                                              |

### How the connection works

- **Production:** Worker → Hyperdrive (pooling at Cloudflare's edge) → Neon **direct** endpoint, as `exdomainvault_app`.
- **Local dev (`npm run dev`):** `apps/web/vite.config.ts` copies `DATABASE_URL_UNPOOLED` from `.env.local`
  into `CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE`, so the local Workers runtime connects
  straight to whichever Neon branch is checked out (as the owner role). An exported value of that variable wins.

### Switching branches locally

```bash
neon checkout dev            # or: neon checkout dev --create  (if it has expired)
npm run db:migrate           # bring the branch schema up to date
neon checkout production     # back to the live branch (read-mostly; migrations are guarded)
```

### Least-privilege application role

**Do not create it with `neon roles create` or the Neon console**: roles created that way are members of
`neon_superuser` (`pg_read_all_data`, `pg_write_all_data`, `CREATEROLE`, `BYPASSRLS`). Create it with SQL as
the owner on the `production` branch instead:

```sql
CREATE ROLE exdomainvault_app LOGIN PASSWORD '<generated>'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO exdomainvault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO exdomainvault_app;
-- Append-only tables: no UPDATE or DELETE for the application.
REVOKE UPDATE, DELETE ON audit_logs, finding_status_history, finding_comments FROM exdomainvault_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO exdomainvault_app;
```

Verified on 2026-10-22: no role memberships; DML on normal tables works; `UPDATE audit_logs`,
`DELETE finding_status_history`, `CREATE TABLE`, `DROP TABLE` and `CREATE ROLE` are denied. The password
exists only inside the Hyperdrive configuration (rotation: [Secrets](#secrets-inventory-and-rotation)).

Retention (Milestone 12) deletes old observations and scan jobs as `exdomainvault_app`, which the
`DELETE` grant on those tables already allows; it never touches the append-only tables.

### Hyperdrive configuration

```bash
cd apps/web
npx wrangler hyperdrive create exdomainvault-db \
  --connection-string="postgresql://exdomainvault_app:<password>@<production-direct-host>/neondb"
npx wrangler hyperdrive update <id> --caching-disabled
```

Use the **direct** (non-pooler) host. Put the printed id in the `HYPERDRIVE` binding in
`apps/web/wrangler.jsonc`, then `npm run cf-typegen`. **Query caching stays disabled** (2026-10-22):
cached reads showed stale state for up to a minute after changes, including the authorisation and
kill-switch re-checks the worker API depends on.

## Authentication: Cloudflare Access

The Worker verifies Access tokens itself (signature, issuer, audience, expiry). Access also sits in front
of the Worker so unauthenticated users never reach it.

### Access policy

| Policy                      | Action       | Include                                   | Purpose                                                    |
| --------------------------- | ------------ | ----------------------------------------- | ---------------------------------------------------------- |
| `demo-allowlist` (people)   | Allow        | the owner's email (add other users here)  | Who may reach the app; ExDomainVault roles decide the rest |
| `exdomainvault-home-worker` | Service Auth | Service Token `exdomainvault-home-worker` | Lets the home worker through; never a user session         |

Scope **All traffic** (not "Previews only"), session duration 24 hours, preview URLs disabled in
`wrangler.jsonc` so no unprotected hostname exists. Never add a _Bypass_ policy. Adding a user takes
two steps: include their email in the Allow policy **and** add them in **Settings → Users** (otherwise
`403`).

### First-time setup

1. **Workers & Pages → exdomainvault → Access → Protect this Worker behind Access** with the policies above.
2. The Access tab then shows **Application values**: the **AUD tag** and a JWKS URL whose host is the team
   domain (`<team>.cloudflareaccess.com`). Both are public identifiers.
3. Set the Worker vars in `apps/web/wrangler.jsonc`:

   ```jsonc
   "AUTH_PROVIDER": "cloudflare_access",
   "ACCESS_TEAM_DOMAIN": "<team>.cloudflareaccess.com",
   "ACCESS_AUD": "<aud tag>",
   ```

4. Bootstrap admin as a secret (keeps the email out of git):
   `printf '%s' 'you@example.com' | npx wrangler secret put BOOTSTRAP_ADMIN_EMAILS`
5. On first sign-in, that email becomes an administrator (audited as `user.bootstrap_admin`). Other users
   are added in **Settings → Users**. Delete the secret once the first admin exists.

If `ACCESS_TEAM_DOMAIN` or `ACCESS_AUD` is empty, every protected API route returns `503` and
`/api/v1/health` reports `auth: not_configured`. The development sign-in (`AUTH_PROVIDER=dev`) is refused
when `APP_ENV=production`.

## Scanning: Cron, worker and switches

### Cron Trigger

`"triggers": { "crons": ["*/5 * * * *"] }` in `apps/web/wrangler.jsonc`; `wrangler deploy` registers it.
The `scheduled()` handler (`apps/web/worker/index.ts` → `services/maintenance.ts`) runs lease reaping,
verification expiry/lapse, nonce pruning, the passive/discovery/scheduled-active schedulers, rules
evaluation, accepted-risk expiry, the intelligence feed sync and (Milestone 12) the worker-outage
check and retention. Each step is isolated; results appear in Workers Logs as `maintenance_step` /
`maintenance_step_failed`. Without the `HYPERDRIVE` binding the run logs `maintenance_skipped`.

### `ACTIVE_SCANNING_ENABLED`

A Worker var in `wrangler.jsonc` (`"true"` in production since 2026-10-22). Only `"true"` or `"false"`
is accepted (anything else fails configuration closed); unset means `false`. While `false`, jobs with
active profiles are refused at creation (`409`) and at claim time, and running active jobs are told to
stop at their next heartbeat; passive monitoring is unaffected. Active checks also need the worker's
own switch (`EXDV_ACTIVE_SCANNING_ENABLED=true`, [home-worker-setup.md §15](home-worker-setup.md#15-enabling-active-scanning)).
Port probes (`standard`/`deep`) only reach networks approved in **Settings → Approved networks**.

### Registering the home worker

Full procedure: [home-worker-setup.md](home-worker-setup.md) (key generation, **Settings → Scanning
workers** registration, Access service token, systemd unit). Credentials expire after 365 days by
default; rotation is in §12 of that guide.

### Intelligence feeds

endoflife.date, CISA KEV and NVD need no keys and are synced by the Cron Trigger (`intel_*` steps).
The optional `NVD_API_KEY` secret raises the NVD batch from 5 to 20 CVEs per run. An admin can force a
sync with **Settings → Intelligence feeds** (`POST /api/v1/intel/feeds/sync`).

## Milestone 12 deploy notes

Milestone 12 (production hardening) adds the worker-outage check, retention, `GET /ops/health` /
`GET /ops/alerts`, per-user rate limits and scan quotas. Before deploying it:

- **Migrations:** apply any new migration in `packages/database/migrations/` (check
  `git diff --stat <deployed-commit> -- packages/database/migrations`) as in
  [Migrating production](#2-migrating-production).
- **Rate-limit bindings:** the API's per-user limits use Workers Rate Limiting bindings
  `API_RATE_LIMITER` (300 requests/min) and `MUTATION_RATE_LIMITER` (60/min), declared under
  `ratelimits` in `wrangler.jsonc`. If a binding is missing the API **degrades open** (requests pass,
  `rate_limiter_unavailable` is logged) — confirm after deploy that no such warning appears.
- **Alert:** create the Workers Logs alert for `worker_outage_started`
  ([operations.md](operations.md#alerting-on-worker-outage)).
- **Retention starts deleting** observations older than 180 days and finished scan jobs older than
  365 days on the first Cron run after the deploy. Production data starts on 2026-10-22, so nothing is
  eligible before 2027-04; take a snapshot anyway if the deploy is later than that.

## Migration history

| Migration                   | Deployed with | Notes                                                |
| --------------------------- | ------------- | ---------------------------------------------------- |
| `0000_initial_schema`       | Milestone 2   | 22 tables                                            |
| `0001_domain_authorisation` | Milestone 3   | administrator authorisation columns                  |
| `0002_scan_job_lifecycle`   | Milestone 4   | worker credentials, nonces, results, seeded profiles |
| `0003_approved_networks`    | Milestone 6   | `approved_networks`                                  |
| `0004_findings_engine`      | Milestone 7   | findings columns, evaluation marker                  |
| `0005_finding_lifecycle`    | Milestone 8   | `finding_comments` (append-only for the app role)    |
| `0006_asset_discovery`      | Milestone 9   | asset decisions, discovery profile                   |
| `0007_software_intel`       | Milestone 11  | software inventory, EOL cycles, advisories, feeds    |
