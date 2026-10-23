# Backup and restore

How ExDomainVault's data is protected, how to restore it, and a restore drill the owner can run.
Restoring `production` is an owner action. Commands were checked against the Neon CLI documentation
and the local `neon` CLI 8.10.3 on 2026-10-23.

## What is where

| Data                                                                                                                                                      | Where                                                   | Backed up by                                                                |
| --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | --------------------------------------------------------------------------- |
| Everything the application knows: domains, verifications, assets, scan jobs, observations, findings, history, comments, users, audit log, settings, feeds | Neon project `flat-sound-26073660`, branch `production` | Neon history (point-in-time restore), snapshots, optional `pg_dump`         |
| Application code, `wrangler.jsonc`, migrations, worker code and systemd units                                                                             | Git (`github.com/amrin78-smb/ExDomVault`)               | Git remote                                                                  |
| Deployed Worker versions                                                                                                                                  | Cloudflare (last 100 versions)                          | `wrangler rollback` ([deployment.md](deployment.md#rollback))               |
| Worker secrets (`NVD_API_KEY`, `BOOTSTRAP_ADMIN_EMAILS`)                                                                                                  | Cloudflare (write-only)                                 | **Not backed up** — re-issue/re-enter                                       |
| `exdomainvault_app` password                                                                                                                              | Hyperdrive configuration only                           | **Not backed up** — reset with `ALTER ROLE` + `hyperdrive update`           |
| Access policies, service token                                                                                                                            | Cloudflare Zero Trust                                   | **Not backed up** — recreate ([deployment.md](deployment.md#access-policy)) |
| Worker private key, `worker.env` (key id, service token)                                                                                                  | `/etc/exdomainvault/` on the scan host                  | **Not backed up, by design** — on loss, generate and register a new key     |
| Worker health file                                                                                                                                        | `/var/lib/exdomainvault-worker/`                        | Not needed (regenerated)                                                    |
| Neon owner credentials                                                                                                                                    | `.env.local` (dev machine), Neon console                | Neon console (reset password, `neon env pull`)                              |

Nothing on the scan host needs restoring: job state lives in PostgreSQL, a lost worker's leases expire
and its jobs are retried. Do not copy the worker key anywhere; a new key is cheaper and safer than a
backup of the old one ([home-worker-setup.md §12](home-worker-setup.md#12-credential-rotation)).

## Neon protection on the current plan

Read from the project on 2026-10-23: plan **Free** (`free_v3`), `history_retention_seconds: 21600`.

| Mechanism             | Free plan (current)                      | Launch                               | Scale                        |
| --------------------- | ---------------------------------------- | ------------------------------------ | ---------------------------- |
| History window (PITR) | **6 hours** (fixed; history capped 1 GB) | 1 day default, up to 7 days          | 1 day default, up to 30 days |
| Manual snapshots      | **1**                                    | 100                                  | 100                          |
| Scheduled snapshots   | **not available**                        | daily/weekly/monthly, kept ≤ 35 days | same                         |

The history window is set per project (Console → project → **Settings → Postgres → History window**;
longer windows are billed as history storage). Snapshots can be taken only of a point inside the
window.

**Consequence:** today a bad change can be undone by point-in-time restore only if it is noticed
within **6 hours**. Older states exist only in the single manual snapshot and in any `pg_dump` the
owner has taken. Recommended (owner decision, costs money): move the Neon project to **Launch** and set
the history window to 7 days plus a daily snapshot schedule:

```bash
neon snapshots schedule set --branch production --frequency daily --hour 19 --retention 1209600   # 02:00 Bangkok, 14 days
```

Until then, use the [logical backup](#logical-backup-pg_dump) below weekly and before risky changes.

## Before a production migration

1. Note the UTC time just before migrating: `date -u +%Y-%m-%dT%H:%M:%SZ`. Within 6 hours, that is
   the point-in-time restore target.
2. Take a snapshot that outlives the window (the Free plan holds one manual snapshot; delete the
   previous one first):

   ```bash
   neon snapshots list
   neon snapshots delete <old-snapshot-id>                       # Free plan: only 1 manual snapshot
   neon snapshots create --branch production --name pre-migration-$(date -u +%Y%m%d)
   ```

3. Migrate ([deployment.md](deployment.md#2-migrating-production)).

## Restore procedures

Always **look before you overwrite**: restore into a new branch first, verify, and only then restore
`production` in place.

### A. Inspect a past state in a new branch (safe, non-destructive)

```bash
neon branches create --name restore-check --parent 2026-10-23T08:00:00Z --expires-at "$(date -u -d '+1 day' +%Y-%m-%dT%H:%M:%SZ)"
psql "$(neon connection-string restore-check)" -f verify.sql     # see the drill below
```

`--parent <RFC 3339 timestamp>` branches from the default branch (`production`) at that moment; the
timestamp must lie inside the history window. Copy individual rows back if that is all that is needed
(as the owner role, in a transaction, and note it in the audit trail by hand: direct SQL bypasses the
application's audit log).

### B. Restore `production` in place to a point in time

Overwrites all data and schema of `production` with its state at the timestamp. Connection details stay
the same, so Hyperdrive and the Worker keep working after a brief interruption. Everything written
after the timestamp disappears from `production` but is kept in the preserved branch.

```bash
# 1. Stop writers so nothing is written during the restore
sudo systemctl stop exdomainvault-worker               # scan host
#    (optional) roll the Worker back to the code matching the target schema — deployment.md#rollback

# 2. Restore, keeping the current state under another name
neon branches restore production ^self@2026-10-23T08:00:00Z --preserve-under-name production_before_restore_20261023

# 3. Verify (drill queries below), then restart the worker
psql "$(neon connection-string production)" -f verify.sql
sudo systemctl start exdomainvault-worker
```

- `--preserve-under-name` is required when restoring to `^self`.
- If the restore goes back before a migration, `drizzle.__drizzle_migrations` goes back too; the code
  must be rolled back to a matching version, or the migration re-applied.
- Jobs that were running at the timestamp come back as running; their leases expire and the Cron
  Trigger requeues them (bounded retries). Worker nonces from before the restore can repeat only
  within the 300 s signature window, which has passed.
- The restored and preserved branches are both root branches; delete the preserved one once the
  restore is accepted (it counts toward the Free plan's 10 branches and storage).
- The `exdomainvault_app` role and its grants are part of the branch, so they are restored as they
  were at the timestamp (a password changed after the timestamp reverts: re-run the rotation).

### C. Restore from a snapshot

```bash
neon snapshots list
neon snapshots restore <snapshot-id> --target-branch production   # un-finalized: inspect first
# verify the restored branch the command prints, then swap it in:
neon snapshots finalize <restored-branch-id> --name production_before_snapshot_restore
```

`neon snapshots restore <id> --name recovered` restores into a separate new branch instead (inspection
only).

### D. Restore from a logical dump

For a dump older than the window and the snapshot: create an empty branch or project, restore with
`pg_restore --no-owner --role=<owner> -d "<direct URL>" exdomainvault.dump`, re-create
`exdomainvault_app` and its grants ([deployment.md](deployment.md#least-privilege-application-role)),
point Hyperdrive at it with `wrangler hyperdrive update`, verify, then switch.

## Tested-restore drill

Run monthly (and after any change to backups) on the dev machine. It reads `production`'s history
into a temporary branch and never writes to `production`. About 5 minutes.

1. Pick a timestamp inside the window, e.g. one hour ago:

   ```bash
   TS=$(date -u -d '-1 hour' +%Y-%m-%dT%H:%M:%SZ); echo "$TS"
   ```

2. Create the branch (expires automatically after a day even if step 5 is forgotten):

   ```bash
   neon branches create --name restore-drill --parent "$TS" \
     --expires-at "$(date -u -d '+1 day' +%Y-%m-%dT%H:%M:%SZ)" --no-secrets
   ```

3. Save these verification queries as `verify.sql` (outside the repository, e.g. in `/tmp`):

   ```sql
   \echo '-- migrations applied'
   select count(*) as migrations, max(created_at) as last_migration_ms from drizzle.__drizzle_migrations;
   \echo '-- row counts'
   select 'domains' as t, count(*) from domains
   union all select 'assets', count(*) from assets
   union all select 'scan_jobs', count(*) from scan_jobs
   union all select 'findings', count(*) from findings
   union all select 'finding_status_history', count(*) from finding_status_history
   union all select 'users', count(*) from users
   union all select 'audit_logs', count(*) from audit_logs;
   \echo '-- latest audit row (must be just before the restore timestamp)'
   select created_at, action, actor_type from audit_logs order by created_at desc limit 1;
   \echo '-- latest completed scan job'
   select max(completed_at) as last_completed_job from scan_jobs;
   \echo '-- app role exists without superuser memberships'
   select rolname, rolsuper, rolcreaterole, rolbypassrls from pg_roles where rolname = 'exdomainvault_app';
   ```

4. Run them against the drill branch and against `production` for comparison:

   ```bash
   psql "$(neon connection-string restore-drill)" -f /tmp/verify.sql
   psql "$(neon connection-string production)" -f /tmp/verify.sql
   ```

   **Pass:** the drill branch has the same migration count as production (unless a migration ran in
   the last hour), row counts equal to or slightly below production's (production has an hour of new
   rows), its latest audit row and latest completed job are **before** `$TS` (the completed job
   usually within minutes of it — the daily passive runs spread jobs over the day), and
   `exdomainvault_app` exists with all three flags `f`.

5. Delete the branch and record the drill (date, `$TS`, counts, pass/fail, duration) in
   `docs/progress.md`:

   ```bash
   neon branches delete restore-drill
   ```

`neon connection-string` prints the owner role's URL including the password; it appears in the local
process list while `psql` runs. Run the drill on the single-user dev machine only.

## Logical backup (`pg_dump`)

Until the plan has a longer window, take a weekly custom-format dump and keep it off the scan host,
encrypted. The server runs PostgreSQL 18, so the client must be **18 or newer** (Ubuntu 24.04 ships
16: install `postgresql-client-18` from the PostgreSQL apt repository).

```bash
pg_dump --format=custom --no-owner --no-privileges \
  --dbname="$(neon connection-string production)" --file="exdomainvault-$(date -u +%Y%m%d).dump"
gpg --symmetric --cipher-algo AES256 "exdomainvault-$(date -u +%Y%m%d).dump" && shred -u "exdomainvault-$(date -u +%Y%m%d).dump"
```

The dump contains the full portfolio, findings and the audit log: treat it as confidential. Test a
dump by restoring it into a new branch (procedure D) at least once.

## RPO and RTO

Stated for the current setup (Neon Free plan, no scheduled snapshots, no automated dumps). They are
targets for the owner's single-tenant use, not contractual commitments.

| Scenario                                                           | RPO (data that can be lost)                                                                   | RTO (time to service)                                                     |
| ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| Bad code deploy, schema unchanged                                  | none                                                                                          | ~5 min (`wrangler rollback` + smoke checks)                               |
| Bad migration or data-corrupting bug noticed within 6 h            | none before the bad change (PITR to just before it); later writes are in the preserved branch | ~30 min (inspect branch, restore in place, verify)                        |
| Same, noticed after 6 h                                            | back to the last snapshot or `pg_dump` (up to a week with weekly dumps)                       | 1–2 h                                                                     |
| Neon platform outage                                               | none expected (Neon's replicated storage); not independently verified                         | Neon's recovery time; the app shows the DB as down and the worker retries |
| Scan host lost or rebuilt                                          | none (no durable state on the host)                                                           | ~1 h (reinstall, new key, register, service token)                        |
| Cloudflare account settings lost (Access app, Hyperdrive, secrets) | none in the DB                                                                                | ~1 h following [deployment.md](deployment.md)                             |

With **Launch + 7-day window + daily snapshots** the 6-hour rows become 7 days and the RPO for late
discovery becomes at most 24 hours. Observations lost in a restore are re-collected by the next
passive/discovery runs; audit history, finding decisions and verifications are not re-creatable,
which is why they set the RPO.
