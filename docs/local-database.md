# Self-hosted database (since 2026-10-26)

Owner decision: production data moved from Neon (Free plan compute ran out mid-month because the
database never idles) to PostgreSQL on the scan host. Neon `production` is kept untouched as a
fallback snapshot as of the cutover; nothing writes to it any more.

## Path

```
Worker (Cloudflare) → Hyperdrive "exdomainvault-local" (bdbcfb364f7e4eb298ed503f0719a325, caching off)
  → Workers VPC service "exdomainvault-postgres" (01a17704-9054-72f3-b61c-92b9c8244713, TCP 5432)
  → Cloudflare Tunnel "exdomainvault-db" (f44392a3-c793-4807-9152-efdcfa3ed6aa, cloudflared systemd service)
  → 127.0.0.1:5432 PostgreSQL 16 (Ubuntu package), database `exdomainvault`
```

- No inbound port is opened; the tunnel connects outwards. No domain or public hostname is involved.
- TLS: Hyperdrive requires TLS to Postgres; Postgres uses Ubuntu's self-signed certificate, so the
  VPC service has `cert-verification-mode disabled` for that last loopback hop. The link to
  Cloudflare is the tunnel (authenticated, encrypted).
- Roles: `exdomainvault_owner` owns the database (migrations, backups); `exdomainvault_app` is the
  application role with the same grants as on Neon (DML only; `audit_logs`,
  `finding_status_history`, `finding_comments` INSERT/SELECT only). Both are NOSUPERUSER.
- Passwords live in `~/.config/exdomainvault/local-db.env` (mode 600) and in the Hyperdrive config;
  the tunnel token in `~/.config/exdomainvault/tunnel-token` and the cloudflared service.
- Availability: the app needs this machine on and online. While it is down the API returns 503
  (`service_unavailable`); the scheduler and worker resume when it is back.

## Operations

| Task                                    | Command                                                                                                                                                                                      |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Host setup (once, sudo)                 | `sudo bash scripts/local-db/setup-host.sh`                                                                                                                                                   |
| Migrate                                 | `MIGRATION_DATABASE_URL=postgresql://exdomainvault_owner:<pw>@127.0.0.1:5432/exdomainvault NEON_BRANCH=local npm run db:migrate -w @exdomainvault/database` (source the env file for `<pw>`) |
| Backup now                              | `bash scripts/local-db/backup.sh` (daily 02:30 via the user crontab, 14 days kept in `~/backups/exdomainvault/`)                                                                             |
| Restore                                 | `pg_restore -h 127.0.0.1 -U exdomainvault_owner -d exdomainvault --clean --if-exists <file>.dump`                                                                                            |
| Tunnel status                           | `systemctl status cloudflared`, `journalctl -u cloudflared`                                                                                                                                  |
| Re-copy from Neon (only before cutover) | `bash scripts/local-db/copy-from-neon.sh` — replaces local data                                                                                                                              |

## Rollback to Neon

Data written after the cutover exists only locally. To go back: copy local → Neon (reverse of the
copy script), set the Hyperdrive id in `apps/web/wrangler.jsonc` back to
`c43bce859dcd405c9aaca22897818529`, `npm run build` and `npx wrangler deploy`.

Note: `wrangler deploy` uses the built `dist/` config, so always `npm run build` after editing
`wrangler.jsonc`.
