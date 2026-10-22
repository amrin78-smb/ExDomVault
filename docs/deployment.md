# Deployment

Covers only what is implemented. Nothing in this repository deploys automatically, and Claude does not
deploy or change Cloudflare/Neon account settings without explicit permission.

## Current production state (2026-10-22)

| Item               | Value                                                                                                  |
| ------------------ | ------------------------------------------------------------------------------------------------------ |
| URL                | https://exdomainvault.amrin78.workers.dev (Worker `exdomainvault`, `workers_dev` on, preview URLs off) |
| Cloudflare account | `a2c0616cdf9b25972e26618151f392f7`                                                                     |
| Access             | Worker → **Access** tab, scope _All traffic_, policy `demo-allowlist` (Allow: owner email only)        |
| Access team domain | `fragrant-grass-4d8f.cloudflareaccess.com`                                                             |
| Hyperdrive         | `exdomainvault-db` (`c43bce859dcd405c9aaca22897818529`) → Neon `production` direct endpoint            |
| Database role      | `exdomainvault_app` (least privilege, see below)                                                       |
| Neon `production`  | migrated (`0000_initial_schema`, 22 tables)                                                            |
| Worker secrets     | `BOOTSTRAP_ADMIN_EMAILS`                                                                               |
| Verified           | unauthenticated `/`, `/api/*` and forged assertion header → 302 to Access login; owner sign-in → admin |

`demo-allowlist` is a reusable Access policy shared with another app; anyone added to it can also reach
ExDomainVault (but gets 403 from the API unless provisioned in `users`). Consider a dedicated policy.

## Database: Neon + Cloudflare Hyperdrive

| Item           | Value                                                                                                                                                  |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Neon project   | `ExDomVault` (`flat-sound-26073660`), org `org-holy-dream-05269506`                                                                                    |
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

### Migrating production

Only after the same migration is applied and verified on a development branch, and with the owner's approval:

```bash
neon checkout production
ALLOW_PRODUCTION_MIGRATION=yes npm run db:migrate
neon checkout dev            # do not leave production checked out
```

Then re-apply the grants below if the migration added tables (default privileges cover tables created by
the owner, but re-check `audit_logs` / `finding_status_history` stay append-only).

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
REVOKE UPDATE, DELETE ON audit_logs, finding_status_history FROM exdomainvault_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO exdomainvault_app;
```

Verified on 2026-10-22: no role memberships; DML on normal tables works; `UPDATE audit_logs`,
`DELETE finding_status_history`, `CREATE TABLE`, `DROP TABLE` and `CREATE ROLE` are denied. The password
exists only inside the Hyperdrive configuration; to rotate, `ALTER ROLE ... PASSWORD` and
`wrangler hyperdrive update`.

### Hyperdrive configuration

```bash
cd apps/web
npx wrangler hyperdrive create exdomainvault-db \
  --connection-string="postgresql://exdomainvault_app:<password>@<production-direct-host>/neondb"
```

Use the **direct** (non-pooler) host. Put the printed id in the `HYPERDRIVE` binding in
`apps/web/wrangler.jsonc`, then `npm run cf-typegen`.

## Authentication: Cloudflare Access

The Worker verifies Access tokens itself (signature, issuer, audience, expiry). Access also sits in front
of the Worker so unauthenticated users never reach it.

1. **Workers & Pages → exdomainvault → Access → Protect this Worker behind Access.**
   - Scope: **All traffic** (not "Previews only").
   - Authentication policy: an _Allow_ policy including only the people who should use ExDomainVault.
     Access decides who may reach the app; ExDomainVault roles decide what they can do.
   - Session duration: 24 hours.
2. The Access tab then shows **Application values**: the **AUD tag** and a JWKS URL whose host is the team
   domain (`<team>.cloudflareaccess.com`). Both are public identifiers. (They can also be read from the
   `Location` of the 302 an unauthenticated request receives: host = team domain, `kid` = AUD.)
3. Set the Worker vars in `apps/web/wrangler.jsonc`:

   ```jsonc
   "AUTH_PROVIDER": "cloudflare_access",
   "ACCESS_TEAM_DOMAIN": "<team>.cloudflareaccess.com",
   "ACCESS_AUD": "<aud tag>",
   ```

4. Bootstrap admin as a secret (keeps the email out of git):
   `printf '%s' 'you@example.com' | npx wrangler secret put BOOTSTRAP_ADMIN_EMAILS`
5. On first sign-in, that email becomes an administrator (audited as `user.bootstrap_admin`). Other users
   must be provisioned in the `users` table (user-management UI arrives later) or they receive 403 even
   if Access lets them through. You can delete the secret after the first admin exists
   (`npx wrangler secret delete BOOTSTRAP_ADMIN_EMAILS`).

If `ACCESS_TEAM_DOMAIN` or `ACCESS_AUD` is empty, every protected API route returns `503` and
`/api/v1/health` reports `auth: not_configured`. The development sign-in (`AUTH_PROVIDER=dev`) is refused
when `APP_ENV=production`.

## Application deployment

```bash
npm run lint && npm run typecheck && npm test && npm run build
cd apps/web && npx wrangler deploy
```

Deploying needs the owner's approval. Check afterwards that an unauthenticated
`curl -sI https://exdomainvault.amrin78.workers.dev/api/v1/health` returns `302` to the Access login. Roll
back with `npx wrangler rollback` (lists recent versions). A fuller runbook arrives in Milestone 11.
