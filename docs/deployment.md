# Deployment

Covers only what is implemented. Nothing in this repository deploys automatically, and Claude does not
deploy or change Cloudflare/Neon account settings without explicit permission.

## Database: Neon + Cloudflare Hyperdrive

| Item           | Value                                                                                                                                                  |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Neon project   | `ExDomVault` (`flat-sound-26073660`), org `org-holy-dream-05269506`                                                                                    |
| Branches       | `production` (default, live — **no schema yet**), `dev` (development; created from `neon.ts`, expires 7 days after creation)                           |
| Project link   | `.neon` (git-ignored, records the checked-out branch), policy in `neon.ts`                                                                             |
| Local env      | repo-root `.env.local` (git-ignored), from `neon env pull` / `neon checkout`: `DATABASE_URL` (pooled), `DATABASE_URL_UNPOOLED` (direct), `NEON_BRANCH` |
| Driver         | `pg` (node-postgres) + Drizzle ORM, one client per request (`packages/database`)                                                                       |
| Worker binding | `HYPERDRIVE` in `apps/web/wrangler.jsonc`                                                                                                              |

### How the connection works

- **Production:** Worker → Hyperdrive (pooling at Cloudflare's edge) → Neon **direct** endpoint.
- **Local dev (`npm run dev`):** `apps/web/vite.config.ts` copies `DATABASE_URL_UNPOOLED` from `.env.local`
  into `CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE`, so the local Workers runtime connects
  straight to whichever Neon branch is checked out. An exported value of that variable wins.

### Switching branches locally

```bash
neon checkout dev            # or: neon checkout dev --create  (if it has expired)
npm run db:migrate           # bring the branch schema up to date
neon checkout production     # back to the live branch (read-mostly; migrations are guarded)
```

### Migrating production

Only after the same migration is applied and verified on a development branch:

```bash
neon checkout production
ALLOW_PRODUCTION_MIGRATION=yes npm run db:migrate
```

### Least-privilege application role (owner action, before first deploy)

Local dev currently connects as the owner role (`neondb_owner`). Production must not.

1. Neon console → project → **Roles** → create `exdomainvault_app` on the `production` branch. Save the
   password in your password manager.
2. After migrating production, run as the owner (`psql "$DATABASE_URL_UNPOOLED"` with production checked out):

   ```sql
   GRANT USAGE ON SCHEMA public TO exdomainvault_app;
   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO exdomainvault_app;
   -- Append-only tables: no UPDATE or DELETE for the application.
   REVOKE UPDATE, DELETE ON audit_logs, finding_status_history FROM exdomainvault_app;
   ALTER DEFAULT PRIVILEGES IN SCHEMA public
     GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO exdomainvault_app;
   ```

   Re-check grants after each migration that adds tables.

### Hyperdrive configuration (owner action, before first deploy)

```bash
cd apps/web
npx wrangler login
npx wrangler hyperdrive create exdomainvault-db \
  --connection-string="postgresql://exdomainvault_app:<password>@<production-direct-host>/neondb?sslmode=require"
```

Replace the placeholder id `00000000000000000000000000000000` for the `HYPERDRIVE` binding in
`apps/web/wrangler.jsonc` with the printed id, then `npm run cf-typegen`. The placeholder is deliberate:
deploying fails until a real Hyperdrive configuration exists.

## Authentication: Cloudflare Access (owner action, before first deploy)

The Worker verifies Access tokens itself (signature, issuer, audience, expiry). Access must also sit in
front of the application so unauthenticated users never reach it.

1. **Zero Trust dashboard → Access → Applications → Add an application → Self-hosted.**
   - Application domain: the hostname the Worker will serve (custom domain or `exdomainvault.<subdomain>.workers.dev`).
   - Session duration: e.g. 24 hours.
2. **Policy:** _Allow_, include the specific emails (or an email domain / IdP group) of people who should use
   ExDomainVault. Access decides who may reach the app; ExDomainVault roles decide what they can do.
3. Copy the application's **Audience (AUD) tag** (application → Overview / Basic information).
4. Note your **team domain**: `<team>.cloudflareaccess.com` (Settings → Custom pages / General).
5. Set the Worker vars in `apps/web/wrangler.jsonc` (these are not secrets):

   ```jsonc
   "AUTH_PROVIDER": "cloudflare_access",
   "ACCESS_TEAM_DOMAIN": "<team>.cloudflareaccess.com",
   "ACCESS_AUD": "<aud tag>",
   "BOOTSTRAP_ADMIN_EMAILS": "<your email>"
   ```

6. On first sign-in, the email in `BOOTSTRAP_ADMIN_EMAILS` becomes an administrator (audited). Other users
   must be provisioned in the `users` table (user-management UI arrives later) or they receive 403 even
   if Access lets them through. You can clear `BOOTSTRAP_ADMIN_EMAILS` after the first admin exists.

Until `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` are set, every protected API route returns `503` and
`/api/v1/health` reports `auth: not_configured`. The development sign-in (`AUTH_PROVIDER=dev`) is refused
when `APP_ENV=production`.

## Application deployment

Not yet performed. Before the first `wrangler deploy`: complete the three owner actions above, migrate
production, and confirm `/api/v1/health` reports `database: ok` and `auth: ok` via
`npx wrangler dev --remote`. A deploy and rollback runbook arrives in Milestone 11.
