# Deployment

Covers only what is implemented. Nothing in this repository deploys automatically, and Claude does not
deploy or change Cloudflare/Neon account settings without explicit permission.

## Database: Neon + Cloudflare Hyperdrive

| Item           | Value                                                                                                                                                             |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Neon project   | `ExDomVault` (`flat-sound-26073660`), org `org-holy-dream-05269506`                                                                                               |
| Neon branch    | `production` (default)                                                                                                                                            |
| Project link   | `.neon` (git-ignored), policy in `neon.ts`                                                                                                                        |
| Local env      | `.env.local` at the repo root (git-ignored), written by `neon env pull` / `neon deploy`: `DATABASE_URL` (pooled), `DATABASE_URL_UNPOOLED` (direct), `NEON_BRANCH` |
| Driver         | `pg` (node-postgres) + Drizzle ORM, one client per request (`packages/database`)                                                                                  |
| Worker binding | `HYPERDRIVE` in `apps/web/wrangler.jsonc`                                                                                                                         |

### How the connection works

- **Production:** Worker → Hyperdrive (connection pooling at Cloudflare's edge) → Neon **direct** endpoint.
  Hyperdrive does the pooling, so its origin must be Neon's _unpooled_ connection string.
- **Local dev (`npm run dev`):** `apps/web/vite.config.ts` copies `DATABASE_URL_UNPOOLED` from `.env.local`
  into `CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE`, so the local Workers runtime connects
  straight to Neon over TLS. An explicitly exported value of that variable takes precedence.
- **Health:** `GET /api/v1/health` runs `select 1` through the binding and reports `database` as
  `ok`, `down`, or `not_configured`. Failure details go to server logs only.

### Refreshing local credentials

```bash
neon env pull          # rewrites .env.local from the linked branch
neon deploy            # applies neon.ts to the branch and pulls env vars
```

### Before the first production deploy (owner actions)

1. **Create a least-privilege Neon role for the app.** Local dev currently uses the owner role
   (`neondb_owner`) from `.env.local`; production must not. In the Neon console → Roles, create
   `exdomainvault_app` (grants are defined with the schema in Milestone 2). Migrations will use a separate
   role, and the worker never gets database credentials.
2. **Create the Hyperdrive configuration** using that role's **direct (unpooled)** connection string:

   ```bash
   cd apps/web
   npx wrangler login
   npx wrangler hyperdrive create exdomainvault-db \
     --connection-string="postgresql://exdomainvault_app:<password>@<direct-host>/neondb?sslmode=require"
   ```

3. **Replace the placeholder id** (`00000000000000000000000000000000`) for the `HYPERDRIVE` binding in
   `apps/web/wrangler.jsonc` with the id printed by step 2, then run `npm run cf-typegen`.

The placeholder id is deliberate: a deploy fails until a real Hyperdrive configuration exists.

## Application deployment

Not yet documented — requires Cloudflare Access authentication (Milestone 2) first. Production must
not be deployed without authentication.
