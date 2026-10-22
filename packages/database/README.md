# @exdomainvault/database

Neon PostgreSQL access for the Worker API.

- **Driver:** `pg` (node-postgres) with **Drizzle ORM**. In production the Worker connects through
  **Cloudflare Hyperdrive** (`env.HYPERDRIVE.connectionString`), which pools connections to Neon's
  direct endpoint. Locally, the Hyperdrive binding connects straight to Neon (see `apps/web/vite.config.ts`).
- `connect()` opens one short-lived client per request; `pingDatabase()` backs the health check.

Schema (`schema/`) and versioned migrations (`migrations/`) arrive in Milestone 2.
