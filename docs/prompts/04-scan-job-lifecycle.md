# Milestone 4 — Scan job lifecycle

Read `CLAUDE.md`, `docs/progress.md`, and `docs/prompts/00-master-build-prompt.md` (especially §6–§11). Check `git status` and confirm the previous milestone is marked done in `docs/progress.md`; if it is not, report what is missing and finish it first.

Spec: `docs/design.md` §3.3, §5.6–5.7, §6, §10 (Scans, Internal worker API), §13. Milestone definition: master prompt §5, "Milestone 4".

## Scope
- Seed the Quick/Standard/Deep scan profiles (ports, timeouts, concurrency, rate limits) as server-defined data.
- `POST /domains/:id/scans`: authorise, require verified domain + approved assets, validate profile, write job with immutable `scope_snapshot` and `scan_job_targets`; return immediately (202).
- Internal worker API: `claim` (atomic `FOR UPDATE SKIP LOCKED`, expiring lease, attempt count), `heartbeat` (extends lease, records progress), `results` (idempotency key per result; duplicate submissions are no-ops), `failures` (bounded retries with backoff, terminal `failed`). Lease-expiry reaper via Cron Trigger.
- Worker auth: per-worker credential stored hashed in `worker_registry`, rotatable/expiring; HMAC-signed requests with timestamp + nonce for replay protection; rate limiting. Never accept targets from the worker that are not in the job snapshot.
- Cancellation (`POST /scans/:id/cancel`) where safe; `GET /scans`, `GET /scans/:id`.
- Optional Queues dispatch as a notification only — state stays in Postgres.
- Tests: concurrent claim exclusivity, lease expiry + reclaim, retry ceiling, duplicate result delivery, replayed/expired signatures, cancellation.

## Finish
1. Run lint, typecheck, test, build (and `worker:test` if the worker changed). Fix failures; report anything that genuinely cannot run and why.
2. Update the relevant docs in `docs/` to match what was actually built.
3. Update `docs/progress.md`: status table, decisions, operator actions, limitations, session log.
4. Summarise files changed, check results, remaining limitations, and the next milestone. Commit and push to `main`.
