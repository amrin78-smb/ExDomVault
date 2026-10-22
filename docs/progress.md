# ExDomainVault — Build Progress

Updated by Claude at the end of every milestone. Newest entries at the top of each section.

## Milestone status

| # | Milestone | Status | Notes |
|---|---|---|---|
| 1 | Repository foundation | not started | |
| 2 | Database and authentication | not started | |
| 3 | Domain inventory | not started | |
| 4 | Scan job lifecycle | not started | |
| 5 | Python worker | not started | |
| 6 | Scanning and target safety (security gate) | not started | Active scanning disabled until complete |
| 7 | Deterministic rules engine | not started | |
| 8 | Finding lifecycle | not started | |
| 9 | Passive subdomain discovery | not started | |
| 10 | Frontend integration | not started | |
| 11 | Production hardening | not started | |

## Decisions log

- 2026-10-22 — Deploy target is Cloudflare Workers; `netlify.toml` from the design layout is not used.
- 2026-10-22 — Resolved findings that recur are reopened (same fingerprint) with a status-history entry `reason = recurrence`.

## Operator actions required

_Things only the owner can do (Cloudflare account, Neon project, Access app, secrets). Add exact steps as they arise._

## Known limitations

_None yet._

## Session log

_Per milestone: files changed, checks run (with real results), limitations, next step._
