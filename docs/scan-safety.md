# Scan safety

Principle: ExDomainVault only checks what it is authorised to check, with server-defined behaviour,
and every decision is explainable. This document separates what is **implemented today** (Milestone 4:
job lifecycle, no scanner yet) from what Milestone 6 adds. Nothing here performs exploitation,
credential testing or destructive checks, and nothing ever will.

## Current state

No component sends scan traffic yet. The Cloudflare Worker records jobs and never contacts scan targets
(its only DNS lookup is the DNS-over-HTTPS query to a public resolver for domain verification). The Python worker only
validates its configuration; job claiming and checks arrive in Milestone 5.

## Controls implemented today

| Control                                 | How it works                                                                                                                                                                                                                                                                                    |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Server-defined profiles only            | A scan request names a profile key (`passive`, `quick`, `standard`, `deep`); nothing else about scan behaviour is accepted from users. Profiles live in `scan_profiles` and are validated with a strict schema (`scanProfileConfigSchema`) on every read; an invalid stored profile is ignored. |
| No scanner flags                        | A profile config is data: a list of named checks, a port list (1–65535, ≤1024, only with the `tcp_ports` check), timeouts, concurrency, rate and target limits. There is no field for command-line arguments, and user input never reaches one.                                                 |
| Active scanning disabled (server)       | `ACTIVE_SCANNING_ENABLED` is `"false"`. Active-profile jobs are refused at creation (`409`) and, if one exists, refused again at claim time (`cancelled`, `active_scanning_disabled`).                                                                                                          |
| Active scanning disabled (worker)       | The Python worker's `active_scanning_enabled` is hard-coded `False` and is not configurable.                                                                                                                                                                                                    |
| Verification gates active scans only    | Active profiles require the domain to be `verified` (DNS TXT, or administrator authorisation whose review date has not passed). Passive monitoring needs no verification (owner decision).                                                                                                      |
| Passive never contacts target hosts     | The passive profile may only contain `dns` and `rdap` checks — queries to public resolvers and registration registries, not connections to the domain's own hosts. The schema rejects any other check unless the profile is marked active.                                                      |
| Approved targets only                   | Targets are approved assets within the domain (exact DNS label-boundary check) plus, for passive jobs, the apex. For active jobs, verification approves the apex as an asset (audited) unless it was explicitly rejected or suspended. Pending (e.g. CT-discovered) assets are never targets.   |
| Immutable scope snapshot                | Each job stores its domain authorisation state, profile version and full config, and target list at creation. Later scope changes never enlarge a job; retries run against the same snapshot.                                                                                                   |
| Claim-time re-authorisation             | Before an active-profile job is handed to a worker, the server re-checks the flag and the domain's current verification. A job whose authorisation was revoked or lapsed is cancelled (`domain_not_authorised`) and audited `scan.refused`.                                                     |
| Worker reports only on snapshot targets | Result submissions must name target ids belonging to that job; any other id rejects the whole submission. The worker can act only on the job and attempt it holds (fencing).                                                                                                                    |
| Authenticated worker                    | Ed25519-signed requests with timestamp window, nonce replay protection and per-credential rate limit; only public keys are stored; keys expire and can be revoked; workers can be disabled.                                                                                                     |
| Bounded load                            | One queued/active job per domain and profile (partial unique index); at most `max_attempts` (3) attempts with exponential backoff; profiles cap targets (50), concurrency and rate.                                                                                                             |
| Failed scans resolve nothing            | Failed, cancelled and expired jobs never change findings. (Findings are produced from results in later milestones; only a successful relevant check confirming absence will resolve one.)                                                                                                       |
| Audit                                   | `scan.requested`, `scan.cancelled`, `scan.cancel_requested`, `scan.refused`, `scan.scheduled`, `asset.approved` (verification basis) and every worker/credential change.                                                                                                                        |

## Added by Milestone 6 (not implemented yet)

Active scanning stays disabled until all of this exists and is tested:

- A scope validator in the worker that validates every resolved address **immediately before connecting**
  and pins the connection to it.
- Rejection of loopback, private, link-local, multicast, reserved, CGNAT and documentation ranges,
  including IPv4-mapped IPv6 and alternative address encodings.
- Re-validation of every CNAME hop and HTTP redirect against the approved scope.
- No scanning of third-party hosting, CDN or cloud addresses merely because the domain is verified.
- Nmap invoked only with server-defined profile arguments as an argument list (never a shell, never
  user-supplied flags).
- A logged decision for every allow/deny.

Only then may `ACTIVE_SCANNING_ENABLED` and the worker's own flag be turned on.
