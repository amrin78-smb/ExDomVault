# ExDomainVault — Build Progress

Updated by Claude at the end of every milestone. Newest entries at the top of each section.

## Milestone status

| #   | Milestone                                   | Status | Notes                                   |
| --- | ------------------------------------------- | ------ | --------------------------------------- |
| 1   | Repository foundation                       | done   |                                         |
| 2   | Database and authentication                 | done   | Deployed; production migrated           |
| 3   | Domain inventory                            | done   | Deployed 2026-10-22 (`cf062f76`)        |
| 4   | Scan job lifecycle                          | done   | Deployed 2026-10-22 (`663d3165`)        |
| 5   | Python worker                               | done   | Deployed; worker live on this host      |
| 6   | Scanning and target safety (security gate)  | done   | Gate passed; active scanning ON in prod |
| 7   | Deterministic rules engine                  | done   | Deployed 2026-10-22 (`7dff53fc`)        |
| 8   | Finding lifecycle                           | done   | Deployed 2026-10-22 (`9e0ed55b`)        |
| 9   | Passive subdomain discovery                 | done   | Deployed 2026-10-23 (`d12f8709`)        |
| 10  | Frontend integration                        | done   | Deployed 2026-10-23 (`43af2122`)        |
| 11  | Exposed-software / vulnerability monitoring | done   | Deployed 2026-10-23 (`cb709106`)        |
| 12  | Production hardening                        | done   | Built; not yet deployed                 |

## Decisions log

- 2026-10-26 — **Host import** (owner request; CT discovery misses hosts behind wildcard certificates): `POST /domains/:id/assets/import` (`domains:write` = admin only) adds hostnames from a zone export (XLSX/CSV records, BIND zone file, or plain list) as `pending` assets, source `import`. Files are parsed in the browser (own minimal XLSX reader, no dependency; 10 MB file / 50 MB inflated / 20 000 rows caps); the server re-validates every name (syntax, exact label boundary, no `_`/`*` labels), never approves, changes existing assets, enables monitoring or queues jobs. Only A/AAAA/CNAME rows count; CNAME targets from the file feed `classifyHosting` (refreshed from live DNS once monitored; the worker still refuses out-of-scope CNAME targets). `dryRun` preview; one `asset.imported` audit row with counts. Body cap 4 MB for this route.

- 2026-10-24 — **Rate limits via Workers Rate Limiting bindings** (`API_RATE_LIMITER` 300/min, `MUTATION_RATE_LIMITER` 60/min per user, after authentication): cross-isolate, no migration; approximate (per Cloudflare location) and fail-open with a `rate_limiter_unavailable` log. **Scan quotas** are exact DB counts inside `createScan` (per-user lock): 60 user-requested scans/hour/user, 24 active scans/domain/day, 6 discovery/domain/day; scheduled jobs never count.
- 2026-10-24 — **Strict CSP** for the SPA (`apps/web/public/_headers`): no `'unsafe-inline'`; API responses `default-src 'none'`; plus Permissions-Policy, COOP/CORP, HSTS. Inline-style bars replaced by SVG attributes.
- 2026-10-24 — **Ops:** `GET /ops/health` (admins) and `GET /ops/alerts` (all users, banner). Worker outage = no worker seen for 30 min while jobs are queued; cron logs `worker_outage_started`/`_ended` once per transition (state in `application_settings.ops_state`); alerting via Cloudflare Monitors on that log line (docs/operations.md), no email channel.
- 2026-10-24 — **Retention:** observations > 180 days and finished jobs > 365 days, ≤ 5000 rows/table/run, hourly; the latest successful (and latest any-status) observation per key always survives; jobs referenced by finding history, still owning observations, or unevaluated are kept. Audit logs, findings, history and comments are never deleted.
- 2026-10-24 — **Errors and logs:** DB availability failures → 503 `service_unavailable` + `Retry-After: 30`; other DB errors → 500 (bugs, not outages). DB errors are logged by class/SQLSTATE only (driver errors carry SQL and parameters); the logger redacts sensitive keys and credential-looking text.
- 2026-10-24 — **CI security:** `security.yml` (npm audit: high+ prod / critical dev; pip-audit; gitleaks CLI with pinned checksum; weekly), actions pinned to SHAs, Dependabot weekly with 14-day cooldown, lockfile drift check. **certifi** PYSEC-2026-4320 exception until 2026-11-03 (fix release too new for the 14-day rule).
- 2026-10-24 — **Red-team result:** no high/medium defects. One low (asset-owner existence oracle on `GET /domains/:id/software`) fixed via `assertDomainVisible`. The route matrix enumerates every registered route and fails when a new route lacks an access expectation.

- 2026-10-23 — **Scheduled active scans** (design §6 default schedules): off by default; an admin (`scan_policies:manage`, audited) enables Quick or Standard every 1–30 days in Settings → Scan profiles. Only monitored domains currently authorised for active scanning, only while `ACTIVE_SCANNING_ENABLED` is on; staggered by domain-id hash, ≤ 30 jobs per cron run, priority 220 (behind manual 100 and passive 200). Each job re-checks authorisation under a row lock and uses the normal target rules. Any earlier job of the profile (manual too) counts toward the interval.
- 2026-10-23 — **Implicit apex approval by the scheduler** is recorded with the admin who last saved the schedule as `approved_by` (the schema requires a user); the audit row is a system action with `trigger: schedule` and `onBehalfOf`. Without such a user no apex is approved implicitly and the domain is skipped (`no_targets`).

- 2026-10-23 — **Exposed-software monitoring uses public feeds, not nocvault-eol/secvault** (both cover network/firewall gear only): endoflife.date API v1 (release cycles), CISA KEV (known-exploited CVEs, word-boundary alias pre-match), NVD CVE API 2.0 (affected ranges of those KEV CVEs, 5 lookups per cron run, 20 with optional `NVD_API_KEY`). Feeds sync from the 5-minute cron, each isolated, fetched over HTTPS from three allow-listed hosts with timeouts, size caps and zod validation; errors stored as short classes.
- 2026-10-23 — **Software is parsed server-side from existing evidence** (HTTP `Server`/`X-Powered-By`, Nmap product/version) — no worker change. Catalogue of 16 products (`packages/shared/src/domain/software.ts`); unknown tokens ignored; distribution markers (Ubuntu, Debian, RHEL…) recorded as backport hints. HTTP sightings are located by hostname only (CDN addresses rotate).
- 2026-10-23 — **Rules SOFT-001 (end-of-life software) and SOFT-002 (version possibly affected by a CISA KEV CVE)**: fingerprints exclude the version; SOFT-001 medium (high when EOL > 365 days for key web products or service identification); SOFT-002 high (critical for CVSS ≥ 9 or ransomware-associated); confidence low when a distribution is named. Resolve only when the same location reports a non-affected version; a hidden version or missing product is unknown and never resolves. Both allow manual resolution after verifying a backport. Findings refresh on the next scan, not when feeds change.

- 2026-10-23 — **User administration** (`users:manage`): adding a user pre-provisions email + role (the person must also be allowed by the Cloudflare Access policy; identity binds on first sign-in). Guards: no self role change/deactivation; the last active admin can never be demoted or deactivated (active-admin rows locked before counting, so concurrent demotions serialise). Deactivated users are refused on every request (their Access session may remain until it expires).
- 2026-10-23 — **Reports:** `GET /reports/summary` is pure SQL aggregation (eight fixed statements). Asset owners see only their visible findings; domain-level sections are empty for them. Expiring certificates use the latest successful TLS observation per hostname from the last 90 days (hosts no longer scanned don't stay "expired" forever). Trend "resolved" counts only findings still resolved.
- 2026-10-23 — **CSV export** (`reports:generate`, ≤ 5000 rows, `X-Truncated`), formula-injection prefixing and RFC 4180 quoting, audited `report.exported`. The UI downloads with fetch + blob so errors, truncation and an expired Access session are reported in the page.
- 2026-10-23 — **Charts are hand-written SVG** (no chart library; bundle 668 kB / 188 kB gzip), with a data-table alternative; severity colour only via `SeverityBadge`.
- 2026-10-23 — **Asset owners** are set per asset (`PATCH /assets/:id`, `assets:approve`, audited); asset-owner users see only their assets and those assets' findings.
- 2026-10-23 — **Page states:** permission-denied (403) empty states, Retry on load errors, and a stale-data notice that keeps the last data visible when a reload fails.

- 2026-10-23 — **Workers Standard (paid) plan** in place (owner): the 10 ms CPU limit no longer applies (default 30 s per request).
- 2026-10-23 — **Milestone order changed (owner):** exposed-software / vulnerability monitoring (see Future enhancements) becomes Milestone 11, right after frontend integration; production hardening moves to Milestone 12 (its kickoff prompt keeps the file name `docs/prompts/11-production-hardening.md`).
- 2026-10-23 — **Discovery runs in the Python worker**, not the Cloudflare Worker: crt.sh responses can be tens of MB (far beyond the 10 ms CPU budget) and all outbound collection stays on one host. `discovery` is a passive check (never contacts target hosts) with its own profile and job type (`discovery`), requested via `POST /domains/:id/discovery` or scheduled weekly (priority 250, ≤ 50 per cron run, staggered over 7 days by domain-id hash). It is never offered as a scan profile.
- 2026-10-23 — **Provider abstraction, first provider crt.sh:** fixed HTTPS URL, verified TLS, no redirects, no env proxies, identifying User-Agent, ≥ 3 s between requests, 32 MB streamed cap (incremental parser keeps complete entries → `partial`), certificates kept only if valid within the last 365 days. Transient failures (timeouts, 429/5xx) → retryable job failure; malformed responses → one `error` observation for the domain (run known incomplete).
- 2026-10-23 — **Candidate pipeline:** lowercase, trailing dot stripped, leading `*.` stripped and flagged (`wildcard_only` while every sighting was a wildcard), other `*`/emails/IPs/underscores/invalid labels dropped, IDNA 2008 + UTS #46 (`idna` package) with round-trip, exact label-boundary check (worker and server), dedupe, cap 2000 (sorted by depth then name), the first 300 resolved (A/AAAA/CNAME) via public resolvers.
- 2026-10-23 — **Discovered names are `pending` assets; ingestion never changes an asset's status.** Approval (admin, `assets:approve`, reason, audited) is the only way into scan scope; approving turns asset monitoring on, reject/suspend turn it off. Suspending flags in-flight active jobs for cancellation and refuses further active evidence about the asset. Transitions: pending → approved/rejected, approved → suspended, suspended/rejected → approved; the apex is never rejectable.
- 2026-10-23 — **Third-party hosting policy:** a deterministic CNAME-suffix table (`HOSTING_PROVIDER_SUFFIXES`, ~40 CDN/cloud/PaaS/SaaS providers) labels assets; approving one with a hint requires `acknowledgeThirdPartyHosting` (approval allows browser-like web checks only; network checks still need an approved network, and the worker still refuses out-of-scope CNAME targets).
- 2026-10-23 — **An asset decision immediately resolves its ASSET-001 finding** (history `asset_decided`), under the same per-domain lock as evaluation so a racing evaluation cannot reopen it.

- 2026-10-22 — **Finding lifecycle transitions** are one table in `packages/shared/src/domain/finding-lifecycle.ts`, enforced by the API and used by the UI. Analysts triage/accept risk/reopen; asset owners (`findings:remediate`) only start or pause remediation on findings they can see; viewers nothing. `resolved` is terminal by hand: a recurrence observed by a successful scan reopens it.
- 2026-10-22 — **Manual resolution only for change-detection rules** (`Rule.manualResolution`: DNS-001, REG-002, EXP-001) whose condition can never become "absent"; every other finding resolves only through a successful scan (hard rule). Users ask for a **Re-check** instead (`POST /findings/:id/reassess`, cheapest profile running the rule's checks, normal scan authorisation applies).
- 2026-10-22 — **Accepted risk:** reason ≥ 10 chars, the acting user is the approver, review date required and ≤ 366 days (UI default 90). The 5-minute cron reopens lapsed acceptances (`accepted_risk_expired`, system audit). Resolution or recurrence clears the acceptance.
- 2026-10-22 — **Optimistic concurrency:** PATCH carries `expectedStatus`; a finding changed meanwhile (user or scan) → `409 conflict` with `details[0].path = expectedStatus` and nothing changes. Error codes stay within the shared `ERROR_CODES`; the specific cause is in `details[0].path`. Evaluation now locks the findings it touches (`FOR UPDATE`) so history never records a stale "from" status.
- 2026-10-22 — **History reasons are codes** (`detected`, `recurrence`, `condition_absent`, `accepted_risk_expired`, `manual`); a user's explanation goes in `note`. Remediation notes are a separate append-only `finding_comments` table (production role: INSERT/SELECT only).
- 2026-10-22 — **Bulk triage** (`POST /findings/bulk`, ≤ 500 ids) for the 339-domain portfolio, set-based (few statements) to stay within the Workers CPU budget; per-finding skip reasons returned.
- 2026-10-22 — **Vitest capped at 2 workers** (PGlite per file; the default one-per-core run exhausted memory and killed other sessions on the scan host).
- 2026-10-22 — **Hyperdrive query caching disabled** (owner-approved): cached reads showed stale state for up to 60 s, including authorisation/kill-switch re-checks.
- 2026-10-22 — **Workers free plan CPU limit (10 ms/request) observed in production** with 339 monitored domains: result uploads and some page loads fail with `exceededCpu` and are retried. Recommended Workers Paid ($5/month) — owner decision pending. Moving to another host was considered and rejected (Access, Hyperdrive, cron rework).

- 2026-10-22 — **Rules engine (`packages/rules`) is pure and deterministic:** rules return findings plus the components they CHECKED with successful evidence; only checked-and-absent components resolve; rules lacking successful evidence are skipped (neither raise nor resolve); a throwing rule produces nothing. Fingerprint `ruleId|domainId|hostname|component`. Risk model v1 = severity weight (5/25/50/75/95) × exposure (public record 0.8, web 1.0, network service 1.1) × criticality (0.7/0.85/1.0/1.15), clamped 0–100, inputs stored.
- 2026-10-22 — **23 rules**: the 14 from design §8 plus DNS-005 (no DNSSEC), DNS-006 (no CAA), DNS-007 (DMARC `p=none`), TLS-005 (untrusted chain), HTTP-001…005 (no HTTPS, no HTTP→HTTPS redirect, no HSTS, missing headers, version disclosure). `docs/advisory-rules.md` is generated from the registry (`npm run rules:docs`; CI fails on drift).
- 2026-10-22 — **Change rules (DNS-001, REG-002) do not auto-resolve** (the baseline moves with every scan); they stay open until reviewed (Milestone 8 workflow). EXP-001 only flags a port the previous scan actually checked.
- 2026-10-22 — **Findings belong to a domain** (`domain_id`, `hostname`, `component`, `category`; `asset_id` optional, SET NULL on asset deletion) — most evidence today is domain-level (DMARC, registration).
- 2026-10-22 — **Evaluation** runs per succeeded job, once (`scan_jobs.rules_evaluated_at`), in job-completion order per domain (advisory lock + deferral), immediately after results (best effort) and by the 5-minute cron (guaranteed). Timestamps use the job's completion time. Existing statuses (acknowledged, accepted risk…) are preserved on refresh; recurrence reopens the same row (`recurrence`); accepted-risk findings resolve when the condition is gone.
- 2026-10-22 — **Worker requests both `https://` and `http://`** for each target (as a visitor typing the name), so HTTP→HTTPS redirect behaviour is observed.
- 2026-10-22 — **Overview shows live data now** (pulled forward from Milestone 10) and the Domains list has **bulk monitoring** (`POST /domains/monitoring`), at the owner's request (339 domains).

- 2026-10-22 — **SECURITY GATE (Milestone 6): PASSED.** Scope validator implemented and tested (worker `policy.py`/`net.py`, server re-validation), two independent red-team reviews (worker 497 + server 500 attack tests, kept in the suite), all Critical/High/Medium findings fixed, and a real end-to-end active scan behaved as designed (below). Active scanning may now be enabled — in production only with the owner's explicit approval (server `ACTIVE_SCANNING_ENABLED` + worker `EXDV_ACTIVE_SCANNING_ENABLED`).
- 2026-10-22 — **Tiered third-party policy (owner decision):** browser-like web checks (TLS handshake, HTTP GET) may reach any public address of an in-scope hostname; network checks (ports, service identification, TLS configuration) only admin-approved networks (`approved_networks`, reason + review date ≤ 24 months, audited; IPv4 ≤ /16, IPv6 ≤ /32, never overlapping prohibited space).
- 2026-10-22 — **Port scanning with Nmap `-sT` (owner decision):** TCP connect, `--unprivileged`, fixed argv templates from profile data only, explicit validated IPs, `-n -Pn`, rate/parallelism/host-timeout caps, 2 MB output cap, rlimits via an exec stub, process-group kill. `-sV --version-light` runs Nmap's "version" NSE category (46 scripts on 7.94, none intrusive).
- 2026-10-22 — **Redirects:** never automatic; followed only to http/https on default or original ports and only to approved target hostnames; out-of-domain → `redirect_out_of_scope`, unapproved in-domain → `redirect_not_approved_target`, recorded but never contacted.
- 2026-10-22 — **Kill switches act mid-job:** heartbeat/results re-check authorisation; revoking/lapsing a domain flags its in-flight active jobs; heartbeat returns the effective approved networks (scope only shrinks).
- 2026-10-22 — **Home self-protection:** the worker always denies its own interface addresses/IPv6 /64s and its egress IP (DNS `whoami.cloudflare`); unknown egress IP + empty `EXDV_DENY_NETWORKS` → active checks refused (fail closed).
- 2026-10-22 — **Out-of-scope CNAME targets are always refused** (no "separately approved CNAME" mechanism yet) — sites behind third-party CNAMEs get passive data only for now.

- 2026-10-22 — **Milestone 5 built by four parallel agents** (server ingestion, Python worker, deployment/docs, UI) after I fixed the shared contract first: `packages/shared/src/api/observations.ts` + `docs/worker-protocol.md`, with an RFC 8032-based signing test vector asserted by both the TypeScript and Python test suites.
- 2026-10-22 — **Observations ride on `results` submissions**, ingested in the same transaction after the idempotency row (duplicates store nothing); row ids `jobId:resultId:index`. DNS hostnames must be within the job's domain on a label boundary; registration only for the apex target; `observedAt` within −7 days/+5 min of server time. The newest successful RDAP observation updates the domain's registrar/dates/status (never regressing; `unavailable` doesn't erase known data).
- 2026-10-22 — **Worker DNS defaults to public resolvers** (1.1.1.1, 9.9.9.9 + IPv6), not the host stub: systemd-resolved answered DS/DNSKEY with SERVFAIL in the end-to-end run, and records should be seen as the internet sees them. `EXDV_DNS_RESOLVERS=system` opts back in.
- 2026-10-22 — **Worker runtime deps** pinned (≥14 days old): httpx 0.28.1, dnspython 2.8.0, cryptography 50.0.2 (+ transitive). No Nmap; network-connecting checks (`tls_checks`, `http_checks`, `port_checks`) only raise the scope error until Milestone 6.
- 2026-10-22 — **Deployment:** systemd unit with a dedicated system user, `LoadCredential=` for the root-owned private key, no capabilities, `IPAddressDeny` for private/LAN ranges (allowing the local DNS stub), strict sandboxing (offline `systemd-analyze security` 1.2); optional hardened Docker image (non-root, read-only). The worker reaches the app through a Cloudflare Access **service token** with a Service Auth policy (configured by the owner 2026-10-22).

- 2026-10-22 — **Worker authentication uses Ed25519 request signatures, not HMAC.** The spec asked for credentials "stored hashed" and "HMAC-signed requests", which conflict (HMAC verification needs the secret). With Ed25519 the server stores only public keys, so nothing in the database can impersonate a worker. Signing string `EDV1\nMETHOD\npath\ntimestamp\nnonce\nsha256(body)`, ±300 s window, single-use nonces (DB primary key), 120 requests/min per key, keys expire (≤730 days), rotate (several active keys) and revoke. Small-order public keys are rejected.
- 2026-10-22 — **Fencing token = attempt number.** Heartbeat/results/failures must quote the attempt returned by claim; a worker that lost its lease is refused (409). No extra column needed.
- 2026-10-22 — **Profiles seeded by migration** (`passive`, `quick`, `standard`, `deep`) and validated with `scanProfileConfigSchema` on every read (an invalid stored profile is ignored = fail closed). `passive` (DNS + RDAP only) never contacts target hosts, so it runs for any domain (owner decision on verification).
- 2026-10-22 — **Active scanning is refused server-side** (`ACTIVE_SCANNING_ENABLED=false` in `wrangler.jsonc`) until Milestone 6, both at job creation and again at claim time; active jobs are also re-checked against the domain's current authorisation at claim time.
- 2026-10-22 — **One queued/active job per domain and profile** (partial unique index) instead of idempotency keys on create: duplicate clicks and overlapping schedules collapse.
- 2026-10-22 — **Domain verification approves the apex as an asset** (audited `asset.approved`, basis `domain_verification`) when the first active scan is requested; a rejected/suspended apex is never re-approved implicitly.
- 2026-10-22 — **No Cloudflare Queues:** the worker polls `claim` (state stays in Postgres; avoids another resource). **Cron Trigger every 5 min** runs lease reaping, verification expiry, nonce pruning and the daily passive scheduler (23 h interval, 200 domains per run, priority 200 behind manual scans).
- 2026-10-22 — Retries: max 3 attempts, backoff 60 s × 2^(attempt−1) capped at 30 min; non-retryable errors fail immediately; `complete: true` marks unreported targets `failed/not_reported` (never "checked").

- 2026-10-22 — **Verification gates only active scanning (owner decision).** Passive monitoring (public DNS, certificates, CT logs, registration data) is allowed for every domain; monitoring no longer requires verification. Milestones 4–6 must require `verification_status = 'verified'` (either method, review date not passed) before any active scan.
- 2026-10-22 — **Second verification method: administrator authorisation (owner decision)** for owned domains whose DNS cannot carry a TXT record (317 of the 339 portfolio domains use the registrar's CSC DNS). Requires `domains:verify`, a reason (≥10 chars), optional reference, review-by date (default 12 months, max 24); audited per domain; labelled "Authorised (admin)" everywhere, distinct from "Verified (DNS)"; lapses on the review date. Available per domain, in bulk from the list, and as an option on CSV import.
- 2026-10-22 — **Revocation** of either method with a mandatory reason (`revoked` status); re-verification is allowed afterwards.
- 2026-10-22 — **Bulk writes are set-based** (one statement per step + one multi-row audit insert): 339-domain import with authorisation went from 66 s to 1.4 s against Neon.
- 2026-10-22 — **Portfolio import file** built from the CSC export with only `domain`, `criticality` (`Vital Domain` = Yes → high, else medium) and `business_owner` (`Business Unit`). Registrant/admin/tech contact data is deliberately not imported. Registration and expiry dates in the export are not imported either; RDAP collection will supply verified values.
- 2026-10-22 — `punycode` is imported from its ES-module file (`punycode/punycode.es6.js`): the CommonJS entry broke the local workerd dev runner, and `punycode/` broke plain Node ESM.

- 2026-10-22 — **Only registrable domains (eTLD+1) can be registered**; subdomains are rejected with a suggestion (they become assets later). PSL via `tldts` 7.4.17, ICANN section only: private-section suffixes (`github.io`, `workers.dev`), unknown/special-use TLDs and `.arpa` are rejected.
- 2026-10-22 — **IDN handling:** WHATWG URL (UTS #46) produces A-labels; ASCII input is pre-filtered to `[a-z0-9.-]` first so percent-encoding and numeric IP shorthands never reach the parser; `xn--` labels must round-trip. Canonical A-label is shown first; Unicode form is secondary; mixed-script labels are flagged (`mixed_script`) but allowed, because DNS verification proves control anyway.
- 2026-10-22 — **Verification by DoH from the Worker** (Cloudflare `dns-query` JSON), not a worker job: one passive query to a public resolver, no scanning infrastructure needed. Record `_exdomainvault-challenge.<domain>` TXT `exdomainvault-verification=<token>`.
- 2026-10-22 — **Challenge secrecy:** 256-bit token shown once, SHA-256 stored (no pepper: the token is high-entropy). Lost value → issue a new challenge (old one `superseded`). **72 h expiry**, applied lazily on reads/writes and audited as a system action. Checks throttled to one per 10 s per challenge (atomic UPDATE). Failed checks are audited (`domain.verification_failed`).
- 2026-10-22 — **Monitoring can only be enabled on verified domains** (409 otherwise). Turning it on/off requires a UI confirmation. Monitoring has no scanning effect until later milestones.
- 2026-10-22 — **Permissions unchanged:** domain create/edit/import need `domains:write`, verification `domains:verify` (admin only today); analysts and viewers read. Asset owners have no domain access.
- 2026-10-22 — **CSV import is stateless:** preview returns the file's SHA-256; confirm must send the same file + digest, is re-validated, inserts only valid rows in one transaction (`ON CONFLICT DO NOTHING`). Unknown/repeated columns block the whole file. Limits 1000 rows / 256 KB.
- 2026-10-22 — `revoked` verification status exists in the schema but nothing sets it yet.

- 2026-10-22 — **Production deployed** to `exdomainvault.amrin78.workers.dev`, protected by the Worker's Access tab (All traffic, owner-only Allow policy). Preview URLs disabled so no unprotected alternate hostname exists.
- 2026-10-22 — **`exdomainvault_app` created with SQL, not the Neon CLI/console** — those add `neon_superuser` membership (read/write all data, CREATEROLE, BYPASSRLS).
- 2026-10-22 — **`BOOTSTRAP_ADMIN_EMAILS` is a Worker secret**, not a `wrangler.jsonc` var, so the owner's email is not committed. Access team domain and AUD are committed (public identifiers).
- 2026-10-22 — **Migrations: drizzle-kit `generate` only; applied by `scripts/migrate.ts`** (drizzle-orm migrator). Guarded: refuses `NEON_BRANCH=production` without `ALLOW_PRODUCTION_MIGRATION=yes`, and pooled URLs. TLS mode forced to `verify-full`.
- 2026-10-22 — **Schema work happens on Neon branch `dev`** (from `neon.ts`, 7-day TTL); `production` stays empty until the owner approves migrating it.
- 2026-10-22 — **DB tests use PGlite** (PostgreSQL in WASM) with the real migrations — no Docker or local Postgres needed, runs in CI.
- 2026-10-22 — **Auth: Cloudflare Access JWT verified in the Worker** (jose, RS256, issuer + AUD + expiry, JWKS cached per isolate); header or `CF_Authorization` cookie. Service tokens rejected for user sessions. Dev provider is a fixed server-side identity, refused when `APP_ENV=production`.
- 2026-10-22 — **Unconfigured auth → 503 on all protected routes** (health still reports `auth: not_configured`). Unknown API paths also require auth.
- 2026-10-22 — **User provisioning:** authentication never auto-creates users except emails in `BOOTSTRAP_ADMIN_EMAILS` (become admin, audited). Pre-provisioned emails bind their subject on first sign-in; an email already bound to another subject is denied.
- 2026-10-22 — **Permissions** defined in `packages/shared` (18 permissions, 4 roles). Asset-owner object-level scoping is enforced per endpoint as those endpoints are built.
- 2026-10-22 — **CSRF:** unsafe methods require `Origin` equal to the request origin (Access session is cookie-based).
- 2026-10-22 — **Findings recurrence** modelled per CLAUDE.md: partial unique index on `fingerprint WHERE status <> 'resolved'` plus `recurrence_count` and status history.
- 2026-10-22 — **Worker credentials not modelled yet** (no secrets in `worker_registry`); HMAC key storage is designed in Milestone 4.
- 2026-10-22 — `typecheck` uses per-project `tsc -p` (not `tsc -b`), after build-mode reported a stale pass once.
- 2026-10-22 — **Neon linked**: project `ExDomVault` (`flat-sound-26073660`), branch `production`, via `neon init` + `neon deploy` (no policy changes). Credentials in git-ignored `.env.local`.
- 2026-10-22 — **DB driver: `pg` (node-postgres) + Drizzle through Cloudflare Hyperdrive**, per Neon's agent-skill guidance and Cloudflare's Neon guide. Hyperdrive's origin is Neon's direct endpoint; the Worker opens one client per request. `@neondatabase/serverless` not used.
- 2026-10-22 — Local dev reaches Neon through the Hyperdrive binding's local connection string (`DATABASE_URL_UNPOOLED` → `CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE`, set in `vite.config.ts`).
- 2026-10-22 — Neon tooling (`neon` CLI global; `@neon/config`, `@neon/env` as root devDependencies). `neon.ts` holds the branch policy (non-default branches expire after 7 days).
- 2026-10-22 — **npm workspaces** chosen as the single package manager (pnpm not installed; npm 11 available).
- 2026-10-22 — **Hono** for Worker API routing: small, Workers-native, typed context, easy to test via `app.request()`.
- 2026-10-22 — SPA and API live in one Worker (`apps/web`): `src/` = UI, `worker/` = API. Matches Cloudflare's React + Vite template; responsibilities stay in separate directories.
- 2026-10-22 — TypeScript pinned to `~6.0` (typescript-eslint 8.72 supports `<6.1`; TS 7 not yet supported).
- 2026-10-22 — API tests run the Hono app in Node (Vitest) rather than in workerd; revisit `@cloudflare/vitest-pool-workers` in M2 when bindings (Hyperdrive) exist.
- 2026-10-22 — Client-supplied `X-Request-Id` is ignored; the server always generates the request ID.
- 2026-10-22 — npm 11 blocks install scripts by default; `esbuild` and `workerd` are explicitly allowed in root `package.json` `allowScripts`.
- 2026-10-22 — Deploy target is Cloudflare Workers; `netlify.toml` from the design layout is not used.
- 2026-10-22 — Resolved findings that recur are reopened (same fingerprint) with a status-history entry `reason = recurrence`.

## Operator actions required

_Things only the owner can do (Cloudflare account, Neon project, Access app, secrets). Add exact steps as they arise._

- [x] ~~Install Python venv support on the scan host~~ — done 2026-10-22; `npm run worker:install` / `worker:lint` / `worker:test` verified locally (18 pass).
- [x] ~~First production deploy~~ — done 2026-10-22: production migrated, `exdomainvault_app` + grants, Hyperdrive, Access, bootstrap admin signed in (details in `docs/deployment.md`).
- [ ] Optional: replace the shared `demo-allowlist` Access policy with a dedicated ExDomainVault policy.
- [ ] Optional: delete the `BOOTSTRAP_ADMIN_EMAILS` secret now that the first admin exists.
- [x] ~~Cloudflare Access service token + Service Auth policy for the worker~~ — done by the owner 2026-10-22.
- [x] ~~Install the worker on this host~~ — done by the owner 2026-10-22 (`install.sh`, key registered as `home-worker-01`, service token in `worker.env`, systemd unit enabled).
- [x] ~~Install Nmap on the scan host~~ — done 2026-10-22 (7.94).
- [ ] **After the Milestone 9 deploy:** on the scan host, `git pull && sudo bash worker/deploy/install.sh`, add `discovery` to `EXDV_PROFILES` in `/etc/exdomainvault/worker.env` (e.g. `EXDV_PROFILES=passive,discovery,quick,standard,deep`), then `sudo systemctl restart exdomainvault-worker`. Outbound HTTPS to `crt.sh` must be allowed.
- [x] ~~Upgrade to Workers Paid~~ — done by the owner 2026-10-23 (Standard plan; verified: a request using 15 ms CPU completed `ok`).
- [x] ~~Production migrated to 0005 and `finding_comments` made append-only for `exdomainvault_app`~~ — done 2026-10-22 (verified: INSERT, SELECT only).

- [x] ~~NVD API key~~ — set as Worker secret `NVD_API_KEY` 2026-10-23.

- [ ] Enable GitHub Dependabot alerts/security updates, secret scanning and push protection (repo Settings → Code security).
- [ ] Create the Cloudflare Monitor on `worker_outage_started` and test it once (docs/operations.md).
- [ ] Delete the `BOOTSTRAP_ADMIN_EMAILS` Worker secret.
- [ ] Neon backups: move to the Launch plan (7-day PITR + snapshots) or run a weekly `pg_dump` (install `postgresql-client-18`); run the restore drill in docs/backup-restore.md once.
- [ ] Bump certifi to 2026.10.19 on/after 2026-11-03 (CI fails then otherwise).
- [ ] Rotate the Access service-token secret shown in a screenshot on 2026-10-23.

## Future enhancements (owner requests)

- **Exposed software / vulnerability monitoring** (asked 2026-10-22, re CSA alert AL-2026-151 "PHP2Shell", CVE-2026-109618/-109619). Approach agreed in principle, not scheduled: the worker records product/version fingerprints it already sees (HTTP `Server`/`X-Powered-By`, cookies, TLS, limited service identification) with confidence levels (M5–6); deterministic rules for EOL versions, version disclosure and advisory matches reported as "possibly affected — verify" (M7); feed data (CISA KEV + a web-stack CVE/EOL feed, ideally published by nocvault-eol, which already serves Ed25519-signed EOL and firewall-CVE feeds) after M11. Caveats: distro backports keep old version strings, hidden banners mean "unknown" never "not affected", no exploit or vulnerability probing.

- **Built-in intelligence (deterministic "AI")** (asked 2026-10-22). Our own explainable logic, no LLM, every output traceable to evidence and a versioned rule (fits CLAUDE.md: severity only from deterministic rules). Builds on Milestone 7 (rules) and 8 (lifecycle):
  - _Correlation:_ group related findings into one issue (e.g. 40 parked CSC domains all missing DMARC → one portfolio-wide recommendation; a cert expiring on a hostname that also serves HTTP without HSTS).
  - _Change detection and baselines:_ diff each scan against the previous successful one (new open port, nameserver change, MX change, certificate issuer change, new subdomain) and flag deviations from a domain's own history.
  - _Prioritisation:_ risk score from stored inputs (asset criticality, exposure tier, exploitability signals such as KEV listing, time open, recurrence), kept separate from severity; a ranked "fix this first" list with the reasoning shown.
  - _Recommendations engine:_ rule-driven advisories with concrete remediation steps, templated per provider where detectable (e.g. CSC-managed DNS, Cloudflare), grouped into playbooks.
  - _Portfolio insights:_ coverage and hygiene scores per business unit (DMARC/SPF/DNSSEC/CAA adoption, expiry runway, registrar lock), trends over time.
  - _Explainability:_ every finding/recommendation shows "why": the observations, rule id/version, inputs to the score, and what would resolve it.
    Fits after Milestone 8; parts (change detection, correlation) can start in Milestone 7.

- **Kept in view (owner, 2026-10-26; not scheduled):** suggested next milestones — (13) notifications (email/Teams/Slack webhook, digest, outage alert), remediation SLAs with due dates/overdue and MTTR reporting, scheduled executive reports; (14) per-asset change timeline, lookalike/typosquat domain monitoring (passive), subdomain-takeover fingerprint confirmation for DNS-002, deterministic domain/business-unit score; later: Jira/ServiceNow ticketing, scoped read-only API tokens for SIEM, Access group → role mapping. Email delivery needs an owner decision on a provider (e.g. Resend).

## Known limitations

- Neon `dev` branch expires 2026-10-29; recreate with `neon checkout dev --create && npm run db:migrate`.
- A positive DNS TXT verification has only been tested with a mocked resolver (needs a domain whose DNS you control); administrator authorisation was exercised end to end on the Neon `dev` branch with all 339 portfolio domains.
- Local dev connects as the Neon owner role (`neondb_owner`); production uses `exdomainvault_app`.
- No deploy workflow; deploys are manual `wrangler deploy` with owner approval.
- No domain deletion, no rate limit on domain creation beyond permissions.
- Discovery: crt.sh is the only provider and is often slow or erroring for large domains (retried, then failed); its live response format was not tested against the real service. Only the first 300 candidates per run are resolved. Hosting hints see only the CNAME chain (A-record-only third-party hosting is not detected). The asset detail page does not show services/TLS yet.
- ASSET-001 creates one informational finding per pending candidate; on a large portfolio expect many (bulk-approve/reject on the Assets page resolves them).
- Scheduled active scans cover Quick or Standard (one profile at a time); Deep stays on request.
- Finding history timestamps: system entries use the scan's completion time, user entries wall-clock time, so a delayed evaluation can sort before a user change (each entry's "from" status is still correct).
- Assignment notifications (email etc.) are not implemented; assignment is visible in the UI and filterable (`assignee=me`).

## Session log

_Per milestone: files changed, checks run (with real results), limitations, next step._

### Collapsible pages — 2026-10-26

**Why:** owner feedback that the domain page is too long. `Card` gained `collapsible` (open/closed remembered per card type in localStorage `exdv.card.<key>`), `defaultOpen` and a one-line `summary` shown while collapsed; `useCollapseAll` adds Expand all / Collapse all; `useShowAll` limits long lists. Applied to domain detail (reordered: Findings, Software, Assets first; others collapsed by default), finding, asset and scan detail, Overview, Reports and Settings → System health. Presentation only, no API changes.

**Checks:** lint, typecheck, db:check, rules:docs:check pass; `npm test` 94 files / 2809 tests pass; build pass; worker:test 1515 pass.

**Production (owner-approved):** deployed version `44fa5d23-4cd5-4827-a481-f969d22ae2a4`.

### Host import — 2026-10-26

**Why:** the owner's thaiunion.com zone export (22 Jan 2026) lists 115 host names; only 8 were known assets (CT discovery found 9 incl. two newer `claudepoc` hosts).

**Files:** `packages/shared/src/api/asset-import.ts` (+ test), `apps/web/worker/services/asset-import.ts`, `routes/domains.ts`, `routes/asset-import.test.ts`, `testing/route-matrix.ts`, `validation.hardening.test.ts`; UI `src/lib/{xlsx,csv-parse,host-file}.ts` (+ tests), `pages/domains/AssetImportPage.tsx` (+ test), `components/assets/DomainAssetsCard.tsx`, `pages/assets/AssetsPage.tsx`, `routes.tsx`, `lib/api.ts`; `docs/api-specification.md`.

**Checks:** lint, typecheck, db:check, rules:docs:check pass; `npm test` 94 files / 2796 tests pass; build pass; worker:test 1515 pass. The XLSX reader parsed the owner's real file: 175 rows → 115 unique hostnames (44 non-host records, 13 service names skipped).

**Production (owner-approved):** deployed version `7693b910-c0db-4d8d-bea5-609b4d98491f` (no migration).

**Limitations:** imported hosts get IPs/hosting data only after approval (passive DNS covers approved assets); a hosting hint relies on the file's CNAME until then.

### Milestone 12 — 2026-10-24

**Built (contract first, then four parallel agents: server, tests/red team, CI/docs, UI):** contract `packages/shared/src/api/ops.ts`. Server: rate-limit middleware + bindings, `services/quotas.ts`, `services/ops.ts` + `routes/ops.ts`, `services/retention.ts`, logger redaction/`child()`, DB error mapping, `public/_headers` CSP. Tests: route authz matrix (552), validation hardening (217), object-level tenancy matrix, Access JWT attacks, worker protocol/lease/idempotency, secret scanning of repo and bundle, migration verification, Python scope property tests (124). CI: `security.yml`, pinned actions, Dependabot, lockfile check. UI: Settings → System health, global ops alert banner, 429 messages, CSP-safe bars. Docs: deployment (deploy + rollback), backup-restore (Neon Free plan: 6 h PITR), operations, troubleshooting, README.

**Checks:** `npm run lint` pass; `npm run typecheck` pass; `npm run db:check` pass; `npm run rules:docs:check` pass; `npm test` 86 files, 2623 tests pass; `npm run build` pass; `npm run worker:lint` pass; `npm run worker:test` 1515 pass. Audits: npm prod 0; npm dev 4 moderate (drizzle-kit → esbuild, no safe fix); pip-audit 1 (certifi, time-boxed exception); gitleaks full history clean after allowlisting the public Access AUD.

**Definition of done (design §17):**

1. Domain inventory and verification end to end — **met**: 339 domains imported in production; DNS TXT (mock-tested) and audited admin authorisation in use.
2. DNS, registration, TLS and HTTP observations persist in Neon — **met**: production passive scans for all monitored domains; TLS/HTTP from Quick scans (scheduled scans available).
3. Passive discovery produces deduplicated pending assets — **met**: crt.sh discovery live (owner-verified 2026-10-23); dedupe and boundary tests.
4. Approved TCP scans only within authorised scope — **met**: scope validator + tiered policy, two red-team passes, systemd `IPAddressDeny`, approved networks only for ports.
5. Findings deterministic, explainable, evidence-backed — **met**: 25 versioned rules, generated `advisory-rules.md`, evidence + risk inputs stored.
6. Failed scans never cause false resolution — **met**: evaluator only resolves checked components of succeeded jobs; tests in rules, evaluation and hardening suites.
7. Duplicate jobs/retries create no duplicate active findings — **met**: partial unique index on fingerprint, idempotent results, concurrency tests.
8. User permissions and worker authentication enforced — **met**: route matrix over every route × role, Ed25519 worker signatures with replay protection, Access JWT verification.
9. Secrets not committed or exposed to the frontend — **met**: gitleaks history scan, repo + bundle secret tests, secrets only in Worker secrets / `/etc/exdomainvault`.
10. Automated tests, deployment instructions and recovery procedures — **met**: 2623 + 1515 tests in CI; deployment/rollback, backup-restore (restore drill), operations, troubleshooting docs. Restore drill not yet executed on production by the owner.

**Owner actions:** see Operator actions (enable GitHub security features, create the outage Monitor, delete `BOOTSTRAP_ADMIN_EMAILS`, decide on Neon Launch plan or weekly `pg_dump`, bump certifi after 2026-11-03).

**Production (owner pre-approved 2026-10-24):** deployed version `de3fb4a9-5966-44a8-bd71-caaba3e19e76` together with CSV exports (no migration; rate-limit bindings `API_RATE_LIMITER` 300/60 s and `MUTATION_RATE_LIMITER` 60/60 s active). Smoke check: protected routes 302 without Access; ~6 min of live logs — 27 requests and 2 cron runs all `ok`, no warnings/errors, retention ran (0 rows due), no outage; last 24 h 526 jobs succeeded, 0 failed; software inventory 22 rows, 15 software findings so far (scheduled Standard scans enabled by the owner, daily).

**CSV exports (owner request, 2026-10-24):** `GET /exports/<resource>.csv` for domains, assets, advisories, software, scans, users, audit-logs (same filters/visibility as the lists, UTF-8 BOM, ≤ 10,000 rows with `X-Truncated`/`X-Total-Rows`, formula-injection protection, audited `report.exported`); shared `ExportCsvButton` on those pages plus domain-scoped findings/software exports. Checks before deploy: lint, typecheck, db:check, rules:docs:check pass; `npm test` 89 files, 2731 pass; build pass; worker 1515 pass.

### Milestone 11 — 2026-10-23

**Built (contracts first, then three parallel agents: rules, server, UI):** contracts — software catalogue, `api/software.ts`, migration `0007_software_intel` (software_inventory, software_eol_cycles, vulnerability_advisories, intel_feeds; findings category `software`), `SoftwareIntel` evaluation context, rules software API contract. Rules: `packages/rules/src/software/` (banner parser, version comparator, EOL cycle mapping, advisory matching), SOFT-001/SOFT-002 (25 rules total). Server: `lib/feed-fetch.ts`, `services/intel-feeds.ts` (endoflife.date, KEV, NVD), `services/software.ts`, evaluation loads intel + upserts inventory, `GET /software`, `/software/summary`, `/domains/:id/software`, `GET /intel/feeds`, `POST /intel/feeds/sync`. UI: Software page (rollup + inventory + explainer), domain Software card, Settings → Intelligence feeds, CVE/range evidence rendering, Overview tile. Docs: api-specification, architecture, threat-model (feeds as untrusted input), deployment, advisory-rules (regenerated).

**Checks:** `npm run lint` pass; `npm run typecheck` pass; `npm run db:check` pass; `npm run rules:docs:check` pass; `npm test` 68 files, 1651 tests pass (all feed tests mocked — no network); `npm run build` pass; `npm run worker:test` 1391 pass (worker unchanged).

**Limitations:** software data appears only after Quick/Standard/Deep scans (still on request); IIS/OpenSSH have no endoflife.date data; NVD `not_found`/`no_product_match` are final; summary `hosts` counts locations; feeds were verified against provider documentation, not yet fetched live.

**Production (owner-approved):** migrated to 0007 (8 migrations), `NVD_API_KEY` secret set, deployed version `cb709106-7c7d-49d5-92e4-e5cd2640f81c`.

**Scheduled active scans deployed 2026-10-23** (version `36d3d0c3-4604-45e1-90e9-b7903b20916c`, no migration; off until an admin enables it).

**Next:** Milestone 12 — production hardening.

### Milestone 10 — 2026-10-23

**Built (contracts first, then three parallel agents: server, Settings UI, Reports/Overview UI):** contracts `packages/shared/src/api/{users,audit,reports}.ts` + asset owner. Server: `services/{user-admin,audit-log,reports}.ts`, `routes/{audit-logs,reports}.ts`, users routes, asset owner PATCH, `findingFilters` shared by list and CSV. UI: Settings sections (Workers/networks, Users, Scan profiles, Audit log; `?tab=`), asset owner picker, Reports page (coverage, severity/status, 30-day trend chart, mean time to resolve, top domains, business owners, expiring registrations/certificates, accepted risks due, CSV export also from Findings), Overview asset tiles + trend, `StaleDataNotice`/`PermissionDenied`/`LoadError` across list pages, workflow tests (add + verify domain, approve asset, launch scan, update finding). Docs: api-specification (Users, Audit log, Reports, asset owner), threat-model.

**Checks:** `npm run lint` pass; `npm run typecheck` pass; `npm run db:check` pass; `npm run rules:docs:check` pass; `npm test` 61 files, 1478 tests pass; `npm run build` pass. Worker (Python) unchanged. No migration in this milestone.

**Limitations:** the business-owner table has no drill-down (no business-owner filter on findings/domains); owner picker lists ≤ 100 active users; asset detail still lacks observed services/TLS.

**Production (owner-approved):** deployed version `43af2122-641b-40a6-81f8-7d3aaf797ac7` (no migration).

**Next:** Milestone 11 — exposed-software / vulnerability monitoring.

### Milestone 9 — 2026-10-23

**Built (contracts first, then three parallel agents: Python worker, server, UI):** contracts — `discovery` check/observation, `packages/shared/src/api/assets.ts` (asset DTO, list/detail, decisions, bulk, `allowedAssetActions`, `classifyHosting`), migration `0006_asset_discovery` (asset decision columns, hosting hint, wildcard flags, `discovery` profile seed). Worker: `worker/app/discovery.py` (provider protocol, crt.sh provider, candidate pipeline, resolution, batching), queue integration, default `EXDV_PROFILES=passive,discovery`. Server: discovery ingestion → pending assets, DNS → `asset_ips` + hosting hint, weekly scheduler, `POST /domains/:id/discovery`, assets API (`services/assets.ts`, `routes/assets.ts`), suspend cancels in-flight active jobs, ASSET-001 resolution on decision, reassess for asset rules. UI: Assets page (filters, bulk decisions with third-party acknowledgement), asset detail (decision panel, IP history, sightings), domain Assets card with Run discovery, discovery jobs on Scans pages. Docs: worker-protocol, scan-safety, home-worker-setup, api-specification, database-schema, threat-model.

**Checks:** `npm run lint` pass; `npm run typecheck` pass; `npm run db:check` pass; `npm run rules:docs:check` pass; `npm test` 52 files, 1391 tests pass; `npm run build` pass; `npm run worker:lint` pass; `npm run worker:test` 1391 pass (141 new discovery tests, all mocked — nothing contacts crt.sh, resolvers or targets).

**Production (owner-approved):** migrated to 0006 (7 migrations; discovery profile seeded, asset columns present, comments grants unchanged), deployed version `d12f8709-153d-4847-8f11-bbe489747191`. Worker upgrade on the scan host pending (operator action above).

**Next:** Milestone 10 — frontend integration (remaining placeholders: Reports, Settings sections), or the proposed scheduled Quick scans.

### Milestone 8 — 2026-10-22

**Built (contracts first, then two parallel agents: server, UI):** transition matrix + requirements (`packages/shared/src/domain/finding-lifecycle.ts`), update/bulk/comment/reassess/assignable-user schemas, `Rule.manualResolution`, migration `0005_finding_lifecycle` (`finding_comments`, accepted-risk review index). Server: `services/finding-lifecycle.ts` (PATCH with row lock + `expectedStatus`, bulk set-based, comments, reassess via `createScan`, accepted-risk expiry sweep in cron), `routes/users.ts` (`GET /users/assignable`), read model with assignee/acceptedRisk/manualResolution/comments and `assignee` filter, evaluation locks findings and clears stale acceptance. UI: Workflow card (status actions from the matrix with inline reason/review-date forms, conflict handling, assignee picker, accepted-risk block, Re-check), comments, readable history, findings list assignee column/filter, row selection with bulk actions. Docs: API spec Findings section (was missing), schema, deployment (Hyperdrive caching, comments grant).

**Checks:** `npm run lint` pass; `npm run typecheck` pass; `npm run db:check` pass; `npm run rules:docs:check` pass; `npm test` 47 files, 1311 tests pass (incl. 28 server lifecycle tests covering every from/to pair for all four roles, concurrency, recurrence after manual resolve, failed scans never resolving; 26 UI lifecycle tests); `npm run build` pass. Worker (Python) unchanged.

**Production (owner-approved):** migrated to 0005 (6 migrations), `REVOKE UPDATE, DELETE ON finding_comments` verified, deployed version `9e0ed55b-59c0-4ff5-9081-2911a90486f5` on the free plan (Workers Paid still recommended). Root `vitest.config.ts` caps workers at 2 (`VITEST_MAX_WORKERS`): the default exhausted the 16 GB host's memory; full suite now 56 s, 1.4 GB peak, 1311 pass.

**Next:** Milestone 9 — passive subdomain discovery (CT logs). Proposed small follow-up: opt-in scheduled Quick scans.

### Milestone 1 — 2026-10-22

**Built:** npm-workspace monorepo; React/Vite/Tailwind SPA with persistent navigation, Overview dashboard (honest empty states, optional labelled dev fixtures stripped from prod), placeholder sections, API status indicator; Cloudflare Worker API (Hono) with request IDs, JSON logging, security headers, fail-closed config, standard error envelope and typed `GET /api/v1/health`; `packages/shared` zod contracts; Python worker skeleton with validated config; ESLint/Prettier/tsc/Vitest/ruff/pytest; GitHub Actions CI; README, `docs/architecture.md`, CLAUDE.md commands.

**Checks (all run locally):**

- `npm run lint` — pass
- `npm run typecheck` — pass
- `npm test` — 7 files, 22 tests pass
- `npm run build` — pass (fixture data confirmed absent from production JS)
- `npm run dev` — verified in workerd: `/api/v1/health` 200 with headers, unknown API path → 404 envelope, `/domains` serves SPA; UI checked in a browser
- Worker: `ruff check`, `ruff format --check`, `pytest` (18 pass) — run in a scratch venv bootstrapped without `python3-venv`; `npm run worker:install` itself not runnable here yet
- CI — first run happens on this push

### Neon wiring — 2026-10-22

**Changed:** `neon init`/`neon deploy` linked the repo (`.neon`, `neon.ts`, `.env.local`); new `packages/database` (`connect()`, `pingDatabase()` with `pg` + Drizzle); `HYPERDRIVE` binding (placeholder id) in `wrangler.jsonc`; `vite.config.ts` feeds the local Hyperdrive connection string from `.env.local`; health route pings the DB; `docs/deployment.md`.

**Checks:** lint pass · typecheck pass · 27 tests pass · build pass (no DB code in browser bundle) · dev server: `/api/v1/health` → `"database":"ok"` (~300 ms per ping to Neon) · with a deliberately wrong password → `"database":"down"`, Neon's auth error only in server logs.

**Next:** Milestone 2 — database and authentication (`docs/prompts/02-database-and-auth.md`).

### Milestone 2 — 2026-10-22

**Built:** Drizzle schema for all design §5 entities (22 tables, 17 enums, checks, partial unique indexes) + initial migration; guarded migration runner; PGlite test harness; replaceable `AuthProvider` with Cloudflare Access JWT verification and dev provider; identity → user resolution with admin bootstrap; role/permission matrix; `requireAuth` / `requirePermission`; CSRF same-origin check; per-request DB connection; audit writer; `GET /api/v1/me`; health reports real auth status; top bar shows the signed-in user; docs (`database-schema.md`, `api-specification.md`, `deployment.md` Access/roles/Hyperdrive steps, `architecture.md`).

**Checks (all run locally):**

- `npm run lint` pass · `npm run typecheck` pass (verified it catches a deliberate error) · `npm run build` pass (PGlite not in Worker bundle)
- `npm test` — 12 files, 86 tests pass (migrations + constraints on PGlite; Access JWT: valid/cookie/missing/spoofed header/wrong aud/wrong iss/expired/unknown key/no email/alg=none/tampered; user resolution; config; API auth flows; CSRF; permissions; UI user states)
- `npm run db:check` pass; `drizzle-kit generate` reports no drift
- `npm run db:migrate` on Neon `dev`: 22 tables created (PostgreSQL 18.6); re-run is a no-op; production-branch and pooled-URL guards refuse
- `npm run dev` (workerd + Neon `dev`): health `database: ok, auth: ok`; `/me` bootstrapped `dev@example.com` as admin with one `user.bootstrap_admin` audit row; CSRF 403 without/foreign Origin; Access mode unconfigured → 503, configured without token → 401, spoofed identity header → 401; dev provider with `APP_ENV=production` → 500

**Next:** Milestone 3 — domain inventory (`docs/prompts/03-domain-inventory.md`).

### Production setup — 2026-10-22

**Done (owner-approved):** Neon `production` migrated (22 tables); `exdomainvault_app` created via SQL after the CLI-created role turned out to inherit `neon_superuser` (deleted); grants verified (append-only tables enforced, no DDL/role creation); Hyperdrive `exdomainvault-db`; Worker deployed (first with auth unconfigured → `/me` 503, health `database: ok`); owner enabled Access on the Worker; `ACCESS_TEAM_DOMAIN`/`ACCESS_AUD` set, `BOOTSTRAP_ADMIN_EMAILS` secret, redeployed (version `fc72fb76`).

**Verified live:** unauthenticated `/`, `/api/v1/health`, `/api/v1/me` and a forged `Cf-Access-Jwt-Assertion` → 302 to Access login; owner signed in → UI shows Administrator, API healthy, `production`; Neon `production` has one admin user bound to the Access subject and one `user.bootstrap_admin` audit row.

### Milestone 3 — 2026-10-22

**Built:** domain normalisation + label-boundary helper (`packages/shared/src/hostname`, `tldts` + `punycode`); shared domain/pagination/import contracts; Worker routes `GET/POST /domains`, `GET/PATCH /domains/:id`, `POST /domains/:id/verification`, `POST /domains/:id/verify`, `POST /domains/import/preview`, `POST /domains/import`; services for domains, DNS TXT verification (DoH resolver, hashing, expiry, throttle) and CSV import (RFC 4180 parser); request validation helpers; audit events `domain.created|updated|monitoring_enabled|monitoring_disabled|verification_started|verification_failed|verification_expired|verified|import_completed`. UI: session/permission context, Domains list (search, filters, sort, pagination), add form, detail page (verification panel with one-time value, owner/criticality edit, confirmed monitoring toggle, registration status, empty states), CSV import with preview/confirm. Docs: `api-specification.md` (domains), `architecture.md`. No schema change, so no migration.

**Checks (all run locally):**

- `npm run lint` pass · `npm run typecheck` pass · `npm run build` pass (PSL only in the Worker bundle, 1.0 MB / 278 KB gzip; none in the browser bundle)
- `npm test` — 18 files, 215 tests pass (+58 normalisation incl. `evil-example.com`, `example.com.evil.net`, Cyrillic homograph, IDN, PSL boundaries, IP shorthands; +40 domain API incl. RBAC denials per role, duplicates, CSRF, hash-only storage, superseded value rejected, expiry at exactly 72 h vs 1 ms before, throttle, import preview/confirm/digest mismatch; DoH/CSV/hash unit tests; 11 UI tests)
- Mutation checks: disabling the throttle and the expiry sweep each made the corresponding test fail
- `npm run dev` (workerd + Neon `dev`): create (normalised), duplicate → 409, subdomain → 400 with suggestion, start verification, real DoH check → `record_not_found`, second check → `too_soon`, monitoring before verification → 409, list/search, import preview/confirm; detail page checked in a browser
- Bug found by that run and fixed: Workers `fetch` rejects `redirect: 'error'` (Node accepts it) → DoH returned `dns_error`; now `redirect: 'manual'` with redirects treated as failures (unit-tested)
- `worker:test` not run — Python worker unchanged

**Deployed** 2026-10-22 on request, version `cf062f76-4896-4c7a-be8a-50d813fbd696` (no migration needed). Unauthenticated `/`, `/domains`, `/api/v1/domains` and a forged-token POST → 302 to the Access login.

**Next:** Milestone 4 — scan job lifecycle (`docs/prompts/04-scan-job-lifecycle.md`).

### Milestone 3 follow-up: administrator authorisation — 2026-10-22

**Why:** 339 owned domains, most with registrar-managed DNS where a TXT record per domain is impractical (owner request).

**Built:** migration `0001_domain_authorisation` (new enum values, attestation fields, domain verification method/review date, backfill, checks); `services/domain-authorisation.ts` (authorise single/bulk, revoke, lapse); routes `POST /domains/:id/authorise`, `POST /domains/authorise`, `POST /domains/:id/revoke`; optional `authorisation` on import confirm; monitoring no longer gated; set-based bulk audit (`writeAuditMany`). UI: badges distinguish DNS vs admin, "Authorise without DNS" form, revoke with reason, list row selection + bulk authorise, rows per page, import "also authorise" option.

**Checks:** lint pass · typecheck pass · build pass · `db:check` pass, no drift · `npm test` 18 files / 235 tests pass (+ constraint and backfill migration tests, authorisation API incl. review-date validation, RBAC, bulk skip rules, lapse at end of review day, revoke, import+authorise and rollback, UI flows) · Neon `dev` migrated (`0001`) · rehearsal on `dev`: full 339-row portfolio import with authorisation → 339 created/authorised, 1.4 s, audit rows per domain.

**Production (owner-approved):** Neon `production` migrated with `0001` (existing `thaiunion.com` unchanged; `exdomainvault_app` has privileges on the new columns), then deployed as version `5d9dae9a-0ec1-45d8-8b3e-226db24a33e5`. Unauthenticated requests, including a forged-token POST to `/domains/authorise`, → 302 to Access.

### Milestone 4 — 2026-10-22

**Built:** migration `0002_scan_job_lifecycle` (worker credentials, request nonces, processed results, one-active-job index, seeded profiles); shared contracts for profiles, jobs, snapshots, worker admin and the signed worker protocol; services for scan creation (immutable snapshot + targets, apex approval, active gating), listing/detail/cancel, claim (`FOR UPDATE SKIP LOCKED`, lease, attempt fencing, claim-time re-authorisation), heartbeat, idempotent results, failures with bounded backoff, lease reaper, passive scheduler, nonce pruning; Ed25519 worker-auth middleware (timestamp window, nonce replay, rate limit, revocation/expiry/disabled checks); worker admin API; Cron Trigger (`scheduled` handler, every 5 min); `ACTIVE_SCANNING_ENABLED` flag. UI: Scans list and detail (auto-refresh while active, cancel), Scans card on domain detail, Settings → Workers (register key, revoke, disable). Docs: API spec, architecture, database schema, deployment, scan safety.

**Checks:**

- `npm run lint` pass · `npm run typecheck` pass · `npm run build` pass · `npm run db:check` pass, no drift
- `npm test` — 21 files, 279 tests pass (incl. 29 scan/worker API tests: one job to one worker, lease expiry → requeue with backoff → old attempt fenced, retry ceiling, non-retryable failure, duplicate result no-op, foreign target rejected, cancellation queued/running, claim-time refusal, active flag; signature tests: unsigned, tampered body, wrong key, stale timestamp, unknown key, replayed nonce, revoked/expired key, disabled worker, rate limit, user session refused; small-order key rejection; scheduler idempotency; UI tests)
- Neon `dev` migrated (`0002`); local workerd + Neon `dev`: Cron handler ran all four steps and scheduled 30 passive jobs; **40 concurrent signed claims from two workers → 30 jobs claimed, 30 unique, 10 empty (real PostgreSQL `SKIP LOCKED`)**, heartbeat, results, replayed result → `accepted: false`, other worker → 409. Test data removed afterwards.
- A unit test caught that an all-zero (small-order) Ed25519 key was accepted → now rejected.
- A parallel docs agent reviewed the code while documenting it; fixed from its findings: body limits now in bytes and 1 MB on the worker API, refused jobs' targets marked `skipped`, scheduled jobs refused if monitoring was turned off, scheduler applies the label-boundary check, duplicate-result lookup limited to the submitting worker (no status probing), final target statuses can no longer regress, UI shows lapsed authorisations, stale schema comment. Left as documented behaviour: a job completed after a cancel request ends `succeeded`; profile `default_schedule` is not used yet (only passive is scheduled); key rotation is API-only.
- `worker:test` not run — Python worker unchanged (Milestone 5).

**Production (owner-approved):** Neon `production` migrated with `0002` (profiles seeded; `exdomainvault_app` has privileges on the new tables; the owner's 339-domain import is present, monitoring off), deployed as `663d3165-211d-4998-8172-71b3eaff4e92` with the `*/5 * * * *` trigger. `wrangler tail` showed the Cron runs at 08:35 and 08:40 UTC completing all four maintenance steps through Hyperdrive. `/scans`, `/api/v1/scans` and the internal worker API without Access → 302.

**Next:** Milestone 5 — Python worker (`docs/prompts/05-python-worker.md`), split across parallel agents.

### Milestone 5 — 2026-10-22

**Built (in parallel by four agents, integrated by me):**

- _Contract:_ observation schemas (`dns`, `registration`) in worker results; `GET /domains/:id/observations` read model; `docs/worker-protocol.md`; signing test vector.
- _Server:_ `services/observations.ts` (validated, idempotent batch ingestion; domain registration update; latest-per-record read), route, 14 tests.
- _Python worker:_ `worker/app/` — config, identity, signed httpx client (retries re-sign, 409 stops work), scope guard (passive checks only, label-boundary target check), DNS checks (dnspython, rate/concurrency limits), RDAP (IANA bootstrap, redaction detection), batching, queue loop with heartbeats/cancellation/graceful SIGTERM, health file + `--health`, JSON logs with redaction; 145 pytest tests (mocked API, DNS and RDAP; no live targets).
- _Deployment:_ `worker/Dockerfile` (+ `.dockerignore`), `worker/deploy/exdomainvault-worker.service` (+ health timer), `.env.example`, `worker/README.md`, `docs/home-worker-setup.md`.
- _UI:_ Registration and DNS records cards on the domain page (expiry highlighting, redacted/unavailable wording, grouped record sets), 9 tests.

**Checks:**

- `npm run lint` pass (now also covers `apps/web/worker/` — `.prettierignore` had been excluding it; found by the server agent) · `npm run typecheck` pass · `npm run build` pass · `npm test` 23 files / 303 tests pass
- `npm run worker:install` · `worker:lint` pass · `worker:test` 145 passed
- **End to end (real Python worker → local workerd → Neon `dev`):** registered a key, requested a passive scan of `armoric.com`, `exdomainvault-worker --once` claimed, ran real DNS + RDAP lookups (public resolvers/registry only), uploaded 11 DNS + 1 registration observations, job `succeeded`; domain page showed registrar CSC, registered 1997-10-14, expiry 2027-10-13, CSC nameservers, A/MX/NS/SOA, no DMARC, no DNSSEC. Test data removed afterwards.
- Found and fixed by the end-to-end run: systemd-resolved SERVFAIL on DS/DNSKEY (→ public resolver default); `pip install .` failed because `deploy/` made setuptools see two packages (→ explicit `packages = ["app"]`, `worker:install` now installs the CLI).
- Not verifiable here: Docker image build (Docker not installed), the systemd unit under real root (`systemd-analyze verify` only).
- Deployed to production 2026-10-22 on request (no migration): version `98621b00-60c9-4d98-baee-0a6a3ea001d6`.
- Pre-install review found that `worker.env` setting `EXDV_PRIVATE_KEY_FILE` would override the unit's `LoadCredential=` path (systemd `EnvironmentFile=` beats `Environment=`) and break start-up; removed from the template and guide. Added `worker/deploy/install.sh` (idempotent; steps 2–4 + unit install; shellcheck clean).

**Production worker (2026-10-22):** first start failed `--check-config`: systemd `LoadCredential=` copies are `0440` inside the per-service credentials directory, which the strict `0600` key check rejected → fixed (`f2c57c5`: inside `$CREDENTIALS_DIRECTORY` the directory and file must be closed to others; elsewhere `0600` still required). After `install.sh` + restart the worker started, passed Access with the service token and the signature check, and completed the queued passive scan of `alstertor.info` (11 DNS + 1 registration observation; registrar CSC, expiry 2027-03-04, data status `redacted`).

**Next:** Milestone 6 — scanning and target safety (the security gate for active scanning).

### Milestone 6 — 2026-10-22 (security gate)

**Built (parallel agents on fixed contracts, then two red-team agents, two fix agents, two docs agents):** worker scope validator (`policy.py`: strict parsing, prohibited ranges incl. all IPv4-in-IPv6 forms and alternative encodings, label boundaries, CNAME hop validation, deny list, tiers, approved networks; `net.py`: pinned TCP/TLS/HTTP with manual redirect validation and bounded I/O; `self_protection.py`), active checks (TLS certificate, HTTP availability/headers, Nmap ports/service identification), server `approved_networks` (migration `0003`, admin API, audit), snapshot networks with claim-time intersection, validated ingestion of tls/http/port observations, shared prohibited-range table with a TS↔Python parity test, in-flight cancellation, UI (Settings → Approved networks; TLS/HTTP/Ports cards), `docs/threat-model.md`, rewritten `docs/scan-safety.md`.

**Checks:**

- `npm run lint` pass · `npm run typecheck` pass · `npm run build` pass · `npm run db:check` pass
- `npm test` 31 files / 1032 tests pass (incl. 500 server red-team tests) · `worker:lint` pass · `worker:test` 1250 passed (incl. 497 worker red-team tests) · `systemd-analyze verify` clean
- Red team, worker: GATE PASS (no Critical/High); Medium RT-1 (redirect to arbitrary ports), RT-2 (redirect to unapproved hosts), RT-5 (home network self-exposure) fixed, Lows fixed. Server: GATE FAIL → fixed: High F1 (in-flight jobs ignored kill switch/revocation), Medium F2–F4, Lows F5–F7.
- **End to end (real worker → local workerd → Neon `dev`, active scanning enabled locally only):** quick scan of `armoric.com` — every decision logged; TLS/HTTP connected only to the validated CSC addresses; the HTTP `301` to `meralliance.com` refused (`redirect_out_of_scope`); port 443 unanswered → recorded as `timeout` with evidence. Standard scan — port probes refused for both addresses (`network_not_approved` → `no_allowed_address`), Nmap never started. Local flag and test data removed afterwards.

**Production (owner-approved 2026-10-22):** Neon `production` migrated with `0003` (app role has privileges on `approved_networks`), deployed `2bad1d5c-e888-47eb-8308-141f455f9ece` with `ACTIVE_SCANNING_ENABLED=true`. The worker on the scan host still needs upgrading and `EXDV_ACTIVE_SCANNING_ENABLED=true` (owner, `docs/home-worker-setup.md` step 15) before active jobs run. `tls_configuration` accepted but not run.

**Next:** Milestone 7 — deterministic rules engine.

### Milestone 7 — 2026-10-22

**Built (contracts by me; four parallel agents: two rule sets, server, UI):** `packages/rules` (types, evaluator, risk model, exposure policy, registry, 23 rules with fixtures and tests, docs generator); migration `0004_findings_engine`; evaluation service (current/previous observation sets, transactional upsert/resolve/reopen with status history and advisories); findings/advisories/rules APIs with asset-owner scoping; bulk monitoring API; UI: Findings list and detail (evidence, risk explainer, advisory, resolution, history), Advisories, domain Findings card, live Overview, bulk monitoring; worker always probes http:// too.

**Checks:** lint pass · typecheck pass · build pass · `db:check` pass · `rules:docs:check` up to date · `npm test` 44 files / 1246 tests pass · `worker:lint` pass · `worker:test` 1250 passed.

**End to end (real worker → local workerd → Neon `dev`):** passive scan of `armoric.com` produced 4 accurate findings within seconds — DNS-003 no DMARC (medium, risk 40), DNS-004 MX but no SPF (low), DNS-005 no DNSSEC (low), DNS-006 no CAA (informational) — with advisories and `detected` history; a second scan kept 4 findings (first seen preserved, last seen updated), both jobs evaluated exactly once. Test data removed.

**Production (owner-approved):** Neon `production` migrated with `0004` (app role has the new column privileges), deployed `7dff53fc-b712-4607-898a-8ad90177a3fb`; the 5 earlier succeeded production jobs are evaluated by the cron. Owner next: upgrade the worker (both-schemes HTTP) and turn on monitoring for all domains.

**Next:** Milestone 8 — finding lifecycle (status workflow, assignment, accepted risk, user audit).
