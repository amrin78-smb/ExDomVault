# Worker protocol and configuration

The contract between the home scanning worker (`worker/`, Python) and the application's internal
worker API (`apps/web/worker/routes/internal-worker.ts`). Request/response shapes are the zod schemas
in `packages/shared/src/api/workers.ts` and `packages/shared/src/api/observations.ts`; this document
is the language-neutral summary the Python implementation follows.

## Transport

- Outbound HTTPS only, from the worker to `EXDV_API_BASE_URL` + `/api/v1/internal/worker/<endpoint>`.
  The worker never listens on a port.
- Every request is `POST`, `Content-Type: application/json`, body ≤ 1 MB, compact JSON.
- The application hostname is behind Cloudflare Access. When `EXDV_ACCESS_CLIENT_ID` and
  `EXDV_ACCESS_CLIENT_SECRET` are set, send them as `CF-Access-Client-Id` / `CF-Access-Client-Secret`
  (a Cloudflare Access service token). This only gets the request past Access; the application
  authenticates the worker by signature alone.
- Do not follow redirects (a redirect means Access or the URL is misconfigured; treat it as an error).
- Timeouts: connect 10 s, total 30 s per request.

## Signing (Ed25519)

Headers:

| Header                 | Value                                                               |
| ---------------------- | ------------------------------------------------------------------- |
| `X-EDV-Key-Id`         | credential id (UUID) shown when the public key was registered       |
| `X-EDV-Timestamp`      | Unix time in seconds (must be within ±300 s of the server's clock)  |
| `X-EDV-Nonce`          | 16–64 chars of `A–Z a–z 0–9 _ -`, unique per request (never reused) |
| `X-EDV-Signature`      | standard base64 of the 64-byte Ed25519 signature                    |
| `X-EDV-Worker-Version` | worker version string (≤ 40 chars; recorded for display)            |

Signing string (lines joined with `\n`, no trailing newline):

```text
EDV1
POST
/api/v1/internal/worker/<endpoint>
<timestamp>
<nonce>
<lowercase hex SHA-256 of the exact request body bytes>
```

A nonce is consumed as soon as authentication succeeds, so **every retry must be re-signed with a new
nonce and timestamp**. More than 120 requests per minute per key → `429`.

**Test vector** (RFC 8032 test 1 key; both implementations assert it):

```json
{
  "seedHex": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  "publicKeyB64": "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
  "body": "{\"profiles\":[\"passive\"]}",
  "bodySha256": "def6b531b6f37f9c565098a3ac8c254408e4ed44786231270b37aa796805b174",
  "signingString": "EDV1\nPOST\n/api/v1/internal/worker/claim\n1792656000\nvector-nonce-0123456789abcdef\ndef6b531b6f37f9c565098a3ac8c254408e4ed44786231270b37aa796805b174",
  "signatureB64": "ZezimbXKZPd6JLSnkaX3KsoP2/w/b/UCe2jDS3DGdsbswJ3XZ5nzjH//t/NgiZ2N15xQyUS/JW0704Lw+gTMBw=="
}
```

## Endpoints

| Endpoint    | Request                                                                                                 | Response                                                |
| ----------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| `claim`     | `{ "profiles"?: ["passive"] }`                                                                          | `{ "job": ClaimedJob \| null }`                         |
| `heartbeat` | `{ jobId, attempt, progress?: { completedTargets, totalTargets, message? } }`                           | `{ leaseExpiresAt, cancelRequested, approvedNetworks }` |
| `results`   | `{ jobId, attempt, resultId, targets: [{ targetId, status, errorCode? }], observations: [], complete }` | `{ accepted, status }` (`accepted: false` = duplicate)  |
| `failures`  | `{ jobId, attempt, errorCode, errorSummary, retryable }`                                                | `{ status, retryAt }`                                   |

`ClaimedJob`: `{ id, attempt, profile, leaseExpiresAt, leaseSeconds, heartbeatSeconds, snapshot,
targets: [{ id, hostname, ip }] }`. `snapshot.profile.config` holds `active`, `checks`, `tcpPorts`,
`timeouts { connectMs, readMs, targetSeconds }`, `concurrency`, `ratePerSecond`, `maxTargets`;
`snapshot.domain.fqdn` is the job's domain; `snapshot.targets` lists every approved target hostname of
the job; `snapshot.approvedNetworks` is the job's network scope (creation-time snapshot intersected
with the approvals still active at claim; always `[]` for passive profiles).

Rules the worker must follow:

- `attempt` from `claim` is a fencing token: send it with every call. `409` means stop work on that job
  immediately and do not report further. It is returned when the lease is lost, and also by `results`
  when the job is no longer authorised for active checks and the submission carries `tls`, `http` or
  `port` observations (see below).
- Heartbeat every `heartbeatSeconds` (60) while working. If `cancelRequested` is true, stop and report
  `failures` with `errorCode: "cancelled"`.
- `approvedNetworks` in the heartbeat response is the job's **current** network scope (snapshot ∩
  approvals active now; `[]` for passive jobs and for jobs that are no longer authorised). The worker
  replaces its scope with the intersection of what it holds and this list before starting any further
  check (`ScopePolicy.with_approved_networks_shrunk`): scope can only shrink, never grow. Malformed
  entries, or entries broader than /8 (IPv4) or /20 (IPv6), count as nothing approved.
- `resultId` (8–128 chars `A–Z a–z 0–9 _ -`) is an idempotency key: generate it once per batch and
  reuse it on retries of that same batch. Batches: ≤ 500 observations and ≤ 1000 target updates.
- The final batch sets `complete: true`; targets not reported by then are marked failed by the server.
- `errorCode` matches `^[a-z0-9_]{1,64}$`; `errorSummary` ≤ 500 chars, no secrets or stack traces.
- **Never run a check the profile does not list, never contact a host that is not a target, and never
  run a network-connecting check while active scanning is disabled.** Passive checks (`dns`, `rdap`)
  query resolvers and registries only.

### Authorisation withdrawn mid-job

Every `heartbeat` and `results` call re-runs the claim-time authorisation check
(`services/job-lifecycle.ts` `heldJobRefusal`): server `ACTIVE_SCANNING_ENABLED` still `true` (active
profiles), domain still present and authorised for active scanning (verified, review date not passed),
and monitoring still on (scheduled jobs). Revoking a domain (`revokeDomain`) or its authorisation
lapsing (`expireStaleChallenges`, also run by the Cron Trigger) additionally flags the domain's
claimed/running active jobs in the same transaction, and cancels its queued ones. When a held job is no
longer authorised:

- the server sets `cancel_requested_at` (audited `scan.cancel_requested`, actor `system`, with the
  reason);
- `heartbeat` answers `200` with `cancelRequested: true` and `approvedNetworks: []`;
- `results` with any `tls`/`http`/`port` observation is refused as a whole with `409 conflict` (the
  cancellation flag is committed first); status-only and passive (`dns`/`registration`) submissions are
  still accepted so the job can wind down.

The worker then stops and reports `failures` with `cancelled`; the job ends `cancelled`.

## Observations (Milestone 5)

Common fields: `kind`, `targetId`, `observedAt` (ISO UTC), `checkerVersion`, `resultStatus`
(`success|partial|error|timeout|skipped`), `evidence` (object ≤ 16 KB, no secrets).

- `dns`: `hostname` (lowercase A-label, no trailing dot; the target or a name beneath the job domain
  such as `_dmarc.<domain>`), `recordType` (`A AAAA CNAME MX NS TXT CAA SOA DS DNSKEY`), `ttl`
  (int or null), `values` (presentation format, sorted, ≤ 100). NXDOMAIN/NODATA → `success` with
  `values: []` and `evidence.rcode`; resolver failure → `error`/`timeout`.
  Normalisation as implemented: names inside values keep the trailing dot (presentation format, e.g.
  `10 mx.example.com.`, null MX `0 .`); CNAME/NS/MX/SOA values are lowercased (resolvers may randomise
  case), TXT/CAA/DS/DNSKEY keep their case. NODATA is `success`, `values: []`,
  `evidence: { rcode: "NOERROR", noData: true }`. Queried per target: A, AAAA, CNAME; at the apex also
  MX, NS, TXT, CAA, SOA, DS, DNSKEY and `_dmarc.<apex>` TXT.
- `registration` (RDAP, apex target only): `registrar`, `registeredAt`, `expiresAt` (ISO or null),
  `nameservers` (lowercase, no trailing dot), `dataStatus` (`available` | `redacted` when the registry
  withholds data | `unavailable` when no RDAP data could be obtained).

## Active checks (Milestone 6)

Tiers (owner decision): **web** checks (`tls_certificate`, `http_availability`, `http_headers`) may
connect to any public address an in-scope hostname resolves to; **network** checks (`tcp_ports`,
`service_identification`, `tls_configuration`) only to addresses inside the job's approved networks
(`snapshot.approvedNetworks`, shrunk by heartbeats). Every connection goes resolve → validate →
connect to the validated IP (pinned; SNI/Host set separately). CNAME chains must stay within the job's
domain. Prohibited addresses (the shared table in `packages/shared/src/net/prohibited-ranges.ts`,
mirrored in `worker/app/policy.py`), the operator deny list and this host's own and egress addresses
(self-protection) are always refused. Details: [`scan-safety.md`](scan-safety.md).

Redirects are never auto-followed. Each hop is re-parsed, re-resolved and re-validated (≤ 5 redirects)
and is followed only when the new URL

1. is inside the job's domain (`redirect_out_of_scope` otherwise);
2. names the first URL's host or one of the job's approved target hostnames (the claimed targets plus
   the in-domain hostnames in `snapshot.targets`) (`redirect_not_approved_target` otherwise — other
   names under the domain, e.g. pending CT discoveries, are neither resolved nor contacted);
3. uses the scheme's default port (80/443) or the first URL's explicit port (`port_not_allowed`
   otherwise).

All hops of one URL share one deadline, `min(start + 2 × timeout, target's remaining budget)`, and the
job's stop signal is checked before every hop (`stopped`).

The worker refuses a job domain that is a single label, under `.arpa` or a built-in public suffix
(`co.uk`, `github.io`, `workers.dev`, …; about 150 entries) with `scope_rejected` — a backstop; the
server enforces the full Public Suffix List when a domain is added.

Additional observation kinds (all with the common fields):

- `tls`: `check` (`tls_certificate`, the default, or `tls_configuration`), `hostname` (SNI; **must
  equal the observation's target hostname**), `ipAddress` (pinned), `port`, `protocolVersion`,
  `notBefore`, `notAfter`, `issuer`, `subject`, `subjectAltNames`, `fingerprintSha256` (lowercase
  hex), `hostnameMatches`. Evidence: `{ trusted, verifyError? }` (the chain is not exposed, so no
  chain length). The server rejects `check: "tls_configuration"` unless the profile lists that check
  and `ipAddress` lies inside the job's networks as intersected at ingestion; it stores the check name
  in the stored row's `evidence.check` (server-set, so the worker cannot mislabel it). The worker
  currently only produces `tls_certificate` observations.
- `http`: `url` (first request; its host **must equal the observation's target hostname**),
  `ipAddress` (first hop), `statusCode`, `finalUrl`, `redirectCount`, `hstsEnabled`. Evidence (as
  implemented): `hops` (each `{ url, ip, status, decision, error? }`; decision `followed`, `final`,
  `stopped`, or a refusal: `redirect_out_of_scope`, `redirect_not_approved_target`,
  `port_not_allowed`, `scheme_not_allowed`, `too_many_redirects`, `invalid_url`, `out_of_scope_host`,
  `prohibited_address`, `no_allowed_address`, `cname_out_of_scope`, `cname_chain_invalid`, `error`);
  with `http_headers` also `securityHeaders` (`strict-transport-security`, `content-security-policy`,
  `x-content-type-options`, `x-frame-options`, `referrer-policy`, `permissions-policy` → value or
  null), `server` and `xPoweredBy` (version disclosure; values ≤ 512 printable ASCII chars). Never
  cookies or bodies. A refused redirect makes the observation `partial`.
- `port`: `ipAddress`, `port` (must be in the profile's `tcpPorts`), `protocol: "tcp"`,
  `state` (`open|closed|filtered`), `service`. Evidence: `{ method: "nmap-sT", reason?, product?,
version?, serviceMethod? }`. `tls_configuration` is accepted in profiles but not run yet (no
  per-version handshakes; logged `check_not_implemented`); the negotiated version is recorded in
  `tls.protocolVersion`.

Hostnames in observations are validated syntactically (`packages/shared/src/hostname/labels.ts`
`isValidHostname`): lowercase LDH A-labels of 1–63 characters, at least two labels, no empty labels;
`dns` query names may additionally start with `_` service labels (`_dmarc.example.com`). Evidence is
limited to 16 KB measured in UTF-8 bytes.

The server re-validates: hostnames within the domain (and, for `tls`/`http`, equal to the target's
hostname), addresses public, ports in the profile, and `port` (and `tls_configuration`) addresses inside
the job's approved networks at ingestion time.

## Error codes

Job-level codes (sent by the worker in `failures`, or set by the server when it refuses a job):

| Code                                                                                                        | Meaning                                                                                                                                      |
| ----------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `cancelled`                                                                                                 | The worker stopped because `cancelRequested` was true (user cancel or authorisation withdrawn).                                              |
| `profile_not_supported`, `unsupported_check`, `invalid_profile`, `invalid_job`                              | The worker refused the job before running anything (profile not in `EXDV_PROFILES`, unknown check, malformed job).                           |
| `active_scanning_disabled`                                                                                  | Worker: active job while `EXDV_ACTIVE_SCANNING_ENABLED` is not `true`. Server: active job claimed while the server flag is off.              |
| `scope_rejected`                                                                                            | Worker: a target outside the domain or not in the snapshot, too many targets, or a non-registrable job domain.                               |
| `domain_missing`, `domain_not_authorised`, `monitoring_disabled`, `invalid_snapshot`, `no_approved_targets` | Server, at claim: the job is cancelled instead of being handed out. `no_approved_targets`: every remaining target's asset lost its approval. |

Target-level codes (`targets[].errorCode`):

| Code                                                                                                                                                                                                 | Meaning                                                                                                                                    |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `asset_not_approved`                                                                                                                                                                                 | Server, at claim of an active job: the target's asset is no longer `approved` (rejected, suspended or deleted); the target is `skipped`.   |
| `egress_ip_unknown`                                                                                                                                                                                  | Worker self-protection: the public egress IPv4 could not be detected and `EXDV_DENY_NETWORKS` is empty, so web/network checks fail closed. |
| `out_of_scope_host`, `cname_out_of_scope`, `cname_chain_invalid`, `no_allowed_address`, `prohibited_address`, `deny_listed`, `network_not_approved`, `check_not_allowed`, `active_scanning_disabled` | Scope validator refusals (`worker/app/policy.py`).                                                                                         |
| `target_timeout`, `http_error`, `http_timeout`, `nmap_unavailable`, `nmap_timeout`, `nmap_failed`, `nmap_output_too_large`, `nmap_output_invalid`, `nmap_no_results`                                 | Check failures.                                                                                                                            |
| `not_reported`                                                                                                                                                                                       | Server: the target was not reported before `complete: true`.                                                                               |

RDAP failures are not target codes: they are recorded in the `registration` observation's
`evidence.error` (`resultStatus` `error`/`timeout`). Besides the bootstrap/HTTP codes
(`bootstrap_unavailable`, `invalid_bootstrap`, `http_error`, `invalid_json`, `invalid_response`,
`response_too_large`, `too_many_redirects`, `redirect_without_location`, `non_https_url`), a registry
redirect is checked **before** it is followed: it must be HTTPS to a valid host name or a public IP
literal, and every A/AAAA answer for the host (through the worker's resolver) must pass the prohibited
table; otherwise `redirect_invalid_host`, `redirect_prohibited_address`, `redirect_unresolvable`,
`redirect_resolution_failed` or `redirect_unverifiable` (no resolver configured). httpx resolves the
name again itself, so this is a pre-check, not pinning; the systemd `IPAddressDeny=` filter backs it up.

## Worker configuration (environment)

| Variable                       | Required | Meaning                                                                                                                                                                                                                                                                                                               |
| ------------------------------ | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `EXDV_API_BASE_URL`            | yes      | e.g. `https://exdomainvault.amrin78.workers.dev`; `https` required outside development                                                                                                                                                                                                                                |
| `EXDV_WORKER_ID`               | yes      | worker name as registered (informational, in logs)                                                                                                                                                                                                                                                                    |
| `EXDV_KEY_ID`                  | yes      | credential id (UUID) of the registered public key                                                                                                                                                                                                                                                                     |
| `EXDV_PRIVATE_KEY_FILE`        | yes      | PEM (PKCS#8) Ed25519 private key, e.g. from `openssl genpkey -algorithm ed25519`; must not be group/world readable (set by the systemd unit to its `LoadCredential=` copy)                                                                                                                                            |
| `EXDV_ACCESS_CLIENT_ID`        | no       | Cloudflare Access service token id (set together with the secret)                                                                                                                                                                                                                                                     |
| `EXDV_ACCESS_CLIENT_SECRET`    | no       | Cloudflare Access service token secret                                                                                                                                                                                                                                                                                |
| `EXDV_ENVIRONMENT`             | no       | `production` (default) or `development`                                                                                                                                                                                                                                                                               |
| `EXDV_POLL_INTERVAL_SECONDS`   | no       | idle poll interval, 5–3600, default 30                                                                                                                                                                                                                                                                                |
| `EXDV_PROFILES`                | no       | comma-separated profiles to claim, default `passive` (e.g. `passive,quick,standard`)                                                                                                                                                                                                                                  |
| `EXDV_ACTIVE_SCANNING_ENABLED` | no       | `true` to run active (target-connecting) checks; default `false`. Only `true`/`false` accepted (anything else stops start-up). Read at start-up. The server's `ACTIVE_SCANNING_ENABLED` must also be `true`.                                                                                                          |
| `EXDV_DENY_NETWORKS`           | no       | Extra networks never contacted, on top of the prohibited ranges: comma-separated canonical CIDRs (host bits zero) or single addresses, ≤ 100; a malformed entry stops start-up. Put the home's public IPv4 (`/32`) and IPv6 prefix (`/64`) here. **IPv6-only hosts must set it** (egress detection only counts IPv4). |
| `EXDV_NMAP_PATH`               | no       | absolute path without whitespace, default `/usr/bin/nmap`; network checks fail (`nmap_unavailable`) if it is not an executable file                                                                                                                                                                                   |
| `EXDV_DNS_RESOLVERS`           | no       | comma-separated resolver IPs; default `1.1.1.1,9.9.9.9` (+ IPv6); `system` = host resolver                                                                                                                                                                                                                            |
| `EXDV_HEALTH_FILE`             | no       | health JSON path, default `/var/lib/exdomainvault-worker/health.json`                                                                                                                                                                                                                                                 |
| `EXDV_LOG_LEVEL`               | no       | `DEBUG INFO WARNING ERROR`, default `INFO`                                                                                                                                                                                                                                                                            |

**Self-protection** (`worker/app/self_protection.py`, only while `EXDV_ACTIVE_SCANNING_ENABLED=true`):
at start-up and then hourly the worker adds to every active job's deny list (a) every address on a
local interface (IPv4 from `/proc/self/net/fib_trie`, fallback `SIOCGIFADDR`; global IPv6 addresses
as their /64, others as /128) and (b) its public egress address(es) from one `whoami.cloudflare` CHAOS
TXT query to `1.1.1.1` and `2606:4700:4700::1111` (a resolver query, not a target contact; IPv6 egress
denied as its /64). A previously detected egress address stays denied if a later detection fails. If no
IPv4 egress address is detected **and** `EXDV_DENY_NETWORKS` is empty, web and network checks fail
closed with `egress_ip_unknown` until a later detection succeeds. Detected values are logged
(`self_protection_refreshed`).
