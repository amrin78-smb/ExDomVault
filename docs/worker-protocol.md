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

| Endpoint    | Request                                                                                                 | Response                                               |
| ----------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| `claim`     | `{ "profiles"?: ["passive"] }`                                                                          | `{ "job": ClaimedJob \| null }`                        |
| `heartbeat` | `{ jobId, attempt, progress?: { completedTargets, totalTargets, message? } }`                           | `{ leaseExpiresAt, cancelRequested }`                  |
| `results`   | `{ jobId, attempt, resultId, targets: [{ targetId, status, errorCode? }], observations: [], complete }` | `{ accepted, status }` (`accepted: false` = duplicate) |
| `failures`  | `{ jobId, attempt, errorCode, errorSummary, retryable }`                                                | `{ status, retryAt }`                                  |

`ClaimedJob`: `{ id, attempt, profile, leaseExpiresAt, leaseSeconds, heartbeatSeconds, snapshot,
targets: [{ id, hostname, ip }] }`. `snapshot.profile.config` holds `active`, `checks`, `tcpPorts`,
`timeouts { connectMs, readMs, targetSeconds }`, `concurrency`, `ratePerSecond`, `maxTargets`;
`snapshot.domain.fqdn` is the job's domain.

Rules the worker must follow:

- `attempt` from `claim` is a fencing token: send it with every call. `409` means the lease is lost —
  stop work on that job immediately and do not report further.
- Heartbeat every `heartbeatSeconds` (60) while working. If `cancelRequested` is true, stop and report
  `failures` with `errorCode: "cancelled"`.
- `resultId` (8–128 chars `A–Z a–z 0–9 _ -`) is an idempotency key: generate it once per batch and
  reuse it on retries of that same batch. Batches: ≤ 500 observations and ≤ 1000 target updates.
- The final batch sets `complete: true`; targets not reported by then are marked failed by the server.
- `errorCode` matches `^[a-z0-9_]{1,64}$`; `errorSummary` ≤ 500 chars, no secrets or stack traces.
- **Never run a check the profile does not list, never contact a host that is not a target, and never
  run a network-connecting check while active scanning is disabled.** Passive checks (`dns`, `rdap`)
  query resolvers and registries only.

## Observations (Milestone 5)

Common fields: `kind`, `targetId`, `observedAt` (ISO UTC), `checkerVersion`, `resultStatus`
(`success|partial|error|timeout|skipped`), `evidence` (object ≤ 16 KB, no secrets).

- `dns`: `hostname` (lowercase A-label, no trailing dot; the target or a name beneath the job domain
  such as `_dmarc.<domain>`), `recordType` (`A AAAA CNAME MX NS TXT CAA SOA DS DNSKEY`), `ttl`
  (int or null), `values` (presentation format, sorted, ≤ 100). NXDOMAIN/NODATA → `success` with
  `values: []` and `evidence.rcode`; resolver failure → `error`/`timeout`.
- `registration` (RDAP, apex target only): `registrar`, `registeredAt`, `expiresAt` (ISO or null),
  `nameservers` (lowercase, no trailing dot), `dataStatus` (`available` | `redacted` when the registry
  withholds data | `unavailable` when no RDAP data could be obtained).

## Worker configuration (environment)

| Variable                     | Required | Meaning                                                                                                            |
| ---------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------ |
| `EXDV_API_BASE_URL`          | yes      | e.g. `https://exdomainvault.amrin78.workers.dev`; `https` required outside development                             |
| `EXDV_WORKER_ID`             | yes      | worker name as registered (informational, in logs)                                                                 |
| `EXDV_KEY_ID`                | yes      | credential id (UUID) of the registered public key                                                                  |
| `EXDV_PRIVATE_KEY_FILE`      | yes      | PEM (PKCS#8) Ed25519 private key, e.g. from `openssl genpkey -algorithm ed25519`; must not be group/world readable |
| `EXDV_ACCESS_CLIENT_ID`      | no       | Cloudflare Access service token id (set together with the secret)                                                  |
| `EXDV_ACCESS_CLIENT_SECRET`  | no       | Cloudflare Access service token secret                                                                             |
| `EXDV_ENVIRONMENT`           | no       | `production` (default) or `development`                                                                            |
| `EXDV_POLL_INTERVAL_SECONDS` | no       | idle poll interval, 5–3600, default 30                                                                             |
| `EXDV_PROFILES`              | no       | comma-separated profiles to claim, default `passive`                                                               |
| `EXDV_DNS_RESOLVERS`         | no       | comma-separated resolver IPs; default system resolvers                                                             |
| `EXDV_HEALTH_FILE`           | no       | health JSON path, default `/var/lib/exdomainvault-worker/health.json`                                              |
| `EXDV_LOG_LEVEL`             | no       | `DEBUG INFO WARNING ERROR`, default `INFO`                                                                         |

Active scanning is **not** configurable: it is hard-coded off until Milestone 6.
