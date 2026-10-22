# Scan safety

Principle: ExDomainVault only contacts what it is authorised to contact, with server-defined behaviour,
and every decision is explainable. This document describes the controls **as implemented** at
Milestone 6. Nothing here performs exploitation, credential testing or destructive checks.

Related: [`threat-model.md`](threat-model.md), [`worker-protocol.md`](worker-protocol.md),
[`home-worker-setup.md`](home-worker-setup.md).

## Current state

- Active (target-connecting) checks are implemented behind the Milestone 6 scope validator
  (`worker/app/policy.py`) and pinned network primitives (`worker/app/net.py`).
- Active scanning is **off** unless both independent kill switches are turned on (see
  [Kill switches](#kill-switches)). `apps/web/wrangler.jsonc` ships `ACTIVE_SCANNING_ENABLED: "false"`;
  the worker defaults `EXDV_ACTIVE_SCANNING_ENABLED` to `false`, and the shipped `worker.env`
  (`worker/deploy/install.sh`, `worker/.env.example`) sets `EXDV_PROFILES=passive`.
- Passive checks (`dns`, `rdap`) query public resolvers and registries only and never contact the
  domain's own hosts.

## Tiered policy (owner decision)

Every check belongs to exactly one tier (`policy.tier_of`, `PASSIVE_TIER_CHECKS` / `WEB_TIER_CHECKS` /
`NETWORK_TIER_CHECKS`; mirrored server-side by `PASSIVE_CHECKS` / `WEB_CHECKS` / `NETWORK_CHECKS` in
`packages/shared/src/api/scans.ts`). An unknown check is refused (`check_not_allowed`).

| Tier    | Checks                                                     | May contact                                                                                              |
| ------- | ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| passive | `dns`, `rdap`                                              | Configured DNS resolvers, IANA RDAP bootstrap and the registry's RDAP server. Never a target host.       |
| web     | `tls_certificate`, `http_availability`, `http_headers`     | Any **public** address an in-scope hostname resolves to (browser-like: one handshake / one GET per hop). |
| network | `tcp_ports`, `service_identification`, `tls_configuration` | Only public addresses **inside the job's admin-approved networks**.                                      |

Domain verification never authorises the network tier on its own: a verified domain hosted on a CDN or
cloud provider gets web checks only, unless an administrator approves the specific network
(`/api/v1/approved-networks`, permission `scan_policies:manage`, admin only).

## Requirement mapping (Milestone 6)

The 14 requirements from `docs/prompts/00-master-build-prompt.md` §5 Milestone 6. Python paths are under
`worker/`, TypeScript under `apps/web/worker/` unless stated.

| #   | Requirement                                                              | Implementation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Tests                                                                                                                                                                                                                                                                                                                                                                                                          |
| --- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Accept only approved scan profiles                                       | Server: `services/scans.ts` `getProfile` (known, enabled, `scanProfileConfigSchema`-valid; invalid stored profiles are dropped by `listProfiles`). Schema forbids non-passive checks on non-active profiles and ports without `tcp_ports`. Worker: `app/queue.py` `parse_job` (range-checks every config field), `Worker._refusal` (profile must be in `EXDV_PROFILES`, checks in `KNOWN_CHECKS`, connecting checks only on active profiles), `ScopePolicy.assert_check_allowed` (check must be listed in the job's profile). | `routes/scans.test.ts` ("enforces permissions and validates the profile"); `tests/test_queue.py` (`test_unknown_check_is_refused`, `test_non_active_profile_with_connecting_checks_is_refused`, `test_malformed_tcp_ports_make_the_job_invalid`); `tests/test_policy.py` (`test_check_must_be_in_profile`, `test_tier_of_unknown_check`)                                                                       |
| 2   | Targets derived from approved database records                           | `services/scans.ts` `resolveTargets` (approved assets only; apex approved via verification and audited `asset.approved`; never re-approves a rejected/suspended apex; capped at `maxTargets`); immutable `scope_snapshot`. Worker: `scope.validate_job_targets` and `ScopePolicy.from_job` (every target in the domain **and** listed in the snapshot, else `scope_rejected`). Server: `job-lifecycle.ts` `submitResultsDetailed` rejects target ids outside the job.                                                         | `routes/scans.test.ts` ("approves the apex … snapshots approved targets only", "never implicitly re-approves a rejected apex", "rejects results for targets outside the job snapshot"); `tests/test_policy.py` `test_from_job_validates_targets_against_domain_and_snapshot`; `tests/test_queue.py` `test_target_outside_domain_is_refused`                                                                    |
| 3   | Exact DNS label boundaries                                               | Worker: `scope.normalise_hostname`, `scope.name_within_domain`, `ScopePolicy.assert_hostname` (`name == domain or name.endswith("." + domain)` after strict A-label normalisation). Server: `isWithinDomain` (`packages/shared/src/hostname/normalise.ts`), used by `resolveTargets` and observation ingestion.                                                                                                                                                                                                               | `tests/test_policy.py` (`test_hostname_within_domain`, `test_hostname_label_boundary_bypasses`); `tests/test_scope.py` `test_name_within_domain_label_boundaries`; `packages/shared/src/hostname/normalise.test.ts` (`isWithinDomain`)                                                                                                                                                                         |
| 4   | Validate IPv4 and IPv6 destinations                                      | Worker: `policy.parse_address` — canonical dotted quad only (rejects octal, hex, integer, short forms), IPv6 without zone ids, brackets or whitespace; `parse_network` with host bits zero. Server: `packages/shared/src/net/ip.ts` `parseIp` / `parseCidr` (same strictness, BigInt).                                                                                                                                                                                                                                        | `tests/test_policy.py` (`test_parse_address_rejects_non_canonical`, `test_parse_address_accepts_canonical`, `test_parse_network_strict`); `packages/shared/src/net/ip.test.ts` (`parseIp`, CIDR helpers)                                                                                                                                                                                                       |
| 5   | Reject loopback, private, link-local, multicast, reserved and prohibited | `policy.address_prohibited_reason` (explicit tables, IPv6 outside `2000::/3` refused, stdlib properties as a fail-closed backstop), operator deny list `EXDV_DENY_NETWORKS` (`deny_listed`). Server: `prohibitedReason` / `isProhibitedAddress` in `ip.ts` for approved networks and observations. See [Prohibited addresses](#prohibited-addresses).                                                                                                                                                                         | `tests/test_policy.py` (`test_prohibited_ranges_both_edges`, `test_ipv6_transition_and_embedded_forms`, `test_public_unicast_is_allowed`, `test_scoped_ipv6_object_is_refused`, `test_deny_list_always_refused`, `test_no_flag_permits_loopback`); `ip.test.ts` (`isProhibitedAddress`)                                                                                                                        |
| 6   | Validate every resolved destination immediately before connecting        | `ScopePolicy.resolve` validates each A/AAAA answer; `ScopePolicy.assert_destination` re-validates the exact address inside `net.connect_tcp` (the only place a target socket is opened) before the socket exists; `port_checks.check_tcp_ports` re-asserts every address immediately before starting Nmap.                                                                                                                                                                                                                    | `tests/test_net.py` (`test_connect_tcp_refuses_before_creating_a_socket`, `test_connect_tcp_network_tier_needs_approved_network`); `tests/test_port_checks.py` `test_any_refused_address_aborts_before_nmap_runs`; `tests/test_policy.py` `test_assert_destination_*`                                                                                                                                          |
| 7   | Prevent DNS rebinding and TOCTOU                                         | The validated address object is what gets connected to (pinning, below); no component re-resolves the name between check and use. `resolve` refuses a CNAME chain that changed between the hop-by-hop walk and the address query (`cname_chain_invalid`). Nmap is given literal addresses with `-n`.                                                                                                                                                                                                                          | `tests/test_policy.py` (`test_rebinding_resolve_then_assert_destination`, `test_resolve_chain_changed_between_queries_refused`); `tests/test_net.py` (`test_rebinding_connection_uses_pinned_validated_address`, `test_connect_tcp_does_no_name_resolution`)                                                                                                                                                   |
| 8   | Validate every redirect destination                                      | `net.http_get`: redirects are never followed automatically; each `Location` is parsed strictly (`_parse_url`), its host checked with `assert_hostname`, then resolved and validated through `resolve` and pinned like the first hop. See [Redirects](#http-redirects).                                                                                                                                                                                                                                                        | `tests/test_net.py` (`test_redirect_hop_is_resolved_and_pinned_separately`, `test_redirect_to_ip_literal_is_refused_without_connecting`, `test_redirect_to_in_scope_name_resolving_private`, `test_redirect_out_of_scope_host`, `test_redirect_scheme_not_allowed`, `test_redirect_loop_is_cut`, `test_redirect_cap`); `tests/test_http_checks.py` `test_refused_redirect_is_partial_and_stops_at_the_refusal` |
| 9   | Reject out-of-scope CNAME targets unless separately approved             | `ScopePolicy.resolve` walks the chain hop by hop; any hop outside the job's domain is refused (`cname_out_of_scope`), as are loops, more than 8 hops and multiple CNAMEs at one name (`cname_chain_invalid`). **There is no "separately approved" mechanism: out-of-scope CNAME targets are always refused.**                                                                                                                                                                                                                 | `tests/test_policy.py` (`test_resolve_follows_in_scope_cname_chain`, `test_resolve_cname_leaving_domain`, `test_resolve_cname_out_and_back_in_is_refused`, `test_resolve_cname_loop`, `test_resolve_cname_chain_cap`, `test_resolve_multiple_cnames_refused`); `tests/test_net.py` `test_http_get_cname_escape`                                                                                                |
| 10  | Pin validated destination addresses                                      | `net.connect_tcp` connects to the literal validated address; `tls_handshake` and `_exchange` pass the hostname only as SNI / `Host`; the non-verifying certificate-capture handshake reuses the same pinned address. Nmap receives validated literal IPs (`-n`, no hostnames).                                                                                                                                                                                                                                                | `tests/test_net.py` (`test_connect_tcp_connects_to_exact_literal_address`, `test_https_default_port_and_pinning`, `test_tls_handshake_pins_ipv6`); `tests/test_port_checks.py` `test_scan_runs_on_validated_network_tier_addresses`                                                                                                                                                                            |
| 11  | Timeouts, concurrency caps, request and rate limits                      | See [Resource limits](#resource-limits). `checks.CheckContext` (per-target deadline), `checks.RateLimiter` (per job), `ThreadPoolExecutor(max_workers=concurrency)`, `net` caps, Nmap `--max-rate` / `--max-parallelism` / `--host-timeout`; server: one queued/active job per domain and profile, `maxTargets`, 120 signed requests/min per worker key.                                                                                                                                                                      | `tests/test_net.py` (`test_connect_tcp_caps_timeout`, `test_slow_drip_headers_hit_the_hop_deadline`, `test_no_response_times_out`); `tests/test_port_checks.py` (`test_host_timeout_is_capped_by_the_remaining_budget`, `test_too_little_budget_left_is_a_target_timeout`); `routes/scans.test.ts` ("refuses a second queued or active job…", "rate-limits each credential")                                   |
| 12  | No user-supplied shell commands or scanner flags                         | Profiles are data (`scanProfileConfigSchema`, strict); there is no field for arguments. `port_checks.build_nmap_argv` is a fixed template filled only with validated integers and canonical IPs; `run_nmap` uses `shell=False`, argument list, `env={"PATH": "/usr/bin:/bin"}`. `EXDV_NMAP_PATH` must be absolute without whitespace.                                                                                                                                                                                         | `tests/test_port_checks.py` (`test_standard_profile_argv_is_exact`, `test_deep_profile_argv_is_exact_ipv6`, `test_argv_without_service_identification_and_never_dangerous_flags`, `test_invalid_profile_ports_are_refused`); `tests/test_config.py` `test_nmap_path_must_be_absolute_without_whitespace`                                                                                                       |
| 13  | Bound scanner output and process resources                               | `run_nmap`: stdout ≤ 2 MB (process group killed on overflow), stderr counted and discarded (≤ 64 KB accounted), wall-clock timeout, rlimits; XML screened for DTDs/entities before parsing. HTTP: headers ≤ 32 KB / 100 headers, body ≤ 64 KB read and discarded. systemd `MemoryMax=512M`, `TasksMax=64`, `CPUQuota=50%`.                                                                                                                                                                                                    | `tests/test_port_checks.py` (`test_run_returns_stdout_with_minimal_env_and_rlimits`, `test_oversized_output_kills_the_process`, `test_timeout_kills_the_process_group`, `test_stop_request_kills_the_process`, `test_dtds_and_entities_are_refused`); `tests/test_net.py` (`test_oversized_headers_are_bounded`, `test_header_count_is_bounded`, `test_body_is_bounded`)                                       |
| 14  | Record scope validation decisions in logs                                | `ScopePolicy._log` emits a structured `scope_decision` event (`jobId`, `subject`, `tier`, `allowed`, `reason`) for every check, host, CNAME hop, address and destination decision. Also `approved_network_ignored`, `check_refused`, `check_failed`, `nmap_started`, `nmap_failed`. Server: audit `scan.refused`, `network.approved`, `network.revoked`, `scan.requested`.                                                                                                                                                    | `tests/test_policy.py` `test_every_decision_is_logged_as_structured_json`, `test_resolve_mixed_answers_keeps_only_public`; `routes/networks.test.ts` ("approves … and audits the approval", "revokes an approval, audits it…")                                                                                                                                                                                 |

## Prohibited addresses

Worker table (`policy._IPV4_PROHIBITED`, `policy._IPV6_PROHIBITED`); first match gives the reason.

| Range                                               | Reason          | Range                                       | Reason            |
| --------------------------------------------------- | --------------- | ------------------------------------------- | ----------------- |
| `0.0.0.0/8`                                         | `unspecified`   | `::/128`                                    | `unspecified`     |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`     | `private`       | `::1/128`                                   | `loopback`        |
| `100.64.0.0/10`                                     | `cgnat`         | `::ffff:0:0/96`, `::ffff:0:0:0/96`          | `ipv4_mapped`     |
| `127.0.0.0/8`                                       | `loopback`      | `::/96`                                     | `ipv4_compatible` |
| `169.254.0.0/16`                                    | `link_local`    | `64:ff9b::/96`, `64:ff9b:1::/48`            | `nat64`           |
| `192.0.0.0/24`                                      | `reserved`      | `100::/64`                                  | `discard`         |
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | `documentation` | `2001::/32`                                 | `teredo`          |
| `192.88.99.0/24`                                    | `6to4`          | `2001:2::/48`                               | `benchmarking`    |
| `198.18.0.0/15`                                     | `benchmarking`  | `2001:10::/28`, `2001:20::/28`, `2001::/23` | `reserved`        |
| `224.0.0.0/4`                                       | `multicast`     | `2001:db8::/32`, `3fff::/20`                | `documentation`   |
| `255.255.255.255/32`                                | `broadcast`     | `2002::/16`                                 | `6to4`            |
| `240.0.0.0/4`                                       | `reserved`      | `fc00::/7`                                  | `ula`             |
|                                                     |                 | `fe80::/10`                                 | `link_local`      |
|                                                     |                 | `fec0::/10`                                 | `site_local`      |
|                                                     |                 | `ff00::/8`                                  | `multicast`       |

Additionally:

- Any IPv6 address outside `2000::/3`, or with a scope id, is `reserved`.
- Every IPv6 transition form that embeds IPv4 (mapped, compatible, NAT64, 6to4, Teredo) is refused even
  when the embedded IPv4 address is public: the worker never reaches IPv4 through IPv6 forms.
- Backstop: if Python's `ipaddress` considers the address loopback, private, link-local, multicast,
  reserved, unspecified or not global, it is refused (`reserved`). The tables do not depend on those
  properties, which differ between Python releases.
- `EXDV_DENY_NETWORKS` (≤ 100 canonical CIDRs, validated at start-up; a malformed entry stops the worker,
  and `ScopePolicy.from_job` fails closed on one) adds operator-specific ranges — **the home's own public
  IP belongs here** — refused at every tier with reason `deny_listed`.
- There is no flag, environment variable or argument that permits a prohibited address. Tests that need
  a loopback server monkeypatch `address_prohibited_reason` for one address (`test_no_flag_permits_loopback`,
  `test_loopback_allowance_is_test_only`).

Server table: `PROHIBITED_RANGES` in `packages/shared/src/net/ip.ts` (same ranges except as noted under
[Residual risks](#what-is-not-done--residual-risks)); a range is refused if it overlaps a prohibited range
in either direction.

## Resolution, CNAMEs and pinning

`ScopePolicy.resolve(hostname, resolver, tier, lifetime)` (web and network tiers only):

1. `assert_hostname`: strict A-label normalisation; the name must be the job's domain or beneath it on
   a label boundary (`out_of_scope_host`), otherwise nothing is queried.
2. CNAME walk: query `CNAME` at the current name; every target must be a valid name inside the job's
   domain (`cname_out_of_scope`), with no loop, at most `MAX_CNAME_HOPS = 8`, and one CNAME per name
   (`cname_chain_invalid`). Each hop is logged.
3. Query `A` and `AAAA` at the final name. If the resolver's canonical name differs from the walked
   chain's end (the chain changed between queries), refuse (`cname_chain_invalid`).
4. Each answer is parsed strictly; wrong-family answers, prohibited, deny-listed and (network tier)
   unapproved addresses are dropped with a logged reason. Mixed answers keep only the allowed addresses.
   If none remain: `no_allowed_address`.

DNS errors (`NXDOMAIN`, timeout) propagate unchanged; NODATA is "no records". The resolver is
`dns_checks.DnspythonResolver` with its cache disabled, using `EXDV_DNS_RESOLVERS` (default Cloudflare
and Quad9 over IPv4/IPv6).

**Pinning.** `net.connect_tcp` calls `assert_destination` (re-validates the address, the tier, approved
networks, the deny list and the active-scanning flag) **before** creating a socket, then connects to
the literal address — no name resolution happens. TLS uses `server_hostname=<hostname>` for SNI and
certificate checking; HTTP sends `Host: <hostname>`. Because the connection never re-resolves, a
rebinding answer after validation cannot redirect it.

Address selection: `tls_certificate` checks at most the first allowed IPv4 and first allowed IPv6
address (`tls_checks.select_addresses`); HTTP uses the first allowed address per hop; port checks use
up to `MAX_ADDRESSES = 4` per target.

## HTTP redirects

`net.http_get` (http/https only, GET, `Connection: close`, written by hand on the pinned socket):

- Redirect statuses 301/302/303/307/308 with `Location` are followed manually, at most
  `MAX_REDIRECTS = 5` (callers may lower it). A URL seen before ends the chain (`too_many_redirects`).
- Each next URL is resolved against the current one, the fragment dropped, then parsed strictly:
  printable ASCII, ≤ 2048 chars, scheme `http`/`https` only (`scheme_not_allowed`), host must be a
  name — IP literals, brackets and userinfo are refused (`invalid_url`); explicit port 1–65535 without
  leading zero.
- The host must be inside the job's domain (`redirect_out_of_scope`, recorded without connecting);
  it is then resolved and validated by `resolve` and pinned exactly like the first hop.
- Every hop, including refused ones, is recorded in the `http` observation's `evidence.hops`
  (`url`, `ip`, `status`, `decision`, `error`). A refused redirect makes the observation `partial`.
- `https://` is tried first; `http://` only if the HTTPS attempt reached an address but got no HTTP
  response (`http_checks.check_http`).

## Nmap (network tier)

Built only by `port_checks.build_nmap_argv`; run by `run_nmap`:

```text
[nmap, -sT, -Pn, -n, --unprivileged, --max-retries, 1, --host-timeout, <T>s,
 --max-rate, <R>, --max-parallelism, <P>, -p, <ports>, (-sV --version-light), (-6),
 -oX, -, <ip>...]
```

- `<R>` = clamp(round(`ratePerSecond` × 10), 1, 100); `<P>` = clamp(`concurrency` × 4, 1, 16);
  `<T>` = max(5, min(`targetSeconds`, remaining target budget)). Seeded profiles: standard `R=10`,
  `P=8`; deep `R=5`, `P=4`.
- `<ports>`: the profile's `tcpPorts`, validated integers 1–65535, at most 1024, sorted and unique.
- `-sV --version-light` only when the profile lists `service_identification`. `-6` for IPv6; IPv4 and
  IPv6 are separate runs. No `--script`, `-O`, `-sS`, `-A` or any other option exists in the template.
- `<ip>`: canonical text of validated addresses (cannot start with `-`), each re-asserted with
  `assert_destination(tier="network")` immediately before the run; one refusal aborts the check before
  any process starts.
- Process: `shell=False`, stdin `/dev/null`, `env={"PATH": "/usr/bin:/bin"}` (no `HOME`, `NMAPDIR`),
  `close_fds`, new session; process group killed (`SIGKILL`) on timeout, output overflow or job stop;
  wall clock `<T> + 30 s`; rlimits `RLIMIT_AS` 512 MB, `RLIMIT_CPU` = wall clock + 1 s,
  `RLIMIT_NOFILE` 1024, no core dumps (clamped to existing hard limits).
- Output: XML on stdout ≤ 2 MB. Before parsing, any `<!ENTITY` or a DOCTYPE other than Nmap's bare
  `<!DOCTYPE nmaprun>` is refused. Only `(validated IP, profile port)` pairs become `port`
  observations; anything else Nmap reports is ignored. A run with no results fails the check
  (`nmap_no_results`), so an empty scan is never reported as "all closed".

## Resource limits

| Limit             | Value / source                                                                                                                                                                          |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Targets per job   | `maxTargets` (seeded 50; schema ≤ 1000), enforced at creation and by the worker                                                                                                         |
| Concurrency       | `concurrency` threads per job (seeded 1–4; schema ≤ 16); one job at a time per worker                                                                                                   |
| Rate              | `RateLimiter(ratePerSecond)` per job before every network step (DNS query set, TLS handshake, HTTP URL attempt, Nmap run; redirect hops within one attempt are not separately spaced)   |
| Per-target budget | `timeouts.targetSeconds` (`TargetTimeout` → target `failed`, `target_timeout`)                                                                                                          |
| Socket timeouts   | `connectMs` / `readMs`, clipped to the remaining budget; `net` caps any timeout at 60 s                                                                                                 |
| HTTP hop deadline | 2 × timeout per hop (slow-drip servers cannot hold the worker)                                                                                                                          |
| HTTP response     | headers ≤ 32 KB, ≤ 100 headers, values ≤ 2048 chars; body ≤ 64 KB read and discarded                                                                                                    |
| Redirects         | ≤ 5                                                                                                                                                                                     |
| Evidence          | ≤ 16 KB per observation; header values ≤ 512 printable ASCII; no cookies or bodies stored                                                                                               |
| Nmap              | see above                                                                                                                                                                               |
| Server            | one queued/claimed/running job per domain and profile (partial unique index); ≤ 3 attempts with backoff; worker API 120 req/min per key, body ≤ 1 MB, ≤ 500 observations per submission |
| systemd           | `MemoryMax=512M`, `TasksMax=64`, `CPUQuota=50%`, `LimitNOFILE=4096`                                                                                                                     |

## Server-side controls

**Job creation** (`services/scans.ts` `createScan`, permission `scans:request` — admin and analyst):
active profiles need `ACTIVE_SCANNING_ENABLED=true` and a currently authorised domain
(`domainAuthorisedForActive`: `verified` and review date not passed). The snapshot stores the domain
state, profile version and config, targets and — for active profiles only — the currently active
approved networks. Scheduled (Cron) jobs are passive only (`services/maintenance.ts`).

**Claim-time re-authorisation** (`services/job-lifecycle.ts` `claimJob` / `claimRefusal`): before an
active job is handed out, the server re-checks the flag (`active_scanning_disabled`) and the domain's
current authorisation (`domain_not_authorised`); a refused job is cancelled, its targets skipped, and
`scan.refused` audited. The snapshot's approved networks are **intersected** with the networks still
active (`networks.ts` `intersectNetworks`): revocation or expiry shrinks scope; nothing is added.

**Approved networks** (`services/networks.ts`): canonical CIDR, entirely public (no overlap with a
prohibited range, IPv6 within `2000::/3`), no broader than /16 (IPv4) or /32 (IPv6), no overlap with
another active approval, reason ≥ 10 chars, review date ≤ 24 months; approval and revocation audited
(`network.approved`, `network.revoked`). The worker additionally ignores (logs) malformed entries or
entries broader than /8 / /20.

**Ingestion re-validation** (`services/observations.ts` `validate`, in the results transaction): every
observation must reference a target of the job, have `observedAt` within −7 days / +5 minutes, and:
`dns` hostnames inside the domain; `registration` for the apex only; `tls`/`http`/`port` only for an
active profile listing a producing check; their `ipAddress` must be strictly-formatted public unicast
(`isProhibitedAddress`); `tls` hostname and `http` URL host (strict parser, no IP literals or userinfo)
inside the domain; `port` in the profile's `tcpPorts` and inside the job's networks as intersected
**at ingestion time**. Any invalid observation rejects the whole submission (400).

## Kill switches

Two independent switches; both must be on for any target connection.

| Switch                                  | Where                           | Effect when off                                                                                                                                                                                                                                                        |
| --------------------------------------- | ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ACTIVE_SCANNING_ENABLED` (server)      | `apps/web/wrangler.jsonc` var   | Active jobs refused at creation (409) and cancelled at claim (`active_scanning_disabled`). Only `"true"`/`"false"` accepted; anything else fails configuration closed (`config.ts` `parseFlag`). Changing it needs a deploy.                                           |
| `EXDV_ACTIVE_SCANNING_ENABLED` (worker) | `/etc/exdomainvault/worker.env` | Job with an active profile or connecting check refused before any check (`Worker._refusal`); and `assert_check_allowed` / `assert_destination` refuse every connection (`active_scanning_disabled`). Only `true`/`false`; read at start-up, so changes need a restart. |

`EXDV_PROFILES` is a further operator control: the worker claims only the listed profiles (default
`passive`). Neither switch interrupts a job that is already running; to stop one, cancel it (picked up
at the next heartbeat) or stop the service.

## Defence in depth: systemd egress filter

`worker/deploy/exdomainvault-worker.service` sets:

```ini
IPAddressAllow=127.0.0.53/32
IPAddressDeny=localhost link-local multicast 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 172.16.0.0/12 192.168.0.0/16 fc00::/7
```

systemd implements `IPAddressAllow=`/`IPAddressDeny=` as eBPF programs attached to the **unit's
cgroup**; they filter IP packets of every process in that cgroup. Child processes inherit their
parent's cgroup, and `start_new_session` changes the session, not the cgroup, so **Nmap launched by the
worker is subject to the same filter** (and to the unit's `MemoryMax`, `TasksMax`, `CPUQuota`, seccomp
filter and empty capability set). Caveats:

- It relies on cgroup v2 with BPF support in the kernel; it was not separately verified on the host
  with a test connection. Verify with e.g. `systemd-run -p IPAddressDeny=… curl …` if in doubt.
- It covers fewer ranges than the application tables (no documentation, benchmarking, `192.0.0.0/24`,
  `240.0.0.0/4` or IPv6 transition prefixes) and **not the home's public IP** (hair-pinning to the
  router). It is a backstop for LAN access, not a replacement for the scope validator.
- It applies to all of the worker's traffic, including RDAP and resolver queries; a LAN resolver needs
  an `IPAddressAllow=` entry.

## What is not done / residual risks

- **`tls_configuration` is not run.** It is accepted in the deep profile but only logged
  (`check_not_implemented`); `net` has no version-pinned handshake primitive. The negotiated version is
  recorded in `tls.protocolVersion`. The target's status does not reflect the skipped check.
- **Out-of-scope CNAME targets are always refused.** Requirement 9's "unless separately approved" has
  no mechanism, so hostnames that CNAME to a CDN or SaaS name outside the domain get no web or network
  checks (`cname_out_of_scope`).
- **Redirect and CNAME scope is domain-level, not target-level.** Any name under the job's domain is
  followed, including names that are not approved assets (e.g. still `pending`).
- **The resolver is trusted for public address choice.** Web checks go to whatever public address the
  domain's DNS returns; a domain owner (or a spoofed, non-DNSSEC-validated answer) can point a
  hostname at a third party's public address, which then receives one TLS handshake and HTTP GETs.
  Prohibited and deny-listed ranges are still enforced. Network checks are limited to approved
  networks.
- **`-sV` may run NSE scripts.** Nmap runs `version`-category NSE scripts when version detection is
  requested; they are non-intrusive probes but more than a bare connect. `--version-light` limits probe
  intensity. No other scripts can be selected.
- **`preexec_fn` in a threaded process.** Python documents `preexec_fn` as unsafe with threads (the
  child could deadlock before `exec`). The worker is multi-threaded (check pool, heartbeat); the
  limiter computes limits in the parent and only calls `setrlimit` in the child. A deadlocked child
  would be killed by the wall-clock timeout, but the check would fail.
- **Shared IPs are scanned once per target.** Targets resolving to the same address each trigger
  their own TLS/HTTP/Nmap work within one job; there is no per-address de-duplication or cross-job
  rate budget.
- **Revocation does not interrupt a running job.** Domain revocation or network revocation is applied
  at the next claim (and port observations are re-checked at ingestion), but the worker keeps the
  network list it was given until the job ends. Asset rejection after job creation does not shrink the
  job's target list.
- **Worker scope decisions stay local.** `scope_decision` events go to the home host's journal; only
  target `errorCode`s and observation evidence (hop decisions) reach the application.
- **RDAP redirects are not scope-validated.** RDAP follows ≤ 3 HTTPS-only redirects from registry
  servers without the address policy; only the systemd egress filter applies.
- **Server/worker table drift.** The server's `PROHIBITED_RANGES` lacks `3fff::/20` (documentation,
  RFC 9637) and the `2001::/23` aggregate that the worker refuses, so the server would accept an
  approved network or observation address there (the worker would still refuse to contact it).
  The worker's minimum approved prefix (/8, /20) is looser than the server's (/16, /32); the server is
  authoritative.
